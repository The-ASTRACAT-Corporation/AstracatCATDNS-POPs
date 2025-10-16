package resolver

import (
	"context"
	"log"
	"time"

    "dns-resolver/internal/backend"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
    "dns-resolver/internal/interfaces"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
    backend    interfaces.Backend
	workerPool *WorkerPool
	metrics    *metrics.Metrics
}

// NewResolver creates a new resolver instance.
func NewResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *Resolver {
	r := &Resolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
        backend:    backend.New(cfg, m),
		workerPool: NewWorkerPool(cfg.MaxWorkers),
		metrics:    m,
	}
	c.SetResolver(r)
	return r
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *Resolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *Resolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check the cache first.
	if cachedMsg, found, revalidate := r.cache.Get(key); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		cachedMsg.Id = req.Id

		if revalidate {
			r.metrics.IncrementCacheRevalidations()
			// Trigger a background revalidation using the worker pool
			go func() {
				if err := r.workerPool.Acquire(context.Background()); err != nil {
					log.Printf("Failed to acquire worker for revalidation: %v", err)
					return
				}
				defer r.workerPool.Release()

				ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
				defer cancel()

				// Create a new request for revalidation to avoid race conditions on the original request object.
				revalidationReq := new(dns.Msg)
				revalidationReq.SetQuestion(q.Name, q.Qtype)
				revalidationReq.RecursionDesired = true
				if opt := req.IsEdns0(); opt != nil {
					revalidationReq.SetEdns0(opt.UDPSize(), opt.Do())
				}

				res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.exchange(ctx, revalidationReq)
				})
				if err != nil {
					log.Printf("Background revalidation failed for %s: %v", q.Name, err)
					return
				}

				if msg, ok := res.(*dns.Msg); ok {
					r.cache.Set(key, msg, r.config.StaleWhileRevalidate, r.config.PrefetchInterval)
					log.Printf("Successfully revalidated and updated cache for %s", q.Name)
				}
			}()
		}
		return cachedMsg, nil
	}

	// Use singleflight to ensure only one lookup for a given question is in flight at a time.
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.exchange(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	msg := res.(*dns.Msg)
	msg.Id = req.Id

	// Cache the response
	r.cache.Set(key, msg, r.config.StaleWhileRevalidate, r.config.PrefetchInterval)

	return msg, nil
}

// exchange is a wrapper around the unbound resolver's Resolve method.
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
    q := req.Question[0]
    startTime := time.Now()

    msg, dnssec, err := r.backend.Exchange(ctx, req)

    // Determine latency either from backend or measured here
    if obs, ok := r.backend.(interfaces.BackendLatencyObserver); ok {
        r.metrics.RecordLatency(q.Name, obs.LastExchangeLatency())
    } else {
        r.metrics.RecordLatency(q.Name, time.Since(startTime))
    }

    if msg == nil {
        // Ensure we never return nil message to callers
        msg = new(dns.Msg)
        msg.SetRcode(req, dns.RcodeServerFailure)
    }

    if msg.Rcode == dns.RcodeNameError {
        r.metrics.RecordNXDOMAIN(q.Name)
    }

    switch dnssec {
    case interfaces.DNSSECBogus:
        r.metrics.RecordDNSSECValidation("bogus")
        log.Printf("DNSSEC validation for %s resulted in BOGUS.", q.Name)
    case interfaces.DNSSECSecure:
        r.metrics.RecordDNSSECValidation("secure")
        log.Printf("DNSSEC validation for %s resulted in SECURE.", q.Name)
    case interfaces.DNSSECInsecure:
        r.metrics.RecordDNSSECValidation("insecure")
        log.Printf("DNSSEC validation for %s resulted in INSECURE.", q.Name)
    default:
        // unknown/no-op
    }

    if err != nil {
        return msg, err
    }
    return msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}
