package resolver

import (
	"context"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"

	"github.com/miekg/dns"
	extresolver "github.com/nsmithuk/resolver"
	"golang.org/x/sync/singleflight"
)

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	dnssec     *extresolver.Resolver
	workerPool *WorkerPool
}

// NewResolver creates a new resolver instance.
func NewResolver(cfg *config.Config, c *cache.Cache) *Resolver {
	r := &Resolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		dnssec:     extresolver.NewResolver(),
		workerPool: NewWorkerPool(cfg.MaxWorkers),
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
			// Trigger a background revalidation using the worker pool
			go func() {
				if err := r.workerPool.Acquire(context.Background()); err != nil {
					log.Printf("Failed to acquire worker for revalidation: %v", err)
					return
				}
				defer r.workerPool.Release()

				ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
				defer cancel()

				res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.exchange(ctx, req)
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

// exchange is a wrapper around the DNSSEC resolver's Exchange method.
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	result := r.dnssec.Exchange(ctx, req)
	if result.Err != nil {
		// Don't log SERVFAIL as a validation error, as it's an expected outcome for bogus domains.
		if result.Msg == nil || result.Msg.Rcode != dns.RcodeServerFailure {
			log.Printf("DNSSEC validation error for %s: %v", req.Question[0].Name, result.Err)
		}
		return nil, result.Err
	}

	// The underlying library can incorrectly report unsigned domains as Secure.
	// We'll implement our own check and ignore the library's `Auth` field.
	isSecure := false
	// A secure answer must have at least one RRSIG and one other record.
	if len(result.Msg.Answer) > 1 {
		hasRRSIG := false
		for _, rr := range result.Msg.Answer {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
				break
			}
		}
		isSecure = hasRRSIG
	}

	if isSecure {
		log.Printf("Determined DNSSEC status for %s as Secure (RRSIG found)", req.Question[0].Name)
	} else {
		log.Printf("Determined DNSSEC status for %s as Insecure (no RRSIG found or empty answer)", req.Question[0].Name)
	}

	// Set the Authenticated Data (AD) bit explicitly based on our own check.
	result.Msg.AuthenticatedData = isSecure

	return result.Msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}
