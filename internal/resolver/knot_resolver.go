package resolver

import (
	"context"
	"errors"
	"log"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/knot"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// KnotResolver is a recursive DNS resolver using Knot DNS library.
type KnotResolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	knot       *knot.Resolver
	workerPool *WorkerPool
	metrics    *metrics.Metrics
}

// NewKnotResolver creates a new Knot resolver instance.
func NewKnotResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) (*KnotResolver, error) {
	// Create Knot resolver with DNSSEC enabled
	knotResolver, err := knot.NewResolver(true, cfg.UpstreamTimeout, "")
	if err != nil {
		return nil, err
	}

	r := &KnotResolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		knot:       knotResolver,
		workerPool: NewWorkerPool(cfg.MaxWorkers),
		metrics:    m,
	}

	return r, nil
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *KnotResolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *KnotResolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *KnotResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
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
					r.cache.Set(key, msg, r.config.StaleWhileRevalidate)
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
	r.cache.Set(key, msg, r.config.StaleWhileRevalidate)

	return msg, nil
}

// exchange performs the actual DNS resolution using Knot.
func (r *KnotResolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	startTime := time.Now()

	// Convert DNS types to Knot types
	qtype := uint16(q.Qtype)
	qclass := uint16(q.Qclass)

	// Perform resolution using Knot
	result, err := r.knot.Resolve(ctx, q.Name, qtype, qclass)
	latency := time.Since(startTime)

	// Always record latency
	r.metrics.RecordLatency(q.Name, latency)

	if err != nil {
		r.metrics.IncrementUnboundErrors()
		log.Printf("Knot resolution error for %s: %v", q.Name, err)
		// When an error occurs, construct a SERVFAIL to send back to the client.
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Convert Knot result to DNS message
	msg, err := r.convertKnotResult(req, result)
	if err != nil {
		log.Printf("Failed to convert Knot result for %s: %v", q.Name, err)
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Handle DNSSEC validation results
	if result.Bogus {
		r.metrics.RecordDNSSECValidation("bogus")
		log.Printf("DNSSEC validation for %s resulted in BOGUS.", q.Name)
		msg.Rcode = dns.RcodeServerFailure
		return msg, errors.New("BOGUS: DNSSEC validation failed")
	} else if result.Secure {
		r.metrics.RecordDNSSECValidation("secure")
		log.Printf("DNSSEC validation for %s resulted in SECURE.", q.Name)
		msg.AuthenticatedData = true
	} else {
		r.metrics.RecordDNSSECValidation("insecure")
		log.Printf("DNSSEC validation for %s resulted in INSECURE.", q.Name)
		msg.AuthenticatedData = false
	}

	// Handle NXDOMAIN
	if result.Rcode == 3 { // NXDOMAIN
		r.metrics.RecordNXDOMAIN(q.Name)
	}

	return msg, nil
}

// convertKnotResult converts Knot resolution result to DNS message.
func (r *KnotResolver) convertKnotResult(req *dns.Msg, result *knot.ResolveResult) (*dns.Msg, error) {
	// Create response message
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = result.Rcode

	// If we have wire data, try to parse it
	if len(result.Wire) > 0 {
		// Parse the wire format response
		wireMsg := new(dns.Msg)
		if err := wireMsg.Unpack(result.Wire); err != nil {
			// If parsing fails, create a basic response
			msg.Rcode = result.Rcode
			return msg, nil
		}

		// Copy the parsed data
		msg.Answer = wireMsg.Answer
		msg.Ns = wireMsg.Ns
		msg.Extra = wireMsg.Extra
		msg.Rcode = wireMsg.Rcode
		msg.Authoritative = wireMsg.Authoritative
		msg.Truncated = wireMsg.Truncated
		msg.RecursionDesired = wireMsg.RecursionDesired
		msg.RecursionAvailable = wireMsg.RecursionAvailable
		msg.AuthenticatedData = wireMsg.AuthenticatedData
		msg.CheckingDisabled = wireMsg.CheckingDisabled
	}

	return msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *KnotResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *KnotResolver) Close() {
	if r.knot != nil {
		r.knot.Close()
		r.knot = nil
	}
}