package resolver

import (
	"context"
	"errors"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"golang.org/x/sync/singleflight"
)

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	unbound    *unbound.Unbound
	workerPool *WorkerPool
}

// NewResolver creates a new resolver instance.
func NewResolver(cfg *config.Config, c *cache.Cache) *Resolver {
	u := unbound.New()
	// It's recommended to configure a trust anchor for DNSSEC validation.
	// This could be from a file, or you can use the built-in one.
	// For simplicity, we'll try to load a standard root key file.
	if err := u.AddTaFile("/etc/unbound/root.key"); err != nil {
		log.Printf("Warning: could not load root trust anchor: %v. DNSSEC validation might not be secure.", err)
	}

	r := &Resolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		unbound:    u,
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

// exchange is a wrapper around the unbound resolver's Resolve method.
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]

	// Note: The Go wrapper for libunbound doesn't seem to support passing context for cancellation.
	result, err := r.unbound.Resolve(q.Name, q.Qtype, q.Qclass)
	if err != nil {
		log.Printf("Unbound resolution error for %s: %v", q.Name, err)
		// When an error occurs, unbound does not return a message.
		// We'll construct a SERVFAIL to send back to the client.
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Create a new response message from the result.
	// We need to manually construct the dns.Msg.
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = result.Rcode

	// The unbound result gives us a flat list of RRs. We will add them
	// to the Answer section.
	if result.HaveData {
		msg.Answer = result.Rr
	}

	if result.Bogus {
		log.Printf("DNSSEC validation for %s resulted in BOGUS.", q.Name)
		// The test expects an error for bogus domains. We'll return a SERVFAIL
		// message that the calling handler can use, along with an error.
		msg.Rcode = dns.RcodeServerFailure
		return msg, errors.New("BOGUS: DNSSEC validation failed")
	} else if result.Secure {
		log.Printf("DNSSEC validation for %s resulted in SECURE.", q.Name)
		msg.AuthenticatedData = true
	} else {
		log.Printf("DNSSEC validation for %s resulted in INSECURE.", q.Name)
		msg.AuthenticatedData = false
	}

	// Unlike the previous library, unbound doesn't return a fully-formed dns.Msg.
	// We've constructed it from the pieces in the result.
	return msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}
