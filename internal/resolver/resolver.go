package resolver

import (
	"context"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
	"golang.org/x/sync/singleflight"
)

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config            *config.Config
	cache             *cache.MultiLevelCache
	sf                singleflight.Group
	recursiveResolver *resolver.Resolver
}

// NewResolver creates a new resolver instance.
func NewResolver(cfg *config.Config, c *cache.MultiLevelCache) *Resolver {
	r := &Resolver{
		config:            cfg,
		cache:             c,
		sf:                singleflight.Group{},
		recursiveResolver: resolver.NewResolver(),
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
	key := cache.Key(q) // Define key early

	// Check the cache first.
	if cachedMsg, found, revalidate := r.cache.Get(q); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		cachedMsg.Id = req.Id

		if revalidate {
			// Trigger a background revalidation using the worker pool
			go func() {
				// For revalidation, we don't need a worker pool as the resolver library is concurrent.
				ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
				defer cancel()

				_, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.exchange(ctx, req)
				})
				if err != nil {
					log.Printf("Background revalidation failed for %s: %v", q.Name, err)
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

// exchange performs a recursive DNS lookup using the integrated library.
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	result := r.recursiveResolver.Exchange(ctx, req)
	if result.Err != nil {
		// Even if there's an error, the response might contain useful information (e.g., SERVFAIL).
		// We return both, and the caller can decide how to handle it.
		return result.Msg, result.Err
	}
	return result.Msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}
