package main

import (
	"context"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
	"log"
	"time"
)

// CachingResolver wraps a resolver to add a caching layer.
type CachingResolver struct {
	cache    *ShardedCache
	resolver *resolver.Resolver
}

// NewCachingResolver creates a new CachingResolver.
func NewCachingResolver(cache *ShardedCache, resolver *resolver.Resolver) *CachingResolver {
	return &CachingResolver{
		cache:    cache,
		resolver: resolver,
	}
}

// Exchange performs a DNS query, using the cache first.
func (r *CachingResolver) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	cacheKey := msg.Question[0].Name + ":" + dns.TypeToString[msg.Question[0].Qtype]

	// Try to get the response from cache
	if cachedMsg, found, isNegative, _ := r.cache.Get(cacheKey); found {
		if isNegative {
			log.Printf("Cache HIT (negative) for %s", cacheKey)
			m := new(dns.Msg)
			m.SetRcode(msg, dns.RcodeServerFailure) // Or whatever the cached rcode was
			return m, nil
		} else {
			log.Printf("Cache HIT (positive) for %s", cacheKey)
			cachedMsg.Id = msg.Id
			return cachedMsg, nil
		}
	}
	log.Printf("Cache MISS for %s", cacheKey)

	upstreamMsg := new(dns.Msg)
	upstreamMsg.SetQuestion(msg.Question[0].Name, msg.Question[0].Qtype)
	upstreamMsg.SetEdns0(4096, true)

	result := r.resolver.Exchange(ctx, upstreamMsg)
	if result.Err != nil {
		log.Printf("Error exchanging DNS query: %v", result.Err)
		if r.cache.config.NegativeCacheEnabled {
			ttl := time.Duration(r.cache.config.NegativeTTLSecs) * time.Second
			r.cache.Set(cacheKey, nil, ttl, true, false)
		}
		return nil, result.Err
	}

	result.Msg.SetRcode(msg, result.Msg.Rcode)
	result.Msg.RecursionAvailable = true

	isNegative := result.Msg.Rcode != dns.RcodeSuccess
	ttl := r.getTTL(result.Msg, isNegative)

	// We only cache validated responses, but the underlying resolver library
	// doesn't seem to populate the AuthenticatedData flag correctly in all cases.
	// For now, we will cache all successful responses.
	// A future improvement would be to ensure DNSSEC validation is robust and only cache validated data.
	if !isNegative {
		r.cache.Set(cacheKey, result.Msg, ttl, false, true)
	} else if r.cache.config.NegativeCacheEnabled {
		r.cache.Set(cacheKey, result.Msg, ttl, true, true)
	}

	return result.Msg, nil
}

func (r *CachingResolver) getTTL(msg *dns.Msg, isNegative bool) time.Duration {
	var ttl uint32

	if isNegative {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl = soa.Minttl
				break
			}
		}
		if ttl == 0 {
			return time.Duration(r.cache.config.NegativeTTLSecs) * time.Second
		}
		if r.cache.config.NegativeTTLSecs > 0 && ttl > uint32(r.cache.config.NegativeTTLSecs) {
			ttl = uint32(r.cache.config.NegativeTTLSecs)
		}
	} else if len(msg.Answer) > 0 {
		ttl = msg.Answer[0].Header().Ttl
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		return time.Duration(r.cache.config.MinTTLSecs) * time.Second
	}

	if r.cache.config.MinTTLSecs > 0 && ttl < uint32(r.cache.config.MinTTLSecs) {
		ttl = uint32(r.cache.config.MinTTLSecs)
	}
	if r.cache.config.MaxTTLSecs > 0 && ttl > uint32(r.cache.config.MaxTTLSecs) {
		ttl = uint32(r.cache.config.MaxTTLSecs)
	}

	return time.Duration(ttl) * time.Second
}
