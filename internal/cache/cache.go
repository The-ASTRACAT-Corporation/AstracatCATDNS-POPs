package cache

import (
	"dns-resolver/internal/metrics"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"dns-resolver/internal/interfaces"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
)

// CacheItem represents an item in the cache.
type CacheItem struct {
	Msg                  *dns.Msg
	Expiration           time.Time
	StaleWhileRevalidate time.Duration
}

// Cache is a thread-safe, sharded DNS cache with Ristretto.
type Cache struct {
	cache    *ristretto.Cache
	resolver interfaces.CacheResolver
	metrics  *metrics.Metrics
	msgPool  sync.Pool
}

// NewCache creates and returns a new Cache with Ristretto.
func NewCache(size int, m *metrics.Metrics) (*Cache, error) {
	if size <= 0 {
		size = DefaultCacheSize
	}

	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: int64(size * 10), // Recommended value from Ristretto docs
		MaxCost:     int64(size),
		BufferItems: 64, // Default value
		Metrics:     true,
		OnEvict: func(item *ristretto.Item) {
			if item.Value != nil {
				if cacheItem, ok := item.Value.(*CacheItem); ok {
					if cacheItem.Msg != nil {
						// Here you might want to put the dns.Msg back into a sync.Pool
						// For now, we'll just let it be garbage collected.
					}
				}
			}
			m.IncrementCacheEvictions()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ristretto cache: %w", err)
	}

	c := &Cache{
		cache:   ristrettoCache,
		metrics: m,
		msgPool: sync.Pool{
			New: func() interface{} {
				return new(dns.Msg)
			},
		},
	}

	return c, nil
}

// Close gracefully closes the cache.
func (c *Cache) Close() {
	if c.cache != nil {
		c.cache.Close()
	}
}

func (c *Cache) Get(key string) (*dns.Msg, bool, bool) {
	value, found := c.cache.Get(key)
	if !found {
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	item, ok := value.(*CacheItem)
	if !ok {
		c.metrics.IncrementCacheMisses() // Treat as a miss if the type is wrong
		log.Printf("Cache item for key %s has wrong type", key)
		return nil, false, false
	}

	if time.Now().After(item.Expiration) {
		if item.StaleWhileRevalidate > 0 && time.Now().Before(item.Expiration.Add(item.StaleWhileRevalidate)) {
			c.metrics.IncrementCacheHits()
			// Return a deep copy to prevent race conditions
			msgCopy := item.Msg.Copy()
			return msgCopy, true, true // Stale
		}
		c.cache.Del(key)
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	c.metrics.IncrementCacheHits()
	// Return a deep copy to prevent race conditions
	msgCopy := item.Msg.Copy()
	return msgCopy, true, false // Not stale
}

func (c *Cache) Set(key string, msg *dns.Msg, swr time.Duration) {
	if msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeNameError {
		return
	}

	ttl := getMinTTL(msg)
	expiration := time.Now().Add(time.Duration(ttl) * time.Second)

	item := &CacheItem{
		Msg:                  msg.Copy(), // Store a copy to avoid race conditions
		Expiration:           expiration,
		StaleWhileRevalidate: swr,
	}

	// The cost is 1, as we are not sizing items individually for this cache.
	// The TTL for Ristretto should be the total lifetime of the item.
	totalTTL := time.Duration(ttl)*time.Second + swr
	c.cache.SetWithTTL(key, item, 1, totalTTL)
}

func (c *Cache) SetResolver(r interfaces.CacheResolver) {
	c.resolver = r
}

func Key(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

func getMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 0

	if len(msg.Answer) > 0 {
		minTTL = msg.Answer[0].Header().Ttl
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	} else if len(msg.Ns) > 0 {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return soa.Minttl
			}
		}
	}

	if minTTL == 0 {
		return 60 // Default TTL if no other is found
	}

	return minTTL
}

func (c *Cache) GetCacheMetrics() *ristretto.Metrics {
	return c.cache.Metrics
}
