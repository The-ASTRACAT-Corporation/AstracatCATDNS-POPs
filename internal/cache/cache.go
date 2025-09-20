package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheItem represents an item in the cache.
type CacheItem struct {
	Message    *dns.Msg
	Expiration time.Time
}

// Cache is a thread-safe DNS cache.
type Cache struct {
	mu    sync.RWMutex
	items map[string]*CacheItem
}

// NewCache creates and returns a new Cache.
func NewCache() *Cache {
	return &Cache{
		items: make(map[string]*CacheItem),
	}
}

// Key generates a cache key from a dns.Question.
func Key(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

// Get retrieves a message from the cache.
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found || time.Now().After(item.Expiration) {
		if found {
			// Item has expired, so we'll need to remove it.
			// We can't do it here because we have a read lock.
			// It will be overwritten by the next Set operation.
		}
		return nil, false
	}

	// Return a copy to prevent race conditions on the message
	return item.Message.Copy(), true
}

// Set adds a message to the cache.
func (c *Cache) Set(key string, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := getMinTTL(msg)
	expiration := time.Now().Add(time.Duration(ttl) * time.Second)

	c.items[key] = &CacheItem{
		Message:    msg.Copy(),
		Expiration: expiration,
	}
}

// getMinTTL extracts the minimum TTL from a DNS message.
func getMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 0

	// Find the minimum TTL in the Answer section
	if len(msg.Answer) > 0 {
		minTTL = msg.Answer[0].Header().Ttl
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	} else if len(msg.Ns) > 0 { // For negative caching (e.g., NXDOMAIN)
		// The SOA record in the authority section contains the negative caching TTL.
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return soa.Minttl
			}
		}
	}

	// As a fallback, if no TTL is found, use a default.
	// This can happen for messages with no answer and no SOA in authority.
	if minTTL == 0 {
		return 60 // Default to 60 seconds
	}

	return minTTL
}
