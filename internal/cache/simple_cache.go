package cache

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// SimpleCache is a basic in-memory cache that implements the resolver.CacheInterface.
type SimpleCache struct {
	mu    sync.RWMutex
	store map[string]*dns.Msg
}

// NewSimpleCache creates a new SimpleCache.
func NewSimpleCache() *SimpleCache {
	return &SimpleCache{
		store: make(map[string]*dns.Msg),
	}
}

// Get retrieves a message from the cache.
func (c *SimpleCache) Get(zone string, question dns.Question) (*dns.Msg, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.key(zone, question)
	msg, found := c.store[key]
	if found {
		// Return a copy to prevent race conditions
		return msg.Copy(), nil
	}
	return nil, nil // Not found
}

// Update adds or updates a message in the cache.
func (c *SimpleCache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.key(zone, question)
	// Store a copy to prevent race conditions
	c.store[key] = msg.Copy()
	return nil
}

// key generates a unique cache key for a zone and question.
func (c *SimpleCache) key(zone string, q dns.Question) string {
	return fmt.Sprintf("%s:%s:%d:%d", zone, q.Name, q.Qtype, q.Qclass)
}
