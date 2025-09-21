package cache

import (
	"github.com/miekg/dns"
)

// MultiLevelCache provides a two-tier caching system (L1/L2).
type MultiLevelCache struct {
	l1 *LRUCache
	l2 *LRUCache
}

// NewMultiLevelCache creates a new MultiLevelCache with given sizes for L1 and L2.
func NewMultiLevelCache(l1Size, l2Size int) *MultiLevelCache {
	return &MultiLevelCache{
		l1: NewLRUCache(l1Size),
		l2: NewLRUCache(l2Size),
	}
}

// Get retrieves a message from the cache, checking L1 then L2.
// If an item is found in L2, it's promoted to L1.
func (c *MultiLevelCache) Get(zone string, question dns.Question) (*dns.Msg, error) {
	// Try L1 first
	msg, err := c.l1.Get(zone, question)
	if err != nil {
		return nil, err
	}
	if msg != nil {
		return msg, nil
	}

	// L1 miss, try L2
	msg, err = c.l2.Get(zone, question)
	if err != nil {
		return nil, err
	}
	if msg != nil {
		// Promote to L1
		c.l1.Update(zone, question, msg)
		return msg, nil
	}

	// Miss in both caches
	return nil, nil
}

// Update adds or updates a message in both L1 and L2 caches.
func (c *MultiLevelCache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	// Update both caches. Order doesn't particularly matter,
	// but we can do L1 first. If an error occurs, we should probably
	// try to update the other one anyway.
	err1 := c.l1.Update(zone, question, msg)
	err2 := c.l2.Update(zone, question, msg)

	if err1 != nil {
		return err1
	}
	return err2
}
