package cache

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// entry is used to hold a value in the LRU cache.
type entry struct {
	key   string
	value *dns.Msg
}

// LRUCache is a thread-safe, in-memory LRU cache.
type LRUCache struct {
	maxSize int
	mu      sync.RWMutex
	ll      *list.List
	cache   map[string]*list.Element
}

// NewLRUCache creates a new LRUCache with a given size.
func NewLRUCache(maxSize int) *LRUCache {
	if maxSize <= 0 {
		maxSize = 10000 // Default size
	}
	return &LRUCache{
		maxSize: maxSize,
		ll:      list.New(),
		cache:   make(map[string]*list.Element),
	}
}

// key generates a unique cache key for a zone and question.
func (c *LRUCache) key(zone string, q dns.Question) string {
	return fmt.Sprintf("%s:%s:%d:%d", zone, q.Name, q.Qtype, q.Qclass)
}

// Get retrieves a message from the cache.
func (c *LRUCache) Get(zone string, question dns.Question) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.key(zone, question)
	if elem, hit := c.cache[key]; hit {
		c.ll.MoveToFront(elem)
		return elem.Value.(*entry).value.Copy(), nil
	}
	return nil, nil
}

// Update adds or updates a message in the cache.
func (c *LRUCache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.key(zone, question)
	if elem, hit := c.cache[key]; hit {
		c.ll.MoveToFront(elem)
		elem.Value.(*entry).value = msg.Copy()
		return nil
	}

	newEntry := &entry{key: key, value: msg.Copy()}
	elem := c.ll.PushFront(newEntry)
	c.cache[key] = elem

	if c.ll.Len() > c.maxSize {
		c.removeOldest()
	}
	return nil
}

// removeOldest removes the oldest item from the cache.
func (c *LRUCache) removeOldest() {
	elem := c.ll.Back()
	if elem != nil {
		c.ll.Remove(elem)
		delete(c.cache, elem.Value.(*entry).key)
	}
}
