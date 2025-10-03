package cache

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"container/list"
	"dns-resolver/internal/interfaces"
	"github.com/miekg/dns"
)
// CacheItem represents an item in the cache.
type CacheItem struct {
	Message    *dns.Msg
	Expiration time.Time
	// StaleWhileRevalidate will be used to store the duration for which a stale entry can be served.
	StaleWhileRevalidate time.Duration
	// Prefetch will be used to store the duration before expiration to trigger a prefetch.
	Prefetch time.Duration
	// element is a reference to the list.Element in the LRU list for quick deletion/movement.
	element *list.Element
	// parentList is a reference to the list.List this item belongs to.
	parentList *list.List
}

// slruSegment represents one segment of the SLRU cache.
type slruSegment struct {
	sync.RWMutex
	items             map[string]*CacheItem
	probationList     *list.List // Probation segment (MRU of this list moves to protected)
	protectedList     *list.List // Protected segment (MRU of this list stays, LRU moves to probation or evicted)
	probationCapacity int
	protectedCapacity int
}

// Cache is a thread-safe, sharded DNS cache with SLRU eviction policy.
type Cache struct {
	shards    []*slruSegment
	numShards uint32
	// These are total capacities, distributed among shards
	probationSize int
	protectedSize int

	// Prefetch related fields
	prefetchInterval time.Duration
	stopPrefetch     chan struct{}
	resolver         interfaces.CacheResolver // Reference to the resolver for prefetching
}

// NewCache creates and returns a new Cache.
func NewCache(size int, numShards int, prefetchInterval time.Duration) *Cache {
	if size <= 0 {
		size = DefaultCacheSize
	}
	if numShards <= 0 {
		numShards = DefaultShards
	}

	probationSize := int(float64(size) * SlruProbationFraction)
	protectedSize := size - probationSize

	shards := make([]*slruSegment, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &slruSegment{
			items:             make(map[string]*CacheItem),
			probationList:     list.New(),
			protectedList:     list.New(),
			probationCapacity: probationSize / numShards,
			protectedCapacity: protectedSize / numShards,
		}
	}

	return &Cache{
		shards:           shards,
		numShards:        uint32(numShards),
		probationSize:    probationSize,
		protectedSize:    protectedSize,
		prefetchInterval: prefetchInterval,
		stopPrefetch:     make(chan struct{}),
	}
}

// SetResolver sets the resolver instance for the cache to use for prefetching.
func (c *Cache) SetResolver(r interfaces.CacheResolver) {
	c.resolver = r
	go c.runPrefetcher()
}

// runPrefetcher periodically checks for items to prefetch.
func (c *Cache) runPrefetcher() {
	ticker := time.NewTicker(c.prefetchInterval / 2) // Check more frequently than prefetch interval
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkAndPrefetch()
		case <-c.stopPrefetch:
			return
		}
	}
}

// checkAndPrefetch iterates through cache items and prefetches those nearing expiration.
func (c *Cache) checkAndPrefetch() {
	// Iterate over all shards and their items
	for _, shard := range c.shards {
		shard.RLock()
		for key, item := range shard.items {
			if item.Prefetch > 0 && time.Now().Add(item.Prefetch).After(item.Expiration) {
				// Item is nearing expiration, trigger prefetch
				go c.performPrefetch(key, item.Message.Question[0])
			}
		}
		shard.RUnlock()
	}
}

// performPrefetch performs a background DNS lookup for a given question.
func (c *Cache) performPrefetch(key string, q dns.Question) {
	// Use singleflight to avoid duplicate prefetch requests
	_, err, _ := c.resolver.GetSingleflightGroup().Do(key+"-prefetch", func() (interface{}, error) {
		log.Printf("Prefetching %s", q.Name)
		// Create a new request for prefetching
		req := new(dns.Msg)
		req.SetQuestion(q.Name, q.Qtype)
		req.RecursionDesired = true

		ctx, cancel := context.WithTimeout(context.Background(), c.resolver.GetConfig().UpstreamTimeout)
		defer cancel()

		resp, err := c.resolver.LookupWithoutCache(ctx, req) // Assuming a method to lookup without cache
		if err != nil {
			log.Printf("Prefetch failed for %s: %v", q.Name, err)
			return nil, err
		}

		// Update the cache with the new response
		c.Set(key, resp, c.resolver.GetConfig().StaleWhileRevalidate, c.resolver.GetConfig().PrefetchInterval)
		return resp, nil
	})

	if err != nil {
		log.Printf("Prefetch singleflight error for %s: %v", q.Name, err)
	}
}

// Key generates a cache key from a dns.Question.
func Key(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

// getShard returns the shard for a given key.
func (c *Cache) getShard(key string) *slruSegment {
	hash := fnv32(key)
	return c.shards[hash%c.numShards]
}

// fnv32 generates a 32-bit FNV hash for a string.
func fnv32(key string) uint32 {
	hash := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		hash *= 16777619
		hash ^= uint32(key[i])
	}
	return hash
}

// Get retrieves a message from the cache.
func (c *Cache) Get(key string) (*dns.Msg, bool, bool) {
	shard := c.getShard(key)
	shard.RLock()
	defer shard.RUnlock()

	item, found := shard.items[key]
	if !found {
		return nil, false, false // Not found, not stale
	}

	// Check if the item is expired
	if time.Now().After(item.Expiration) {
		// Item is expired. Check for stale-while-revalidate.
		if item.StaleWhileRevalidate > 0 {
			// Return stale item, and indicate that a revalidation is needed.
			copiedMsg := item.Message.Copy()
			copiedMsg.Id = 0
			return copiedMsg, true, true // Found, stale, revalidate needed
		}
		// Item is expired and not within stale-while-revalidate window.
		return nil, false, false // Not found, not stale
	}

	// Move item within SLRU segments (if found and not expired)
	shard.accessItem(item)

	// Return a copy to prevent race conditions on the message
	// Reset the ID to 0 as it's specific to the request, not the cached response
	copiedMsg := item.Message.Copy()
	copiedMsg.Id = 0
	return copiedMsg, true, false // Found, not stale, no revalidation needed
}

// Set adds a message to the cache.
func (c *Cache) Set(key string, msg *dns.Msg, swr, prefetch time.Duration) {
	// Do not cache responses with SERVFAIL or NXDOMAIN RCODEs.
	if msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeNameError {
		return
	}

	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	ttl := getMinTTL(msg)
	expiration := time.Now().Add(time.Duration(ttl) * time.Second)

	// If the item already exists, update it and move to front of protected segment.
	if existingItem, found := shard.items[key]; found {
		existingItem.Message = msg.Copy()
		existingItem.Expiration = expiration
		existingItem.StaleWhileRevalidate = swr
		existingItem.Prefetch = prefetch
		// Move to front of protected list
		if existingItem.element != nil {
			if existingItem.parentList == shard.probationList {
				shard.probationList.Remove(existingItem.element)
				shard.addProtected(key, existingItem)
			} else if existingItem.parentList == shard.protectedList {
				shard.protectedList.MoveToFront(existingItem.element)
			}
		}
		return
	}

	// New item, add to probation segment.
	item := &CacheItem{
		Message:              msg.Copy(),
		Expiration:           expiration,
		StaleWhileRevalidate: swr,
		Prefetch:             prefetch,
	}
	shard.addProbation(key, item)
}

// addProbation adds an item to the probation segment.
func (s *slruSegment) addProbation(key string, item *CacheItem) {
	// Evict if probation segment is full
	if s.probationList.Len() >= s.probationCapacity {
		oldest := s.probationList.Back()
		if oldest != nil {
			delete(s.items, oldest.Value.(string))
			s.probationList.Remove(oldest)
		}
	}
	item.element = s.probationList.PushFront(key)
	item.parentList = s.probationList
	s.items[key] = item
}

// addProtected adds an item to the protected segment.
func (s *slruSegment) addProtected(key string, item *CacheItem) {
	// Evict if protected segment is full
	if s.protectedList.Len() >= s.protectedCapacity {
		oldest := s.protectedList.Back()
		if oldest != nil {
			// Move from protected to probation
			keyToMove := oldest.Value.(string)
			itemToMove := s.items[keyToMove]
			s.protectedList.Remove(oldest)
			s.addProbation(keyToMove, itemToMove)
		}
	}
	item.element = s.protectedList.PushFront(key)
	item.parentList = s.protectedList
	s.items[key] = item
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

// accessItem moves an item to the front of its respective SLRU list (probation or protected).
func (s *slruSegment) accessItem(item *CacheItem) {
	if item.element == nil {
		// This should not happen for items retrieved from cache, but as a safeguard.
		return
	}

	if item.parentList == s.probationList {
		// Item is in probation, move to protected.
		s.probationList.Remove(item.element)
		s.addProtected(item.element.Value.(string), item)
	} else if item.parentList == s.protectedList {
		// Item is already in protected, move to front.
		s.protectedList.MoveToFront(item.element)
	}
}

// GetCacheSize returns the number of items in the probation and protected segments.
func (c *Cache) GetCacheSize() (int, int) {
	var probationSize, protectedSize int
	for _, shard := range c.shards {
		shard.RLock()
		probationSize += shard.probationList.Len()
		protectedSize += shard.protectedList.Len()
		shard.RUnlock()
	}
	return probationSize, protectedSize
}