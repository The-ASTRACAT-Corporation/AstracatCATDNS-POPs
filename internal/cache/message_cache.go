package cache

import (
	"context"
	"dns-resolver/internal/config"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"container/list"
	"dns-resolver/internal/interfaces"
	"github.com/miekg/dns"
)

const (
	// DefaultCacheSize is the default number of items the cache can hold.
	DefaultCacheSize = 10000
	// DefaultShards is the default number of shards for the cache.
	DefaultShards = 32

	// slruProbationFraction is the fraction of the cache size allocated to the probation segment.
	slruProbationFraction = 0.8
)

// MessageCacheItem represents an item in the message cache.
type MessageCacheItem struct {
	Message    *dns.Msg
	Expiration time.Time
	OriginalTTL time.Duration
	// StaleWhileRevalidate will be used to store the duration for which a stale entry can be served.
	StaleWhileRevalidate time.Duration
	// Prefetch will be used to store the duration before expiration to trigger a prefetch.
	Prefetch time.Duration
	// element is a reference to the list.Element in the LRU list for quick deletion/movement.
	element *list.Element
	// parentList is a reference to the list.List this item belongs to.
	parentList *list.List
}

// messageSlruSegment represents one segment of the SLRU message cache.
type messageSlruSegment struct {
	sync.RWMutex
	items             map[string]*MessageCacheItem
	probationList     *list.List // Probation segment (MRU of this list moves to protected)
	protectedList     *list.List // Protected segment (MRU of this list stays, LRU moves to probation or evicted)
	probationCapacity int
	protectedCapacity int
}

// MessageCache is a thread-safe, sharded DNS message cache with SLRU eviction policy.
type MessageCache struct {
	shards    []*messageSlruSegment
	numShards uint32
	// These are total capacities, distributed among shards
	probationSize int
	protectedSize int

	// Prefetch related fields
	prefetchInterval time.Duration
	stopPrefetch     chan struct{}
	resolver         interfaces.CacheResolver // Reference to the resolver for prefetching
	config           *config.Config
}

// NewMessageCache creates and returns a new MessageCache.
func NewMessageCache(cfg *config.Config, numShards int) *MessageCache {
	size := cfg.MessageCacheSize
	if size <= 0 {
		size = DefaultCacheSize
	}
	if numShards <= 0 {
		numShards = DefaultShards
	}

	probationSize := int(float64(size) * slruProbationFraction)
	protectedSize := size - probationSize

	shards := make([]*messageSlruSegment, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &messageSlruSegment{
			items:             make(map[string]*MessageCacheItem),
			probationList:     list.New(),
			protectedList:     list.New(),
			probationCapacity: probationSize / numShards,
			protectedCapacity: protectedSize / numShards,
		}
	}

	return &MessageCache{
		shards:           shards,
		numShards:        uint32(numShards),
		probationSize:    probationSize,
		protectedSize:    protectedSize,
		prefetchInterval: cfg.PrefetchInterval,
		stopPrefetch:     make(chan struct{}),
		config:           cfg,
	}
}

// SetResolver sets the resolver instance for the cache to use for prefetching.
func (c *MessageCache) SetResolver(r interfaces.CacheResolver) {
	c.resolver = r
	go c.runPrefetcher()
}

// runPrefetcher periodically checks for items to prefetch.
func (c *MessageCache) runPrefetcher() {
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
func (c *MessageCache) checkAndPrefetch() {
	now := time.Now()
	// Iterate over all shards and their items
	for _, shard := range c.shards {
		shard.RLock()
		for key, item := range shard.items {
			if item.OriginalTTL > 0 {
				remainingTTL := item.Expiration.Sub(now)
				// Prefetch if the remaining TTL is less than 10% of the original TTL.
				if remainingTTL > 0 && remainingTTL < (item.OriginalTTL/10) {
					go c.performPrefetch(key, item.Message.Question[0])
				}
			}
		}
		shard.RUnlock()
	}
}

// performPrefetch performs a background DNS lookup for a given question.
func (c *MessageCache) performPrefetch(key string, q dns.Question) {
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
func (c *MessageCache) getShard(key string) *messageSlruSegment {
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
func (c *MessageCache) Get(key string) (*dns.Msg, bool, bool) {
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
		if item.StaleWhileRevalidate > 0 && time.Now().Before(item.Expiration.Add(item.StaleWhileRevalidate)) {
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
func (c *MessageCache) Set(key string, msg *dns.Msg, swr, prefetch time.Duration) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	rawTTL := time.Duration(getRawMinTTL(msg)) * time.Second
	clampedTTL := c.clampTTL(rawTTL)
	expiration := time.Now().Add(clampedTTL)

	// If the item already exists, update it and move to front of protected segment.
	if existingItem, found := shard.items[key]; found {
		existingItem.Message = msg.Copy()
		existingItem.Expiration = expiration
		existingItem.OriginalTTL = rawTTL
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
	item := &MessageCacheItem{
		Message:              msg.Copy(),
		Expiration:           expiration,
		OriginalTTL:          rawTTL,
		StaleWhileRevalidate: swr,
		Prefetch:             prefetch,
	}
	shard.addProbation(key, item)
}

// addProbation adds an item to the probation segment.
func (s *messageSlruSegment) addProbation(key string, item *MessageCacheItem) {
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
func (s *messageSlruSegment) addProtected(key string, item *MessageCacheItem) {
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

// getRawMinTTL extracts the minimum TTL from a DNS message.
func getRawMinTTL(msg *dns.Msg) uint32 {
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
				// According to RFC 2308, the negative TTL is the minimum of the
				// SOA's MINIMUM field and the SOA's TTL.
				minTTL = soa.Minttl
				if rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
				break // Found SOA, no need to check other NS records
			}
		}
	}

	// As a fallback, if no TTL is found, use a default.
	if minTTL == 0 {
		minTTL = 60 // Default to 60 seconds
	}

	return minTTL
}

// getAndClampMinTTL extracts the minimum TTL from a DNS message and clamps it according to the config.
func (c *MessageCache) getAndClampMinTTL(msg *dns.Msg) time.Duration {
	rawTTL := getRawMinTTL(msg)
	return c.clampTTL(time.Duration(rawTTL) * time.Second)
}

// clampTTL ensures that the TTL is within the configured min and max bounds.
func (c *MessageCache) clampTTL(ttl time.Duration) time.Duration {
	if c.config.CacheMaxTTL > 0 && ttl > c.config.CacheMaxTTL {
		return c.config.CacheMaxTTL
	}
	if ttl < c.config.CacheMinTTL {
		return c.config.CacheMinTTL
	}
	return ttl
}

// accessItem moves an item to the front of its respective SLRU list (probation or protected).
func (s *messageSlruSegment) accessItem(item *MessageCacheItem) {
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
