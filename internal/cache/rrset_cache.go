package cache

import (
	"container/list"
	"dns-resolver/internal/config"
	"dns-resolver/internal/interfaces"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RRsetCacheItem represents an item in the RRset cache.
type RRsetCacheItem struct {
	RRset      []dns.RR
	Expiration time.Time
	// element is a reference to the list.Element in the LRU list for quick deletion/movement.
	element *list.Element
	// parentList is a reference to the list.List this item belongs to.
	parentList *list.List
}

// rrsetSlruSegment represents one segment of the SLRU RRset cache.
type rrsetSlruSegment struct {
	sync.RWMutex
	items             map[string]*RRsetCacheItem
	probationList     *list.List
	protectedList     *list.List
	probationCapacity int
	protectedCapacity int
}

// RRsetCache is a thread-safe, sharded DNS RRset cache with SLRU eviction policy.
type RRsetCache struct {
	shards    []*rrsetSlruSegment
	numShards uint32
	resolver  interfaces.CacheResolver
	config    *config.Config
}

// NewRRsetCache creates and returns a new RRsetCache.
func NewRRsetCache(cfg *config.Config, numShards int) *RRsetCache {
	size := cfg.RRsetCacheSize
	if size <= 0 {
		size = DefaultCacheSize
	}
	if numShards <= 0 {
		numShards = DefaultShards
	}

	probationSize := int(float64(size) * slruProbationFraction)
	protectedSize := size - probationSize

	shards := make([]*rrsetSlruSegment, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &rrsetSlruSegment{
			items:             make(map[string]*RRsetCacheItem),
			probationList:     list.New(),
			protectedList:     list.New(),
			probationCapacity: probationSize / numShards,
			protectedCapacity: protectedSize / numShards,
		}
	}

	return &RRsetCache{
		shards:    shards,
		numShards: uint32(numShards),
		config:    cfg,
	}
}

// SetResolver sets the resolver instance for the cache.
func (c *RRsetCache) SetResolver(r interfaces.CacheResolver) {
	c.resolver = r
}

// getShard returns the shard for a given key.
func (c *RRsetCache) getShard(key string) *rrsetSlruSegment {
	hash := fnv32(key)
	return c.shards[hash%c.numShards]
}

// Get retrieves an RRset from the cache.
func (c *RRsetCache) Get(key string) ([]dns.RR, bool) {
	shard := c.getShard(key)
	shard.RLock()
	defer shard.RUnlock()

	item, found := shard.items[key]
	if !found {
		return nil, false
	}

	if time.Now().After(item.Expiration) {
		// Item is expired, remove it.
		// A more advanced implementation might handle stale data.
		shard.RUnlock()
		shard.Lock()
		// Re-check after acquiring write lock
		if item, found = shard.items[key]; found && time.Now().After(item.Expiration) {
			s := c.getShard(key)
			if item.parentList == s.probationList {
				s.probationList.Remove(item.element)
			} else {
				s.protectedList.Remove(item.element)
			}
			delete(s.items, key)
		}
		shard.Unlock()
		shard.RLock()
		return nil, false
	}

	shard.accessItem(item)

	// Return a copy of the RRset
	rrsetCopy := make([]dns.RR, len(item.RRset))
	copy(rrsetCopy, item.RRset)
	return rrsetCopy, true
}

// Set adds an RRset to the cache.
func (c *RRsetCache) Set(key string, rrset []dns.RR) {
	if len(rrset) == 0 {
		return
	}

	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	ttl := time.Duration(rrset[0].Header().Ttl) * time.Second
	clampedTTL := c.clampTTL(ttl)
	expiration := time.Now().Add(clampedTTL)

	// If the item already exists, update it and move to the front of the protected segment.
	if existingItem, found := shard.items[key]; found {
		existingItem.RRset = rrset
		existingItem.Expiration = expiration
		if existingItem.parentList == shard.probationList {
			shard.probationList.Remove(existingItem.element)
			shard.addProtected(key, existingItem)
		} else if existingItem.parentList == shard.protectedList {
			shard.protectedList.MoveToFront(existingItem.element)
		}
		return
	}

	// New item, add to the probation segment.
	item := &RRsetCacheItem{
		RRset:      rrset,
		Expiration: expiration,
	}
	shard.addProbation(key, item)
}

// addProbation adds an item to the probation segment.
func (s *rrsetSlruSegment) addProbation(key string, item *RRsetCacheItem) {
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
func (s *rrsetSlruSegment) addProtected(key string, item *RRsetCacheItem) {
	if s.protectedList.Len() >= s.protectedCapacity {
		oldest := s.protectedList.Back()
		if oldest != nil {
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

// accessItem moves an item to the appropriate place in the SLRU lists.
func (s *rrsetSlruSegment) accessItem(item *RRsetCacheItem) {
	if item.parentList == s.probationList {
		s.probationList.Remove(item.element)
		s.addProtected(item.element.Value.(string), item)
	} else if item.parentList == s.protectedList {
		s.protectedList.MoveToFront(item.element)
	}
}

// clampTTL ensures that the TTL is within the configured min and max bounds.
func (c *RRsetCache) clampTTL(ttl time.Duration) time.Duration {
	if c.config.CacheMaxTTL > 0 && ttl > c.config.CacheMaxTTL {
		return c.config.CacheMaxTTL
	}
	if ttl < c.config.CacheMinTTL {
		return c.config.CacheMinTTL
	}
	return ttl
}