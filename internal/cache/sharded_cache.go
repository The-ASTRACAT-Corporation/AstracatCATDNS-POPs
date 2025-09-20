package cache

import (
	"container/list"
	"hash/fnv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultShards = 32 // Example: 32 shards
)

// CacheConfig holds configuration for the cache.
type CacheConfig struct {
	MaxEntries           int
	MinTTLSecs           int
	MaxTTLSecs           int
	NegativeCacheEnabled bool
	NegativeTTLSecs      int
}

// CacheEntry represents a single entry in the cache.
type CacheEntry struct {
	Key             string
	Msg             *dns.Msg
	Expiry          time.Time
	IsNegative      bool
	DNSSECValidated bool
}

// Shard is a part of the ShardedCache, protected by a mutex.
type Shard struct {
	entries    map[string]*list.Element
	lruList    *list.List
	mu         sync.RWMutex
	maxEntries int // Maximum number of entries in this shard
}

// ShardedCache implements a sharded, in-memory cache for DNS responses.
type ShardedCache struct {
	shards          []*Shard
	numShards       uint32
	Config          CacheConfig
	stop            chan struct{}
	cleanupInterval time.Duration
}

// NewShardedCache creates a new ShardedCache with the specified number of shards.
func NewShardedCache(numShards int, cleanupInterval time.Duration, config CacheConfig) *ShardedCache {
	if numShards <= 0 {
		numShards = defaultShards
	}
	shards := make([]*Shard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &Shard{
			entries:    make(map[string]*list.Element),
			lruList:    list.New(),
			maxEntries: config.MaxEntries,
		}
	}
	cache := &ShardedCache{
		shards:          shards,
		numShards:       uint32(numShards),
		Config:          config,
		stop:            make(chan struct{}),
		cleanupInterval: cleanupInterval,
	}

	cache.startCleanup()
	return cache
}

// Get retrieves a DNS message from the cache.
func (c *ShardedCache) Get(key string) (*dns.Msg, bool, bool, bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	element, found := shard.entries[key]
	if !found {
		return nil, false, false, false
	}

	entry := element.Value.(*CacheEntry)
	if time.Now().After(entry.Expiry) {
		return nil, false, false, false
	}

	shard.lruList.MoveToFront(element)
	return entry.Msg, true, entry.IsNegative, entry.DNSSECValidated
}

// Set adds a DNS message to the cache.
func (c *ShardedCache) Set(key string, msg *dns.Msg, ttl time.Duration, isNegative bool, dnssecValidated bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if element, found := shard.entries[key]; found {
		entry := element.Value.(*CacheEntry)
		entry.Msg = msg
		entry.Expiry = time.Now().Add(ttl)
		entry.IsNegative = isNegative
		entry.DNSSECValidated = dnssecValidated
		shard.lruList.MoveToFront(element)
		return
	}

	if shard.lruList.Len() >= shard.maxEntries && shard.maxEntries > 0 {
		element := shard.lruList.Back()
		if element != nil {
			entry := shard.lruList.Remove(element).(*CacheEntry)
			delete(shard.entries, entry.Key)
		}
	}

	entry := &CacheEntry{
		Key:             key,
		Msg:             msg,
		Expiry:          time.Now().Add(ttl),
		IsNegative:      isNegative,
		DNSSECValidated: dnssecValidated,
	}
	element := shard.lruList.PushFront(entry)
	shard.entries[key] = element
}

// Stop stops the background cleanup goroutines.
func (c *ShardedCache) Stop() {
	close(c.stop)
}

// getShard determines which shard a key belongs to.
func (c *ShardedCache) getShard(key string) *Shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%c.numShards]
}

// startCleanup starts a goroutine for each shard to periodically remove expired entries.
func (c *ShardedCache) startCleanup() {
	for i := 0; i < int(c.numShards); i++ {
		go c.shards[i].cleanup(c.cleanupInterval, c.stop)
	}
}

// cleanup removes expired entries from the shard.
func (s *Shard) cleanup(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			// Iterate backwards from the least recently used, as they are most likely to be expired.
			for element := s.lruList.Back(); element != nil; element = element.Prev() {
				entry := element.Value.(*CacheEntry)
				if now.After(entry.Expiry) {
					s.lruList.Remove(element)
					delete(s.entries, entry.Key)
				} else {
					// Since the list is ordered by access time, we can stop
					// once we find a non-expired item.
					break
				}
			}
			s.mu.Unlock()
		case <-stop:
			return
		}
	}
}