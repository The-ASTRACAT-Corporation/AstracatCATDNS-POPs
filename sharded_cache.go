package main

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a single entry in the cache.
type CacheEntry struct {
	Msg             *dns.Msg
	Expiry          time.Time
	IsNegative      bool
	DNSSECValidated bool
}

// Shard is a part of the ShardedCache, protected by a mutex.
type Shard struct {
	entries    map[string]CacheEntry
	mu         sync.RWMutex
	maxEntries int // Maximum number of entries in this shard
}

// ShardedCache implements a sharded, in-memory cache for DNS responses.
type ShardedCache struct {
	shards    []*Shard
	numShards uint32
	stop      chan struct{}
	cleanupInterval time.Duration
}

// NewShardedCache creates a new ShardedCache with the specified number of shards.
func NewShardedCache(numShards int, cleanupInterval time.Duration) *ShardedCache {
	if numShards <= 0 {
		numShards = defaultShards
	}
	shards := make([]*Shard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &Shard{
			entries: make(map[string]CacheEntry),
			// A reasonable default limit to prevent unbounded growth.
			// This should be configurable in a real-world scenario.
			maxEntries: 10000,
		}
	}
	cache := &ShardedCache{
		shards:    shards,
		numShards: uint32(numShards),
		stop:      make(chan struct{}),
		cleanupInterval: cleanupInterval,
	}

	cache.startCleanup()
	return cache
}

// Get retrieves a DNS message from the cache.
func (c *ShardedCache) Get(key string) (*dns.Msg, bool, bool, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, found := shard.entries[key]

	if !found || time.Now().After(entry.Expiry) {
		return nil, false, false, false
	}

	return entry.Msg, true, entry.IsNegative, entry.DNSSECValidated
}

// Set adds a DNS message to the cache.
func (c *ShardedCache) Set(key string, msg *dns.Msg, ttl time.Duration, isNegative bool, dnssecValidated bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Prevent unbounded cache growth. If the shard is full,
	// we drop the new entry. The periodic cleanup will clear space.
	// A more sophisticated eviction strategy could be used here if needed.
	if len(shard.entries) >= shard.maxEntries {
		// Optional: log that we are dropping the entry due to a full cache.
		return
	}

	shard.entries[key] = CacheEntry{
		Msg:             msg,
		Expiry:          time.Now().Add(ttl),
		IsNegative:      isNegative,
		DNSSECValidated: dnssecValidated,
	}
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
			for key, entry := range s.entries {
				if now.After(entry.Expiry) {
					delete(s.entries, key)
				}
			}
			s.mu.Unlock()
		case <-stop:
			return
		}
	}
}