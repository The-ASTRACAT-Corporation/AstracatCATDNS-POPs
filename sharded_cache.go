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
	LastAccess      time.Time // For LRU eviction
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
			maxEntries: 1000, // Example: max 1000 entries per shard
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
	entry, found := shard.entries[key]
	shard.mu.RUnlock()

	if !found || time.Now().After(entry.Expiry) {
		return nil, false, false, false
	}

	// Update LastAccess for LRU
	shard.mu.Lock()
	entry.LastAccess = time.Now()
	shard.entries[key] = entry
	shard.mu.Unlock()

	return entry.Msg, true, entry.IsNegative, entry.DNSSECValidated
}

// Set adds a DNS message to the cache.
func (c *ShardedCache) Set(key string, msg *dns.Msg, ttl time.Duration, isNegative bool, dnssecValidated bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Implement LRU eviction if shard is full
	if len(shard.entries) >= shard.maxEntries {
		var oldestKey string
		var oldestTime time.Time
		for k, e := range shard.entries {
			if oldestKey == "" || e.LastAccess.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.LastAccess
			}
		}
		if oldestKey != "" {
			delete(shard.entries, oldestKey)
		}
	}

	shard.entries[key] = CacheEntry{
		Msg:             msg,
		Expiry:          time.Now().Add(ttl),
		IsNegative:      isNegative,
		DNSSECValidated: dnssecValidated,
		LastAccess:      time.Now(),
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