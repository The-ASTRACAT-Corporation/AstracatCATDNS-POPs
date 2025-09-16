package goresolver

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a cached DNS response with its expiration time.
type CacheEntry struct {
	Message   *dns.Msg
	Timestamp time.Time
	TTL       time.Duration
	IsNegative bool
}

// DNSCache implements a time-aware, sharded cache for DNS responses.
type DNSCache struct {
	shards []*cacheShard
	numShards uint32
}

type cacheShard struct {
	entries map[string]CacheEntry
	mu      sync.RWMutex
}

// NewDNSCache creates a new DNSCache with the specified number of shards.
func NewDNSCache(numShards int) *DNSCache {
	if numShards <= 0 {
		numShards = 1 // Ensure at least one shard
	}
	shards := make([]*cacheShard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &cacheShard{
			entries: make(map[string]CacheEntry),
		}
	}
	return &DNSCache{
		shards: shards,
		numShards: uint32(numShards),
	}
}

// getShard returns the appropriate shard for a given key.
func (c *DNSCache) getShard(key string) *cacheShard {
	h := fnv32(key)
	return c.shards[h%c.numShards]
}

// Add adds a DNS message to the cache with a given TTL.
func (c *DNSCache) Add(key string, msg *dns.Msg, ttl time.Duration, isNegative bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.entries[key] = CacheEntry{
		Message:   msg,
		Timestamp: time.Now(),
		TTL:       ttl,
		IsNegative: isNegative,
	}
}

// Get retrieves a DNS message from the cache.
func (c *DNSCache) Get(key string) (*dns.Msg, time.Duration, bool, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, found := shard.entries[key]
	if !found {
		return nil, 0, false, false
	}

	if time.Since(entry.Timestamp) >= entry.TTL {
		delete(shard.entries, key)
		return nil, 0, false, false
	}

	return entry.Message, entry.TTL - time.Since(entry.Timestamp), true, entry.IsNegative
}

// Delete removes a DNS message from the cache.
func (c *DNSCache) Delete(key string) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.entries, key)
}

// fnv32 generates a 32-bit FNV hash for a string.
func fnv32(key string) uint32 {
	hash := uint32(2166136261)
	prime := uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash *= prime
		hash ^= uint32(key[i])
	}
	return hash
}