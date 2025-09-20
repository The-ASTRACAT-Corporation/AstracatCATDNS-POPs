package cache_test

import (
	"dns-resolver/internal/cache"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheSetGet(t *testing.T) {
	config := cache.CacheConfig{MaxEntries: 10}
	cache := cache.NewShardedCache(1, 1*time.Minute, config)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	cache.Set("key1", msg, 1*time.Minute, false, true)

	retrievedMsg, found, isNegative, isValidated := cache.Get("key1")
	if !found {
		t.Fatal("Expected to find key1 in cache")
	}
	if retrievedMsg == nil {
		t.Fatal("Expected to get a message back, got nil")
	}
	if isNegative {
		t.Error("Expected isNegative to be false")
	}
	if !isValidated {
		t.Error("Expected isValidated to be true")
	}
}

func TestCacheEviction(t *testing.T) {
	config := cache.CacheConfig{MaxEntries: 2}
	cache := cache.NewShardedCache(1, 1*time.Minute, config)

	msg1 := new(dns.Msg)
	msg1.SetQuestion("example1.com.", dns.TypeA)
	cache.Set("key1", msg1, 1*time.Minute, false, false)

	msg2 := new(dns.Msg)
	msg2.SetQuestion("example2.com.", dns.TypeA)
	cache.Set("key2", msg2, 1*time.Minute, false, false)

	// Access key1 to make it the most recently used, so key2 is the LRU
	cache.Get("key1")

	// Add a third key, which should evict key2
	msg3 := new(dns.Msg)
	msg3.SetQuestion("example3.com.", dns.TypeA)
	cache.Set("key3", msg3, 1*time.Minute, false, false)

	// Check that key2 is evicted
	_, found, _, _ := cache.Get("key2")
	if found {
		t.Error("Expected key2 to be evicted from the cache")
	}

	// Check that key1 and key3 are still there
	_, found, _, _ = cache.Get("key1")
	if !found {
		t.Error("Expected key1 to be in the cache")
	}
	_, found, _, _ = cache.Get("key3")
	if !found {
		t.Error("Expected key3 to be in the cache")
	}
}

func TestCacheExpiration(t *testing.T) {
	config := cache.CacheConfig{MaxEntries: 10}
	cache := cache.NewShardedCache(1, 5*time.Millisecond, config)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	cache.Set("key1", msg, 1*time.Millisecond, false, true)

	_, found, _, _ := cache.Get("key1")
	if !found {
		t.Fatal("Expected to find key1 immediately after setting")
	}

	time.Sleep(10 * time.Millisecond)

	_, found, _, _ = cache.Get("key1")
	if found {
		t.Error("Expected key1 to be expired and not found")
	}
}
