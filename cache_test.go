package goresolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCache_AddAndGet(t *testing.T) {
	cache := NewDNSCache(10)
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	// Test adding and getting a valid entry
	cache.Add("example.com:A", msg, time.Minute, false)
	if cachedMsg, _, found, _ := cache.Get("example.com:A"); !found || cachedMsg == nil {
		t.Error("Failed to retrieve cached message")
	}

	// Test TTL expiration
	cache.Add("expired.com:A", msg, time.Microsecond, false)
	time.Sleep(time.Millisecond)
	if _, _, found, _ := cache.Get("expired.com:A"); found {
		t.Error("Expired entry should not be found")
	}
}

func TestDNSCache_NegativeCache(t *testing.T) {
	cache := NewDNSCache(10)
	msg := &dns.Msg{}
	msg.SetQuestion("nonexistent.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError

	// Test negative caching
	cache.Add("nonexistent.com:A", msg, time.Minute, true)
	if _, _, found, isNegative := cache.Get("nonexistent.com:A"); !found || !isNegative {
		t.Error("Failed to retrieve negative cache entry")
	}
}

func TestDNSCache_Sharding(t *testing.T) {
	cache := NewDNSCache(2) // 2 shards
	msg := &dns.Msg{}
	msg.SetQuestion("shard1.com.", dns.TypeA)

	// Test shard distribution
	cache.Add("shard1.com:A", msg, time.Minute, false)
	cache.Add("shard2.com:A", msg, time.Minute, false)
	cache.Add("shard3.com:A", msg, time.Minute, false)

	// Verify entries are distributed across shards
	if _, _, found, _ := cache.Get("shard1.com:A"); !found {
		t.Error("Entry in shard1 not found")
	}
	if _, _, found, _ := cache.Get("shard2.com:A"); !found {
		t.Error("Entry in shard2 not found")
	}
	if _, _, found, _ := cache.Get("shard3.com:A"); !found {
		t.Error("Entry in shard3 not found")
	}
}