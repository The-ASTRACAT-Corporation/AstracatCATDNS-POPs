package cache

import (
	"dns-resolver/internal/config"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRRsetCache_SetGet(t *testing.T) {
	cfg := config.NewConfig()
	c := NewRRsetCache(cfg, DefaultShards)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	rrset := []dns.RR{rr}

	c.Set(key, rrset)

	retrievedRRset, found := c.Get(key)
	if !found {
		t.Fatal("expected to find RRset in cache")
	}

	if len(retrievedRRset) != 1 {
		t.Fatalf("expected RRset of length 1, got %d", len(retrievedRRset))
	}

	if retrievedRRset[0].String() != rr.String() {
		t.Errorf("expected RRset %s, got %s", rr.String(), retrievedRRset[0].String())
	}
}

func TestRRsetCache_Expiration(t *testing.T) {
	cfg := config.NewConfig()
	cfg.CacheMaxTTL = 1 * time.Second // Clamp TTL to 1 second for test
	c := NewRRsetCache(cfg, DefaultShards)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	// TTL is 60, but should be clamped to 1 by CacheMaxTTL
	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	rrset := []dns.RR{rr}

	c.Set(key, rrset)

	// Wait for the item to expire
	time.Sleep(2 * time.Second)

	_, found := c.Get(key)
	if found {
		t.Fatal("expected RRset to be expired from cache")
	}
}