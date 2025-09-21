package cache

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLRUCache_GetAndUpdate(t *testing.T) {
	cache := NewLRUCache(2)
	zone := "."
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}})

	// Test Get on empty cache
	if m, _ := cache.Get(zone, q); m != nil {
		t.Error("expected nil from empty cache")
	}

	// Test Update
	cache.Update(zone, q, msg)
	if m, _ := cache.Get(zone, q); m == nil {
		t.Error("failed to get item from cache")
	}

	// Test update existing
	msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{5, 6, 7, 8}})
	cache.Update(zone, q, msg)
	m, _ := cache.Get(zone, q)
	if len(m.Answer) != 2 {
		t.Error("failed to update item in cache")
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	cache := NewLRUCache(2)
	zone := "."

	q1 := dns.Question{Name: "example1.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg1 := new(dns.Msg)
	msg1.SetQuestion("example1.com.", dns.TypeA)

	q2 := dns.Question{Name: "example2.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg2 := new(dns.Msg)
	msg2.SetQuestion("example2.com.", dns.TypeA)

	q3 := dns.Question{Name: "example3.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg3 := new(dns.Msg)
	msg3.SetQuestion("example3.com.", dns.TypeA)

	// Fill the cache
	cache.Update(zone, q1, msg1)
	cache.Update(zone, q2, msg2)

	// Access q1 to make it most recently used
	cache.Get(zone, q1)

	// Add a third item, which should evict q2
	cache.Update(zone, q3, msg3)

	// q1 should still be in the cache
	if m, _ := cache.Get(zone, q1); m == nil {
		t.Error("q1 should be in the cache")
	}

	// q2 should have been evicted
	if m, _ := cache.Get(zone, q2); m != nil {
		t.Error("q2 should have been evicted from the cache")
	}

	// q3 should be in the cache
	if m, _ := cache.Get(zone, q3); m == nil {
		t.Error("q3 should be in the cache")
	}
}
