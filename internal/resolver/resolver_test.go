package resolver

import (
	"context"
	"dns-resolver/internal/cache"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestResolver_ResolveA(t *testing.T) {
	// Create a new resolver with a cache
	c := cache.NewShardedCache(1, 1*time.Minute, cache.CacheConfig{})
	defer c.Stop()
	r := &Resolver{Cache: c, DNSSECEnabled: false}

	// Create a DNS message for an A record query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	msg.SetEdns0(4096, true)

	// Resolve the query
	result := r.Exchange(context.Background(), msg)

	// Check for errors
	if result.Err != nil {
		t.Fatalf("Expected no error, but got: %v", result.Err)
	}

	// Check if the response has an answer
	if len(result.Msg.Answer) == 0 {
		t.Fatalf("Expected at least one A record, but got none")
	}

	// Check if the answer contains an A record
	foundA := false
	for _, rr := range result.Msg.Answer {
		if _, ok := rr.(*dns.A); ok {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Fatalf("Expected an A record in the answer, but none was found")
	}
}
