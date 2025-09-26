package resolver

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolver_Resolve(t *testing.T) {
	// Create a new cache and resolver for the test.
	cfg := config.NewConfig()
	c := cache.NewCache(cache.DefaultCacheSize, cache.DefaultShards, cfg.PrefetchInterval)
	r := NewResolver(cfg, c)

	// Define the question to test.
	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(4096, true) // Enable DNSSEC OK bit

	// Resolve the domain.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := r.Resolve(ctx, req)

	// Check for errors.
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	// Check if we got a response.
	if msg == nil {
		t.Fatal("Resolve() returned a nil message.")
	}

	// Check if the response contains at least one answer.
	if len(msg.Answer) == 0 {
		t.Fatal("Response contains no answer records.")
	}

	// Check if the response code is NOERROR.
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("Response code is not NOERROR, got %s", dns.RcodeToString[msg.Rcode])
	}

	t.Logf("Successfully resolved %s", req.Question[0].Name)
	for _, ans := range msg.Answer {
		t.Logf(" -> %s", ans.String())
	}
}
