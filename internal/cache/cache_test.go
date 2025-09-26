package cache

import (
	"dns-resolver/internal/config"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCache_SetGet(t *testing.T) {
	cfg := config.NewConfig()
	c := NewMultiLevelCache(cfg)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	msg.Answer = append(msg.Answer, rr)

	c.Set(key, msg, 0, 0)

	retrievedMsg, found, _ := c.Get(q)
	if !found {
		t.Fatal("expected to find message in cache")
	}

	if retrievedMsg.Question[0].Name != msg.Question[0].Name {
		t.Errorf("expected question name %s, got %s", msg.Question[0].Name, retrievedMsg.Question[0].Name)
	}

	if retrievedMsg.Answer[0].String() != msg.Answer[0].String() {
		t.Errorf("expected answer %s, got %s", msg.Answer[0].String(), retrievedMsg.Answer[0].String())
	}
}

func TestCache_Expiration(t *testing.T) {
	cfg := config.NewConfig()
	c := NewMultiLevelCache(cfg)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	// Use a very short TTL
	rr, err := dns.NewRR("example.com. 1 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	msg.Answer = append(msg.Answer, rr)

	c.Set(key, msg, 0, 0)

	// Wait for the item to expire
	time.Sleep(2 * time.Second)

	_, found, _ := c.Get(q)
	if found {
		t.Fatal("expected message to be expired from cache")
	}
}

func TestCache_GetCopy(t *testing.T) {
	cfg := config.NewConfig()
	c := NewMultiLevelCache(cfg)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	msg.Answer = append(msg.Answer, rr)

	c.Set(key, msg, 0, 0)

	retrievedMsg, found, _ := c.Get(q)
	if !found {
		t.Fatal("expected to find message in cache")
	}

	// Modify the retrieved message
	retrievedMsg.Answer[0].(*dns.A).A[0] = 255

	// Get the message again and check if it was modified in the cache
	retrievedMsg2, _, _ := c.Get(q)
	if retrievedMsg2.Answer[0].(*dns.A).A[0] == 255 {
		t.Fatal("Get should return a copy of the message, but the original was modified")
	}
}

func TestCache_NXDOMAIN_Caching_And_Expiration(t *testing.T) {
	cfg := config.NewConfig()
	// Set a very short max TTL to ensure expiration is tested properly
	cfg.CacheMaxTTL = 2 * time.Second
	c := NewMultiLevelCache(cfg)

	q := dns.Question{Name: "nonexistent.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.SetRcode(msg, dns.RcodeNameError) // Set Rcode to NXDOMAIN

	// Add an SOA record with a TTL that should be clamped by CacheMaxTTL
	soaRR, err := dns.NewRR("nonexistent.com. 60 IN SOA ns1.nonexistent.com. hostmaster.nonexistent.com. 2023010101 7200 360000 604800 60")
	if err != nil {
		t.Fatalf("failed to create SOA RR: %v", err)
	}
	msg.Ns = append(msg.Ns, soaRR)

	c.Set(key, msg, 0, 0)

	retrievedMsg, found, _ := c.Get(q)
	if !found {
		t.Fatal("expected to find NXDOMAIN message in cache")
	}

	if retrievedMsg.Rcode != dns.RcodeNameError {
		t.Errorf("expected RcodeNameError, got %d", retrievedMsg.Rcode)
	}

	// Test expiration for NXDOMAIN
	time.Sleep(3 * time.Second)
	_, foundAfterDelay, _ := c.Get(q)
	if foundAfterDelay {
		t.Fatal("expected NXDOMAIN message to be expired from cache due to CacheMaxTTL")
	}
}