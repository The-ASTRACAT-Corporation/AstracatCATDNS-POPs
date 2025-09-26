package cache

import (
	"dns-resolver/internal/config"
	"testing"

	"github.com/miekg/dns"
)

func TestMultiLevelCache_SynthesizeFromRRset(t *testing.T) {
	cfg := config.NewConfig()
	c := NewMultiLevelCache(cfg)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	// Manually add an RRset to the rrsetCache
	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	rrset := []dns.RR{rr}
	c.rrsetCache.Set(key, rrset)

	// The message should not be in the message cache
	_, found, _ := c.messageCache.Get(key)
	if found {
		t.Fatal("message cache should be empty for this test")
	}

	// Now, Get from the multi-level cache should synthesize a response
	retrievedMsg, found, _ := c.Get(q)
	if !found {
		t.Fatal("expected to synthesize a message from the RRset cache")
	}

	// Verify the synthesized message
	if retrievedMsg.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", retrievedMsg.Rcode)
	}
	if len(retrievedMsg.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(retrievedMsg.Answer))
	}
	if retrievedMsg.Answer[0].String() != rr.String() {
		t.Errorf("expected answer %s, got %s", rr.String(), retrievedMsg.Answer[0].String())
	}
	if retrievedMsg.Question[0].String() != q.String() {
		t.Errorf("expected question %s, got %s", q.String(), retrievedMsg.Question[0].String())
	}
}

func TestMultiLevelCache_SynthesizeWithCNAME(t *testing.T) {
	cfg := config.NewConfig()
	c := NewMultiLevelCache(cfg)

	// Setup CNAME chain: www.example.com -> real.example.com -> 1.2.3.4
	q := dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cnameRR, _ := dns.NewRR("www.example.com. 60 IN CNAME real.example.com.")
	aRR, _ := dns.NewRR("real.example.com. 60 IN A 1.2.3.4")

	// Add records to RRset cache
	c.rrsetCache.Set(Key(dns.Question{Name: "www.example.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}), []dns.RR{cnameRR})
	c.rrsetCache.Set(Key(dns.Question{Name: "real.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}), []dns.RR{aRR})

	// Get from multi-level cache, which should synthesize the response
	msg, found, _ := c.Get(q)
	if !found {
		t.Fatal("expected to synthesize a message for a CNAME query")
	}

	// Verify the synthesized message
	if len(msg.Answer) != 2 {
		t.Fatalf("expected 2 answer records (CNAME and A), got %d", len(msg.Answer))
	}

	foundCNAME := false
	foundA := false
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			foundCNAME = true
		}
		if _, ok := rr.(*dns.A); ok {
			foundA = true
		}
	}

	if !foundCNAME {
		t.Error("synthesized response should contain the CNAME record")
	}
	if !foundA {
		t.Error("synthesized response should contain the A record")
	}
}