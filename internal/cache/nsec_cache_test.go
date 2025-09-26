package cache

import (
	"dns-resolver/internal/config"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNsecCache_AddAndCheck(t *testing.T) {
	cfg := config.NewConfig()
	nc := NewNsecCache(cfg)
	defer nc.Stop()

	// Add an NSEC record for a.example.com, pointing to c.example.com
	nsecRR, err := dns.NewRR("a.example.com. 60 IN NSEC c.example.com. A AAAA RRSIG")
	if err != nil {
		t.Fatalf("failed to create NSEC RR: %v", err)
	}
	nc.Add(nsecRR.(*dns.NSEC))

	// Test case 1: Check for a name that should be covered (NXDOMAIN)
	qNxdomain := dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg, found := nc.Check(qNxdomain)
	if !found {
		t.Fatal("expected to get NXDOMAIN proof from NSEC cache")
	}
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("expected RcodeNameError, got %d", msg.Rcode)
	}
	if len(msg.Ns) != 1 || msg.Ns[0].Header().Name != nsecRR.Header().Name {
		t.Errorf("expected the covering NSEC record in the authority section")
	}

	// Test case 2: Check for a type that doesn't exist (NODATA)
	qNodata := dns.Question{Name: "a.example.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	msg, found = nc.Check(qNodata)
	if !found {
		t.Fatal("expected to get NODATA proof from NSEC cache")
	}
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess for NODATA, got %d", msg.Rcode)
	}
	if len(msg.Ns) != 1 || msg.Ns[0].Header().Name != nsecRR.Header().Name {
		t.Errorf("expected the NSEC record in the authority section for NODATA proof")
	}

	// Test case 3: Check for a type that does exist
	qExists := dns.Question{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, found = nc.Check(qExists)
	if found {
		t.Fatal("should not get a match for a type that exists")
	}
}

func TestNsecCache_Expiration(t *testing.T) {
	cfg := config.NewConfig()
	cfg.CacheMaxTTL = 1 * time.Second // Clamp TTL to 1 second
	nc := NewNsecCache(cfg)
	defer nc.Stop()

	nsecRR, err := dns.NewRR("a.example.com. 60 IN NSEC c.example.com. A")
	if err != nil {
		t.Fatalf("failed to create NSEC RR: %v", err)
	}
	nc.Add(nsecRR.(*dns.NSEC))

	// Check that the key exists before expiration
	key := strings.ToLower(nsecRR.Header().Name)
	nc.RLock()
	item, ok := nc.items[key]
	nc.RUnlock()
	if !ok {
		t.Fatal("NSEC record was not added to the cache")
	}
	// Check if TTL was clamped
	if item.Expiration.Sub(time.Now()) > 2*time.Second {
		t.Fatalf("TTL was not clamped correctly. Expiration is %v", item.Expiration)
	}

	time.Sleep(2 * time.Second)

	// Check if the item has been removed by the cleaner
	// Note: The default cleaner runs every 5 minutes. For a more precise test,
	// we would need to trigger the cleanup manually or use a shorter interval.
	// Here, we'll just check if the Check function ignores the expired record.
	q := dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, found := nc.Check(q)
	if found {
		t.Fatal("expected expired NSEC record to be ignored")
	}
}