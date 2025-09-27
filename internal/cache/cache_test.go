package cache

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Helper function to create a simple DNS message for testing.
func createTestMsg(qname string, ttl uint32, answer string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	if answer != "" {
		rr, _ := dns.NewRR(dns.Fqdn(qname) + " " + strconv.Itoa(int(ttl)) + " IN A " + answer)
		msg.Answer = []dns.RR{rr}
	}
	return msg
}

func TestCacheSetAndGet(t *testing.T) {
	c := NewCache(128, 1, 0) // size, shards, prefetchInterval (0 to disable)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("example.com.", 60, "1.2.3.4")

	c.Set(key, msg, 0, 0)

	retrievedMsg, found, revalidate := c.Get(key)
	if !found {
		t.Fatal("expected to find message in cache, but didn't")
	}
	if revalidate {
		t.Error("expected revalidate to be false for a fresh entry")
	}
	if retrievedMsg == nil {
		t.Fatal("retrieved message was nil")
	}
	if len(retrievedMsg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(retrievedMsg.Answer))
	}
	if retrievedMsg.Answer[0].Header().Name != "example.com." {
		t.Errorf("unexpected answer name: %s", retrievedMsg.Answer[0].Header().Name)
	}
}

func TestCacheNotFound(t *testing.T) {
	c := NewCache(128, 1, 0)
	q := dns.Question{Name: "notfound.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	_, found, _ := c.Get(key)
	if found {
		t.Fatal("expected to not find message in cache, but did")
	}
}

func TestCacheExpiration(t *testing.T) {
	c := NewCache(128, 1, 0)
	q := dns.Question{Name: "shortlived.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	// TTL of 1 second
	msg := createTestMsg("shortlived.com.", 1, "2.3.4.5")

	c.Set(key, msg, 0, 0)

	// Wait for the item to expire
	time.Sleep(1100 * time.Millisecond)

	_, found, _ := c.Get(key)
	if found {
		t.Fatal("expected message to be expired and not found, but it was found")
	}
}

func TestCacheStaleWhileRevalidate(t *testing.T) {
	c := NewCache(128, 1, 0)
	q := dns.Question{Name: "stale.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	// TTL of 1 second, SWR of 5 seconds
	msg := createTestMsg("stale.com.", 1, "3.4.5.6")
	swrDuration := 5 * time.Second

	c.Set(key, msg, swrDuration, 0)

	// Wait for item to become stale but not fully expired
	time.Sleep(1100 * time.Millisecond)

	retrievedMsg, found, revalidate := c.Get(key)
	if !found {
		t.Fatal("expected to get stale message, but got nothing")
	}
	if !revalidate {
		t.Error("expected revalidate to be true for a stale entry")
	}
	if retrievedMsg == nil {
		t.Fatal("retrieved stale message was nil")
	}
	if len(retrievedMsg.Answer) != 1 {
		t.Fatalf("expected 1 answer in stale message, got %d", len(retrievedMsg.Answer))
	}

	// Wait for SWR window to close
	time.Sleep(swrDuration)

	_, found, _ = c.Get(key)
	if found {
		t.Fatal("expected message to be fully expired after SWR window, but it was found")
	}
}