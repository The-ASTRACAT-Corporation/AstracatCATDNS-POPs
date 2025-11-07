package cache

import (
	"dns-resolver/internal/metrics"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a new cache instance for testing.
func newTestCache(t *testing.T) (*Cache, func()) {
	t.Helper()

	m := metrics.NewMetrics()
	cache, err := NewCache(128, m)
	assert.NoError(t, err)

	cleanup := func() {
		cache.Close()
	}

	return cache, cleanup
}

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
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("example.com.", 60, "1.2.3.4")

	c.Set(key, msg, 0)

	// Ristretto is eventually consistent, so we might need a short wait
	time.Sleep(10 * time.Millisecond)

	retrievedMsg, found, revalidate := c.Get(key)
	assert.True(t, found, "expected to find message in cache, but didn't")
	assert.False(t, revalidate, "expected revalidate to be false for a fresh entry")
	assert.NotNil(t, retrievedMsg, "retrieved message was nil")
}

func TestCacheNotFound(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "notfound.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	_, found, _ := c.Get(key)
	assert.False(t, found, "expected to not find message in cache, but did")
}

func TestCacheExpiration(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "shortlived.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("shortlived.com.", 1, "2.3.4.5")

	c.Set(key, msg, 0)

	time.Sleep(1100 * time.Millisecond)

	_, found, _ := c.Get(key)
	assert.False(t, found, "expected message to be expired and not found, but it was found")
}

func TestCacheStaleWhileRevalidate(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "stale.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	// TTL of 1 second, SWR of 5 seconds
	msg := createTestMsg("stale.com.", 1, "3.4.5.6")
	swrDuration := 5 * time.Second

	c.Set(key, msg, swrDuration)

	// Wait for item to become stale but not fully expired from SWR window
	time.Sleep(1100 * time.Millisecond)

	retrievedMsg, found, revalidate := c.Get(key)
	assert.True(t, found, "expected to get stale message, but got nothing")
	assert.True(t, revalidate, "expected revalidate to be true for a stale entry")
	assert.NotNil(t, retrievedMsg, "retrieved stale message was nil")
	assert.Len(t, retrievedMsg.Answer, 1, "expected 1 answer in stale message")

	// Wait for the SWR window to close
	time.Sleep(swrDuration)

	// After the SWR window, the item should be gone
	_, found, _ = c.Get(key)
	assert.False(t, found, "expected message to be expired and not found after SWR window, but it was found")
}
