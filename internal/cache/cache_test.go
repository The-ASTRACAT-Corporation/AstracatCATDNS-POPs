package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCache_SetGet(t *testing.T) {
	c := NewCache()
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	msg.Answer = append(msg.Answer, rr)

	c.Set(key, msg)

	retrievedMsg, found := c.Get(key)
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
	c := NewCache()
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

	c.Set(key, msg)

	// Wait for the item to expire
	time.Sleep(2 * time.Second)

	_, found := c.Get(key)
	if found {
		t.Fatal("expected message to be expired from cache")
	}
}

func TestCache_GetCopy(t *testing.T) {
	c := NewCache()
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
	msg.Answer = append(msg.Answer, rr)

	c.Set(key, msg)

	retrievedMsg, found := c.Get(key)
	if !found {
		t.Fatal("expected to find message in cache")
	}

	// Modify the retrieved message
	retrievedMsg.Answer[0].(*dns.A).A[0] = 255

	// Get the message again and check if it was modified in the cache
	retrievedMsg2, _ := c.Get(key)
	if retrievedMsg2.Answer[0].(*dns.A).A[0] == 255 {
		t.Fatal("Get should return a copy of the message, but the original was modified")
	}
}
