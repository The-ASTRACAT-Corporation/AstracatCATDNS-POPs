package resolver

import (
	"dns-resolver/internal/cache"
	"testing"

	"github.com/miekg/dns"
)

func TestResolver_Resolve(t *testing.T) {
	// Create a new cache and resolver for the test.
	c := cache.NewMultiLevelCache(100, 1000)
	r := NewResolver(c)

	// Define the question to test.
	question := dns.Question{
		Name:   "www.google.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	// Resolve the domain.
	msg, err := r.Resolve(question)

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

	t.Logf("Successfully resolved %s", question.Name)
	for _, ans := range msg.Answer {
		t.Logf(" -> %s", ans.String())
	}
}
