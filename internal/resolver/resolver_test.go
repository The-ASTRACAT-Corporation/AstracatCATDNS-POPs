package resolver

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newTestServer starts a mock DNS server and returns its address.
func newTestServer(t *testing.T, handler dns.HandlerFunc) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Second, WriteTimeout: time.Second}
	server.Handler = handler

	go func() {
		err := server.ActivateAndServe()
		if err != nil {
			// Don't log error on graceful shutdown
			if err.Error() != "dns: Server closed" {
				t.Logf("Mock server error: %v", err)
			}
		}
	}()

	t.Cleanup(func() {
		server.Shutdown()
	})

	return pc.LocalAddr().String()
}

func TestResolver_Resolve(t *testing.T) {
	// Mock DNS server that returns a simple A record.
	mockHandler := func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP("1.2.3.4"),
		})
		w.WriteMsg(msg)
	}
	mockServerAddr := newTestServer(t, mockHandler)

	// Create a new cache and resolver for the test.
	cfg := config.NewConfig()
	cfg.KnotResolverAddr = mockServerAddr // Point to our mock server
	dir, err := os.MkdirTemp("", "test-resolver-lmdb")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	m := metrics.NewMetrics()
	c := cache.NewCache(cache.DefaultCacheSize, cache.DefaultShards, cfg.PrefetchInterval, dir, m)
	defer c.Close()
	r := NewResolver(cfg, c, m)

	// Define the question to test.
	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)

	// Resolve the domain.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	// Check the answer content
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Expected A record, got %T", msg.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("Expected A record to be 1.2.3.4, got %s", a.A.String())
	}
}

func TestResolver_Resolve_DNSSEC(t *testing.T) {
	testCases := []struct {
		name          string
		domain        string
		handler       dns.HandlerFunc
		expectADBit   bool
		expectRCode   int
		expectError   bool
		expectAnswers bool
	}{
		{
			name:   "Secure Domain",
			domain: "secure.example.com.",
			handler: func(w dns.ResponseWriter, r *dns.Msg) {
				msg := new(dns.Msg)
				msg.SetReply(r)
				msg.AuthenticatedData = true
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   net.ParseIP("1.1.1.1"),
				})
				w.WriteMsg(msg)
			},
			expectADBit:   true,
			expectRCode:   dns.RcodeSuccess,
			expectError:   false,
			expectAnswers: true,
		},
		{
			name:   "Insecure Domain",
			domain: "insecure.example.com.",
			handler: func(w dns.ResponseWriter, r *dns.Msg) {
				msg := new(dns.Msg)
				msg.SetReply(r)
				msg.AuthenticatedData = false
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   net.ParseIP("2.2.2.2"),
				})
				w.WriteMsg(msg)
			},
			expectADBit:   false,
			expectRCode:   dns.RcodeSuccess,
			expectError:   false,
			expectAnswers: true,
		},
		{
			name:   "Bogus Domain",
			domain: "bogus.example.com.",
			handler: func(w dns.ResponseWriter, r *dns.Msg) {
				msg := new(dns.Msg)
				msg.SetReply(r)
				msg.Rcode = dns.RcodeServerFailure
				w.WriteMsg(msg)
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockServerAddr := newTestServer(t, tc.handler)
			cfg := config.NewConfig()
			cfg.KnotResolverAddr = mockServerAddr
			dir, err := os.MkdirTemp("", "test-dnssec-lmdb")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(dir)
			m := metrics.NewMetrics()
			c := cache.NewCache(cache.DefaultCacheSize, cache.DefaultShards, cfg.PrefetchInterval, dir, m)
			defer c.Close()
			r := NewResolver(cfg, c, m)

			req := new(dns.Msg)
			req.SetQuestion(tc.domain, dns.TypeA)
			req.SetEdns0(4096, true) // DNSSEC OK

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			msg, err := r.Resolve(ctx, req)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error for domain %s, but got none", tc.domain)
				}
				return
			}

			if err != nil {
				t.Fatalf("Resolve() failed for %s: %v", tc.domain, err)
			}
			if msg == nil {
				t.Fatalf("Resolve() returned a nil message for %s.", tc.domain)
			}
			if msg.Rcode != tc.expectRCode {
				t.Errorf("Expected RCode %s, but got %s", dns.RcodeToString[tc.expectRCode], dns.RcodeToString[msg.Rcode])
			}
			if msg.AuthenticatedData != tc.expectADBit {
				t.Errorf("Expected AD bit to be %t, but got %t", tc.expectADBit, msg.AuthenticatedData)
			}
			if tc.expectAnswers && len(msg.Answer) == 0 {
				t.Errorf("Expected answers for %s, but got none", tc.domain)
			}
		})
	}
}
