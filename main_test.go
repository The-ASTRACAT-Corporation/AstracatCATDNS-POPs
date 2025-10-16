package main

import (
	"log"
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
		if err != nil && err.Error() != "dns: Server closed" {
			t.Logf("Mock server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		server.Shutdown()
	})

	return pc.LocalAddr().String()
}

// TestMain sets up a mock upstream resolver and runs the main server against it.
func TestMain(m *testing.M) {
	// Dummy testing.T for the mock server setup
	t := &testing.T{}

	// Mock DNS server that handles all queries.
	mockHandler := func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		q := r.Question[0]

		// Simple routing based on domain for different test cases.
		switch q.Name {
		case "ripe.net.":
			msg.AuthenticatedData = true // Simulate secure response
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP("193.0.6.139"),
			})
		default: // For cloudflare.com and example.com
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP("1.1.1.1"),
			})
		}
		w.WriteMsg(msg)
	}

	mockKnotResolverAddr := newTestServer(t, mockHandler)
	os.Setenv("KNOT_RESOLVER_ADDR", mockKnotResolverAddr)

	// Start the main application server in the background
	go func() {
		log.SetOutput(os.NewFile(0, os.DevNull))
		main()
	}()

	// Give the server a moment to start up
	time.Sleep(1 * time.Second)

	// Run the tests
	exitCode := m.Run()

	// Exit with the test result
	os.Exit(exitCode)
}

func TestIntegration_ResolveA(t *testing.T) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	// Using cloudflare.com as it's a well-known, stable domain.
	msg.SetQuestion("cloudflare.com.", dns.TypeA)

	// The server is running on the default address from config.
	serverAddr := "127.0.0.1:5053"

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		t.Fatalf("Failed to exchange with server: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 0 {
		t.Error("Expected to receive at least one answer")
	}
}

func TestIntegration_ResolveDNSSEC(t *testing.T) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	// Using ripe.net as it's known to be DNSSEC-signed.
	msg.SetQuestion("ripe.net.", dns.TypeA)
	// Set the DO (DNSSEC OK) bit to request DNSSEC data.
	msg.SetEdns0(4096, true)

	serverAddr := "127.0.0.1:5053"

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		t.Fatalf("Failed to exchange with server: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 0 {
		t.Error("Expected to receive at least one answer")
	}

	// Check for the AD (Authenticated Data) bit in the response.
	// This indicates that the resolver was able to validate the data.
	if !resp.AuthenticatedData {
		t.Error("Expected Authenticated Data (AD) bit to be set for a DNSSEC-signed domain")
	}
}

func BenchmarkResolve(b *testing.B) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	serverAddr := "127.0.0.1:5053"

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := client.Exchange(msg, serverAddr)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
