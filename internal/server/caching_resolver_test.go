package server_test

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

// mockHandler is a function that generates a response for a given request.
type mockHandler func(req *dns.Msg) *dns.Msg

// mockDNSServer is a helper for testing that listens on a local port.
func mockDNSServer(t *testing.T, handler mockHandler) (addr string, cleanup func()) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("Failed to listen on UDP: %v", err)
	}

	cleanup = func() {
		l.Close()
	}

	go func() {
		for {
			buf := make([]byte, 512)
			n, remoteAddr, err := l.ReadFromUDP(buf)
			if err != nil {
				return // Closed
			}

			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				fmt.Println("Failed to unpack request:", err)
				continue
			}

			resp := handler(req)
			resp.SetReply(req)

			packed, err := resp.Pack()
			if err != nil {
				fmt.Println("Failed to pack response:", err)
				continue
			}
			_, err = l.WriteToUDP(packed, remoteAddr)
			if err != nil {
				fmt.Println("Failed to write response:", err)
			}
		}
	}()

	return l.LocalAddr().String(), cleanup
}

// mockResolver is a mock implementation of the resolver.Resolver for testing.
type mockResolver struct {
	exchangeFunc func(ctx context.Context, msg *dns.Msg) *resolver.Result
}

func (m *mockResolver) Exchange(ctx context.Context, msg *dns.Msg) *resolver.Result {
	if m.exchangeFunc != nil {
		return m.exchangeFunc(ctx, msg)
	}
	return &resolver.Result{Err: fmt.Errorf("mockResolver.Exchange not implemented")}
}

func TestCachingResolverCacheHit(t *testing.T) {
	cacheConfig := cache.CacheConfig{MaxEntries: 10}
	shardedCache := cache.NewShardedCache(1, 1*time.Minute, cacheConfig)

	qname := "example.com."
	qtype := dns.TypeA

	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	rr, _ := dns.NewRR(qname + " 60 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, rr)

	shardedCache.Set(qname+":"+dns.TypeToString[qtype], msg, 60*time.Second, false, true)

	// The underlying resolver should not be called.
	baseResolver := &mockResolver{
		exchangeFunc: func(ctx context.Context, msg *dns.Msg) *resolver.Result {
			t.Fatal("Expected resolver.Exchange not to be called on cache hit")
			return nil
		},
	}
	cachingResolver := server.NewCachingResolver(shardedCache, baseResolver)

	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)

	resp, err := cachingResolver.Exchange(context.Background(), req)

	if err != nil {
		t.Fatalf("Expected no error on cache hit, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected a message back, got nil")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Expected 1 answer record, got %d", len(resp.Answer))
	}
}

func TestCachingResolverCacheMiss(t *testing.T) {
	qname := "example.com."
	qtype := dns.TypeA
	cacheConfig := cache.CacheConfig{MaxEntries: 10, MinTTLSecs: 1}
	shardedCache := cache.NewShardedCache(1, 1*time.Minute, cacheConfig)

	// Mock resolver returns a successful response.
	mockResp := new(dns.Msg)
	mockResp.SetQuestion(qname, qtype)
	rr, _ := dns.NewRR(qname + " 60 IN A 1.2.3.4")
	mockResp.Answer = append(mockResp.Answer, rr)

	baseResolver := &mockResolver{
		exchangeFunc: func(ctx context.Context, msg *dns.Msg) *resolver.Result {
			return &resolver.Result{Msg: mockResp}
		},
	}
	cachingResolver := server.NewCachingResolver(shardedCache, baseResolver)

	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)

	resp, err := cachingResolver.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Expected no error from exchange, got %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected a success Rcode, got %s", dns.RcodeToString[resp.Rcode])
	}

	// Verify that the response is now in the cache.
	cacheKey := qname + ":" + dns.TypeToString[qtype]
	cachedMsg, found, isNegative, _ := shardedCache.Get(cacheKey)

	if !found {
		t.Fatal("Expected to find a cache entry after resolution")
	}
	if isNegative {
		t.Error("Expected the cache entry not to be negative")
	}
	if len(cachedMsg.Answer) != 1 {
		t.Fatalf("Expected 1 answer record in cached message, got %d", len(cachedMsg.Answer))
	}
}
