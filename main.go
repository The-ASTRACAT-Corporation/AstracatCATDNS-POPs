package main

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func main() {
	go func() {
		log.Println("Starting pprof server on :6060")
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			log.Fatalf("pprof server failed: %v", err)
		}
	}()

	var (
		port                 = flag.String("port", ":5053", "Port to listen on")
		concurrency          = flag.Int("concurrency", 500, "Number of concurrent resolutions")
		cacheShards          = flag.Int("cache-shards", 256, "Number of cache shards")
		rateLimitRPS         = flag.Int("rate-limit-rps", 1000, "Rate limit: requests per second per IP")
		rateLimitBurst       = flag.Int("rate-limit-burst", 2000, "Rate limit: burst size per IP")
		cacheMaxEntries      = flag.Int("cache-max-entries", 10000, "Cache: maximum number of entries per shard")
		cacheMinTTLSecs      = flag.Int("cache-min-ttl-secs", 60, "Cache: minimum TTL in seconds")
		cacheMaxTTLSecs      = flag.Int("cache-max-ttl-secs", 86400, "Cache: maximum TTL in seconds")
		cacheNegativeEnabled = flag.Bool("cache-negative-enabled", true, "Cache: enable negative caching")
		cacheNegativeTTLSecs = flag.Int("cache-negative-ttl-secs", 60, "Cache: TTL for negative responses in seconds")
		enableDnssec         = flag.Bool("dnssec", true, "Enable DNSSEC validation")
	)
	flag.Parse()

	semaphore := make(chan struct{}, *concurrency)

	cacheConfig := cache.CacheConfig{
		MaxEntries:           *cacheMaxEntries,
		MinTTLSecs:           *cacheMinTTLSecs,
		MaxTTLSecs:           *cacheMaxTTLSecs,
		NegativeCacheEnabled: *cacheNegativeEnabled,
		NegativeTTLSecs:      *cacheNegativeTTLSecs,
	}
	shardedCache := cache.NewShardedCache(*cacheShards, 1*time.Minute, cacheConfig)
	defer shardedCache.Stop()

	recursionCache := cache.NewShardedCache(*cacheShards, 1*time.Minute, cacheConfig)
	defer recursionCache.Stop()

	baseResolver := resolver.NewResolver(recursionCache, *enableDnssec)
	cachingResolver := server.NewCachingResolver(shardedCache, baseResolver)

	rateLimiter := server.NewRateLimiter(*rateLimitRPS, *rateLimitBurst, 3*time.Minute)
	defer rateLimiter.Stop()

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeFormatError)
			w.WriteMsg(m)
			return
		}

		ip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		if !rateLimiter.Allow(ip) {
			log.Printf("Rate limit exceeded for IP: %s", ip)
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}

		if req.Question[0].Qtype == dns.TypeANY {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}

		go func() {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resp, err := cachingResolver.Exchange(context.Background(), req)
			if err != nil {
				log.Printf("Error resolving query: %v", err)
				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}
			w.WriteMsg(resp)
		}()
	})

	var wg sync.WaitGroup

	packetConn, err := net.ListenPacket("udp", *port)
	if err != nil {
		log.Fatalf("Failed to create UDP listener: %v", err)
	}
	listener, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		server := &dns.Server{PacketConn: packetConn, UDPSize: 65535}
		if err := server.ActivateAndServe(); err != nil {
			log.Printf("UDP server error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		server := &dns.Server{Listener: listener}
		if err := server.ActivateAndServe(); err != nil {
			log.Printf("TCP server error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down servers...")
	packetConn.Close()
	listener.Close()

	wg.Wait()
	log.Println("Servers stopped.")
}