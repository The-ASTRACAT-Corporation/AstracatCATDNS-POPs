package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

const (
	defaultShards = 32 // Example: 32 shards
)

// RateLimiter stores request counts for IP addresses.
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	rps      int           // requests per second
	burst    int           // max burst size
	cleanup  time.Duration // cleanup interval
}

type visitor struct {
	tokens   int
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rps, burst int, cleanup time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rps:      rps,
		burst:    burst,
		cleanup:  cleanup,
	}
	go rl.startCleanup()
	return rl
}

// Allow checks if a request from a given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{tokens: rl.burst - 1, lastSeen: time.Now()}
		return true
	}

	elapsed := time.Since(v.lastSeen)
	tokensToAdd := int(elapsed.Seconds() * float64(rl.rps))
	if tokensToAdd > 0 {
		v.tokens += tokensToAdd
		v.lastSeen = time.Now()
	}

	if v.tokens > rl.burst {
		v.tokens = rl.burst
	}

	if v.tokens > 0 {
		v.tokens--
		return true
	}

	return false
}

func (rl *RateLimiter) startCleanup() {
	ticker := time.NewTicker(rl.cleanup)
	for {
		<-ticker.C
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > rl.cleanup {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

type DnsJob struct {
	w   dns.ResponseWriter
	req *dns.Msg
	cr  *CachingResolver
}

func (j *DnsJob) Execute() {
	resp, err := j.cr.Exchange(context.Background(), j.req)
	if err != nil {
		log.Printf("Error resolving query: %v", err)
		m := new(dns.Msg)
		m.SetRcode(j.req, dns.RcodeServerFailure)
		j.w.WriteMsg(m)
		return
	}

	j.w.WriteMsg(resp)
}

func main() {
	var (
		port                 = flag.String("port", ":5053", "Port to listen on")
		workers              = flag.Int("workers", 100, "Number of worker goroutines")
		queueSize            = flag.Int("queue-size", 1000, "Size of the job queue")
		cacheShards          = flag.Int("cache-shards", defaultShards, "Number of cache shards")
		rateLimitRPS         = flag.Int("rate-limit-rps", 10, "Rate limit: requests per second per IP")
		rateLimitBurst       = flag.Int("rate-limit-burst", 20, "Rate limit: burst size per IP")
		cacheMaxEntries      = flag.Int("cache-max-entries", 10000, "Cache: maximum number of entries per shard")
		cacheMinTTLSecs      = flag.Int("cache-min-ttl-secs", 60, "Cache: minimum TTL in seconds")
		cacheMaxTTLSecs      = flag.Int("cache-max-ttl-secs", 86400, "Cache: maximum TTL in seconds")
		cacheNegativeEnabled = flag.Bool("cache-negative-enabled", true, "Cache: enable negative caching")
		cacheNegativeTTLSecs = flag.Int("cache-negative-ttl-secs", 60, "Cache: TTL for negative responses in seconds")
	)
	flag.Parse()

	resolver.Query = func(s string) {
		// Quiet mode
	}

	cacheConfig := CacheConfig{
		MaxEntries:           *cacheMaxEntries,
		MinTTLSecs:           *cacheMinTTLSecs,
		MaxTTLSecs:           *cacheMaxTTLSecs,
		NegativeCacheEnabled: *cacheNegativeEnabled,
		NegativeTTLSecs:      *cacheNegativeTTLSecs,
	}
	shardedCache := NewShardedCache(*cacheShards, 1*time.Minute, cacheConfig)
	defer shardedCache.Stop()

	baseResolver := resolver.NewResolver()
	cachingResolver := NewCachingResolver(shardedCache, baseResolver)

	workerPool := NewWorkerPool(*workers, *queueSize)
	workerPool.Start()
	defer workerPool.Stop()

	rateLimiter := NewRateLimiter(*rateLimitRPS, *rateLimitBurst, 3*time.Minute)

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

		job := &DnsJob{
			w:   w,
			req: req,
			cr:  cachingResolver,
		}
		workerPool.Submit(job)
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