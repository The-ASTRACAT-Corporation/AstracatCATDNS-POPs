package main

import (
	"context"
	"flag"
	"log"
	"net"
	"sync"
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
	tokens  int
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

	// Refill tokens based on elapsed time.
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
	w            dns.ResponseWriter
	req          *dns.Msg
	shardedCache *ShardedCache
	r            *resolver.Resolver
}

func (j *DnsJob) Execute() {
	// Generate a cache key from the DNS question
	cacheKey := j.req.Question[0].Name + ":" + dns.TypeToString[j.req.Question[0].Qtype]

	// Try to get the response from cache
	if cachedMsg, found, isNegative, _ := j.shardedCache.Get(cacheKey); found {
		if isNegative {
			log.Printf("Cache HIT (negative) for %s", cacheKey)
			m := new(dns.Msg)
			m.SetRcode(j.req, dns.RcodeServerFailure)
			j.w.WriteMsg(m)
			return
		} else {
			log.Printf("Cache HIT (positive) for %s", cacheKey)
			cachedMsg.Id = j.req.Id
			j.w.WriteMsg(cachedMsg)
			return
		}
	}
	log.Printf("Cache MISS for %s", cacheKey)
	msg := new(dns.Msg)
	msg.SetQuestion(j.req.Question[0].Name, j.req.Question[0].Qtype)
	msg.SetEdns0(4096, true)

	result := j.r.Exchange(context.Background(), msg)
	if result.Err != nil {
		log.Printf("Error exchanging DNS query: %v", result.Err)
		m := new(dns.Msg)
		m.SetRcode(j.req, dns.RcodeServerFailure)
		j.w.WriteMsg(m)
		j.shardedCache.Set(cacheKey, m, 30*time.Second, true, false)
		return
	}

	result.Msg.SetRcode(j.req, result.Msg.Rcode)
	result.Msg.RecursionAvailable = true

	ttl := 60 * time.Second
	if len(result.Msg.Answer) > 0 {
		minTTL := result.Msg.Answer[0].Header().Ttl
		for _, rr := range result.Msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		ttl = time.Duration(minTTL) * time.Second
	}

	dnssecValidated := result.Msg.AuthenticatedData
	if !dnssecValidated {
		ttl = 5 * time.Second
	}

	j.shardedCache.Set(cacheKey, result.Msg, ttl, false, dnssecValidated)
	j.w.WriteMsg(result.Msg)
}

func main() {
	var (
		port          = flag.String("port", ":5053", "Port to listen on")
		workers       = flag.Int("workers", 100, "Number of worker goroutines")
		queueSize     = flag.Int("queue-size", 1000, "Size of the job queue")
		cacheShards   = flag.Int("cache-shards", defaultShards, "Number of cache shards")
		rateLimitRPS  = flag.Int("rate-limit-rps", 10, "Rate limit: requests per second per IP")
		rateLimitBurst = flag.Int("rate-limit-burst", 20, "Rate limit: burst size per IP")
	)
	flag.Parse()

	resolver.Query = func(s string) {
		// Quiet mode, uncomment for verbose query logging
		// fmt.Println("Query: " + s)
	}

	shardedCache := NewShardedCache(*cacheShards, 1*time.Minute)
	defer shardedCache.Stop()

	workerPool := NewWorkerPool(*workers, *queueSize)
	workerPool.Start()
	defer workerPool.Stop()

	rateLimiter := NewRateLimiter(*rateLimitRPS, *rateLimitBurst, 3*time.Minute)

	r := resolver.NewResolver()

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		// --- Security and Resilience Enhancements ---
		ip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		if !rateLimiter.Allow(ip) {
			log.Printf("Rate limit exceeded for IP: %s", ip)
			return // Just drop the request
		}

		if len(req.Question) == 0 {
			log.Println("Received request with no questions")
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeFormatError)
			w.WriteMsg(m)
			return
		}

		if req.Question[0].Qtype == dns.TypeANY {
			log.Printf("Refusing ANY query from %s for %s", ip, req.Question[0].Name)
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}
		// --- End Enhancements ---

		job := &DnsJob{
			w:            w,
			req:          req,
			shardedCache: shardedCache,
			r:            r,
		}
		workerPool.Submit(job)
	})

	server := &dns.Server{
		Addr:    *port,
		Net:     "udp",
		UDPSize: 65535,
	}

	log.Printf("Starting DNS resolver on %s", *port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}