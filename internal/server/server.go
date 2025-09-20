package server

import (
	"context"
	"github.com/miekg/dns"
	"log"
	"sync"
	"time"
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
	W   dns.ResponseWriter
	Req *dns.Msg
	Cr  *CachingResolver
}

func (j *DnsJob) Execute() {
	resp, err := j.Cr.Exchange(context.Background(), j.Req)
	if err != nil {
		log.Printf("Error resolving query: %v", err)
		m := new(dns.Msg)
		m.SetRcode(j.Req, dns.RcodeServerFailure)
		j.W.WriteMsg(m)
		return
	}

	j.W.WriteMsg(resp)
}
