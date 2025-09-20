package server

import (
	"hash/fnv"
	"sync"
	"time"
)

const numShards = 32

type visitor struct {
	tokens   int
	lastSeen time.Time
}

type rateLimiterShard struct {
	visitors map[string]*visitor
	mu       sync.Mutex
}

// RateLimiter stores request counts for IP addresses in a sharded map.
type RateLimiter struct {
	shards   []*rateLimiterShard
	rps      int           // requests per second
	burst    int           // max burst size
	cleanup  time.Duration // cleanup interval
	stop     chan struct{}
}

// NewRateLimiter creates a new sharded rate limiter.
func NewRateLimiter(rps, burst int, cleanup time.Duration) *RateLimiter {
	shards := make([]*rateLimiterShard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &rateLimiterShard{
			visitors: make(map[string]*visitor),
		}
	}

	rl := &RateLimiter{
		shards:   shards,
		rps:      rps,
		burst:    burst,
		cleanup:  cleanup,
		stop:     make(chan struct{}),
	}
	go rl.startCleanup()
	return rl
}

func (rl *RateLimiter) getShard(ip string) *rateLimiterShard {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return rl.shards[int(h.Sum32())%numShards]
}

// Allow checks if a request from a given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	shard := rl.getShard(ip)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	v, exists := shard.visitors[ip]
	if !exists {
		shard.visitors[ip] = &visitor{tokens: rl.burst - 1, lastSeen: time.Now()}
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
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, shard := range rl.shards {
				go rl.cleanupShard(shard)
			}
		case <-rl.stop:
			return
		}
	}
}

func (rl *RateLimiter) cleanupShard(shard *rateLimiterShard) {
	shard.mu.Lock()
	defer shard.mu.Unlock()

	for ip, v := range shard.visitors {
		if time.Since(v.lastSeen) > rl.cleanup {
			delete(shard.visitors, ip)
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stop)
}
