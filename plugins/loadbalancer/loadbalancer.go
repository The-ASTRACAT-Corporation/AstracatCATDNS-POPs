package loadbalancer

import (
	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// Backend represents a server to which traffic can be routed.
type Backend struct {
	Address string `json:"address"` // IP address or hostname
	Weight  int    `json:"weight"`  // for weighted round-robin
	// for GeoDNS
	Country string `json:"country"`
	// for health checks
	Healthy bool `json:"healthy"`
}

// Pool represents a collection of backends for a specific domain.
type Pool struct {
	Name      string     `json:"name"` // e.g., "socks.example.com"
	Backends  []*Backend `json:"backends"`
	Policy    string     `json:"policy"` // "round-robin", "weighted-round-robin", "geoip"
	mu        sync.RWMutex
	nextIndex int // for round-robin
}

// LoadBalancerPlugin is the main plugin struct.
type LoadBalancerPlugin struct {
	pools map[string]*Pool
	mu    sync.RWMutex
}

// New creates a new LoadBalancerPlugin.
func New() *LoadBalancerPlugin {
	lb := &LoadBalancerPlugin{
		pools: make(map[string]*Pool),
	}
	go lb.startHealthChecks()
	return lb
}

func (p *LoadBalancerPlugin) Name() string {
	return "LoadBalancer"
}

// Execute is the main entry point for the plugin.
func (p *LoadBalancerPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	if len(msg.Question) == 0 {
		return nil
	}
	q := msg.Question[0]

	p.mu.RLock()
	pool, ok := p.pools[q.Name]
	p.mu.RUnlock()

	if !ok {
		return nil // No pool for this domain, continue chain
	}

	log.Printf("[%s] handling request for %s", p.Name(), q.Name)

	backend, err := p.selectBackend(pool, ctx.ResponseWriter.RemoteAddr().String())
	if err != nil {
		log.Printf("[%s] error selecting backend for %s: %v", p.Name(), q.Name, err)
		return nil // Or handle error appropriately
	}

	res := new(dns.Msg)
	res.SetReply(msg)

	// Create an A or AAAA record based on the backend address
	ip := net.ParseIP(backend.Address)
	if ip == nil {
		log.Printf("[%s] invalid IP address for backend %s", p.Name(), backend.Address)
		return nil
	}

	if ip.To4() != nil {
		rr, err := dns.NewRR(dns.Fqdn(q.Name) + " 300 IN A " + backend.Address)
		if err == nil {
			res.Answer = append(res.Answer, rr)
		}
	} else {
		rr, err := dns.NewRR(dns.Fqdn(q.Name) + " 300 IN AAAA " + backend.Address)
		if err == nil {
			res.Answer = append(res.Answer, rr)
		}
	}

	ctx.ResponseWriter.WriteMsg(res)
	ctx.Stop = true // We have handled the request

	return nil
}

// selectBackend selects a backend from a pool based on the configured policy.
func (p *LoadBalancerPlugin) selectBackend(pool *Pool, clientIP string) (*Backend, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	healthyBackends := p.getHealthyBackends(pool)
	if len(healthyBackends) == 0 {
		return nil, &net.DNSError{Err: "no healthy backends", Name: pool.Name}
	}

	switch pool.Policy {
	case "round-robin":
		return p.roundRobin(pool, healthyBackends), nil
	case "weighted-round-robin":
		return p.weightedRoundRobin(pool, healthyBackends), nil
	case "geoip":
		// GeoIP lookup logic would go here
		// For now, fall back to round-robin
		return p.roundRobin(pool, healthyBackends), nil
	default:
		return p.roundRobin(pool, healthyBackends), nil
	}
}

// getHealthyBackends returns a slice of healthy backends.
func (p *LoadBalancerPlugin) getHealthyBackends(pool *Pool) []*Backend {
	var healthy []*Backend
	for _, b := range pool.Backends {
		if b.Healthy {
			healthy = append(healthy, b)
		}
	}
	return healthy
}

// roundRobin selects a backend using simple round-robin.
func (p *LoadBalancerPlugin) roundRobin(pool *Pool, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	backend := backends[pool.nextIndex%len(backends)]
	pool.nextIndex = (pool.nextIndex + 1) % len(backends)
	return backend
}

// weightedRoundRobin selects a backend based on weights.
func (p *LoadBalancerPlugin) weightedRoundRobin(pool *Pool, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.Weight
	}

	if totalWeight == 0 {
		// If all weights are 0, fall back to simple round-robin
		return p.roundRobin(pool, backends)
	}

	// This is a common implementation of weighted round-robin.
	// It's not perfectly smooth, but it's simple and effective.
	for {
		pool.nextIndex = (pool.nextIndex + 1) % len(backends)
		if pool.nextIndex == 0 {
			// When we've completed a cycle, we need to adjust the current weight
			// This is a simplified version of the smooth weighted round-robin algorithm
		}
		// A simple approach is to select a backend with a probability proportional to its weight.
		// A more advanced approach would be to use a GCD-based algorithm for smoother distribution.
		// For now, we will use a simple random selection based on weight.
		// This is not true weighted round-robin, but it's better than the previous implementation.
		rand.Seed(time.Now().UnixNano())
		r := rand.Intn(totalWeight)
		for _, b := range backends {
			r -= b.Weight
			if r < 0 {
				return b
			}
		}
	}
}

// startHealthChecks starts a goroutine to periodically check the health of backends.
func (p *LoadBalancerPlugin) startHealthChecks() {
	ticker := time.NewTicker(30 * time.Second)
	// Don't defer Stop in a goroutine that runs for the lifetime of the app

	for range ticker.C {
		p.mu.RLock()
		for _, pool := range p.pools {
			go p.checkPoolHealth(pool)
		}
		p.mu.RUnlock()
	}
}

// checkPoolHealth checks the health of all backends in a pool.
func (p *LoadBalancerPlugin) checkPoolHealth(pool *Pool) {
	// Note: Locking the pool for the entire duration of health checks
	// might be a bottleneck if checks are slow. Consider more granular locking.
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, backend := range pool.Backends {
		// For SOCKS proxy, a TCP dial is a good basic check.
		// The address should be in "host:port" format.
		// Assuming a default SOCKS port if not specified, e.g., 1080
		addr := backend.Address
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "1080") // Default SOCKS port
		}

		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			if backend.Healthy {
				backend.Healthy = false
				log.Printf("[%s] backend %s is now unhealthy: %v", p.Name(), backend.Address, err)
			}
		} else {
			if !backend.Healthy {
				backend.Healthy = true
				log.Printf("[%s] backend %s is now healthy", p.Name(), backend.Address)
			}
			conn.Close()
		}
	}
}


// AddPool adds a new load balancing pool.
func (p *LoadBalancerPlugin) AddPool(pool *Pool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pools[pool.Name] = pool
}

// GetPools returns all pools.
func (p *LoadBalancerPlugin) GetPools() []*Pool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pools := make([]*Pool, 0, len(p.pools))
	for _, pool := range p.pools {
		pools = append(pools, pool)
	}
	return pools
}


// GetPool returns a pool by name.
func (p *LoadBalancerPlugin) GetPool(name string) (*Pool, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pool, ok := p.pools[name]
	return pool, ok
}

// DeletePool removes a pool by name.
func (p *LoadBalancerPlugin) DeletePool(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pools, name)
}
