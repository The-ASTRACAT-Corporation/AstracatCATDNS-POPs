package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

// --- Custom Cache Implementation ---
// The nsmithuk/resolver library requires developers to provide their own
// implementation of the CacheInterface for caching.

// SimpleInMemoryCache provides a basic, thread-safe in-memory cache.
// NOTE: A production-grade cache would also need to respect DNS TTLs,
// manage memory usage, and have an eviction policy. This is simplified
// for demonstration.
type SimpleInMemoryCache struct {
	mu    sync.RWMutex
	items map[string]*dns.Msg
}

// NewSimpleInMemoryCache creates a new instance of our in-memory cache.
func NewSimpleInMemoryCache() *SimpleInMemoryCache {
	return &SimpleInMemoryCache{
		items: make(map[string]*dns.Msg),
	}
}

// cacheKey generates a consistent key for a given DNS query.
func (c *SimpleInMemoryCache) cacheKey(zone string, question dns.Question) string {
	return fmt.Sprintf("%s:%s:%d:%d", zone, question.Name, question.Qtype, question.Qclass)
}

// Get retrieves a DNS message from the cache. It satisfies the resolver.CacheInterface.
func (c *SimpleInMemoryCache) Get(zone string, question dns.Question) (*dns.Msg, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(zone, question)
	msg, found := c.items[key]

	if !found {
		// No entry in the cache, so we return nil to indicate a cache miss.
		return nil, nil
	}

	// Return a copy to prevent the caller from modifying the cached object.
	return msg.Copy(), nil
}

// Update stores a DNS message in the cache. It satisfies the resolver.CacheInterface.
func (c *SimpleInMemoryCache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(zone, question)
	// Store a copy to ensure the cached object isn't modified elsewhere.
	c.items[key] = msg.Copy()
	return nil
}

func main() {
	// --- OPTIMIZATION 1: ENABLE CACHING ---
	// We enable caching by assigning our custom cache implementation to the
	// package-level 'Cache' variable before creating a resolver.
	resolver.Cache = NewSimpleInMemoryCache()

	// Disable the verbose query logging for a cleaner benchmark output.
	resolver.Query = func(s string) {}

	// Now, create the resolver. It will automatically use the cache we just set.
	r := resolver.NewResolver()

	// Domains to query concurrently.
	domains := []string{
		"test.qazz.uk",
		"google.com",
		"github.com",
		"cloudflare.com",
		"example.com",
	}

	// --- OPTIMIZATION 2: CONCURRENT QUERIES ---
	var wg sync.WaitGroup
	fmt.Println("--- Starting Concurrent DNS Queries (1st run, populating cache) ---")
	start := time.Now()

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(d), dns.TypeA)
			msg.SetEdns0(4096, true)
			r.Exchange(context.Background(), msg)
			fmt.Printf("Query for %s finished.\n", d)
		}(domain)
	}

	wg.Wait()
	duration := time.Since(start)
	fmt.Printf("--- Finished 5 concurrent queries in %s ---\n\n", duration)

	// --- VERIFYING CACHE SPEED ---
	// Run the same queries again. This time, they should be served almost
	// instantly from our custom cache.
	fmt.Println("--- Starting Concurrent DNS Queries (2nd run, from cache) ---")
	start = time.Now()

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(d), dns.TypeA)
			msg.SetEdns0(4096, true)
			result := r.Exchange(context.Background(), msg)
			// The result object from the resolver doesn't explicitly flag
			// a cache hit, but the speed difference will be the proof.
			// Let's dump one result to see the response is still valid.
			if d == "test.qazz.uk" {
				fmt.Println("Dumping cached result for test.qazz.uk:")
				spew.Dump(result)
			}
			fmt.Printf("Query for %s finished.\n", d)
		}(domain)
	}

	wg.Wait()
	duration = time.Since(start)
	fmt.Printf("--- Finished 5 cached queries in %s ---\n", duration)
}