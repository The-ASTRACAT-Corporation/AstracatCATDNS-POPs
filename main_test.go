package main

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

// domainsForBenchmark is a shared list of domains for both benchmarks.
var domainsForBenchmark = []string{
	"test.qazz.uk",
	"google.com",
	"github.com",
	"cloudflare.com",
	"example.com",
}

// runConcurrentQueries is a helper function to execute DNS queries concurrently.
func runConcurrentQueries(r *resolver.Resolver) {
	var wg sync.WaitGroup
	for _, domain := range domainsForBenchmark {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(d), dns.TypeA)
			msg.SetEdns0(4096, true)
			r.Exchange(context.Background(), msg)
		}(domain)
	}
	wg.Wait()
}

// BenchmarkResolverWithoutCache benchmarks the resolver's performance with caching disabled.
func BenchmarkResolverWithoutCache(b *testing.B) {
	// Ensure caching is disabled for this benchmark.
	resolver.Cache = nil
	r := resolver.NewResolver()

	// The b.N loop is managed by the testing framework.
	for i := 0; i < b.N; i++ {
		runConcurrentQueries(r)
	}
}

// BenchmarkResolverWithCache benchmarks the resolver's performance with caching enabled.
func BenchmarkResolverWithCache(b *testing.B) {
	// Enable our custom cache.
	resolver.Cache = NewSimpleInMemoryCache()
	r := resolver.NewResolver()

	// --- Pre-populate the cache ---
	// We run the queries once *before* the benchmark loop starts. This ensures
	// that the cache is warm and we are only measuring the performance of
	// reading from the cache.
	runConcurrentQueries(r)

	// Reset the timer to exclude the cache-warming step from the benchmark results.
	b.ResetTimer()

	// The b.N loop measures the performance of the cached queries.
	for i := 0; i < b.N; i++ {
		runConcurrentQueries(r)
	}
}