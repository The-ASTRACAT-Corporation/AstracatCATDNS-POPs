package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

const (
	port = ":5053"
	defaultShards = 32 // Example: 32 shards
)

type DnsJob struct {
	w  dns.ResponseWriter
	req *dns.Msg
	shardedCache *ShardedCache
	r *resolver.Resolver
}

func (j *DnsJob) Execute() {
	// Generate a cache key from the DNS question
	cacheKey := j.req.Question[0].Name + ":" + dns.TypeToString[j.req.Question[0].Qtype]

	// Try to get the response from cache
	if cachedMsg, found, isNegative, _ := j.shardedCache.Get(cacheKey); found {
		if isNegative {
			log.Printf("Cache HIT (negative) for %s", cacheKey)
			// If it's a negative cache entry, return SERVFAIL or NXDOMAIN directly
			m := new(dns.Msg)
			m.SetRcode(j.req, dns.RcodeServerFailure) // Or appropriate negative response
			j.w.WriteMsg(m)
			return
		} else {
			log.Printf("Cache HIT (positive) for %s", cacheKey)
			// If it's a positive entry but not DNSSEC validated, and we want to re-check often,
			// we could force a re-lookup here or use a very short TTL for such entries.
			// For now, we just return the cached message.
			cachedMsg.SetRcode(j.req, cachedMsg.Rcode) // Ensure the response code is set correctly
			cachedMsg.Id = j.req.Id // Set the ID to match the request ID
			j.w.WriteMsg(cachedMsg)
			return
		}
	}
	log.Printf("Cache MISS for %s", cacheKey)
	// Create a new message to pass to the resolver, mimicking client behavior
	msg := new(dns.Msg)
	msg.SetQuestion(j.req.Question[0].Name, j.req.Question[0].Qtype)
	msg.SetEdns0(4096, true) // Enable EDNS0 with DNSSEC OK bit on the new message

	result := j.r.Exchange(context.Background(), msg)
	if result.Err != nil {
		log.Printf("Error exchanging DNS query: %v", result.Err)
		m := new(dns.Msg)
		// If there's an error, it's not DNSSEC validated
		m.SetRcode(j.req, dns.RcodeServerFailure)
		j.w.WriteMsg(m)
		// Cache SERVFAIL with a short TTL and mark as not DNSSEC validated
		j.shardedCache.Set(cacheKey, m, 30*time.Second, true, false)
		return
	}

	// Set the Recursion Available (RA) flag
	result.Msg.SetRcode(j.req, result.Msg.Rcode)
	result.Msg.RecursionAvailable = true

	// Determine TTL for caching. Use the minimum TTL from answers, or a default.
	ttl := 60 * time.Second // Default TTL
	if len(result.Msg.Answer) > 0 {
		minTTL := result.Msg.Answer[0].Header().Ttl
		for _, rr := range result.Msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		ttl = time.Duration(minTTL) * time.Second
	}

	// Determine DNSSEC validation status
	dnssecValidated := result.Msg.AuthenticatedData

	// If DNSSEC is not validated, use a very short TTL for re-checking
	if !dnssecValidated {
		ttl = 5 * time.Second // Very short TTL for unvalidated entries
	}

	// Cache the positive response
	j.shardedCache.Set(cacheKey, result.Msg, ttl, false, dnssecValidated)

	j.w.WriteMsg(result.Msg)
}

func main() {
	// Override the default logging hook on resolver.
	resolver.Query = func(s string) {
		fmt.Println("Query: " + s)
	}

	// Initialize Sharded Cache
	shardedCache := NewShardedCache(defaultShards, 1*time.Minute)
	defer shardedCache.Stop()

	// Initialize Worker Pool
	workerPool := NewWorkerPool(100, 1000) // 100 workers, 1000 job queue size
	workerPool.Start()
	defer workerPool.Stop()

	r := resolver.NewResolver()

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		job := &DnsJob{
			w:  w,
			req: req,
			shardedCache: shardedCache,
			r: r,
		}
		workerPool.Submit(job)
	})

	server := &dns.Server{
		Addr:    port,
		Net:     "udp",
		UDPSize: 65535, // Set UDPSize to max for EDNS0
	}

	log.Printf("Starting DNS resolver on %s", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}