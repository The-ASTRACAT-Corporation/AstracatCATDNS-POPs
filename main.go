package main

import (
	"context"
	"io"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"github.com/miekg/dns"
)

func main() {
	// Discard logs to avoid file I/O, as systemd handles logging.
	log.SetOutput(io.Discard)
	log.Println("Booting up ASTRACAT Resolver...")

	// Load configuration
	cfg := config.NewConfig()

	// Create cache and resolver
	c := cache.NewMultiLevelCache(cfg)
	res := resolver.NewResolver(cfg, c)

	// Set the resolver in the cache for prefetching
	c.SetResolver(res)

	// Create and start the server
	srv := server.NewServer(cfg)

	// Create a handler function that uses the resolver
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		req := r.Copy()
		req.RecursionDesired = true
		req.SetEdns0(4096, true) // Enable DNSSEC OK bit

		ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		defer cancel()

		msg, err := res.Resolve(ctx, req)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", req.Question[0].Name, err)
			dns.HandleFailed(w, r)
			return
		}

		msg.Id = r.Id

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	// Set the handler on the server
	srv.SetHandler(handler)

	srv.ListenAndServe()
}
