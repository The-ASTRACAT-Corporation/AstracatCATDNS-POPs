package main

import (
	"context"
	"log"
	"os"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"github.com/miekg/dns"
)

func main() {
	// Open a file for logging. Truncate the file if it already exists.
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Set the output of the log package to the file.
	log.SetOutput(logFile)

	log.Println("Booting up ASTRACAT Relover...")

	// Load configuration
	cfg := config.NewConfig()

	// Create cache, worker pool, and resolver
	c := cache.NewCache(cache.DefaultCacheSize, cache.DefaultShards, cfg.PrefetchInterval)
	wp := resolver.NewWorkerPool(cfg.MaxWorkers)
	res := resolver.NewResolver(cfg, c, wp)

	// Set the resolver in the cache for prefetching
	c.SetResolver(res)

	// Create and start the server
	srv := server.NewServer(cfg)

	// Create a handler function that uses the resolver
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		defer cancel()

		msg, err := res.Resolve(ctx, r)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", r.Question[0].Name, err)
			dns.HandleFailed(w, r)
			return
		}

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	// Set the handler on the server
	srv.SetHandler(handler)

	srv.ListenAndServe()
}
