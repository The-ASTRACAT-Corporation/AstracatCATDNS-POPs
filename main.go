package main

import (
	"log"
	"os"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"

	"github.com/miekg/dns"
)

func main() {
	// Open a file for logging.
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Println("Booting up ASTRACAT Resolver...")

	// Load configuration from the original project's config.
	cfg := config.NewConfig()

	// Create the cache and the resolver.
	customCache := cache.NewMultiLevelCache(1000, 10000)
	r := resolver.NewResolver(customCache)
	log.Println("Multi-level cache and new resolver enabled.")

	// Create and start the server using the existing server component.
	srv := server.NewServer(cfg)

	// Create a handler function that uses our new resolver.
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			dns.HandleFailed(w, req)
			return
		}
		question := req.Question[0]

		log.Printf("Received query for %s", question.Name)

		msg, err := r.Resolve(question)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", question.Name, err)
			dns.HandleFailed(w, req)
			return
		}

		// Set the response ID to match the request ID
		msg.Id = req.Id
		msg.Compress = true
		msg.Response = true

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	srv.SetHandler(handler)

	srv.ListenAndServe()
}
