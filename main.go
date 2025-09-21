package main

import (
	"context"
	"log"
	"os"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/server"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
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
	// We'll use this for server settings, not resolver settings.
	cfg := config.NewConfig()

	// --- New Resolver Setup ---
	// Enable the custom cache by assigning it to the resolver's global Cache variable.
	customCache := cache.NewLRUCache(10000)
	resolver.Cache = customCache
	log.Println("LRU in-memory cache enabled.")

	// The nsmithuk/resolver is configured via global variables.
	// We can set timeouts, etc. here if needed.
	// For example: resolver.TimeoutUDP = 200 * time.Millisecond

	// The resolver itself is stateless, so we create a new instance for each request.
	// Or we can create one and reuse it, it doesn't hold state.
	r := resolver.NewResolver()

	// The user's example had a query logger. Let's add that.
	resolver.Query = func(s string) {
		log.Println("Query: " + s)
	}
	// --- End New Resolver Setup ---

	// Create and start the server using the existing server component.
	srv := server.NewServer(cfg)

	// Create a handler function that uses the new resolver.
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		// The library doesn't seem to use the context for timeouts in the same way.
		// The timeouts are global. We'll pass a background context.
		ctx := context.Background()

		// The library handles DNSSEC automatically if the client requests it.
		// We pass the client's request directly to the resolver.
		result := r.Exchange(ctx, req)

		if result.Err != nil {
			log.Printf("Failed to resolve %s: %v", req.Question[0].Name, result.Err)
			dns.HandleFailed(w, req)
			return
		}

		if result.Msg == nil {
			log.Printf("Resolver returned nil message for %s", req.Question[0].Name)
			dns.HandleFailed(w, req)
			return
		}

		// The result from the library has the AD (Authenticated Data) bit set if DNSSEC validation passed.
		log.Printf("Resolved %s, DNSSEC status: %s", req.Question[0].Name, result.Auth.String())

		// Set the response ID to match the request ID
		result.Msg.Id = req.Id

		if err := w.WriteMsg(result.Msg); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	srv.SetHandler(handler)

	srv.ListenAndServe()
}
