package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Старая функция больше не используется, так как теперь используем метод из пакета metrics

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

	// Initialize metrics
	m := metrics.NewMetrics()

	// Create cache and resolver
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.PrefetchInterval, cfg.LMDBPath)
	defer c.Close()
	res := resolver.NewResolver(cfg, c, m)

	// Set the resolver in the cache for prefetching
	c.SetResolver(res)

	// Start a goroutine to periodically update cache stats
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			probation, protected := c.GetCacheSize()
			m.UpdateCacheStats(probation, protected)
		}
	}()

	// Start the metrics server
	go m.StartMetricsServer(cfg.MetricsAddr)

	// Create and start the server
	srv := server.NewServer(cfg, m, res)

	srv.ListenAndServe()
}
