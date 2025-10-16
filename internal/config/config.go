package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr           string
	KnotResolverAddr     string
	MetricsAddr          string
	PrometheusEnabled    bool
	PrometheusNamespace  string
	UpstreamTimeout      time.Duration
	RequestTimeout       time.Duration
	MaxWorkers           int
	CacheSize            int
	MessageCacheSize     int
	RRsetCacheSize       int
	CacheMaxTTL          time.Duration
	CacheMinTTL          time.Duration
	StaleWhileRevalidate time.Duration
	PrefetchInterval     time.Duration
	LMDBPath             string
}

// getEnv returns the value of an environment variable or a default value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvAsInt returns the value of an environment variable as an integer or a default value.
func getEnvAsInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

// NewConfig returns a new Config with default values, overridden by environment variables where applicable.
func NewConfig() *Config {
	return &Config{
		ListenAddr:           getEnv("LISTEN_ADDR", "0.0.0.0:5053"),
		KnotResolverAddr:     getEnv("KNOT_RESOLVER_ADDR", "127.0.0.1:5353"),
		MetricsAddr:          getEnv("METRICS_ADDR", "0.0.0.0:9090"),
		PrometheusEnabled:    getEnv("PROMETHEUS_ENABLED", "false") == "true",
		PrometheusNamespace:  getEnv("PROMETHEUS_NAMESPACE", "dns_resolver"),
		UpstreamTimeout:      time.Duration(getEnvAsInt("UPSTREAM_TIMEOUT_SECONDS", 5)) * time.Second,
		RequestTimeout:       time.Duration(getEnvAsInt("REQUEST_TIMEOUT_SECONDS", 5)) * time.Second,
		MaxWorkers:           getEnvAsInt("MAX_WORKERS", 10),
		CacheSize:            getEnvAsInt("CACHE_SIZE", 5000),
		MessageCacheSize:     getEnvAsInt("MESSAGE_CACHE_SIZE", 5000),
		RRsetCacheSize:       getEnvAsInt("RRSET_CACHE_SIZE", 5000),
		CacheMaxTTL:          time.Duration(getEnvAsInt("CACHE_MAX_TTL_SECONDS", 3600)) * time.Second,
		CacheMinTTL:          time.Duration(getEnvAsInt("CACHE_MIN_TTL_SECONDS", 60)) * time.Second,
		StaleWhileRevalidate: time.Duration(getEnvAsInt("STALE_WHILE_REVALIDATE_MINUTES", 1)) * time.Minute,
		PrefetchInterval:     time.Duration(getEnvAsInt("PREFETCH_INTERVAL_SECONDS", 30)) * time.Second,
		LMDBPath:             getEnv("LMDB_PATH", "/tmp/dns_cache.lmdb"),
	}
}
