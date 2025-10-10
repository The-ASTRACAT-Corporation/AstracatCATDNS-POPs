package config

import "time"

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr           string
	MetricsAddr          string
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

// NewConfig returns a new Config with default values.
func NewConfig() *Config {
	return &Config{
		ListenAddr:           "0.0.0.0:5053",
		MetricsAddr:          "0.0.0.0:9090",
		UpstreamTimeout:      5 * time.Second,
		RequestTimeout:       5 * time.Second,
		MaxWorkers:           100,
		CacheSize:            50000,
		MessageCacheSize:     50000,
		RRsetCacheSize:       50000,
		CacheMaxTTL:          3600 * time.Second,
		CacheMinTTL:          60 * time.Second,
		StaleWhileRevalidate: 1 * time.Minute,
		PrefetchInterval:     30 * time.Second,
		LMDBPath:             "/tmp/dns_cache.lmdb",
	}
}
