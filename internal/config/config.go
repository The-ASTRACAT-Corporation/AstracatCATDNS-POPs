package config

import "time"

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr           string
	UpstreamTimeout      time.Duration
	RequestTimeout       time.Duration
	MaxWorkers           int
	MessageCacheSize     int
	RRsetCacheSize       int
	MsgCacheSlabs        int
	RRsetCacheSlabs      int
	CacheMaxTTL          time.Duration
	CacheMinTTL          time.Duration
	StaleWhileRevalidate time.Duration
	PrefetchInterval     time.Duration
}

// NewConfig returns a new Config with default values.
func NewConfig() *Config {
	return &Config{
		ListenAddr:           "0.0.0.0:5053",
		UpstreamTimeout:      5 * time.Second,
		RequestTimeout:       5 * time.Second,
		MaxWorkers:           100,
		MessageCacheSize:     50000,  // Default size for the message cache
		RRsetCacheSize:       100000, // Default size for the RRset cache
		MsgCacheSlabs:        32,     // Default number of slabs for the message cache
		RRsetCacheSlabs:      32,     // Default number of slabs for the RRset cache
		CacheMaxTTL:          86400 * time.Second, // 24 hours
		CacheMinTTL:          0 * time.Second,
		StaleWhileRevalidate: 1 * time.Minute,
		PrefetchInterval:     30 * time.Second,
	}
}
