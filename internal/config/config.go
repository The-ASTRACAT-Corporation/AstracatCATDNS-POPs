package config

import "time"

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr      string
	UpstreamTimeout time.Duration
	RequestTimeout  time.Duration
	MaxWorkers      int
}

// NewConfig returns a new Config with default values.
func NewConfig() *Config {
	return &Config{
		ListenAddr:      "0.0.0.0:5053",
		UpstreamTimeout: 2 * time.Second,
		RequestTimeout:  5 * time.Second,
		MaxWorkers:      100,
	}
}
