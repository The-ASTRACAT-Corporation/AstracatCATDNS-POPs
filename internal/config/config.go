package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr           string
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
	LMDBPath             string
	ResolverType         string // "unbound" or "knot"
	ServerRole           string // "master", "slave", or "standalone"
	MasterAPIEndpoint    string
	MasterAPIKey         string
	SlaveAPIKey          string
	SyncInterval         time.Duration
}

// NewConfig loads the configuration from config.json or returns a default config.
func NewConfig() *Config {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		// If config doesn't exist or is invalid, create a default one and save it.
		defaultCfg := &Config{
			ListenAddr:           "0.0.0.0:5053",
			MetricsAddr:          "0.0.0.0:9090",
			PrometheusEnabled:    false,
			PrometheusNamespace:  "dns_resolver",
			UpstreamTimeout:      5 * time.Second,
			RequestTimeout:       5 * time.Second,
			MaxWorkers:           10,
			CacheSize:            5000,
			MessageCacheSize:     5000,
			RRsetCacheSize:       5000,
			CacheMaxTTL:          3600 * time.Second,
			CacheMinTTL:          60 * time.Second,
			StaleWhileRevalidate: 1 * time.Minute,
			LMDBPath:             "/tmp/dns_cache.lmdb",
			ResolverType:         "knot",
			ServerRole:           "master",
			MasterAPIEndpoint:    "http://localhost:8080/api/v1/zones",
			MasterAPIKey:         "master-key",
			SlaveAPIKey:          "slave-key",
			SyncInterval:         1 * time.Minute,
		}
		defaultCfg.Save("config.json")
		return defaultCfg
	}
	return cfg
}

// LoadConfig loads configuration from a file.
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	cfg := &Config{}
	err = decoder.Decode(cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save saves configuration to a file.
func (c *Config) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
