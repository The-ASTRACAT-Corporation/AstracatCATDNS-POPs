package cache

import (
	"dns-resolver/internal/config"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NsecCacheItem holds an NSEC record and its expiration.
type NsecCacheItem struct {
	Nsec       *dns.NSEC
	Expiration time.Time
}

// NsecCache stores NSEC records for aggressive caching.
type NsecCache struct {
	sync.RWMutex
	items  map[string]*NsecCacheItem // Keyed by NSEC owner name (lowercased)
	config *config.Config
	stop   chan struct{}
}

// NewNsecCache creates a new NsecCache.
func NewNsecCache(cfg *config.Config) *NsecCache {
	nc := &NsecCache{
		items:  make(map[string]*NsecCacheItem),
		config: cfg,
		stop:   make(chan struct{}),
	}
	go nc.runCleaner()
	return nc
}

// runCleaner periodically removes expired items from the cache.
func (nc *NsecCache) runCleaner() {
	// A more configurable interval could be added to the config.
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nc.cleanup()
		case <-nc.stop:
			return
		}
	}
}

// cleanup iterates over the cache and removes expired items.
func (nc *NsecCache) cleanup() {
	nc.Lock()
	defer nc.Unlock()

	now := time.Now()
	for key, item := range nc.items {
		if now.After(item.Expiration) {
			delete(nc.items, key)
		}
	}
}

// Stop terminates the background cleaner goroutine.
func (nc *NsecCache) Stop() {
	close(nc.stop)
}

// Add adds an NSEC record to the cache.
func (nc *NsecCache) Add(nsec *dns.NSEC) {
	nc.Lock()
	defer nc.Unlock()

	key := strings.ToLower(nsec.Hdr.Name)
	ttl := time.Duration(nsec.Hdr.Ttl) * time.Second
	clampedTTL := nc.clampTTL(ttl)
	expiration := time.Now().Add(clampedTTL)

	nc.items[key] = &NsecCacheItem{
		Nsec:       nsec,
		Expiration: expiration,
	}
}

// Check attempts to prove the non-existence of a name using cached NSEC records.
func (nc *NsecCache) Check(q dns.Question) (*dns.Msg, bool) {
	nc.RLock()
	defer nc.RUnlock()

	now := time.Now()
	qNameLower := strings.ToLower(q.Name)

	for _, item := range nc.items {
		if now.After(item.Expiration) {
			continue
		}

		nsec := item.Nsec
		ownerLower := strings.ToLower(nsec.Hdr.Name)
		nextLower := strings.ToLower(nsec.NextDomain)

		// Case 1: Exact match on owner name (potential NODATA)
		if ownerLower == qNameLower {
			typeExists := false
			for _, t := range nsec.TypeBitMap {
				if t == q.Qtype || t == dns.TypeCNAME { // If CNAME exists, client must query for that
					typeExists = true
					break
				}
			}
			if !typeExists {
				msg := new(dns.Msg)
				msg.SetQuestion(q.Name, q.Qtype)
				msg.Rcode = dns.RcodeSuccess // NODATA is a success response with no answer
				msg.Ns = append(msg.Ns, nsec)
				return msg, true
			}
		}

		// Case 2: Name falls between owner and next domain (potential NXDOMAIN)
		if ownerLower < qNameLower && qNameLower < nextLower {
			msg := new(dns.Msg)
			msg.SetQuestion(q.Name, q.Qtype)
			msg.Rcode = dns.RcodeNameError
			msg.Ns = append(msg.Ns, nsec)
			return msg, true
		}
	}

	return nil, false
}

// TODO: The current NSEC Check is O(N). A more efficient data structure (e.g., a balanced tree) is needed for production.
// TODO: A full implementation needs to handle RRSIGs for the NSEC records.

// clampTTL ensures that the TTL is within the configured min and max bounds.
func (nc *NsecCache) clampTTL(ttl time.Duration) time.Duration {
	if nc.config.CacheMaxTTL > 0 && ttl > nc.config.CacheMaxTTL {
		return nc.config.CacheMaxTTL
	}
	if ttl < nc.config.CacheMinTTL {
		return nc.config.CacheMinTTL
	}
	return ttl
}