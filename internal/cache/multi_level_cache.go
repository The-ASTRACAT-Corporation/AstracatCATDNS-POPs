package cache

import (
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/interfaces"
	"github.com/miekg/dns"
)

// MultiLevelCache is a cache that combines a message cache, an RRset cache, and an NSEC cache.
type MultiLevelCache struct {
	messageCache *MessageCache
	rrsetCache   *RRsetCache
	nsecCache    *NsecCache
	resolver     interfaces.CacheResolver
}

// NewMultiLevelCache creates a new MultiLevelCache.
func NewMultiLevelCache(cfg *config.Config) *MultiLevelCache {
	return &MultiLevelCache{
		messageCache: NewMessageCache(cfg, cfg.MsgCacheSlabs),
		rrsetCache:   NewRRsetCache(cfg, cfg.RRsetCacheSlabs),
		nsecCache:    NewNsecCache(cfg),
	}
}

// SetResolver sets the resolver for the cache.
func (c *MultiLevelCache) SetResolver(r interfaces.CacheResolver) {
	c.resolver = r
	c.messageCache.SetResolver(r)
	c.rrsetCache.SetResolver(r)
}

// Get retrieves a message from the cache, checking both message and RRset caches.
func (c *MultiLevelCache) Get(q dns.Question) (*dns.Msg, bool, bool) {
	key := Key(q)
	// First, check the message cache.
	if msg, found, revalidate := c.messageCache.Get(key); found {
		return msg, true, revalidate
	}

	// If not in message cache, try to synthesize from RRset cache.
	if msg, found := c.synthesizeFromRRset(q); found {
		return msg, true, false
	}

	// Finally, check the NSEC cache to prove non-existence.
	if msg, found := c.nsecCache.Check(q); found {
		return msg, true, false
	}

	return nil, false, false
}

// Set adds a message to the cache, decomposing it into RRsets as well.
func (c *MultiLevelCache) Set(key string, msg *dns.Msg, swr, prefetch time.Duration) {
	// Add the full message to the message cache.
	c.messageCache.Set(key, msg, swr, prefetch)

	// Decompose the message and add RRsets to the RRset cache.
	c.decomposeAndCacheRRsets(msg)
}

// synthesizeFromRRset tries to build a DNS response from cached RRsets.
func (c *MultiLevelCache) synthesizeFromRRset(q dns.Question) (*dns.Msg, bool) {
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)

	foundAnswer := false
	currentName := q.Name

	for i := 0; i < 10; i++ { // CNAME loop limit
		// Look for the requested type for the current name
		qKey := Key(dns.Question{Name: currentName, Qtype: q.Qtype, Qclass: q.Qclass})
		rrset, found := c.rrsetCache.Get(qKey)
		if found {
			msg.Answer = append(msg.Answer, rrset...)
			foundAnswer = true
			break // Found the answer, no need to look for CNAMEs
		}

		// If no direct answer, look for a CNAME
		cnameKey := Key(dns.Question{Name: currentName, Qtype: dns.TypeCNAME, Qclass: q.Qclass})
		cnameRRset, cnameFound := c.rrsetCache.Get(cnameKey)
		if !cnameFound {
			break // No answer and no CNAME, can't proceed
		}

		msg.Answer = append(msg.Answer, cnameRRset...)
		foundAnswer = true
		if cname, ok := cnameRRset[0].(*dns.CNAME); ok {
			currentName = cname.Target
		} else {
			break // Should be a CNAME, but it's not. Stop.
		}
	}

	if !foundAnswer {
		return nil, false
	}

	// Try to add authority and additional records for the original question's zone.
	nsQ := dns.Question{Name: q.Name, Qtype: dns.TypeNS, Qclass: q.Qclass}
	nsKey := Key(nsQ)
	nsRRset, nsFound := c.rrsetCache.Get(nsKey)
	if nsFound {
		msg.Ns = append(msg.Ns, nsRRset...)
		// Try to add glue records (A/AAAA for the nameservers)
		for _, nsRR := range nsRRset {
			if ns, ok := nsRR.(*dns.NS); ok {
				glueAKey := Key(dns.Question{Name: ns.Ns, Qtype: dns.TypeA, Qclass: q.Qclass})
				if glue, found := c.rrsetCache.Get(glueAKey); found {
					msg.Extra = append(msg.Extra, glue...)
				}
				glueAAAAKey := Key(dns.Question{Name: ns.Ns, Qtype: dns.TypeAAAA, Qclass: q.Qclass})
				if glue, found := c.rrsetCache.Get(glueAAAAKey); found {
					msg.Extra = append(msg.Extra, glue...)
				}
			}
		}
	}

	msg.Rcode = dns.RcodeSuccess
	return msg, true
}

// decomposeAndCacheRRsets breaks down a DNS message into RRsets and caches them.
func (c *MultiLevelCache) decomposeAndCacheRRsets(msg *dns.Msg) {
	rrsets := make(map[string][]dns.RR)
	allRRs := append(append(msg.Answer, msg.Ns...), msg.Extra...)

	// Group RRs by name, type, and class.
	for _, rr := range allRRs {
		switch r := rr.(type) {
		case *dns.NSEC:
			c.nsecCache.Add(r)
		case *dns.OPT:
			// Do not cache OPT records
			continue
		default:
			key := rrsetKey(rr.Header())
			rrsets[key] = append(rrsets[key], rr)
		}
	}

	// Cache each RRset.
	for key, rrset := range rrsets {
		c.rrsetCache.Set(key, rrset)
	}
}

// rrsetKey generates a cache key for an RRset.
func rrsetKey(h *dns.RR_Header) string {
	return Key(dns.Question{Name: h.Name, Qtype: h.Rrtype, Qclass: h.Class})
}