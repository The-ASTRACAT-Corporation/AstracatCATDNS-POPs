package goresolver

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoData = errors.New("no data for this record")
)

const (
	// DefaultTimeout is the default timeout for DNS queries.
	DefaultTimeout = 2 * time.Second
	DefaultCacheTTL = 5 * time.Minute
	DefaultNegativeCacheTTL = 1 * time.Minute
)

// Resolver contains the client configuration for github.com/miekg/dns,
// and the upstream DNS server addresses.
type Resolver struct {
	dnsClient       *dns.Client
	dnsClientConfig *dns.ClientConfig
	queryFn         queryFunc
	Cache           *DNSCache
}

type queryFunc func(name string, qtype uint16) (*dns.Msg, error)

// Errors returned by the verification/validation methods at all levels.
var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrForgedRRsig          = errors.New("forged RRSIG header")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
	ErrInvalidQuery         = errors.New("invalid query input")
)

var CurrentResolver *Resolver

// NewDNSMessage creates and initializes a dns.Msg object, with EDNS enabled
// and the DO (DNSSEC OK) flag set.  It returns a pointer to the created
// object.
func NewDNSMessage(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)
	return m
}

func (r *Resolver) Query(name string, qtype uint16) (*dns.Msg, error) {
	cacheKey := fmt.Sprintf("%s:%d", name, qtype)

	// Try to get from cache first
	if r.Cache != nil {
		if cachedMsg, timeLeft, found, isNegative := r.Cache.Get(cacheKey); found {
			if isNegative {
				return nil, ErrNoData
			}
			// If the record is about to expire, prefetch it
			if timeLeft < DefaultCacheTTL/2 && timeLeft > 0 {
				go r.Prefetch(name, qtype)
			}
			return cachedMsg, nil
		}
	}

	// If the name is an IP address, perform a reverse lookup
	if net.ParseIP(name) != nil {
		return r.queryFn(name, qtype)
	}

	// Check if it's a local domain
	if r.isLocalDomain(name) {
		return r.queryFn(name, qtype)
	}

	// Otherwise, query upstream DNS servers
	msg, err := r.queryUpstream(name, qtype)

	// Add to cache if successful
	if r.Cache != nil && err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
	} else if r.Cache != nil && err != nil {
		// Negative cache for errors
		r.Cache.Add(cacheKey, nil, DefaultNegativeCacheTTL, true)
	}

	// Cache successful responses
	if err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
	} else if err == nil && msg != nil && (msg.Rcode == dns.RcodeNameError || msg.Rcode == dns.RcodeServerFailure) {
		// Cache negative responses
		r.Cache.Add(cacheKey, msg, DefaultNegativeCacheTTL, true)
	}

	return msg, err
}

// Prefetch asynchronously queries and updates the cache for a given DNS record.
func (r *Resolver) Prefetch(name string, qtype uint16) {
	log.Printf("Prefetching %s (type %s)", name, dns.TypeToString[qtype])
	msg, err := r.queryUpstream(name, qtype)
	if err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		cacheKey := fmt.Sprintf("%s:%d", name, qtype)
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
		log.Printf("Prefetched %s (type %s) successfully", name, dns.TypeToString[qtype])
	} else {
		log.Printf("Failed to prefetch %s (type %s): %v", name, dns.TypeToString[qtype], err)
	}
}

func (r *Resolver) isLocalDomain(name string) bool {
	for _, domain := range r.dnsClientConfig.Search {
		if dns.IsSubDomain(domain, name) {
			return true
		}
	}
	return false
}

func (r *Resolver) queryUpstream(name string, qtype uint16) (*dns.Msg, error) {
	m := NewDNSMessage(name, qtype)

	// Try all configured upstream servers
	for _, server := range r.dnsClientConfig.Servers {
		r, _, err := r.dnsClient.Exchange(m, net.JoinHostPort(server, r.dnsClientConfig.Port))
		if err == nil && r != nil && r.Rcode == dns.RcodeSuccess {
			return r, nil
		}
	}
	return nil, fmt.Errorf("failed to query upstream DNS servers for %s", name)
}

// localQuery takes a query name (qname) and query type (qtype) and
// performs a DNS lookup by calling dnsClient.Exchange.
// It returns the answer in a *dns.Msg (or nil in case of an error, in which
// case err will be set accordingly.)
func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := NewDNSMessage(qname, qtype)

	if CurrentResolver.dnsClientConfig == nil {
		return nil, errors.New("dns client not initialized")
	}

	for _, server := range CurrentResolver.dnsClientConfig.Servers {
		r, _, err := CurrentResolver.dnsClient.Exchange(dnsMessage, server+":"+CurrentResolver.dnsClientConfig.Port)
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, ErrNsNotAvailable
}

// queryDelegation takes a domain name and fetches the DS and DNSKEY records
// in that zone.  Returns a SignedZone or nil in case of error.
func queryDelegation(domainName string) (signedZone *SignedZone, err error) {

	signedZone = NewSignedZone(domainName)

	signedZone.dnskey, err = CurrentResolver.queryRRset(domainName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	signedZone.pubKeyLookup = make(map[uint16]*dns.DNSKEY)
	for _, rr := range signedZone.dnskey.rrSet {
		signedZone.addPubKey(rr.(*dns.DNSKEY))
	}

	signedZone.ds, _ = CurrentResolver.queryRRset(domainName, dns.TypeDS)

	return signedZone, nil
}

// NewResolver initializes the package Resolver instance using the default
// dnsClientConfig.
func NewResolver(resolvConf string) (res *Resolver, err error) {
	CurrentResolver = &Resolver{}
	CurrentResolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	CurrentResolver.dnsClientConfig, err = dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		return nil, err
	}
	CurrentResolver.queryFn = localQuery
	CurrentResolver.Cache = NewDNSCache(16) // Initialize cache with 16 shards
	return CurrentResolver, nil
}
