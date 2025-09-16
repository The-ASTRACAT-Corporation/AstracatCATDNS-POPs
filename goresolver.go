package goresolver

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/domainr/dnsr"
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
	dnsrResolver    *dnsr.Resolver // Add dnsr.Resolver
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

	// Use dnsr for all queries
	// Convert qtype to string for dnsr.Resolve
	qtypeStr := dns.TypeToString[qtype]
	if qtypeStr == "" {
		return nil, fmt.Errorf("unknown query type: %d", qtype)
	}

	rrs := r.dnsrResolver.Resolve(name, qtypeStr)

	// Convert dnsr.RR to dns.Msg
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)

	for _, rr := range rrs {
		dnsRR, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rr.Name, rr.TTL, rr.Type, rr.Value))
		if err != nil {
			log.Printf("Error converting dnsr.RR to dns.RR: %v", err)
			continue
		}
		msg.Answer = append(msg.Answer, dnsRR)
	}

	if r.Cache != nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
	} else if r.Cache != nil && len(rrs) == 0 {
		// Negative cache for no data found
		r.Cache.Add(cacheKey, nil, DefaultNegativeCacheTTL, true)
	}

	return msg, nil
}

// Prefetch asynchronously queries and updates the cache for a given DNS record.
func (r *Resolver) Prefetch(name string, qtype uint16) {
	log.Printf("Prefetching %s (type %s)", name, dns.TypeToString[qtype])
	// Use dnsr for prefetching as well
	qtypeStr := dns.TypeToString[qtype]
	if qtypeStr == "" {
		log.Printf("Unknown query type for prefetch: %d", qtype)
		return
	}

	rrs := r.dnsrResolver.Resolve(name, qtypeStr)
	if len(rrs) > 0 {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), qtype)
		msg.RecursionDesired = true
		msg.SetEdns0(4096, true)

		for _, rr := range rrs {
			dnsRR, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rr.Name, rr.TTL, rr.Type, rr.Value))
			if err != nil {
				log.Printf("Error converting dnsr.RR to dns.RR during prefetch: %v", err)
				continue
			}
			msg.Answer = append(msg.Answer, dnsRR)
		}

		cacheKey := fmt.Sprintf("%s:%d", name, qtype)
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
		log.Printf("Prefetched %s (type %s) successfully", name, dns.TypeToString[qtype])
	} else {
		log.Printf("Failed to prefetch %s (type %s): No records found", name, dns.TypeToString[qtype])
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

	// This function is likely for DNSSEC validation, which might not be directly handled by dnsr.Resolver
	// For now, we'll keep it as is, but it might need adjustment if full DNSSEC validation is desired
	// with dnsr as the primary resolver.

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

// RecursiveQuery performs a recursive DNS query using the dnsr library.
// This method is now redundant as Query itself uses dnsr for recursion.
// It can be removed or refactored if not used elsewhere.
func (r *Resolver) RecursiveQuery(name string, qtype string) (dnsr.RRs) {
	// This method is now redundant as Query itself uses dnsr for recursion.
	// It can be removed or refactored if not used elsewhere.
	return r.dnsrResolver.Resolve(name, qtype)
}

// NewResolver initializes the package Resolver instance using the default
// dnsClientConfig.
func NewResolver(resolvConf string) (res *Resolver, err error) {
	CurrentResolver = &Resolver{}
	CurrentResolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	// dnsClientConfig is no longer strictly needed for upstream servers if dnsr handles all recursion.
	// However, it might still be used for search domains or other configurations.
	CurrentResolver.dnsClientConfig, err = dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		log.Printf("Warning: Failed to load resolv.conf: %v. dnsr will be used for all queries.", err)
		// Don't return error, proceed with dnsr as primary resolver
		CurrentResolver.dnsClientConfig = &dns.ClientConfig{ // Initialize with empty config to avoid nil pointer
			Servers: []string{}, Port: "53", Search: []string{}, Timeout: 5,
		}
	}
	CurrentResolver.queryFn = localQuery // This might become redundant if localQuery is not used
	CurrentResolver.Cache = NewDNSCache(16) // Initialize cache with 16 shards
	CurrentResolver.dnsrResolver = dnsr.NewResolver() // Initialize dnsr.Resolver without cache
	return CurrentResolver, nil
}
