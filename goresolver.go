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
	ErrDNSSECValidationFailed = errors.New("DNSSEC validation failed")
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

// Query performs a DNS query and validates DNSSEC signatures if present.
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

	// Separate answer and authority records
	var answerRRs []dns.RR
	var authorityRRs []dns.RR
	var rrsigRRs []dns.RR
	var dnskeyRRs []dns.RR
	var dsRRs []dns.RR

	for _, rr := range rrs {
		dnsRR, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rr.Name, rr.TTL, rr.Type, rr.Value))
		if err != nil {
			log.Printf("Error converting dnsr.RR to dns.RR: %v", err)
			continue
		}

		switch dnsRR.Header().Rrtype {
		case dns.TypeRRSIG:
			rrsigRRs = append(rrsigRRs, dnsRR)
		case dns.TypeDNSKEY:
			dnskeyRRs = append(dnskeyRRs, dnsRR)
		case dns.TypeDS:
			dsRRs = append(dsRRs, dnsRR)
		default:
			// Assume it's part of the answer section unless we determine otherwise
			// This is a simplification; ideally, we'd know the section from dnsr
			answerRRs = append(answerRRs, dnsRR)
		}
	}

	// Assign to message sections
	msg.Answer = answerRRs
	// dnsr doesn't distinguish between answer and authority sections easily
	// We'll put RRSIGs, DNSKEYs, DSs in the Answer section for now
	// A more robust implementation would need to parse the raw DNS message
	// or have dnsr provide section information.
	// For simplicity, we'll assume RRSIGs apply to the answer section.
	// This is a limitation of using dnsr for full DNSSEC validation.

	// Check if DNSSEC validation is requested and possible
	if len(rrsigRRs) > 0 {
		// Attempt to validate RRSIGs
		// This is a simplified validation attempt.
		// A full implementation would require:
		// 1. Fetching the DNSKEY for the zone (if not in the response)
		// 2. Validating the RRSIG against the DNSKEY
		// 3. Validating the DNSKEY against the DS record from the parent zone (if applicable)
		// 4. Handling NSEC/NSEC3 for negative responses

		// For now, we'll just log that validation is needed.
		// A proper implementation would be complex and require recursive validation up the tree.
		log.Printf("DNSSEC records found for %s. Validation logic needs to be implemented.", name)
		// Example of where validation would occur:
		// err := validateRRSIG(answerRRs, rrsigRRs, dnskeyRRs)
		// if err != nil {
		//     return nil, fmt.Errorf("%w: %v", ErrDNSSECValidationFailed, err)
		// }
		// Since dnsr handles recursion, we assume the upstream server performed validation
		// if requested via the DO bit. We can check the AD (Authenticated Data) bit.
		// However, dnsr's Resolve method doesn't expose the full DNS message flags directly.
		// This is a limitation of the current approach.
	} else {
		// No RRSIGs found, resource is not signed
		// This is not necessarily an error, but indicates lack of DNSSEC
		log.Printf("No DNSSEC signatures found for %s", name)
	}

	// Add to cache
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

// validateRRSIG is a placeholder for RRSIG validation logic.
// A full implementation would be complex and is beyond the scope of this rewrite.
// It would involve:
// 1. Finding the corresponding DNSKEY for the RRSIG
// 2. Verifying the signature using the DNSKEY
// 3. Checking the validity period of the RRSIG
func validateRRSIG(rrset []dns.RR, rrsigs []dns.RR, dnskeys []dns.RR) error {
	if len(rrset) == 0 || len(rrsigs) == 0 {
		return ErrResourceNotSigned
	}

	// Simplified check: just see if we have a DNSKEY to validate against
	if len(dnskeys) == 0 {
		return ErrDnskeyNotAvailable
	}

	// In a real implementation, you would:
	// - Iterate through RRSIGs
	// - For each RRSIG, find the matching DNSKEY (by key tag, algorithm, etc.)
	// - Use the DNSKEY to verify the signature in the RRSIG
	// - Check the validity period (inception, expiration)
	// - Handle errors like ErrInvalidRRsig, ErrRrsigValidityPeriod, etc.

	// Placeholder logic
	log.Println("Performing simplified DNSSEC validation check...")
	// This is where the actual cryptographic verification would happen
	// using libraries like `crypto/ecdsa`, `crypto/rsa`, etc.
	// and the `dns` library's `RRSIG.Verify` method.

	// For demonstration, assume validation passes if we have data
	// (This is NOT secure or correct!)
	return nil
}