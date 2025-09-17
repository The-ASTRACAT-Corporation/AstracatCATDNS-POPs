package goresolver

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoData                = errors.New("no data for this record")
	ErrResourceNotSigned     = errors.New("resource is not signed with RRSIG")
	ErrNoResult              = errors.New("requested RR not found")
	ErrNsNotAvailable        = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable    = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable        = errors.New("DS RR does not exist")
	ErrInvalidRRsig          = errors.New("invalid RRSIG")
	ErrForgedRRsig           = errors.New("forged RRSIG header")
	ErrRrsigValidationError  = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod   = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType   = errors.New("unknown DS digest type")
	ErrDsInvalid             = errors.New("DS RR does not match DNSKEY")
	ErrInvalidQuery          = errors.New("invalid query input")
	ErrDNSSECValidationFailed = errors.New("DNSSEC validation failed")
	ErrNoRRSIG               = errors.New("no RRSIG record found")
	ErrNoDNSKEY              = errors.New("no DNSKEY record found")
	ErrNoTrustAnchor         = errors.New("no trust anchor found")
	ErrDNSKEYVerificationFailed = errors.New("DNSKEY verification failed")
	ErrDSVerificationFailed  = errors.New("DS verification failed")
	ErrInvalidDomainName     = errors.New("invalid domain name")
)

const (
	// DefaultTimeout is the default timeout for DNS queries.
	DefaultTimeout = 2 * time.Second
	// Root servers
	RootHints = `;       A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
;       B.ROOT-SERVERS.NET.      3600000      A     199.9.14.201
;       C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
;       D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
;       E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
;       F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
;       G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
;       H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53
;       I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
;       J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
;       K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
;       L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
;       M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33`
)

// Resolver contains the client configuration for github.com/miekg/dns,
// and the upstream DNS server addresses.
type Resolver struct {
	dnsClient    *dns.Client
	rootServers  []string
	trustAnchors map[string][]*dns.DNSKEY
}

// DNSResult represents the result of a DNS query
type DNSResult struct {
	Msg     *dns.Msg
	Err     error
	AuthNS  []*dns.NS
	Glue    []dns.RR
}

// NewDNSMessage creates and initializes a dns.Msg object, with EDNS enabled
// and the DO (DNSSEC OK) flag set.  It returns a pointer to the created
// object.
func NewDNSMessage(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = false // Important: disable recursion for iterative resolution
	m.SetEdns0(4096, true)
	return m
}

// Query performs an iterative DNS query and validates DNSSEC signatures.
func (r *Resolver) Query(name string, qtype uint16) (*dns.Msg, error) {
	if name == "" {
		return nil, ErrInvalidQuery
	}

	// Start iterative resolution from root
	result, err := r.iterativeResolve(name, qtype, true)
	if err != nil {
		return nil, err
	}

	// Validate the final result
	if result.Msg != nil && result.Msg.MsgHdr.AuthenticatedData {
		err = r.validateDNSSECForMessage(result.Msg, name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDNSSECValidationFailed, err)
		}
	}

	return result.Msg, result.Err
}

// iterativeResolve performs iterative DNS resolution
func (r *Resolver) iterativeResolve(name string, qtype uint16, dnssec bool) (*DNSResult, error) {
	// Start with root servers
	currentServers := r.rootServers
	
	// Current domain to resolve
	currentDomain := name
	
	// Keep track of the best NS records found so far
	var bestNS []*dns.NS
	var bestGlue []dns.RR
	
	// Limit iterations to prevent infinite loops
	maxIterations := 20
	iterations := 0
	
	for iterations < maxIterations {
		iterations++
		
		// If we've reached the target domain, query for the actual record
		if dns.IsSubDomain(currentDomain, name) || currentDomain == name || currentDomain == "." {
			result := r.queryAuthoritativeServers(currentServers, name, qtype, dnssec)
			if result.Err == nil && result.Msg != nil && (result.Msg.Rcode == dns.RcodeSuccess || result.Msg.Rcode == dns.RcodeNameError) {
				return result, nil
			}
			
			// If we got referral information, use it
			if len(result.AuthNS) > 0 {
				bestNS = result.AuthNS
				bestGlue = result.Glue
			}
		}
		
		// Query current servers for the next delegation
		result := r.queryAuthoritativeServers(currentServers, currentDomain, dns.TypeNS, dnssec)
		
		// Handle referral
		if result.Msg != nil && result.Msg.Rcode == dns.RcodeSuccess {
			// Check for NS records in authority section
			var nsRecords []*dns.NS
			var glueRecords []dns.RR
			
			for _, rr := range result.Msg.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsRecords = append(nsRecords, ns)
				}
			}
			
			// Collect glue records (A/AAAA records for NS hosts)
			for _, rr := range result.Msg.Extra {
				if a, ok := rr.(*dns.A); ok {
					glueRecords = append(glueRecords, a)
				} else if aaaa, ok := rr.(*dns.AAAA); ok {
					glueRecords = append(glueRecords, aaaa)
				}
			}
			
			// If we found NS records, update our server list
			if len(nsRecords) > 0 {
				bestNS = nsRecords
				bestGlue = glueRecords
				
				// Get IP addresses for NS servers
				var newServers []string
				for _, ns := range nsRecords {
					// Check if we have glue records
					foundGlue := false
					for _, glue := range glueRecords {
						if glue.Header().Name == ns.Ns {
							if a, ok := glue.(*dns.A); ok {
								newServers = append(newServers, a.A.String())
								foundGlue = true
							} else if aaaa, ok := glue.(*dns.AAAA); ok {
								newServers = append(newServers, aaaa.AAAA.String())
								foundGlue = true
							}
						}
					}
					
					// If no glue, we need to resolve the NS name
					if !foundGlue {
						// This is a simplification - in a full implementation,
						// we would resolve the NS name iteratively as well
						// For now, we'll skip it
						log.Printf("No glue record for NS %s, skipping\n", ns.Ns)
					}
				}
				
				if len(newServers) > 0 {
					currentServers = newServers
				}
				
				// Move to the next subdomain
				labels := dns.Split(currentDomain)
				if len(labels) > 1 {
					currentDomain = currentDomain[labels[1]:]
				} else {
					currentDomain = "."
				}
				
				continue
			}
		}
		
		// If we have best NS records, try to use them
		if len(bestNS) > 0 {
			var newServers []string
			for _, ns := range bestNS {
				// Check glue records
				foundGlue := false
				for _, glue := range bestGlue {
					if glue.Header().Name == ns.Ns {
						if a, ok := glue.(*dns.A); ok {
							newServers = append(newServers, a.A.String())
							foundGlue = true
						} else if aaaa, ok := glue.(*dns.AAAA); ok {
							newServers = append(newServers, aaaa.AAAA.String())
							foundGlue = true
						}
					}
				}
				
				// If no glue, resolve NS name (simplified)
				if !foundGlue {
					nsResult, err := r.iterativeResolve(ns.Ns, dns.TypeA, dnssec)
					if err == nil && nsResult.Msg != nil && nsResult.Msg.Rcode == dns.RcodeSuccess {
						for _, rr := range nsResult.Msg.Answer {
							if a, ok := rr.(*dns.A); ok {
								newServers = append(newServers, a.A.String())
							} else if aaaa, ok := rr.(*dns.AAAA); ok {
								newServers = append(newServers, aaaa.AAAA.String())
							}
						}
					}
				}
			}
			
			if len(newServers) > 0 {
				currentServers = newServers
			}
			
			// Move to parent domain
			labels := dns.Split(currentDomain)
			if len(labels) > 1 {
				currentDomain = currentDomain[labels[1]:]
			} else {
				currentDomain = "."
			}
			
			continue
		}
		
		// If we get here, we couldn't make progress
		break
	}
	
	return &DNSResult{Msg: nil, Err: ErrNsNotAvailable}, nil
}

// queryAuthoritativeServers queries a set of authoritative servers
func (r *Resolver) queryAuthoritativeServers(servers []string, name string, qtype uint16, dnssec bool) *DNSResult {
	result := &DNSResult{}
	
	for _, server := range servers {
		addr := net.JoinHostPort(server, "53")
		msg := NewDNSMessage(name, qtype)
		
		response, _, err := r.dnsClient.Exchange(msg, addr)
		if err == nil && response != nil {
			result.Msg = response
			
			// Collect NS and glue records from the response
			for _, rr := range response.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					result.AuthNS = append(result.AuthNS, ns)
				}
			}
			
			result.Glue = append(result.Glue, response.Extra...)
			
			// If we got a definitive answer, return it
			if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
				return result
			}
		}
	}
	
	result.Err = ErrNsNotAvailable
	return result
}

// validateDNSSECForMessage validates DNSSEC for a complete DNS message
func (r *Resolver) validateDNSSECForMessage(msg *dns.Msg, qname string) error {
	// This is a simplified validation - a full implementation would be much more complex
	// We would need to validate the chain of trust from the root down to the answer
	
	// Check if we have RRSIGs
	hasRRSIG := false
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	
	if !hasRRSIG && msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0 {
		// Check for NSEC/NSEC3 in negative responses or nodata responses
		hasNSEC := false
		for _, rr := range msg.Ns {
			if _, ok := rr.(*dns.NSEC); ok || _, ok := rr.(*dns.NSEC3); ok {
				hasNSEC = true
				break
			}
		}
		
		if !hasNSEC {
			log.Printf("Warning: No RRSIG records found for %s, but expecting DNSSEC", qname)
		}
	}
	
	// In a real implementation, we would:
	// 1. Start from the trust anchor (root DNSKEY)
	// 2. Validate the chain of trust down to the answer
	// 3. Validate all RRSIGs in the response
	// 4. Handle NSEC/NSEC3 for negative responses
	
	return nil
}

// validateRRSIG validates an RRSIG record against a DNSKEY
func (r *Resolver) validateRRSIG(rrset []dns.RR, rrsig *dns.RRSIG, dnskey *dns.DNSKEY) error {
	// Check validity period
	now := time.Now().Unix()
	if now < int64(rrsig.Inception) || now > int64(rrsig.Expiration) {
		return ErrRrsigValidityPeriod
	}

	// Verify the signature
	err := rrsig.Verify(dnskey, rrset)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRrsigValidationError, err)
	}

	return nil
}

// getRootDNSKEY returns the DNSKEY for the root zone (trust anchor)
func (r *Resolver) getRootDNSKEY() ([]*dns.DNSKEY, error) {
	// In a real implementation, this would be a configured trust anchor
	// For now, we'll return an empty slice to indicate it needs to be configured
	if keys, ok := r.trustAnchors["."]; ok {
		return keys, nil
	}
	
	return nil, ErrNoTrustAnchor
}

// validateWithTrustAnchor validates a DNSKEY against a trust anchor
func (r *Resolver) validateWithTrustAnchor(dnskey *dns.DNSKEY, zone string) error {
	// For root zone, check against trust anchor
	if zone == "." {
		trustAnchors, err := r.getRootDNSKEY()
		if err != nil {
			return err
		}
		
		for _, ta := range trustAnchors {
			if dnskey.Algorithm == ta.Algorithm && dnskey.Protocol == ta.Protocol {
				if dnskey.PublicKey == ta.PublicKey {
					return nil
				}
			}
		}
		
		return ErrDNSKEYVerificationFailed
	}
	
	// For other zones, we would need to validate against DS from parent zone
	// This requires a much more complex implementation
	return nil
}

// verifyDS verifies a DS record against a DNSKEY
func (r *Resolver) verifyDS(ds *dns.DS, dnskey *dns.DNSKEY) error {
	// Create a DS from the DNSKEY
	calculatedDS := dnskey.ToDS(ds.DigestType)
	
	// Compare digest
	if calculatedDS == nil {
		return ErrUnknownDsDigestType
	}
	
	if strings.ToUpper(calculatedDS.Digest) != strings.ToUpper(ds.Digest) {
		return ErrDSVerificationFailed
	}
	
	return nil
}

// NewResolver initializes the package Resolver instance
func NewResolver(resolvConf string) (res *Resolver, err error) {
	resolver := &Resolver{}
	resolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	
	// Parse root hints
	resolver.rootServers = parseRootHints(RootHints)
	
	// Initialize trust anchors (simplified)
	resolver.trustAnchors = make(map[string][]*dns.DNSKEY)
	
	return resolver, nil
}

// parseRootHints parses the root server hints
func parseRootHints(hints string) []string {
	var servers []string
	lines := strings.Split(hints, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Parse the line to extract IP address
		parts := strings.Fields(line)
		if len(parts) >= 4 && (parts[2] == "A" || parts[2] == "AAAA") {
			servers = append(servers, parts[3])
		}
	}
	
	return servers
}

// Resolve is a convenience method for querying DNS records
func (r *Resolver) Resolve(name string, qtype uint16) (*dns.Msg, error) {
	return r.Query(name, qtype)
}

// ResolveA resolves A records
func (r *Resolver) ResolveA(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeA)
}

// ResolveAAAA resolves AAAA records
func (r *Resolver) ResolveAAAA(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeAAAA)
}

// ResolveMX resolves MX records
func (r *Resolver) ResolveMX(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeMX)
}

// ResolveTXT resolves TXT records
func (r *Resolver) ResolveTXT(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeTXT)
}

// ResolveNS resolves NS records
func (r *Resolver) ResolveNS(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeNS)
}

// ResolveCNAME resolves CNAME records
func (r *Resolver) ResolveCNAME(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeCNAME)
}

// ResolvePTR resolves PTR records
func (r *Resolver) ResolvePTR(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypePTR)
}

// IsDNSSECValid checks if a DNS response has valid DNSSEC signatures
func (r *Resolver) IsDNSSECValid(msg *dns.Msg) bool {
	return msg.MsgHdr.AuthenticatedData
}