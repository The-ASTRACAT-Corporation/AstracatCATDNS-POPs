package goresolver

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoData                = errors.New("no data for this record")
	ErrNoResult              = errors.New("requested RR not found")
	ErrNsNotAvailable        = errors.New("no name server to answer the question")
	ErrInvalidQuery          = errors.New("invalid query input")
	ErrDNSSECValidationFailed = errors.New("DNSSEC validation failed")
	ErrNoTrustAnchor         = errors.New("no trust anchor found")
	ErrMaxIterations         = errors.New("maximum iterations exceeded")
	ErrDnskeyNotAvailable    = errors.New("DNSKEY record not available")
	ErrInvalidRRsig          = errors.New("RRSIG validation failed")
	ErrRrsigValidationError  = errors.New("RRSIG validation error")
	ErrDsNotAvailable        = errors.New("DS record not available")
	ErrDsInvalid             = errors.New("DS record invalid")
	ErrResourceNotSigned     = errors.New("resource record set not signed")
	ErrForgedRRsig           = errors.New("forged RRSIG")
	ErrRrsigValidityPeriod   = errors.New("RRSIG is outside its validity period")
	ErrUnknownDsDigestType   = errors.New("unknown DS digest type")
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
	// Add a cache for validated DNSKEYs to avoid re-validation
	dnskeyCache map[string][]*dns.DNSKEY
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
		if errors.Is(err, ErrDNSSECValidationFailed) {
			// If DNSSEC validation failed, return SERVFAIL
			msg := new(dns.Msg)
			msg.SetRcode(new(dns.Msg), dns.RcodeServerFailure)
			return msg, ErrDNSSECValidationFailed
		}
		return nil, err
	}

	return result.Msg, result.Err
}

// iterativeResolve performs iterative DNS resolution
func (r *Resolver) iterativeResolve(name string, qtype uint16, dnssec bool) (*DNSResult, error) {
	// Start with root servers
	currentServers := r.rootServers
	
	// Current domain to resolve - start with the full query name
	currentDomain := dns.Fqdn(name)
	
	// Limit iterations to prevent infinite loops
	maxIterations := 20
	iterations := 0
	
	log.Printf("Starting iterative resolution for %s (type %s)", name, dns.TypeToString[qtype])
	
	for iterations < maxIterations {
		iterations++
		log.Printf("Iteration %d: Current domain: %s", iterations, currentDomain)
		
		// Query current servers for the target
		result := r.queryAuthoritativeServers(currentServers, currentDomain, qtype, dnssec)
		
		// If we got a direct answer for our target, return it
		if result.Msg != nil && (result.Msg.Rcode == dns.RcodeSuccess || result.Msg.Rcode == dns.RcodeNameError) {
			if isFinalAnswer(currentDomain, name) {
				log.Printf("Got final answer at iteration %d", iterations)
				return result, nil
			}
		}
		
		// Handle referral - look for NS records in authority section
		if result.Msg != nil {
			var nsRecords []*dns.NS
			var glueRecords []dns.RR
			
			// Collect NS records
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
				log.Printf("Found NS records for %s: %d records", currentDomain, len(nsRecords))
				
				// Get IP addresses for NS servers
				var newServers []string
				
				// First, try to use glue records
				for _, ns := range nsRecords {
					foundGlue := false
					for _, glue := range glueRecords {
						if dns.Fqdn(glue.Header().Name) == dns.Fqdn(ns.Ns) {
							if a, ok := glue.(*dns.A); ok {
								newServers = append(newServers, a.A.String())
								foundGlue = true
								log.Printf("Using glue A record for %s: %s", ns.Ns, a.A.String())
							} else if aaaa, ok := glue.(*dns.AAAA); ok {
								newServers = append(newServers, aaaa.AAAA.String())
								foundGlue = true
								log.Printf("Using glue AAAA record for %s: %s", ns.Ns, aaaa.AAAA.String())
							}
						}
					}
					
					// If no glue, we need to resolve the NS name
					if !foundGlue {
						log.Printf("No glue record for NS %s, resolving iteratively", ns.Ns)
						nsResult, err := r.iterativeResolve(trimDot(ns.Ns), dns.TypeA, dnssec)
						if err == nil && nsResult.Msg != nil && nsResult.Msg.Rcode == dns.RcodeSuccess {
							for _, rr := range nsResult.Msg.Answer {
								if a, ok := rr.(*dns.A); ok {
									newServers = append(newServers, a.A.String())
									log.Printf("Resolved NS %s to %s", ns.Ns, a.A.String())
								} else if aaaa, ok := rr.(*dns.AAAA); ok {
									newServers = append(newServers, aaaa.AAAA.String())
									log.Printf("Resolved NS %s to %s", ns.Ns, aaaa.AAAA.String())
								}
							}
						} else {
							log.Printf("Failed to resolve NS name %s: %v", ns.Ns, err)
						}
					}
				}
				
				// DNSSEC: Fetch DS records from the parent zone (current authoritative servers)
				var parentDS []*dns.DS
				if dnssec {
					dsResult := r.queryAuthoritativeServers(currentServers, currentDomain, dns.TypeDS, dnssec)
					if dsResult.Msg != nil && dsResult.Msg.Rcode == dns.RcodeSuccess {
						for _, rr := range dsResult.Msg.Answer {
							if ds, ok := rr.(*dns.DS); ok {
								parentDS = append(parentDS, ds)
							}
						}
					}
					
					// Validate delegation if DS records are present
					if len(parentDS) > 0 || currentDomain == "." {
						// For root, we don't have parent DS, but we still want to validate DNSKEYs
						_, err := r.QueryDelegation(currentDomain, parentDS, dnssec)
						if err != nil {
							log.Printf("DNSSEC validation failed for delegation %s: %v", currentDomain, err)
							return &DNSResult{Msg: nil, Err: ErrDNSSECValidationFailed}, nil
						}
					}
				}
				
				if len(newServers) > 0 {
					currentServers = newServers
				} else {
					log.Printf("No servers found from NS records, using previous servers")
				}
				
				// Move to the next level down (closer to our target)
				nextDomain := getNextDomain(currentDomain, name)
				if nextDomain != currentDomain {
					currentDomain = nextDomain
					log.Printf("Moving to next domain: %s", currentDomain)
					continue
				} else {
					// We can't go further down, try to get the actual record now
					finalResult := r.queryAuthoritativeServers(currentServers, name, qtype, dnssec)
					return finalResult, finalResult.Err
				}
			}
		}
		
		// If we get here, try to get closer to the target domain
		nextDomain := getNextDomain(currentDomain, name)
		if nextDomain != currentDomain {
			currentDomain = nextDomain
			log.Printf("Moving to next domain: %s", currentDomain)
			continue
		} else {
			// Try final query
			finalResult := r.queryAuthoritativeServers(currentServers, name, qtype, dnssec)
			return finalResult, finalResult.Err
		}
	}
	
	return &DNSResult{Msg: nil, Err: ErrMaxIterations}, nil
}

// queryAuthoritativeServers queries a set of authoritative servers
func (r *Resolver) queryAuthoritativeServers(servers []string, name string, qtype uint16, dnssec bool) *DNSResult {
	result := &DNSResult{}
	
	log.Printf("Querying servers %v for %s (type %s)", servers, name, dns.TypeToString[qtype])
	
	for _, server := range servers {
		addr := net.JoinHostPort(server, "53")
		msg := NewDNSMessage(name, qtype)
		
		log.Printf("Sending query to %s", addr)
		response, _, err := r.dnsClient.Exchange(msg, addr)
		if err == nil && response != nil {
			log.Printf("Got response from %s, Rcode: %s", addr, dns.RcodeToString[response.Rcode])
			result.Msg = response
			
			// Collect NS records from the response
			for _, rr := range response.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					result.AuthNS = append(result.AuthNS, ns)
				}
			}
			
			result.Glue = append(result.Glue, response.Extra...)
			
			// If we got a definitive answer, return it
			if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
				log.Printf("Got definitive answer from %s", addr)
				return result
			}
		} else if err != nil {
			log.Printf("Error querying %s: %v", addr, err)
		}
	}
	
	result.Err = ErrNsNotAvailable
	return result
}

// isFinalAnswer checks if we've reached the final answer for our query
func isFinalAnswer(currentDomain, targetDomain string) bool {
	return dns.Fqdn(targetDomain) == currentDomain || dns.IsSubDomain(currentDomain, dns.Fqdn(targetDomain))
}

// getNextDomain gets the next domain closer to the target
func getNextDomain(currentDomain, targetDomain string) string {
	current := dns.Fqdn(currentDomain)
	target := dns.Fqdn(targetDomain)
	
	// If current is root, move to the top level of target
	if current == "." {
		labels := dns.Split(target)
		if len(labels) > 0 {
			return target[labels[len(labels)-1]:]
		}
		return target
	}
	
	// If target is a subdomain of current, move one level down
	if dns.IsSubDomain(current, target) && target != current {
		// Find the next label to add
		currentLabels := dns.Split(current)
		targetLabels := dns.Split(target)
		
		if len(targetLabels) > len(currentLabels) {
			// Move one label closer
			start := targetLabels[len(targetLabels)-len(currentLabels)-1]
			return target[start:]
		}
	}
	
	// Otherwise, move up to parent
	labels := dns.Split(current)
	if len(labels) > 1 {
		return current[labels[0]:]
	}
	return "."
}

// trimDot removes the trailing dot from a domain name
func trimDot(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
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
	resolver.dnskeyCache = make(map[string][]*dns.DNSKEY)
	
	log.Printf("Initialized resolver with %d root servers", len(resolver.rootServers))
	
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

// QueryDelegation performs DNSSEC validation for a delegated zone.
// It fetches DS records from the parent, DNSKEYs from the child, and validates them.
// Returns the validated DNSKEYs for the child zone if successful.
func (r *Resolver) QueryDelegation(zone string, parentDS []*dns.DS, dnssec bool) ([]*dns.DNSKEY, error) {
	if !dnssec {
		return nil, nil // DNSSEC not enabled
	}

	// Check cache first
	if keys, ok := r.dnskeyCache[zone]; ok {
		log.Printf("Using cached DNSKEYs for zone %s", zone)
		return keys, nil
	}

	log.Printf("Performing DNSSEC validation for delegated zone: %s", zone)

	// 1. Query DNSKEYs from the child zone
	childDNSKEYResult := r.queryAuthoritativeServers(r.rootServers, zone, dns.TypeDNSKEY, dnssec)
	if childDNSKEYResult.Err != nil || childDNSKEYResult.Msg == nil || childDNSKEYResult.Msg.Rcode != dns.RcodeSuccess {
		log.Printf("Failed to fetch DNSKEYs for %s: %v", zone, childDNSKEYResult.Err)
		return nil, ErrDNSSECValidationFailed
	}

	var childDNSKEYs []*dns.DNSKEY
	var childRRSIGs []*dns.RRSIG
	for _, rr := range childDNSKEYResult.Msg.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			childDNSKEYs = append(childDNSKEYs, key)
		} else if sig, ok := rr.(*dns.RRSIG); ok {
			childRRSIGs = append(childRRSIGs, sig)
		}
	}

	if len(childDNSKEYs) == 0 {
		log.Printf("No DNSKEYs found for %s", zone)
		return nil, ErrDNSSECValidationFailed
	}

	// 2. Validate RRSIGs for DNSKEYs using the DNSKEYs themselves (self-signed KSKs)
	// This is a simplified approach. A full validator would need to handle ZSKs and KSKs separately.
	ksks := getKSKs(childDNSKEYs)
	if len(ksks) == 0 {
		log.Printf("No KSKs found for %s", zone)
		return nil, ErrDNSSECValidationFailed
	}

	// For each RRSIG, try to validate it with a KSK
	validatedDNSKEYs := make(map[string]*dns.DNSKEY)
	for _, sig := range childRRSIGs {
		if sig.TypeCovered != dns.TypeDNSKEY {
			continue
		}
		for _, key := range ksks {
			if err := sig.Verify(key, childDNSKEYResult.Msg.Answer); err == nil {
				log.Printf("Successfully validated RRSIG for DNSKEYs in %s with KSK ID %d", zone, key.KeyTag())
				// Add all DNSKEYs to the validated set if at least one RRSIG is valid
				for _, k := range childDNSKEYs {
					validatedDNSKEYs[k.String()] = k
				}
				break // Move to next RRSIG
			}
		}
	}

	if len(validatedDNSKEYs) == 0 {
		log.Printf("Failed to validate RRSIGs for DNSKEYs in %s", zone)
		return nil, ErrDNSSECValidationFailed
	}

	// Convert map back to slice
	var finalDNSKEYs []*dns.DNSKEY
	for _, key := range validatedDNSKEYs {
		finalDNSKEYs = append(finalDNSKEYs, key)
	}

	// 3. If parentDS is provided, validate DS records against the child's KSKs
	if len(parentDS) > 0 {
		log.Printf("Validating DS records for %s against child DNSKEYs", zone)
		didValidateDS := false
		for _, ds := range parentDS {
			for _, key := range finalDNSKEYs {
				if key.KeyTag() == ds.KeyTag && ds.Algorithm == key.Algorithm {
					// Re-create DS from DNSKEY and compare digests
					generatedDS := key.ToDS(ds.DigestType)
					if generatedDS != nil && compareDigests([]byte(generatedDS.Digest), []byte(ds.Digest)) {
						didValidateDS = true
						log.Printf("Successfully validated DS record for %s with DNSKEY ID %d", zone, key.KeyTag())
						break
					}
				}
			}
			if didValidateDS {
				break
			}
		}
		if !didValidateDS {
			log.Printf("Failed to validate DS records for %s", zone)
			return nil, ErrDNSSECValidationFailed
		}
	} else {
		log.Printf("No parent DS records provided for %s, skipping DS validation", zone)
	}

	// Cache validated DNSKEYs
	r.dnskeyCache[zone] = finalDNSKEYs
	log.Printf("DNSSEC validation successful for %s. Cached %d DNSKEYs.", zone, len(finalDNSKEYs))
	return finalDNSKEYs, nil
}

// getKSKs extracts Key Signing Keys (KSKs) from a slice of DNSKEYs.
func getKSKs(keys []*dns.DNSKEY) []*dns.DNSKEY {
	var ksks []*dns.DNSKEY
	for _, key := range keys {
		if key.Flags&(dns.ZONE|dns.SEP) == (dns.ZONE|dns.SEP) {
			ksks = append(ksks, key)
		}
	}
	return ksks
}

// compareDigests compares two byte slices for equality.
func compareDigests(d1, d2 []byte) bool {
	if len(d1) != len(d2) {
		return false
	}
	for i := range d1 {
		if d1[i] != d2[i] {
			return false
		}
	}
	return true
}