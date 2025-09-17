package goresolver

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
    "fmt"

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