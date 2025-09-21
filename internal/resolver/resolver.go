package resolver

import (
	"dns-resolver/internal/cache"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Root servers as of 2024.
var rootServers = []string{
	"198.41.0.4",      // a.root-servers.net
	"199.9.14.201",    // b.root-servers.net
	"192.33.4.12",     // c.root-servers.net
	"199.7.91.13",     // d.root-servers.net
	"192.203.230.10",  // e.root-servers.net
	"192.5.5.241",     // f.root-servers.net
	"192.112.36.4",    // g.root-servers.net
	"198.97.190.53",   // h.root-servers.net
	"192.36.148.17",   // i.root-servers.net
	"192.58.128.30",   // j.root-servers.net
	"193.0.14.129",    // k.root-servers.net
	"199.7.83.42",     // l.root-servers.net
	"202.12.27.33",    // m.root-servers.net
}

// Resolver holds the state for our recursive resolver.
type Resolver struct {
	cache *cache.MultiLevelCache
}

// NewResolver creates a new resolver instance.
func NewResolver(cache *cache.MultiLevelCache) *Resolver {
	return &Resolver{
		cache: cache,
	}
}

// Resolve performs a recursive DNS query.
func (r *Resolver) Resolve(question dns.Question) (*dns.Msg, error) {
	// 1. Check cache first.
	// We use "." as the zone for caching top-level queries.
	cachedMsg, err := r.cache.Get(".", question)
	if err != nil {
		// Log the error but continue, as a cache error shouldn't stop resolution.
		// In a real system, you might want more robust error handling.
		// log.Printf("Cache get error: %v", err)
	}
	if cachedMsg != nil {
		return cachedMsg, nil
	}

	// Find the best nameservers to start with from the cache.
	nameservers, err := r.findBestNameservers(question.Name)
	if err != nil {
		// log.Printf("Error finding best nameservers: %v", err)
		nameservers = rootServers
	}


	for i := 0; i < 10; i++ { // Limit recursion depth to 10
		// Query one of the nameservers from the current list.
		var response *dns.Msg
		var err error

		for _, ns := range nameservers {
			response, err = r.sendQuery(ns, question.Name, question.Qtype)
			if err == nil {
				break // Got a response, move on.
			}
		}

		if err != nil {
			return nil, err // Failed to contact any nameservers in the list.
		}

		// If we got an answer, we need to check if it's a CNAME.
		if len(response.Answer) > 0 {
			// Check for CNAME
			if cname, ok := response.Answer[0].(*dns.CNAME); ok {
				// It's a CNAME. We need to resolve the target.
				// We restart the resolution process with the new name.
				// We also need to prevent CNAME loops.
				// A simple way is to limit the number of CNAMEs we follow.
				// Let's add a cname_count to the function call later. For now, we just recurse.
				question.Name = cname.Target
				// The response for the original query should include the CNAME record.
				// We can handle this better later. For now, just resolve the target.
				continue // Restart the loop with the new question name.
			}

			// It's a final answer. Cache and return.
			r.cache.Update(".", question, response)
			return response, nil
		}

		// If we got an NXDOMAIN response, the domain doesn't exist.
		// We should cache this to prevent repeated lookups for non-existent domains.
		if response.Rcode == dns.RcodeNameError {
			r.cache.Update(".", question, response)
			return response, nil // Return the NXDOMAIN response.
		}

		// If we got a referral, we should cache the NS records for the zone.
		if len(response.Ns) > 0 {
			// The zone is the name of the first NS record's header.
			zone := response.Ns[0].Header().Name
			nsQuestion := dns.Question{Name: zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET}

			// We can cache the response directly as it contains the NS records.
			// We should probably strip out unnecessary parts of the response
			// to save cache space, but for now this is fine.
			r.cache.Update(".", nsQuestion, response)
		}

		// If we got a referral, we need to follow it.
		// The new nameservers are in the authority section.
		newNsList, glueRecords := extractNSRecords(response)
		if len(newNsList) == 0 {
			// This can happen if the response is a NOERROR with no answer and no NS records (e.g. for a CNAME).
			// We should have handled this earlier.
			// For now, we'll consider it an error.
			return nil, errors.New("no nameservers found in referral")
		}

		// We need the IPs of the new nameservers.
		// First, check if we got them as "glue" records in the extra section.
		nextNameservers := findIPsInGlue(newNsList, glueRecords)

		// If we didn't get glue records, we need to resolve the nameserver hostnames.
		if len(nextNameservers) == 0 {
			// This is the recursive part. We need to resolve the NS hostnames.
			// For each nameserver, we call this Resolve function again.
			// This is a simplification; a real resolver would be more careful about loops.
			for _, ns := range newNsList {
				// We need to resolve the A record for the nameserver.
				// This is a recursive call.
				nsQuestion := dns.Question{Name: ns, Qtype: dns.TypeA, Qclass: dns.ClassINET}
				nsMsg, err := r.Resolve(nsQuestion)
				if err != nil {
					// Could not resolve this nameserver, try the next.
					continue
				}
				// Extract the IP from the answer.
				for _, ans := range nsMsg.Answer {
					if a, ok := ans.(*dns.A); ok {
						nextNameservers = append(nextNameservers, a.A.String())
					}
				}
			}
		}

		if len(nextNameservers) == 0 {
			return nil, errors.New("could not resolve nameserver IPs")
		}

		nameservers = nextNameservers
	}

	return nil, errors.New("resolution failed: max recursion depth reached")
}

// extractNSRecords extracts NS records and any accompanying A/AAAA records (glue) from a response.
func extractNSRecords(msg *dns.Msg) ([]string, []dns.RR) {
	var ns []string
	var glue []dns.RR
	for _, rr := range msg.Ns {
		if nsRec, ok := rr.(*dns.NS); ok {
			ns = append(ns, nsRec.Ns)
		}
	}
	glue = msg.Extra
	return ns, glue
}

// findIPsInGlue looks for IP addresses for given nameserver hostnames in the glue records.
func findIPsInGlue(nameservers []string, glue []dns.RR) []string {
	var ips []string
	nsSet := make(map[string]bool)
	for _, ns := range nameservers {
		nsSet[strings.ToLower(ns)] = true
	}

	for _, rr := range glue {
		if a, ok := rr.(*dns.A); ok {
			if nsSet[strings.ToLower(a.Hdr.Name)] {
				ips = append(ips, a.A.String())
			}
		}
		// Can also handle AAAA records here.
	}
	return ips
}

// findBestNameservers finds the most specific nameservers we know about for a domain.
func (r *Resolver) findBestNameservers(domain string) ([]string, error) {
	parts := strings.Split(domain, ".")
	// Iterate from the most specific part of the domain to the least specific.
	// e.g., for www.google.com, check "www.google.com.", then "google.com.", then "com.", then "."
	for i := 0; i < len(parts); i++ {
		zone := strings.Join(parts[i:], ".")
		if zone == "" {
			zone = "."
		}

		nsQuestion := dns.Question{Name: zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET}
		cachedMsg, _ := r.cache.Get(".", nsQuestion)

		if cachedMsg != nil && len(cachedMsg.Ns) > 0 {
			// We found cached NS records for this zone.
			newNsList, glueRecords := extractNSRecords(cachedMsg)

			// Resolve their IPs if needed.
			ips := findIPsInGlue(newNsList, glueRecords)
			if len(ips) > 0 {
				return ips, nil
			}

			// If no glue, we need to resolve them.
			// This could be a recursive call, but for simplicity, we'll just return what we have.
			// The main loop will handle the resolution.
			// A better implementation would resolve them here.
			var resolvedIps []string
			for _, ns := range newNsList {
				nsQuestion := dns.Question{Name: ns, Qtype: dns.TypeA, Qclass: dns.ClassINET}
				// Using Resolve here could cause a loop. We need a more careful approach.
				// For now, let's just see if we can get it from cache.
				nsMsg, _ := r.cache.Get(".", nsQuestion)
				if nsMsg != nil {
					for _, ans := range nsMsg.Answer {
						if a, ok := ans.(*dns.A); ok {
							resolvedIps = append(resolvedIps, a.A.String())
						}
					}
				}
			}
			if len(resolvedIps) > 0 {
				return resolvedIps, nil
			}
		}
	}

	// If we found nothing, return the root servers.
	return rootServers, nil
}

// sendQuery sends a DNS query to a specific server and returns the response.
func (r *Resolver) sendQuery(server, domain string, qtype uint16) (*dns.Msg, error) {
	client := dns.Client{
		Timeout: 2 * time.Second,
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = false // We are doing the recursion, not the server.

	// Use port 53 for DNS.
	addr := net.JoinHostPort(server, "53")

	res, _, err := client.Exchange(msg, addr)
	if err != nil {
		return nil, err
	}

	return res, nil
}
