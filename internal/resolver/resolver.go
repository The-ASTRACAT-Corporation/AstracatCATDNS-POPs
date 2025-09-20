package resolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// rootServers is a list of the IP addresses of the root DNS servers.
// In a production system, this list would be managed more dynamically.
var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"199.9.14.201:53",   // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net
}

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	workerPool *WorkerPool
}

// NewResolver creates a new resolver instance.
func NewResolver(cfg *config.Config, c *cache.Cache, wp *WorkerPool) *Resolver {
	r := &Resolver{
		config:     cfg,
		cache:      c,
		workerPool: wp,
		sf:         singleflight.Group{},
	}
	c.SetResolver(r)
	return r
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *Resolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *Resolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check the cache first.
	if cachedMsg, found, revalidate := r.cache.Get(key); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		cachedMsg.Id = req.Id

		if revalidate {
			// Trigger a background revalidation
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
				defer cancel()
				_, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.lookup(ctx, req)
				})
				if err != nil {
					log.Printf("Background revalidation failed for %s: %v", q.Name, err)
				}
			}()
		}
		return cachedMsg, nil
	}

	// Use singleflight to ensure only one lookup for a given question is in flight at a time.
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.lookup(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	msg := res.(*dns.Msg)
	msg.Id = req.Id
	return msg, nil
}

// lookup is the core recursive lookup logic.
func (r *Resolver) lookup(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	nsAddrs := rootServers

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		log.Printf("Querying for %s against %v", q.Name, nsAddrs)
		resp, err := r.query(ctx, nsAddrs, req)
		if err != nil {
			return nil, fmt.Errorf("querying nameservers failed: %w", err)
		}

		if len(resp.Answer) > 0 {
			r.cache.Set(cache.Key(q), resp, r.config.StaleWhileRevalidate, r.config.Prefetch)
			return resp, nil
		}

		if resp.Rcode == dns.RcodeNameError {
			r.cache.Set(cache.Key(q), resp, r.config.StaleWhileRevalidate, r.config.Prefetch)
			return resp, nil
		}

		nextNS, nextNSAddrs := r.extractNextServers(resp)
		if len(nextNSAddrs) > 0 {
			nsAddrs = nextNSAddrs
			continue
		}

		if len(nextNS) > 0 {
			// We have NS records but no IPs. We need to resolve them.
			var resolvedNSAddrs []string
			for _, ns := range nextNS {
				// Create a new request to resolve the NS record
				nsReq := new(dns.Msg)
				nsReq.SetQuestion(ns, dns.TypeA)
				nsReq.RecursionDesired = true

				var nsResp *dns.Msg
				// Check cache for NS A record before resolving
				if cachedNsMsg, found, _ := r.cache.Get(cache.Key(nsReq.Question[0])); found {
					nsResp = cachedNsMsg
				} else {
					// Recursively resolve the NS
					var err error
					nsResp, err = r.Resolve(ctx, nsReq)
					if err != nil {
						log.Printf("Failed to resolve NS %s: %v", ns, err)
						continue
					}
					// Cache the NS record's A record
					if len(nsResp.Answer) > 0 {
						r.cache.Set(cache.Key(nsReq.Question[0]), nsResp, r.config.StaleWhileRevalidate, r.config.Prefetch)
					}
				}

				for _, ans := range nsResp.Answer {
					if a, ok := ans.(*dns.A); ok {
						resolvedNSAddrs = append(resolvedNSAddrs, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}

			if len(resolvedNSAddrs) > 0 {
				nsAddrs = resolvedNSAddrs
				continue
			}
		}

		return r.servfail(req), nil
	}
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.lookup(ctx, req)
}

// query sends a DNS query to a list of nameservers.
func (r *Resolver) query(ctx context.Context, nsAddrs []string, req *dns.Msg) (*dns.Msg, error) {
	if err := r.workerPool.Acquire(ctx); err != nil {
		return nil, err
	}
	defer r.workerPool.Release()

	client := new(dns.Client)
	for _, addr := range nsAddrs {
		queryCtx, cancel := context.WithTimeout(ctx, r.config.UpstreamTimeout)
		defer cancel()

		resp, _, err := client.ExchangeContext(queryCtx, req, addr)
		if err != nil {
			log.Printf("Error querying %s: %v", addr, err)
			continue
		}
		return resp, nil
	}
	return nil, errors.New("all nameservers failed to respond")
}

// extractNextServers extracts NS and A/AAAA records from a response to find the next servers to query.
func (r *Resolver) extractNextServers(msg *dns.Msg) (ns []string, addrs []string) {
	nsMap := make(map[string]bool)

	for _, rr := range msg.Ns {
		if nsRR, ok := rr.(*dns.NS); ok {
			ns = append(ns, nsRR.Ns)
			nsMap[strings.TrimSuffix(nsRR.Ns, ".")] = true
		}
	}

	for _, rr := range msg.Extra {
		switch v := rr.(type) {
		case *dns.A:
			if nsMap[strings.TrimSuffix(v.Header().Name, ".")] {
				addrs = append(addrs, net.JoinHostPort(v.A.String(), "53"))
			}
		case *dns.AAAA:
			// AAAA records are ignored for now to keep it simple.
		}
	}
	return ns, addrs
}

// servfail creates a SERVFAIL response.
func (r *Resolver) servfail(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	return m
}
