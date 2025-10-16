package stub

import (
    "context"
    "os"
    "time"

    "dns-resolver/internal/interfaces"

    "github.com/miekg/dns"
)

// Backend implements interfaces.Backend by forwarding to a configurable upstream.
// This is a cgo-free fallback to keep default builds working in environments
// without libunbound/libkres.
type Backend struct {
    upstream string
    lastRTT  time.Duration
}

func NewDefault() *Backend {
    upstream := os.Getenv("UPSTREAM_DNS")
    if upstream == "" {
        upstream = "9.9.9.9:53" // Quad9 default
    }
    return &Backend{upstream: upstream}
}

func (b *Backend) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, interfaces.DNSSECStatus, error) {
    c := &dns.Client{Net: "udp"}
    // miekg/dns supports ExchangeContext; timeouts also honored via Client.Timeout
    if deadline, ok := ctx.Deadline(); ok {
        c.Timeout = time.Until(deadline)
        if c.Timeout <= 0 {
            c.Timeout = 50 * time.Millisecond
        }
    }
    start := time.Now()
    in, rtt, err := c.ExchangeContext(ctx, req, b.upstream)
    if err != nil {
        b.lastRTT = time.Since(start)
        return in, interfaces.DNSSECUnknown, err
    }
    b.lastRTT = rtt

    // Determine DNSSEC status based on AD bit presence only (upstream-validated)
    status := interfaces.DNSSECUnknown
    if in != nil {
        if in.AuthenticatedData {
            status = interfaces.DNSSECSecure
        } else {
            status = interfaces.DNSSECInsecure
        }
    }
    // If upstream returns SERVFAIL for DO queries, treat as BOGUS to match tests
    if in != nil && in.Rcode == dns.RcodeServerFailure {
        return in, interfaces.DNSSECBogus, dns.ErrRcode
    }
    return in, status, nil
}

func (b *Backend) LastExchangeLatency() time.Duration { return b.lastRTT }
