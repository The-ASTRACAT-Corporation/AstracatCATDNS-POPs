//go:build unbound && cgo

package unbound

import (
    "context"
    "errors"
    "time"

    "dns-resolver/internal/interfaces"
    "dns-resolver/internal/metrics"

    "github.com/miekg/dns"
    "github.com/miekg/unbound"
)

// Backend implements interfaces.Backend using libunbound via github.com/miekg/unbound.
type Backend struct {
    u       *unbound.Unbound
    metrics *metrics.Metrics
    lastRTT time.Duration
}

// New creates a new Unbound backend instance.
func New(_ interface{}, m *metrics.Metrics) *Backend { // cfg placeholder for parity with kres
    u := unbound.New()
    // Best-effort: try to load a common trust anchor if present
    _ = u.AddTaFile("/etc/unbound/root.key")
    return &Backend{u: u, metrics: m}
}

// Exchange resolves the request using libunbound and produces a dns.Msg response.
func (b *Backend) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, interfaces.DNSSECStatus, error) {
    q := req.Question[0]
    start := time.Now()
    result, err := b.u.Resolve(q.Name, q.Qtype, q.Qclass)
    b.lastRTT = time.Since(start)

    if err != nil {
        if b.metrics != nil {
            b.metrics.IncrementUnboundErrors()
        }
        // Build SERVFAIL so caller has a response to send
        msg := new(dns.Msg)
        msg.SetRcode(req, dns.RcodeServerFailure)
        return msg, interfaces.DNSSECUnknown, err
    }

    msg := new(dns.Msg)
    msg.SetReply(req)
    msg.Rcode = result.Rcode

    if result.HaveData {
        msg.Answer = result.Rr
    }

    // Map DNSSEC status
    var status interfaces.DNSSECStatus
    switch {
    case result.Bogus:
        status = interfaces.DNSSECBogus
        msg.Rcode = dns.RcodeServerFailure
        return msg, status, errors.New("BOGUS: DNSSEC validation failed")
    case result.Secure:
        status = interfaces.DNSSECSecure
        msg.AuthenticatedData = true
    default:
        status = interfaces.DNSSECInsecure
        msg.AuthenticatedData = false
    }

    return msg, status, nil
}

// LastExchangeLatency returns the last observed RTT for an Exchange call.
func (b *Backend) LastExchangeLatency() time.Duration {
    return b.lastRTT
}
