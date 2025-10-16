//go:build kres

package kres

import (
    "context"

    "dns-resolver/internal/interfaces"
    "dns-resolver/internal/metrics"

    "github.com/miekg/dns"
)

// Backend is a placeholder for libkres-based implementation.
type Backend struct{}

// New creates a stub Kres backend; to be implemented via cgo bindings.
func New(_ interface{}, _ *metrics.Metrics) *Backend {
    return &Backend{}
}

// Exchange currently returns NOTIMP until libkres integration is implemented.
func (b *Backend) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, interfaces.DNSSECStatus, error) {
    resp := new(dns.Msg)
    resp.SetRcode(req, dns.RcodeNotImplemented)
    return resp, interfaces.DNSSECUnknown, nil
}
