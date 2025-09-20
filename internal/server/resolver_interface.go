package server

import (
	"context"
	"dns-resolver/internal/resolver"
	"github.com/miekg/dns"
)

type ResolverInterface interface {
	Exchange(ctx context.Context, msg *dns.Msg) *resolver.Result
}
