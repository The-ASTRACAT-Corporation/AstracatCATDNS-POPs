//go:build kres

package backend

import (
    "dns-resolver/internal/backend/kres"
    "dns-resolver/internal/config"
    "dns-resolver/internal/interfaces"
    "dns-resolver/internal/metrics"
)

// New returns the Knot Resolver backend when built with -tags=kres.
func New(cfg *config.Config, m *metrics.Metrics) interfaces.Backend {
    return kres.New(cfg, m)
}
