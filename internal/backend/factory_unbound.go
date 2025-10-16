//go:build !kres

package backend

import (
    "os"
    "dns-resolver/internal/backend/stub"
    "dns-resolver/internal/config"
    "dns-resolver/internal/interfaces"
    "dns-resolver/internal/metrics"
)

// New returns the default backend when Knot Resolver is not enabled: Unbound.
func New(cfg *config.Config, m *metrics.Metrics) interfaces.Backend {
    // Provide a cgo-free stub by default to keep builds working in minimal envs.
    // Unbound or Kres backends can be enabled via build tags and their own factories.
    if os.Getenv("ASTRACAT_BACKEND") == "stub" || os.Getenv("ASTRACAT_BACKEND") == "" {
        return stub.NewDefault()
    }
    // Future: allow selecting other backends by name here if desired
    return stub.NewDefault()
}
