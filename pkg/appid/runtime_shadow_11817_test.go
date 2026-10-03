package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestResolveSessionNameUserRedefinedBuiltinShadowed_11817 is the #11817
// RED-on-revert proof. A user redefinition of a predefined/builtin application
// name (junos-http moved to tcp/8080) shadows the hardcoded builtinFallbacks
// entry on the AppID-disabled path. A tcp/80 session must NOT be resurrected
// as "junos-http" from the builtin table — the user map owns that name now,
// and tcp/80 matches nothing, so the honest label is UNKNOWN.
func TestResolveSessionNameUserRedefinedBuiltinShadowed_11817(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"junos-http": {Name: "junos-http", Protocol: "tcp", DestinationPort: "8080"},
			},
		},
	}
	cfg.Services.ApplicationIdentification = false

	// The redefined tuple still resolves through the user map.
	if got := ResolveSessionName(nil, cfg, 6, 40000, 8080, 0); got != "junos-http" {
		t.Fatalf("ResolveSessionName(tcp/8080) = %q, want junos-http via the user redefinition", got)
	}
	// The stale builtin tuple must NOT resurrect the shadowed name.
	if got := ResolveSessionName(nil, cfg, 6, 40000, 80, 0); got != Unknown {
		t.Fatalf("ResolveSessionName(tcp/80) = %q, want %q (user redefinition of junos-http shadows the builtin tcp/80 entry)", got, Unknown)
	}
}

// TestResolveSessionNameBuiltinUnshadowedStillMatches_11817 guards against
// over-suppression: with no user entry claiming the name, the builtin
// tcp/80 → junos-http heuristic still applies on the disabled path.
func TestResolveSessionNameBuiltinUnshadowedStillMatches_11817(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false

	if got := ResolveSessionName(nil, cfg, 6, 40000, 80, 0); got != "junos-http" {
		t.Fatalf("ResolveSessionName(tcp/80) with empty user map = %q, want junos-http (unshadowed builtin)", got)
	}
	if got := ResolveSessionName(nil, nil, 6, 40000, 80, 0); got != "junos-http" {
		t.Fatalf("ResolveSessionName(tcp/80) with nil cfg = %q, want junos-http (unshadowed builtin)", got)
	}
}
