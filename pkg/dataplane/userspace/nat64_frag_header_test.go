// #2008 H16: `security nat natv6v4 no-v6-frag-header` parsed, compiled into
// typed config, and rode the snapshot wire but had NO runtime consumer — the
// global flag never reached the dataplane NAT64 snapshot, so the IPv6->IPv4
// translator could not honor it. This test exercises the full compile ->
// buildNAT64Snapshots path and asserts the flag is replicated onto every
// emitted NAT64 rule. It fails if buildNAT64Snapshots ignores NATv6v4 (the
// pre-fix behavior).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileNAT64FragHeaderConfig(t *testing.T, withNoFragHeader bool) *config.Config {
	t.Helper()
	input := `
security {
    nat {
        source {
            pool nat64-pool {
                address 198.51.100.1/32;
            }
        }
        nat64 {
            rule-set wkp {
                prefix 64:ff9b::/96;
                source-pool nat64-pool;
            }
        }
`
	if withNoFragHeader {
		input += `
        natv6v4 {
            no-v6-frag-header;
        }
`
	}
	input += `    }
}
`
	parser := config.NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestBuildNAT64SnapshotsThreadsNoV6FragHeader(t *testing.T) {
	cfg := compileNAT64FragHeaderConfig(t, true)

	// Precondition: the typed config must carry the option (proves the gap is
	// in the snapshot path, not in parse/compile).
	if cfg.Security.NAT.NATv6v4 == nil || !cfg.Security.NAT.NATv6v4.NoV6FragHeader {
		t.Fatalf("typed config missing NoV6FragHeader: %+v", cfg.Security.NAT.NATv6v4)
	}

	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if !snaps[0].NoV6FragHeader {
		t.Fatalf("NAT64 snapshot dropped no-v6-frag-header: %+v", snaps[0])
	}
}

func TestBuildNAT64SnapshotsDefaultNoV6FragHeaderUnset(t *testing.T) {
	cfg := compileNAT64FragHeaderConfig(t, false)

	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].NoV6FragHeader {
		t.Fatalf("NAT64 snapshot set no-v6-frag-header without natv6v4 config: %+v", snaps[0])
	}
}
