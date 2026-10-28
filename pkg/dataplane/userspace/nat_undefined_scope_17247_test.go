package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileUndefinedScopeLenient17247(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// #17247: undefined-scope findings remain diagnostics, not a new skip marker.
// Tolerant load warns while preserving the original NAT snapshot rows and
// their authored scopes.
func TestLenientUndefinedScopePreservesSourceNATSnapshots17247(t *testing.T) {
	cfg := compileUndefinedScopeLenient17247(t,
		"set security nat source pool p1 address 192.0.2.10/32",
		"set security nat source rule-set bad-interface from interface ge-0/0/9.0",
		"set security nat source rule-set bad-interface rule r-interface match source-address 10.0.0.0/8",
		"set security nat source rule-set bad-interface rule r-interface then source-nat pool p1",
		"set security nat source rule-set bad-instance from routing-instance missing-vrf",
		"set security nat source rule-set bad-instance rule r-instance match source-address 10.1.0.0/16",
		"set security nat source rule-set bad-instance rule r-instance then source-nat pool p1",
		"set security nat source rule-set healthy rule r-healthy match source-address 10.2.0.0/16",
		"set security nat source rule-set healthy rule r-healthy then source-nat pool p1",
	)
	snapshots := buildSourceNATSnapshots(cfg, nil)
	if len(snapshots) != 3 {
		t.Fatalf("source NAT snapshots = %+v, want all three authored rows", snapshots)
	}
	byRule := make(map[string]SourceNATRuleSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		byRule[snapshot.Name] = snapshot
	}
	if got := byRule["r-interface"].FromInterface; got != "ge-0/0/9.0" {
		t.Fatalf("undefined-interface snapshot scope = %q, want authored ge-0/0/9.0", got)
	}
	if got := byRule["r-instance"].FromRoutingInstance; got != "missing-vrf" {
		t.Fatalf("undefined-RI snapshot scope = %q, want authored missing-vrf", got)
	}
	if _, ok := byRule["r-healthy"]; !ok {
		t.Fatalf("healthy sibling missing from snapshots: %+v", snapshots)
	}
}
