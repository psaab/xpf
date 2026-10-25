package api

import (
	"strings"
	"testing"
)

// #16717 fixture-commit canary: one named cell that commits a fixture
// exercising every strict gate that has red the pkg/api suite from a
// fixture (NAT from-zone definition, closed-world pool port tail).
// A future strict gate that rejects this shape reds THIS cell in the
// gate's own PR, instead of silently redding every NAT/metrics cell
// that happens to share the fixture shape. The gates themselves must
// stay fail-closed: the negative legs below pin that repairing the
// fixtures did not weaken any gate.
func TestFixtureCommitCanary16717(t *testing.T) {
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 203.0.113.10/32",
		"set security nat source pool p1 port range low 1024 high 2023",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool p1",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("canary fixture must commit under every strict gate: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("canary: no active config after commit")
	}
	if _, ok := cfg.Security.Zones["trust"]; !ok {
		t.Fatal("canary: trust zone missing from committed config")
	}
	if p := cfg.Security.NAT.SourcePools["p1"]; p == nil || p.PortLow != 1024 || p.PortHigh != 2023 {
		t.Fatalf("canary: pool p1 port window = %+v, want 1024-2023", p)
	}

	// Negative legs: the gates the fixtures tripped must still reject.
	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{"undefined from-zone", "set security nat source rule-set bad from zone nosuchzone", "not defined"},
		{"bogus pool port", "set security nat source pool p2 port range bogus", "invalid"},
	} {
		s2 := newConfigStore(t, t.TempDir())
		if err := s2.EnterConfigure(); err != nil {
			t.Fatalf("%s: EnterConfigure: %v", tc.name, err)
		}
		if _, err := s2.LoadSet("set security zones security-zone trust\nset security zones security-zone untrust\nset security nat source pool p2 address 203.0.113.11/32\n" + tc.line); err != nil {
			t.Fatalf("%s: LoadSet: %v", tc.name, err)
		}
		if _, err := s2.Commit(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: strict gate must reject (%q), got: %v", tc.name, tc.want, err)
		}
	}
}
