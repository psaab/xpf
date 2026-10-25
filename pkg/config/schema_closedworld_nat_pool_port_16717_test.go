package config

import (
	"strings"
	"testing"
)

// #16717: the source-NAT pool `port` value tail (`range low <lo> high
// <hi>`, `range <lo> to <hi>`, single `port <n>`) is a compiler-owned
// grammar (parseSourcePoolPortRange) whose tokens are values, not
// schema keywords. The #10078 security closed-world arm must not read
// them as unknown keywords — that false-reject reds every pkg/api NAT
// fixture that commits an explicit port window. The compiler's strict
// range gate remains the fail-closed judge for malformed tails.

func TestClosedWorldNATPoolPortRangeAccepted16717(t *testing.T) {
	for _, line := range []string{
		"security nat source pool p1 port range low 1024 high 2047",
		"security nat source pool p1 port range 1024 to 2047",
		"security nat source pool p1 port 8080",
	} {
		tree := buildTree(t, cwSecurity9878Set(
			"nat source pool p1 address 192.0.2.1/32",
			strings.TrimPrefix(line, "security "),
		))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valid pool port tail %q must survive the security arm: %v", line, err)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("valid pool port tail %q must compile: %v", line, err)
		}
	}
	// Hierarchical spelling of the same tail.
	tree, perrs := NewParser("security {\n zones { security-zone trust; security-zone untrust; }\n nat {\n  source {\n   pool p1 {\n    address 203.0.113.5/32;\n    port { range 1024 to 2023; }\n   }\n  }\n }\n}\n").Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("hierarchical pool port range must survive the security arm: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical pool port range must compile: %v", err)
	}
	if p := cfg.Security.NAT.SourcePools["p1"]; p == nil || p.PortLow != 1024 || p.PortHigh != 2023 {
		t.Fatalf("hierarchical range compiled to %+v, want 1024-2023", p)
	}
}

func TestClosedWorldNATPoolPortBogusStillRejected16717(t *testing.T) {
	for _, tail := range []string{
		"security nat source pool p1 port range bogus",
		"security nat source pool p1 port bogus-xyz",
		"security nat source pool p1 port range 99999 to 100000",
	} {
		tree := buildTree(t, cwSecurity9878Set(
			"nat source pool p1 address 192.0.2.1/32",
			strings.TrimPrefix(tail, "security "),
		))
		// SchemaValidate may pass the opaque tail; the strict compiler
		// gate must reject it — the pair must never both accept.
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("malformed pool port tail %q must be rejected by the strict gate", tail)
		}
	}
	// A typo'd keyword at the pool level (outside the opaque port tail)
	// still fails closed under the security arm.
	tree := buildTree(t, cwSecurity9878Set(
		"nat source pool p1 adress 192.0.2.1/32",
	))
	if err := SchemaValidate(tree); err == nil || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("pool-level typo must be rejected under closed-world, got: %v", err)
	}
}
