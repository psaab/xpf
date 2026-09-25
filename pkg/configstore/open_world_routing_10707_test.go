package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func hasOpenWorldRoutingWarning10707(warnings []string, marker string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#10707") && strings.Contains(warning, marker) {
			return true
		}
	}
	return false
}

func TestOpenWorldRoutingUnknownLeavesWarnAtStrictCommit10707(t *testing.T) {
	rows := []struct {
		name, valid, unknown, marker string
	}{
		{
			name:    "protocols",
			valid:   `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 10; } } } }`,
			unknown: `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 10; cosst 11; } } } }`,
			marker:  "cosst",
		},
		{
			name:    "policy-options",
			valid:   `policy-options { policy-statement p1 { term t1 { from { protocol bgp; } then { accept; } } } }`,
			unknown: `policy-options { policy-statement p1 { term t1 { from { protocol bgp; } then { accept; acccept; } } } }`,
			marker:  "acccept",
		},
		{
			name:    "routing-options",
			valid:   `routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.1; } } }`,
			unknown: `routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.1; next-hopp 192.0.2.2; } } }`,
			marker:  "next-hopp",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			valid, err := CheckText(row.valid, 0)
			if err != nil {
				t.Fatalf("valid control was rejected: %v", err)
			}
			if hasOpenWorldRoutingWarning10707(valid.Warnings, row.marker) {
				t.Fatalf("valid control unexpectedly warned about %q: %v", row.marker, valid.Warnings)
			}

			compiled, err := CheckText(row.unknown, 0)
			if err != nil {
				t.Fatalf("open-world compatibility changed: unknown leaf must warn, not reject strict commit: %v", err)
			}
			if !hasOpenWorldRoutingWarning10707(compiled.Warnings, row.marker) {
				t.Fatalf("strict commit output omitted the #10707 warning for %q: %v", row.marker, compiled.Warnings)
			}
		})
	}
}

func TestOpenWorldRoutingInstanceSubtreesWarnAtStrictCommit10707(t *testing.T) {
	const text = `routing-instances {
    VRF-A {
        instance-type virtual-router;
        protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 10; cosst 11; } } } }
        routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.1; next-hopp 192.0.2.2; } } }
    }
}
`
	compiled, err := CheckText(text, 0)
	if err != nil {
		t.Fatalf("open-world per-instance config was rejected instead of warned: %v", err)
	}
	for _, marker := range []string{"cosst", "next-hopp"} {
		if !hasOpenWorldRoutingWarning10707(compiled.Warnings, marker) {
			t.Errorf("strict commit omitted the #10707 per-instance warning for %q: %v", marker, compiled.Warnings)
		}
	}
}

func TestOpenWorldRoutingUnknownLeavesWarnOnTolerantIngress10707(t *testing.T) {
	const text = `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 10; cosst 11; } } } }
policy-options { policy-statement p1 { term t1 { from { protocol bgp; } then { accept; acccept; } } } }
routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.1; next-hopp 192.0.2.2; } } }
`
	tree, parseErrors := config.NewParser(text).Parse()
	if len(parseErrors) > 0 {
		t.Fatalf("parse: %v", parseErrors)
	}
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load/sync path rejected an unmodeled legacy config: %v", err)
	}
	for _, marker := range []string{"cosst", "acccept", "next-hopp"} {
		if !hasOpenWorldRoutingWarning10707(compiled.Warnings, marker) {
			t.Errorf("tolerant path omitted the #10707 warning for %q: %v", marker, compiled.Warnings)
		}
	}
}
