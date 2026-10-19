package config

import (
	"strings"
	"testing"
)

// #15196 A02-01: a padded GRE/IPIP tunnel source/destination passes
// ValidateIPAddress (which trims) and commits clean, but the tunnel
// consumers parse the RAW string — pkg/routing/tunnel.go
// applyKernelTunnelLocked (net.ParseIP(tc.Source)) warns "invalid tunnel
// endpoints" and creates nothing; the userspace snapshot producer likewise
// skips an unparseable endpoint. The tunnel is silently absent after a
// green commit. Refuse padding at SchemaValidate (CheckText) so the
// operator fixes the spelling; bare rows must stay green.
//
// Padding is authorable through ordinary ingress: quoted strings preserve
// their contents verbatim (`source " 192.0.2.1 "`), mirroring #14377/#9820.
//
// FAIL-ON-REVERT: reverting either tunnel leaf to ValidateIPAddress (which
// trims), or dropping the `raw != TrimSpace(raw)` arm in
// ValidateTunnelEndpoint, makes the padded cases below commit clean
// again -> RED.

func tunnelPaddedSets15196(prefix, src, dst string) []string {
	quoted := func(v string) string {
		// Quote only when padding is present so bare controls use the
		// ordinary unquoted spelling.
		if v != strings.TrimSpace(v) {
			return `"` + v + `"`
		}
		return v
	}
	return []string{
		"set interfaces gr-0/0/0 " + prefix + "tunnel source " + quoted(src),
		"set interfaces gr-0/0/0 " + prefix + "tunnel destination " + quoted(dst),
		"set interfaces gr-0/0/0 " + prefix + "tunnel mode gre",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.1.0.1/30",
	}
}

func TestTunnelPaddedEndpointSchemaGate_15196(t *testing.T) {
	// Both positions share tunnelSchemaChildren(): interface-level and
	// unit-level tunnel stanzas.
	prefixes := []string{"", "unit 0 "}
	padded := []struct{ name, src, dst string }{
		{"padded src both", " 192.0.2.1 ", "192.0.2.2"},
		{"padded dst both", "192.0.2.1", " 192.0.2.2 "},
		{"padded src leading", " 192.0.2.1", "192.0.2.2"},
		{"padded dst trailing", "192.0.2.1", "192.0.2.2 "},
		{"tab padded src", "\t192.0.2.1\t", "192.0.2.2"},
		{"padded v6 src", " 2001:db8::1 ", "2001:db8::2"},
		{"padded v6 dst", "2001:db8::1", " 2001:db8::2 "},
	}
	for _, pfx := range prefixes {
		for _, tc := range padded {
			sets := tunnelPaddedSets15196(pfx, tc.src, tc.dst)
			tree := flatTreeFromSets(t, sets...)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Errorf("prefix %q %s (%v): expected SchemaValidate to reject padded endpoint, got nil", pfx, tc.name, sets)
			}
		}
	}
	// Direct validator cells.
	for _, v := range []string{" 192.0.2.1 ", " 192.0.2.1", "192.0.2.1 ", "\t192.0.2.1\t", " 2001:db8::1 "} {
		if err := ValidateTunnelEndpoint(v, nil); err == nil {
			t.Errorf("ValidateTunnelEndpoint(%q) = nil, want padded rejection", v)
		}
	}
	// Controls: bare v4 and v6 endpoints still validate/commit.
	for _, tc := range []struct{ src, dst string }{
		{"192.0.2.1", "192.0.2.2"},
		{"2001:db8::1", "2001:db8::2"},
	} {
		for _, v := range []string{tc.src, tc.dst} {
			if err := ValidateTunnelEndpoint(v, nil); err != nil {
				t.Errorf("control ValidateTunnelEndpoint(%q) = %v, want nil", v, err)
			}
		}
		for _, pfx := range prefixes {
			sets := tunnelPaddedSets15196(pfx, tc.src, tc.dst)
			tree := flatTreeFromSets(t, sets...)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Errorf("control prefix %q %v: expected accept, got %v", pfx, sets, err)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Errorf("control prefix %q %v: expected CompileConfig accept, got %v", pfx, sets, err)
			}
		}
	}
	// Non-IP garbage and prefix forms still rejected by the wrapped validator.
	for _, v := range []string{"not.an.ip", "192.0.2.1/24", ""} {
		if err := ValidateTunnelEndpoint(v, nil); err == nil {
			t.Errorf("ValidateTunnelEndpoint(%q) = nil, want error", v)
		}
	}
	// Error names the padded value so the operator sees what to fix.
	tree := flatTreeFromSets(t, tunnelPaddedSets15196("", " 192.0.2.1 ", "192.0.2.2")...)
	err := SchemaValidate(tree, nil)
	if err == nil || !strings.Contains(err.Error(), " 192.0.2.1 ") {
		t.Errorf("padded tunnel source error must name the value, got %v", err)
	}
	// The generic ValidateIPAddress keeps its prior trimmed leniency for
	// its many non-tunnel leaves: this fix is scoped to the tunnel leaves.
	if err := ValidateIPAddress(" 192.0.2.1 ", nil); err != nil {
		t.Errorf("ValidateIPAddress padded = %v, want nil (scoped fix; other leaves unchanged)", err)
	}
}

// Hierarchical (braced) spelling must be gated identically: a quoted padded
// endpoint inside `interfaces { gr-0/0/0 { tunnel { source " ... "; } } }`.
func TestTunnelPaddedEndpointHierarchical_15196(t *testing.T) {
	bad := "interfaces { gr-0/0/0 { tunnel { source \" 192.0.2.1 \"; destination 192.0.2.2; mode gre; } unit 0 { family { inet { address 10.1.0.1/30; } } } } }"
	tree := hierTree(t, bad)
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("hierarchical padded tunnel source: expected SchemaValidate rejection, got nil")
	}
	good := "interfaces { gr-0/0/0 { tunnel { source 192.0.2.1; destination 192.0.2.2; mode gre; } unit 0 { family { inet { address 10.1.0.1/30; } } } } }"
	tree = hierTree(t, good)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("hierarchical bare tunnel control: expected accept, got %v", err)
	}
}
