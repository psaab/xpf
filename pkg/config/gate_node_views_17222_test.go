package config

import (
	"strings"
	"testing"
)

// #17222: the per-cluster-node gate prologue was hand-copied into twelve
// gate files and the #13146 literal-"${node}" fallback reached only
// two of them (vlan-map, vlan-tagging), so on a strict generic commit
// the QinQ (#5879), packed-login (#6662) and login-class-shadow
// (#6701) gates inspected no view at all while the compiler compiled
// the top-level tree. effectiveNodeViews is now the single source of
// truth; this table runs each migrated gate against the #13146
// literal-${node} fixture with a gate-specific offending statement and
// asserts strict reject, with the plain (no-group) control also
// rejected. The "## acceptance" grep in the log guards the prologue
// count itself.

const litNodePrefix17222 = `groups { "${node}" { system { host-name litnode; } } } apply-groups "${node}"; `

func TestGateNodeViewsLiteralNodeFallback17222(t *testing.T) {
	cases := []struct {
		name    string
		lit     string
		control string
		gate    func(*ConfigTree, bool) ([]string, error)
		marker  string
	}{
		{
			name:    "qinq",
			lit:     litNodePrefix17222 + `interfaces { ge-0/0/0 { vlan-tagging; unit 0 { vlan-id 100; inner-vlan-id 200; } } }`,
			control: `interfaces { ge-0/0/0 { unit 0 { vlan-id 100; inner-vlan-id 200; } } }`,
			gate:    validateQinQVLANStackAST,
			marker:  "inner-vlan-id",
		},
		{
			name:    "vlanmap",
			lit:     litNodePrefix17222 + `interfaces { ge-0/0/0 { unit 0 { vlan-id 100; input-vlan-map { push; } } } }`,
			control: `interfaces { ge-0/0/0 { unit 0 { vlan-id 100; input-vlan-map { push; } } } }`,
			gate:    validateVLANMapAST,
			marker:  "input-vlan-map",
		},
		{
			name:    "vlan-tagging",
			lit:     litNodePrefix17222 + `interfaces { ge-0/0/0 { unit 0 { vlan-id 100; } } }`,
			control: `interfaces { ge-0/0/0 { unit 0 { vlan-id 100; } } }`,
			gate:    validateVlanIDTaggingAST,
			marker:  "vlan-tagging",
		},
		{
			name:    "login-shadow",
			lit:     litNodePrefix17222 + `system { login { class super-user { permissions view; } user bob { class super-user; } } }`,
			control: `system { login { class super-user { permissions view; } user bob { class super-user; } } }`,
			gate:    validateLoginClassShadowsBuiltinAST,
			marker:  "SYSTEM-DEFINED",
		},
		{
			name:    "login-packed",
			lit:     litNodePrefix17222 + `system { login { class ops idle-timeout 30; } }`,
			control: `system { login { class ops idle-timeout 30; } }`,
			gate:    validateLoginPackedStatementsAST,
			marker:  "written on the instance line",
		},
		{
			// deny-lit from the issue: the packed second `class ops`
			// statement carries the deny-commands narrowing the packed
			// gate (#6662) must reject rather than silently drop.
			name:    "login-packed-deny",
			lit:     litNodePrefix17222 + `system { login { class ops { permissions all; } class ops deny-commands "request system zeroize"; } }`,
			control: `system { login { class ops { permissions all; } class ops deny-commands "request system zeroize"; } }`,
			gate:    validateLoginPackedStatementsAST,
			marker:  "written on the instance line",
		},
		{
			// #17222 fold: the offending unit arrives only as an
			// interface-range member. On the literal-${node} tree
			// neither per-node view exists, so the generic FALLBACK
			// view must itself apply expandInterfaceRanges — without
			// it the fallback view still carries the unexpanded
			// `interface-range R` stanza and the gate can only report
			// the phantom range name, never the member. The marker
			// therefore names the member interface: RED pre-fold
			// (error names `interface-range`), GREEN post-fold.
			name:    "qinq-range-fallback",
			lit:     litNodePrefix17222 + `interfaces { interface-range R { member ge-0/0/0; vlan-tagging; unit 0 { vlan-id 100; inner-vlan-id 200; } } }`,
			control: `interfaces { interface-range R { member ge-0/0/0; vlan-tagging; unit 0 { vlan-id 100; inner-vlan-id 200; } } }`,
			gate:    validateQinQVLANStackAST,
			marker:  "interfaces ge-0/0/0 unit 0",
		},
		{
			name:    "vlanmap-range-fallback",
			lit:     litNodePrefix17222 + `interfaces { interface-range R { member ge-0/0/0; unit 0 { vlan-id 100; input-vlan-map { push; } } } }`,
			control: `interfaces { interface-range R { member ge-0/0/0; unit 0 { vlan-id 100; input-vlan-map { push; } } } }`,
			gate:    validateVLANMapAST,
			marker:  "interfaces ge-0/0/0 unit 0",
		},
		{
			name:    "vlan-tagging-range-fallback",
			lit:     litNodePrefix17222 + `interfaces { interface-range R { member ge-0/0/0; unit 0 { vlan-id 100; } } }`,
			control: `interfaces { interface-range R { member ge-0/0/0; unit 0 { vlan-id 100; } } }`,
			gate:    validateVlanIDTaggingAST,
			marker:  "interfaces ge-0/0/0 unit 0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"-litnode", func(t *testing.T) {
			tree := hierTree(t, tc.lit)
			_, err := tc.gate(tree, false)
			if err == nil {
				t.Fatalf("literal-${node} fixture compiled with NO error — gate blind on the generic fallback tree (#17222)")
			}
			if !strings.Contains(err.Error(), tc.marker) {
				t.Fatalf("rejected by a DIFFERENT gate (want marker %q): %v", tc.marker, err)
			}
			// Strict generic compile must reject too (the standalone
			// store path that was fail-open).
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict CompileConfig accepted the literal-${node} fixture (#17222)")
			}
		})
		t.Run(tc.name+"-control", func(t *testing.T) {
			_, err := tc.gate(hierTree(t, tc.control), false)
			if err == nil {
				t.Fatalf("control fixture compiled with NO error — gate regression (#17222)")
			}
			if !strings.Contains(err.Error(), tc.marker) {
				t.Fatalf("control rejected by a DIFFERENT gate (want marker %q): %v", tc.marker, err)
			}
		})
	}
}

// TestGateNodeViewsViews17222 pins the helper contract directly: both
// node views when they expand, exactly one generic fallback view when
// neither does, and no fallback view when a node view expands.
func TestGateNodeViewsViews17222(t *testing.T) {
	normal := hierTree(t, `groups { node0 { system { host-name fw0; } } node1 { system { host-name fw1; } } } apply-groups "${node}"; system { host-name base; }`)
	if got := effectiveNodeViews(normal, gateNodeViewOpts{Fallback: true}); len(got) != 2 {
		t.Fatalf("normal ${node} tree: got %d views, want 2 (no fallback)", len(got))
	}
	lit := hierTree(t, `groups { "${node}" { system { host-name lit; } } } apply-groups "${node}"; system { host-name base; }`)
	if got := effectiveNodeViews(lit, gateNodeViewOpts{Fallback: true}); len(got) != 1 {
		t.Fatalf("literal-${node} tree with fallback: got %d views, want 1", len(got))
	}
	if got := effectiveNodeViews(lit, gateNodeViewOpts{}); len(got) != 0 {
		t.Fatalf("literal-${node} tree without fallback: got %d views, want 0", len(got))
	}
	// interfaceUnitsOf: packed tail and braced spelling both enumerate.
	packed := hierTree(t, `interfaces { ge-0/0/0 unit 0 { vlan-id 100; } }`)
	var n int
	for _, ifaces := range packed.FindChildren("interfaces") {
		for _, iface := range ifaces.Children {
			n += len(interfaceUnitsOf(iface))
		}
	}
	if n != 1 {
		t.Fatalf("packed interface tail: interfaceUnitsOf found %d units, want 1", n)
	}
}
