package config

import (
	"strings"
	"testing"
)

// Tests for #5875: strict source-NAT validation ACCEPTED a scoped IPv6 literal
// (`fe80::1%eth0`) in a source-NAT pool address. The Junos lexer permits the
// `%`-qualified text and Go's netip.ParseAddr honors a zone identifier, so the
// address passed the #5627 pool-address grammar gate and the snapshot builder
// copied the raw string onto the wire. But the live Rust allocator
// (expand_pool_address, userspace-dp/src/nat/source.rs) parses each pool member
// as std::net::IpAddr, which has NO zone model — so the scoped form fails to
// parse, the whole pool is marked InvalidPool, and the rule silently stops
// translating after apply: a control-plane/dataplane disagreement.
//
// The fix (validateSourceNATPoolAddressScopeStrict, wired in runUniformGates and
// the #5876 peer-effective SNAT view) hard-rejects a `%zone`-scoped pool address
// at strict commit; the tolerant load / peer-sync path downgrades to a warning
// and the snapshot builder independently marks the pool unusable
// ("zone_scoped_pool_address"), installing nothing rather than shipping the
// unparseable string.
//
// FAIL-ON-REVERT: dropping the `validateSourceNATPoolAddressScopeStrict(cfg)`
// dispatch in compiler_uniformgates.go (or making the validator `return nil`)
// turns every reject case GREEN and so RED here.

// snat5875Tree builds a config with one source-NAT rule-set whose single rule
// references pool `p1` in pool-mode, prefixed by the caller's pool `set` lines.
// Mirrors snat5627Tree (ParseSetCommand + SetPath, never NewParser — the
// flat-set testing gotcha).
func snat5875Tree(t *testing.T, poolCmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := append([]string{}, poolCmds...)
	cmds = append([]string{"set security zones security-zone trust", "set security zones security-zone untrust"}, cmds...)
	cmds = append(cmds,
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool p1",
	)
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestSourceNATPoolZoneScopedAddressRejected: every `%zone`-scoped pool address
// shape the Rust IpAddr parse cannot represent must be REJECTED at strict
// commit, naming the offending pool AND the address. The reject assertions FAIL
// against the unpatched validator (the fail-on-revert proof).
func TestSourceNATPoolZoneScopedAddressRejected(t *testing.T) {
	cases := []struct {
		name string
		pool []string
		addr string // the offending literal the diagnostic must name
	}{
		{
			name: "link-local-named-scope",
			pool: []string{"set security nat source pool p1 address fe80::1%eth0"},
			addr: "fe80::1%eth0",
		},
		{
			name: "link-local-numeric-scope",
			pool: []string{"set security nat source pool p1 address fe80::1%2"},
			addr: "fe80::1%2",
		},
		{
			name: "global-scope",
			pool: []string{"set security nat source pool p1 address 2001:db8::1%eth0"},
			addr: "2001:db8::1%eth0",
		},
		{
			name: "scoped-cidr",
			pool: []string{"set security nat source pool p1 address fe80::1%eth0/64"},
			addr: "fe80::1%eth0/64",
		},
		{
			name: "mixed-valid-scoped",
			pool: []string{
				"set security nat source pool p1 address 203.0.113.5/32",
				"set security nat source pool p1 address fe80::1%eth0",
			},
			addr: "fe80::1%eth0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(snat5875Tree(t, tc.pool...))
			if err == nil {
				t.Fatalf("expected strict commit to reject zone-scoped pool address %q", tc.addr)
			}
			msg := err.Error()
			// Must name the offending pool + address and describe the cause.
			if !strings.Contains(msg, "p1") {
				t.Fatalf("error %q does not name the offending pool", msg)
			}
			if !strings.Contains(msg, tc.addr) {
				t.Fatalf("error %q does not name the offending address %q", msg, tc.addr)
			}
			if !strings.Contains(msg, "zone/scope") {
				t.Fatalf("error %q does not explain the zone/scope cause", msg)
			}
		})
	}
}

// TestSourceNATPoolZoneScopedAddressLenientWarns: the tolerant load / peer-sync
// path (#1960 no-brick) must NOT fail-closed on a scoped pool address — it
// records a warning and boots (the snapshot builder independently marks the
// pool unusable). RED-on-revert: with the gate removed, no warning is recorded.
func TestSourceNATPoolZoneScopedAddressLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(snat5875Tree(t,
		"set security nat source pool p1 address fe80::1%eth0"))
	if err != nil {
		t.Fatalf("lenient compile must not brick on a scoped pool address: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "source-nat pool zone-scoped address") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a source-nat pool zone-scoped address warning; warnings = %v", cfg.Warnings)
	}
	// The pool address is preserved (not stripped) so the snapshot builder can
	// independently mark it unusable — the issue forbids silently stripping the
	// %zone. Assert the raw literal survived compilation.
	p := cfg.Security.NAT.SourcePools["p1"]
	if p == nil {
		t.Fatalf("pool p1 dropped on lenient compile")
	}
	if !strings.Contains(strings.Join(p.Addresses, ","), "fe80::1%eth0") {
		t.Fatalf("lenient compile must preserve the raw scoped literal (no silent strip); got %v", p.Addresses)
	}
}

// TestSourceNATPoolUnscopedAddressCompiles: an UNSCOPED pool address — bare v4,
// a global v6, an unscoped link-local, and a host CIDR — must still compile
// clean on the strict path. Regression guard against a false-reject (the fix
// targets ONLY the `%zone` suffix, not any legitimate v6 literal).
func TestSourceNATPoolUnscopedAddressCompiles(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"bare-v4", []string{"set security nat source pool p1 address 203.0.113.10"}},
		{"global-v6", []string{"set security nat source pool p1 address 2001:db8::1/128"}},
		{"link-local-no-scope", []string{"set security nat source pool p1 address fe80::1"}},
		{"host-cidr", []string{"set security nat source pool p1 address 203.0.113.10/32"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(snat5875Tree(t, tc.pool...)); err != nil {
				t.Fatalf("unscoped pool address %q must compile clean on the strict path: %v", tc.name, err)
			}
		})
	}
}

// TestSourceNATPoolUnreferencedScopedNotRejected pins the scoping decision (same
// as the #5627 grammar gate): the live dataplane only expands pools a pool-mode
// rule references, so a defined-but-UNREFERENCED scoped pool never reaches the
// Rust grammar and must NOT be rejected here — the gate stays grammar-equivalent
// with live rather than Go-stricter.
func TestSourceNATPoolUnreferencedScopedNotRejected(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security nat source pool orphan address fe80::1%eth0",
		"set security nat source pool orphan port range 5000 to 6000",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("an unreferenced pool with a scoped address must not be rejected (grammar-equivalence with live, which never expands it): %v", err)
	}
}

// TestPeerOnlyZoneScopedSNATPoolRejected_5875 proves the scope validator
// composes with the #5876 peer-effective SNAT gate: a `%zone`-scoped pool
// address that appears ONLY on the peer node's `${node}` effective view (node0's
// own view is clean) must be rejected at the origin (node0) commit via
// ValidatePeerEffectiveStrict — otherwise the standby lenient-loads the
// config-synced snapshot and its dataplane fails the pool closed while node0
// committed green. FAIL-ON-REVERT: dropping the scope validator from
// validateSourceNATStrictView leaves node0 accepting the peer-only scoped
// address.
func TestPeerOnlyZoneScopedSNATPoolRejected_5875(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set groups node0 security nat source pool P address 203.0.113.5/32",
		"set groups node1 security nat source pool P address fe80::1%eth0",
		`set apply-groups "${node}"`,
	})
	// node0's own effective view is clean (unscoped address) — the green commit.
	if _, err := CompileConfigForNode(tree, 0); err != nil {
		t.Fatalf("node0 local compile must be clean: %v", err)
	}
	// The peer-effective gate run at a node0 commit must reject the node1-only
	// scoped address.
	err := ValidatePeerEffectiveStrict(tree, 0)
	if err == nil {
		t.Fatal("node0 commit ACCEPTED a peer-only zone-scoped source-NAT pool address (node1 view) — peer-effective fail-open")
	}
	for _, want := range []string{"node1", "P", "fe80::1%eth0", "zone/scope"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("peer-effective scope reject missing %q: %v", want, err)
		}
	}
}

// TestPoolAddressHasZoneScope is a focused unit test of the shared detector so
// the Go strict validator and the userspace snapshot builder agree on what a
// zone-scoped literal is.
func TestPoolAddressHasZoneScope(t *testing.T) {
	scoped := []string{"fe80::1%eth0", "fe80::1%2", "2001:db8::1%eth0", "fe80::1%eth0/64"}
	for _, a := range scoped {
		if !PoolAddressHasZoneScope(a) {
			t.Errorf("PoolAddressHasZoneScope(%q) = false, want true", a)
		}
	}
	unscoped := []string{"fe80::1", "2001:db8::1", "203.0.113.10", "203.0.113.0/24", "2001:db8::/112"}
	for _, a := range unscoped {
		if PoolAddressHasZoneScope(a) {
			t.Errorf("PoolAddressHasZoneScope(%q) = true, want false", a)
		}
	}
}
