package config

import (
	"strings"
	"testing"
)

// findPool returns the named pool in the named group of the v4 local server.
func findPoolV4(t *testing.T, cfg *Config, group, pool string) *DHCPPool {
	t.Helper()
	ls := cfg.System.DHCPServer.DHCPLocalServer
	if ls == nil {
		t.Fatal("DHCPLocalServer is nil")
	}
	g := ls.Groups[group]
	if g == nil {
		t.Fatalf("group %q missing", group)
	}
	for _, p := range g.Pools {
		if p.Name == pool {
			return p
		}
	}
	t.Fatalf("pool %q missing in group %q", pool, group)
	return nil
}

// TestDHCPStaticBindingHierarchical proves the hierarchical AST shape
// (`static-binding <mac> { fixed-address ...; host-name ...; }`) compiles
// into a DHCPStaticBinding on the right pool. #2243.
func TestDHCPStaticBindingHierarchical(t *testing.T) {
	input := `system {
    services {
        dhcp-local-server {
            group lan {
                interface ge-0-0-0;
                pool office {
                    subnet 10.0.1.0/24;
                    address-range low 10.0.1.100 high 10.0.1.200;
                    static-binding 00:11:22:33:44:55 {
                        fixed-address 10.0.1.50;
                        host-name printer;
                    }
                    static-binding aa:bb:cc:dd:ee:ff {
                        fixed-address 10.0.1.51;
                    }
                }
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pool := findPoolV4(t, cfg, "lan", "office")
	if len(pool.StaticBindings) != 2 {
		t.Fatalf("want 2 static bindings, got %d (%+v)", len(pool.StaticBindings), pool.StaticBindings)
	}
	sb := pool.StaticBindings[0]
	if sb.MACAddress != "00:11:22:33:44:55" || sb.FixedAddress != "10.0.1.50" || sb.HostName != "printer" {
		t.Errorf("binding 0: got %+v", sb)
	}
	sb2 := pool.StaticBindings[1]
	if sb2.MACAddress != "aa:bb:cc:dd:ee:ff" || sb2.FixedAddress != "10.0.1.51" || sb2.HostName != "" {
		t.Errorf("binding 1: got %+v", sb2)
	}
}

// TestDHCPStaticBindingFlatSet proves the flat-set AST shape compiles
// identically. Per CLAUDE.md this MUST use ParseSetCommand + SetPath, never
// NewParser. #2243.
func TestDHCPStaticBindingFlatSet(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set system services dhcp-local-server group lan interface ge-0-0-0",
		"set system services dhcp-local-server group lan pool office subnet 10.0.1.0/24",
		"set system services dhcp-local-server group lan pool office address-range low 10.0.1.100 high 10.0.1.200",
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 fixed-address 10.0.1.50",
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 host-name printer",
		"set system services dhcp-local-server group lan pool office static-binding aa:bb:cc:dd:ee:ff fixed-address 10.0.1.51",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pool := findPoolV4(t, cfg, "lan", "office")
	if len(pool.StaticBindings) != 2 {
		t.Fatalf("flat-set: want 2 static bindings, got %d (%+v)", len(pool.StaticBindings), pool.StaticBindings)
	}
	// Index order of bindings is parse order; find by MAC to be robust.
	var printer, nas *DHCPStaticBinding
	for _, sb := range pool.StaticBindings {
		switch sb.MACAddress {
		case "00:11:22:33:44:55":
			printer = sb
		case "aa:bb:cc:dd:ee:ff":
			nas = sb
		}
	}
	if printer == nil || printer.FixedAddress != "10.0.1.50" || printer.HostName != "printer" {
		t.Errorf("flat-set printer binding: got %+v", printer)
	}
	if nas == nil || nas.FixedAddress != "10.0.1.51" {
		t.Errorf("flat-set second binding: got %+v", nas)
	}
}

// TestDHCPStaticBindingV6 proves a v6 static-binding under
// dhcpv6-local-server compiles. #2243.
func TestDHCPStaticBindingV6(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set system services dhcpv6-local-server group lan6 interface ge-0-0-0",
		"set system services dhcpv6-local-server group lan6 pool p6 subnet 2001:db8::/64",
		"set system services dhcpv6-local-server group lan6 pool p6 static-binding 00:11:22:33:44:66 fixed-address 2001:db8::50",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ls := cfg.System.DHCPServer.DHCPv6LocalServer
	if ls == nil || ls.Groups["lan6"] == nil {
		t.Fatal("DHCPv6LocalServer group lan6 missing")
	}
	pool := ls.Groups["lan6"].Pools[0]
	if len(pool.StaticBindings) != 1 || pool.StaticBindings[0].FixedAddress != "2001:db8::50" {
		t.Fatalf("v6 static binding: got %+v", pool.StaticBindings)
	}
}

// buildV4StaticBindingTree returns a candidate tree with one v4 pool and the
// supplied static-binding set lines appended (each "mac ip" pair). Used by
// the strict-validation rejection tests.
func buildV4StaticBindingTree(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	base := []string{
		"set system services dhcp-local-server group lan interface ge-0-0-0",
		"set system services dhcp-local-server group lan pool office subnet 10.0.1.0/24",
		"set system services dhcp-local-server group lan pool office address-range low 10.0.1.100 high 10.0.1.200",
	}
	for _, cmd := range append(base, lines...) {
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

// TestDHCPStaticBindingRejectsOutOfSubnet proves a fixed-address outside the
// pool subnet is rejected at commit (Kea would silently drop it). #2243.
func TestDHCPStaticBindingRejectsOutOfSubnet(t *testing.T) {
	tree := buildV4StaticBindingTree(t,
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 fixed-address 10.0.2.50",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "outside the pool subnet") {
		t.Fatalf("want out-of-subnet rejection, got %v", err)
	}
}

// TestDHCPStaticBindingRejectsDuplicateMAC proves two bindings with the same
// MAC in one pool are rejected. A flat-set repeat of the same MAC merges into
// a single container node (last-write-wins), so a genuine duplicate-identity
// only arises from the hierarchical AST shape (two `static-binding <samemac>`
// blocks) — exercise that. #2243.
func TestDHCPStaticBindingRejectsDuplicateMAC(t *testing.T) {
	input := `system {
    services {
        dhcp-local-server {
            group lan {
                interface ge-0-0-0;
                pool office {
                    subnet 10.0.1.0/24;
                    static-binding 00:11:22:33:44:55 {
                        fixed-address 10.0.1.50;
                    }
                    static-binding 00:11:22:33:44:55 {
                        fixed-address 10.0.1.51;
                    }
                }
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "duplicates the hardware-address") {
		t.Fatalf("want duplicate-MAC rejection, got %v", err)
	}
}

// TestDHCPStaticBindingRejectsDuplicateAddress proves two distinct MACs
// reserving the same fixed-address in one pool are rejected. #2243.
func TestDHCPStaticBindingRejectsDuplicateAddress(t *testing.T) {
	tree := buildV4StaticBindingTree(t,
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 fixed-address 10.0.1.50",
		"set system services dhcp-local-server group lan pool office static-binding aa:bb:cc:dd:ee:ff fixed-address 10.0.1.50",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "already reserved for") {
		t.Fatalf("want duplicate-address rejection, got %v", err)
	}
}

// TestDHCPStaticBindingRejectsFamilyMismatch proves a v6 literal under
// dhcp-local-server (v4) is rejected. #2243.
func TestDHCPStaticBindingRejectsFamilyMismatch(t *testing.T) {
	tree := buildV4StaticBindingTree(t,
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 fixed-address 2001:db8::50",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "not an IPv4 address") {
		t.Fatalf("want family-mismatch rejection, got %v", err)
	}
}

// TestDHCPStaticBindingRejectsMissingFixedAddress proves a static-binding
// with no fixed-address is rejected (no reservation can be emitted). #2243.
func TestDHCPStaticBindingRejectsMissingFixedAddress(t *testing.T) {
	tree := buildV4StaticBindingTree(t,
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 host-name printer",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "no fixed-address") {
		t.Fatalf("want missing-fixed-address rejection, got %v", err)
	}
}

// TestDHCPStaticBindingSchemaRejectsBadMAC proves the schema typed-leaf gate
// rejects a malformed MAC at commit-check (SchemaValidate). #2243.
func TestDHCPStaticBindingSchemaRejectsBadMAC(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set system services dhcp-local-server group lan pool office subnet 10.0.1.0/24",
		"set system services dhcp-local-server group lan pool office static-binding not-a-mac fixed-address 10.0.1.50",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	_, _ = CompileConfig(tree)
	err := SchemaValidate(tree)
	if err == nil || !strings.Contains(err.Error(), "static-binding") {
		t.Fatalf("want schema MAC rejection, got %v", err)
	}
}

// TestDHCPStaticBindingSchemaRejectsBadFixedAddress proves the schema gate
// rejects a malformed fixed-address value. #2243.
func TestDHCPStaticBindingSchemaRejectsBadFixedAddress(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set system services dhcp-local-server group lan pool office subnet 10.0.1.0/24",
		"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 fixed-address not-an-ip",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	_, _ = CompileConfig(tree)
	err := SchemaValidate(tree)
	if err == nil || !strings.Contains(err.Error(), "fixed-address") {
		t.Fatalf("want schema fixed-address rejection, got %v", err)
	}
}

// TestDHCPNoStaticBindingNoError is the no-regression guard: a DHCP-server
// config with no static-bindings still compiles cleanly and yields no
// bindings (existing TestDHCPServerConfig path is unaffected). #2243.
func TestDHCPNoStaticBindingNoError(t *testing.T) {
	tree := buildV4StaticBindingTree(t) // base only, no bindings
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error on no-binding config: %v", err)
	}
	pool := findPoolV4(t, cfg, "lan", "office")
	if len(pool.StaticBindings) != 0 {
		t.Errorf("want no static bindings, got %+v", pool.StaticBindings)
	}
}

// TestDHCPStaticBindingLenientGate is the FAIL-ON-REVERT proof for the
// #1960 no-brick consistency fix (#2243 review): a bad static-binding (here
// out-of-subnet) MUST hard-reject on the strict commit path (CompileConfig)
// but only DOWNGRADE to a cfg.Warnings entry on the tolerant load / peer-sync
// paths (CompileConfigLenient / CompileConfigForNodeLenient) — mirroring every
// sibling fail-open validator. Pre-fix the validator lived in the always-strict
// strictErrs accumulator with no lenient gate, so the tolerant paths
// hard-rejected an already-persisted bad binding and BRICKED boot; this test
// fails on revert (CompileConfigLenient would return a non-nil error).
func TestDHCPStaticBindingLenientGate(t *testing.T) {
	makeBadTree := func() *ConfigTree {
		return buildV4StaticBindingTree(t,
			"set system services dhcp-local-server group lan pool office static-binding 00:11:22:33:44:55 fixed-address 10.0.2.50",
		)
	}

	// Strict commit path: hard-reject.
	if _, err := CompileConfig(makeBadTree()); err == nil ||
		!strings.Contains(err.Error(), "outside the pool subnet") {
		t.Fatalf("CompileConfig: want out-of-subnet hard rejection, got %v", err)
	}

	// Tolerant load path: warn, no error, no brick.
	cfg, err := CompileConfigLenient(makeBadTree())
	if err != nil {
		t.Fatalf("CompileConfigLenient: want no error (downgrade to warning), got %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "DHCP static binding (downgraded to warning on tolerant path)") {
		t.Fatalf("CompileConfigLenient: want a DHCP-static-binding downgrade warning, got %+v", cfg.Warnings)
	}

	// Node-aware tolerant path (Store.SyncApply / peer-interface display):
	// same downgrade.
	cfgN, errN := CompileConfigForNodeLenient(makeBadTree(), 0)
	if errN != nil {
		t.Fatalf("CompileConfigForNodeLenient: want no error (downgrade to warning), got %v", errN)
	}
	if !hasWarningContaining(cfgN.Warnings, "DHCP static binding (downgraded to warning on tolerant path)") {
		t.Fatalf("CompileConfigForNodeLenient: want a DHCP-static-binding downgrade warning, got %+v", cfgN.Warnings)
	}
}
