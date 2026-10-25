package config

import (
	"strings"
	"testing"
)

// #16865: Junos IS-IS NET lives on lo0 `family iso address`; xpf only
// read `protocols isis net`, so Junos configs rendered a NET-less
// `router isis xpf` with interface enrolment — no adjacency, no LSP.

const isisNET16865 = "49.0001.0100.0000.0001.00"

func TestISISNETDerivedFromLo0ISO16865(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"flat lo0", []string{
			"set interfaces lo0 unit 0 family iso address " + isisNET16865,
			"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
			"set protocols isis interface ge-0/0/1.0",
		}},
		{"flat non-lo0 fallback", []string{
			"set interfaces ge-0/0/1 unit 0 family iso address " + isisNET16865,
			"set protocols isis interface ge-0/0/1.0",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			if cfg.Protocols.ISIS == nil || cfg.Protocols.ISIS.NET != isisNET16865 {
				t.Fatalf("derived NET = %+v, want %s", cfg.Protocols.ISIS, isisNET16865)
			}
		})
	}
	// Hierarchical spelling.
	tree, errs := NewParser(`interfaces { lo0 { unit 0 { family iso { address ` + isisNET16865 + `; } } } }
protocols { isis { interface ge-0/0/1.0; } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hier strict compile: %v", err)
	}
	if cfg.Protocols.ISIS.NET != isisNET16865 {
		t.Fatalf("hier derived NET = %q, want %s", cfg.Protocols.ISIS.NET, isisNET16865)
	}
	// Packed one-line hierarchical spelling.
	tree2, errs2 := NewParser(`interfaces { lo0 { unit 0 { family iso address ` + isisNET16865 + `; } } }
protocols { isis { interface ge-0/0/1.0; } }`).Parse()
	if len(errs2) > 0 {
		t.Fatalf("parse2: %v", errs2)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("packed hier strict compile: %v", err)
	}
	if cfg2.Protocols.ISIS.NET != isisNET16865 {
		t.Fatalf("packed hier derived NET = %q, want %s", cfg2.Protocols.ISIS.NET, isisNET16865)
	}
}

func TestISISNETMissingRejected16865(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set protocols isis interface ge-0/0/1.0",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted IS-IS with interfaces but no NET (#16865)")
	} else if !strings.Contains(err.Error(), "no NET") || !strings.Contains(err.Error(), "family iso address") {
		t.Fatalf("error should name the missing NET and the Junos remedy, got: %v", err)
	}
	// Tolerant path warns and keeps the typed config (renderer withholds).
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16865") && strings.Contains(w, "no NET") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient warnings missing #16865 NET warning: %v", cfg.Warnings)
	}
	if !lenientCompileOpts().lenientISISNETPresence16865 {
		t.Fatal("lenientISISNETPresence16865 not registered in lenientCompileOpts (#1960)")
	}
}

func TestISISNETExplicitWinsAndControls16865(t *testing.T) {
	// Explicit NET alone (control i1c shape) still commits.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set protocols isis net " + isisNET16865,
		"set protocols isis interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("explicit NET control rejected: %v", err)
	}
	if cfg.Protocols.ISIS.NET != isisNET16865 {
		t.Fatalf("explicit NET = %q", cfg.Protocols.ISIS.NET)
	}
	// Explicit NET agreeing with lo0 ISO commits.
	cfg, err = CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address " + isisNET16865,
		"set protocols isis net " + isisNET16865,
		"set protocols isis interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("agreeing explicit+ISO rejected: %v", err)
	}
	// No interfaces: NET-less IS-IS is inert, not rejected.
	if _, err := CompileConfig(buildTree(t, []string{
		"set protocols isis export static",
	})); err != nil {
		t.Fatalf("interface-less IS-IS wrongly rejected: %v", err)
	}
	// Disabled protocol needs no NET.
	if _, err := CompileConfig(buildTree(t, []string{
		"set protocols isis disable",
		"set protocols isis interface ge-0/0/1.0",
	})); err != nil {
		t.Fatalf("disabled IS-IS wrongly rejected: %v", err)
	}
	// All interfaces disabled needs no NET.
	if _, err := CompileConfig(buildTree(t, []string{
		"set protocols isis interface ge-0/0/1.0 disable",
	})); err != nil {
		t.Fatalf("all-disabled-interface IS-IS wrongly rejected: %v", err)
	}
}

func TestISISNETConflictsRejected16865(t *testing.T) {
	// Explicit vs ISO conflict.
	if _, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address 49.0001.0100.0000.0002.00",
		"set protocols isis net " + isisNET16865,
		"set protocols isis interface ge-0/0/1.0",
	})); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("explicit/ISO conflict: got %v", err)
	}
	// Two distinct ISO NETs, no explicit arbitrator. Hierarchical
	// spelling carries both (flat-set repeated leaves merge last-wins
	// in the tree, as for other single-value address leaves).
	{
		tree, errs := NewParser(`interfaces { lo0 { unit 0 { family iso { address ` + isisNET16865 + `; address 49.0001.0100.0000.0002.00; } } } }
protocols { isis { interface ge-0/0/1.0; } }`).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse multi: %v", errs)
		}
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "exactly one NET") {
			t.Fatalf("multiple ISO NETs: got %v", err)
		}
	}
	// Duplicate identical ISO NET is not a conflict.
	if _, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address " + isisNET16865,
		"set interfaces ge-0/0/1 unit 0 family iso address " + isisNET16865,
		"set protocols isis interface ge-0/0/1.0",
	})); err != nil {
		t.Fatalf("identical duplicate ISO NET wrongly rejected: %v", err)
	}
	// Malformed ISO NET with interfaces rejects naming the value.
	if _, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address 49.0001",
		"set protocols isis interface ge-0/0/1.0",
	})); err == nil {
		t.Fatal("malformed ISO NET accepted at strict commit (#16865)")
	}
	// Routing-instance IS-IS derives from an ISO NET on its OWN member.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family iso address " + isisNET16865,
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/1.0",
		"set routing-instances tenant protocols isis interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("RI IS-IS with own-member ISO rejected: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].ISIS == nil ||
		cfg.RoutingInstances[0].ISIS.NET != isisNET16865 {
		t.Fatalf("RI derived NET = %+v", cfg.RoutingInstances)
	}
	// Routing-instance IS-IS without any NET rejects.
	if _, err := CompileConfig(buildTree(t, []string{
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant protocols isis interface ge-0/0/1.0",
	})); err == nil {
		t.Fatal("RI IS-IS without NET accepted (#16865)")
	}
}

// F2: distinct per-scope NETs must not cross-derive or conflict; a
// default scope must not borrow an RI-owned NET.
func TestISISNETRoutingInstanceScoped16865(t *testing.T) {
	const netB = "49.0001.0100.0000.0002.00"
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address " + isisNET16865,
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set interfaces ge-0/0/2 unit 0 family iso address " + netB,
		"set protocols isis interface ge-0/0/1.0",
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/2.0",
		"set routing-instances tenant protocols isis interface ge-0/0/2.0",
	}))
	if err != nil {
		t.Fatalf("distinct per-scope NETs rejected: %v", err)
	}
	if cfg.Protocols.ISIS.NET != isisNET16865 {
		t.Fatalf("default NET = %q, want %s", cfg.Protocols.ISIS.NET, isisNET16865)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].ISIS.NET != netB {
		t.Fatalf("tenant NET = %+v, want %s", cfg.RoutingInstances, netB)
	}
	// Default scope cannot borrow the tenant-owned NET.
	if _, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/2 unit 0 family iso address " + netB,
		"set protocols isis interface ge-0/0/1.0",
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/2.0",
		"set routing-instances tenant protocols isis interface ge-0/0/2.0",
	})); err == nil {
		t.Fatal("default IS-IS borrowed an RI-owned NET (#16865 F2)")
	}
	// RI scope cannot borrow the default lo0 NET (no member ISO).
	if _, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address " + isisNET16865,
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/2.0",
		"set routing-instances tenant protocols isis interface ge-0/0/2.0",
	})); err == nil {
		t.Fatal("RI IS-IS borrowed the default lo0 NET without ownership (#16865 F2)")
	}
}

// F4: case / dot-grouping equivalents are one identity.
func TestISISNETCanonicalEquivalence16865(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address 49.0001.ABCD.0000.0001.00",
		"set protocols isis net 49.0001.abcd.0000.0001.00",
		"set protocols isis interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("case-equivalent NETs falsely conflicted: %v", err)
	}
	if cfg.Protocols.ISIS.NET != "49.0001.abcd.0000.0001.00" {
		t.Fatalf("explicit spelling not preserved: %q", cfg.Protocols.ISIS.NET)
	}
	// Grouping-equivalent duplicates (same bytes, different groups):
	// 49.0001.0100.0000.0001.00 == 4900.0101.0000.0000.0100.
	cfg2, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address 49.0001.0100.0000.0001.00",
		"set interfaces ge-0/0/1 unit 0 family iso address 4900.0101.0000.0000.0100",
		"set protocols isis interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("grouping-equivalent NETs falsely conflicted: %v", err)
	}
	if cfg2.Protocols.ISIS.NET != "49.0001.0100.0000.0001.00" {
		t.Fatalf("derived NET = %q, want first-authored spelling", cfg2.Protocols.ISIS.NET)
	}
}

// R1: RI membership spelled with a canonical-unit alias (`...2.00`)
// still owns the interface: tenant derives its NET, default cannot
// borrow it (strict rejects the NET-less default; tolerant withholds).
func TestISISNETRoutingInstanceAliasMember16865(t *testing.T) {
	const netB = "49.0001.0100.0000.0002.00"
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces lo0 unit 0 family iso address " + isisNET16865,
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set interfaces ge-0/0/2 unit 0 family iso address " + netB,
		"set protocols isis interface ge-0/0/1.0",
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/2.00",
		"set routing-instances tenant protocols isis interface ge-0/0/2.0",
	}))
	if err != nil {
		t.Fatalf("alias-member two-scope config rejected: %v", err)
	}
	if cfg.Protocols.ISIS.NET != isisNET16865 {
		t.Fatalf("default NET = %q, want %s", cfg.Protocols.ISIS.NET, isisNET16865)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].ISIS.NET != netB {
		t.Fatalf("tenant NET via .00 member = %+v, want %s", cfg.RoutingInstances, netB)
	}
	// Negative: default cannot borrow the alias-owned tenant NET.
	aliasLines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set interfaces ge-0/0/2 unit 0 family iso address " + netB,
		"set protocols isis interface ge-0/0/1.0",
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/2.00",
		"set routing-instances tenant protocols isis interface ge-0/0/2.0",
	}
	if _, err := CompileConfig(buildTree(t, aliasLines)); err == nil {
		t.Fatal("default IS-IS borrowed tenant NET via .00 alias member (#16865 R1)")
	}
	// Tolerant: tenant still derives B; default scope warns.
	cfg, err = CompileConfigLenient(buildTree(t, aliasLines))
	if err != nil {
		t.Fatalf("tolerant alias config: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].ISIS.NET != netB {
		t.Fatalf("tolerant tenant NET = %+v, want %s", cfg.RoutingInstances, netB)
	}
	if cfg.Protocols.ISIS.NET != "" {
		t.Fatalf("tolerant default NET = %q, want empty (no borrowing)", cfg.Protocols.ISIS.NET)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16865") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant warnings missing #16865: %v", cfg.Warnings)
	}
}

// R1 round 3: slash/dash Linux-name aliases. RI membership spelled
// `ge-0-0-2.0` (or bare `ge-0-0-2`) resolves to declared `ge-0/0/2`
// for actual membership; NET ownership must agree.
func TestISISNETRoutingInstanceDashAlias16865(t *testing.T) {
	const netB = "49.0001.0100.0000.0002.00"
	for _, member := range []string{"ge-0-0-2.0", "ge-0-0-2"} {
		t.Run("own-scope "+member, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{
				"set interfaces lo0 unit 0 family iso address " + isisNET16865,
				"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
				"set interfaces ge-0/0/2 unit 0 family iso address " + netB,
				"set protocols isis interface ge-0/0/1.0",
				"set routing-instances tenant instance-type virtual-router",
				"set routing-instances tenant interface " + member,
				"set routing-instances tenant protocols isis interface ge-0/0/2.0",
			}))
			if err != nil {
				t.Fatalf("dash-alias member %q rejected: %v", member, err)
			}
			if cfg.Protocols.ISIS.NET != isisNET16865 {
				t.Fatalf("default NET = %q, want %s", cfg.Protocols.ISIS.NET, isisNET16865)
			}
			if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].ISIS.NET != netB {
				t.Fatalf("tenant NET via %q = %+v, want %s", member, cfg.RoutingInstances, netB)
			}
		})
		t.Run("no-borrow "+member, func(t *testing.T) {
			lines := []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
				"set interfaces ge-0/0/2 unit 0 family iso address " + netB,
				"set protocols isis interface ge-0/0/1.0",
				"set routing-instances tenant instance-type virtual-router",
				"set routing-instances tenant interface " + member,
				"set routing-instances tenant protocols isis interface ge-0/0/2.0",
			}
			if _, err := CompileConfig(buildTree(t, lines)); err == nil {
				t.Fatalf("default borrowed tenant NET via dash member %q (#16865 R1r3)", member)
			}
			cfg, err := CompileConfigLenient(buildTree(t, lines))
			if err != nil {
				t.Fatalf("tolerant dash member %q: %v", member, err)
			}
			if cfg.Protocols.ISIS.NET != "" {
				t.Fatalf("tolerant default NET = %q, want empty", cfg.Protocols.ISIS.NET)
			}
			if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].ISIS.NET != netB {
				t.Fatalf("tolerant tenant NET via %q = %+v, want %s", member, cfg.RoutingInstances, netB)
			}
		})
	}
}

// F1: a valueless `address;` must not panic on tolerant ingress.
func TestISISISOValuelessAddressTolerant16865(t *testing.T) {
	tree, errs := NewParser(`interfaces { lo0 { unit 0 { family iso { address; } } } }
protocols { isis { interface ge-0/0/1.0; } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	// Strict may reject (schema / NET gate); it must not panic.
	_, _ = CompileConfig(tree)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile with valueless iso address: %v", err)
	}
	if cfg == nil {
		t.Fatal("tolerant compile returned nil config")
	}
}
