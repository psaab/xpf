package config

import (
	"strings"
	"testing"
)

// #16827: a unit-less NAT from/to interface ref on a plain physical
// interface (only unit 0) compiles to the logical-unit name the
// dataplane compares ("ge-0/0/1.0"); a bare ref naming no unit traffic
// reaches it on (no unit, only a non-zero VLAN unit, or an undeclared
// interface) stays inert and is strict-rejected / lenient-warned.
// RED pre-fix: the bare spelling was stored verbatim and the strict
// gate admitted it, so the rule-set never matched.

func bareNATBase16827() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security nat source pool pool1 address 192.0.2.10/32",
		"set security nat destination pool P1 address 10.0.30.100/32",
	}
}

func TestNATBareInterfaceCanonicalizes16827(t *testing.T) {
	// Source from+to bare refs fold to unit 0.
	cfg, err := CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-ok from interface ge-0/0/0",
		"set security nat source rule-set snat-ok to interface ge-0/0/1",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1")))
	if err != nil {
		t.Fatalf("strict must accept bare refs on plain interfaces: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("source rule-sets = %d, want 1", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromInterface != "ge-0/0/0.0" || rs.ToInterface != "ge-0/0/1.0" {
		t.Fatalf("bare scopes = from %q to %q, want ge-0/0/0.0 / ge-0/0/1.0", rs.FromInterface, rs.ToInterface)
	}
	// Destination bare ref.
	cfg, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat destination rule-set dnat-ok from interface ge-0/0/1",
		"set security nat destination rule-set dnat-ok rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-ok rule R1 then destination-nat pool P1")))
	if err != nil {
		t.Fatalf("strict must accept bare DNAT ref: %v", err)
	}
	if got := cfg.Security.NAT.Destination.RuleSets[0].FromInterface; got != "ge-0/0/1.0" {
		t.Fatalf("DNAT FromInterface = %q, want ge-0/0/1.0", got)
	}
	// Static bare ref.
	cfg, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat static rule-set stat-ok from interface ge-0/0/1",
		"set security nat static rule-set stat-ok rule R1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set stat-ok rule R1 then static-nat prefix 10.0.0.5/32")))
	if err != nil {
		t.Fatalf("strict must accept bare static ref: %v", err)
	}
	if got := cfg.Security.NAT.Static[0].FromInterface; got != "ge-0/0/1.0" {
		t.Fatalf("static FromInterface = %q, want ge-0/0/1.0", got)
	}
	// lo0 bare ref folds to lo0.0.
	cfg, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-lo from interface lo0",
		"set security nat source rule-set snat-lo rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-lo rule r1 then source-nat pool pool1")))
	if err != nil {
		t.Fatalf("strict must accept bare lo0 ref: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "lo0.0" {
		t.Fatalf("lo0 FromInterface = %q, want lo0.0", got)
	}
}

func TestNATBareInterfaceControl16827(t *testing.T) {
	// Unit spellings keep compiling to the same name (control cell).
	cfg, err := CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-ok from interface ge-0/0/0.0",
		"set security nat source rule-set snat-ok to interface ge-0/0/1.0",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1")))
	if err != nil {
		t.Fatalf("unit-spelled control must compile: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromInterface != "ge-0/0/0.0" || rs.ToInterface != "ge-0/0/1.0" {
		t.Fatalf("control scopes = from %q to %q", rs.FromInterface, rs.ToInterface)
	}
	// Undefined unit ref still strict-rejects (gate control).
	_, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-bad from interface ge-0/0/9",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")))
	if err == nil {
		t.Fatal("strict must reject bare ref to undeclared interface ge-0/0/9")
	}
	if !strings.Contains(err.Error(), "ge-0/0/9") {
		t.Fatalf("error must name the bare ref, got: %v", err)
	}
}

func TestNATBareInterfaceInertShapes16827(t *testing.T) {
	// No-unit stanza: strict rejects, lenient warns + records, and the
	// stored value stays bare (never widened to a fabricated unit).
	cmds := append(bareNATBase16827(),
		"set interfaces ge-0/0/5 family inet address 10.0.5.1/24",
		"set security nat source rule-set snat-bad from interface ge-0/0/5",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
		t.Fatal("strict must reject bare ref to a unit-less interface stanza")
	}
	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/5" {
		t.Fatalf("inert bare ref must stay bare, got %q", got)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snat-bad") && strings.Contains(w, "ge-0/0/5") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn naming snat-bad/ge-0/0/5, warnings=%v", cfg.Warnings)
	}
	if !cfg.LenientNATUndefinedScopeRuleSets["source\x00snat-bad"] {
		t.Fatalf("lenient must record snat-bad in undefined-scope set, got %v", cfg.LenientNATUndefinedScopeRuleSets)
	}

	// Non-zero-unit-only interface: a bare ref must not widen to unit 0.
	cmds = append(bareNATBase16827(),
		"set interfaces ge-0/0/6 unit 1 vlan-id 10 family inet address 10.0.6.1/24",
		"set security nat source rule-set snat-bad from interface ge-0/0/6",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
		t.Fatal("strict must reject bare ref to a non-zero-unit-only interface")
	}
	cfg, err = CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/6" {
		t.Fatalf("multi-unit bare ref must stay bare (no unit-0 widening), got %q", got)
	}

	// Unit-0-plus-VLAN-units interface: the bare ref names no single
	// unit, so it stays bare and strict-rejects rather than picking .0.
	cmds = append(bareNATBase16827(),
		"set interfaces ge-0/0/7 unit 0 family inet address 10.0.7.1/24",
		"set interfaces ge-0/0/7 unit 1 vlan-id 10 family inet address 10.0.7.2/24",
		"set security nat source rule-set snat-bad from interface ge-0/0/7",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
		t.Fatal("strict must reject bare ref to a multi-unit interface")
	}
	cfg, err = CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/7" {
		t.Fatalf("multi-unit bare ref must stay bare, got %q", got)
	}
}
