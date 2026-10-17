package config

import (
	"strings"
	"testing"
)

// #4313 PR-B — first PRODUCTION closed-world subtree flip.
//
// The destination-NAT rule then-action container
// (security nat destination rule-set <rs> rule <r> then) now sets
// schemaNode.closedWorld (schema_security.go). Its subtree is leaf-complete:
// the only valid Junos DNAT then-action is `destination-nat { off | pool
// <name> }`, all modeled, so closing it carries no false-reject risk. An
// unmodeled keyword (a typo, or garbage trailing a valid action) is now
// REJECTED at strict commit (SchemaValidate) instead of committing clean and
// being silently dropped by the compiler — the #4313 silent-inert bug.
//
// These tests use the production ParseSetCommand + SetPath + SchemaValidate
// path. Each rejection test is RED on revert of the closedWorld flag: without
// it, SchemaValidate returns nil (open-world silent-accept) and the test fails.

// dnatThenSet builds a minimal destination-NAT rule-set whose then-action is
// the supplied token stream (e.g. "pool dp", "off", "bogus", "poool dp").
func dnatThenSet(thenAction string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
		"set security nat destination rule-set rs1 rule r1 then destination-nat " + thenAction,
	}
}

// TestClosedWorldDNATThen_RejectsUnknownActionKeyword is the core RED-on-revert
// discriminator: an unmodeled keyword under the closed-world DNAT then subtree
// is rejected at strict commit. On revert of closedWorld the same input is
// silently accepted (SchemaValidate returns nil) and this test fails — proving
// the flip closes the #4313 silent-inert gap.
func TestClosedWorldDNATThen_RejectsUnknownActionKeyword(t *testing.T) {
	tree := buildTree(t, dnatThenSet("bogus"))
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("an unmodeled keyword under the closed-world destination-NAT then must be rejected at commit (RED on revert: silently accepted + dropped)")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the keyword and the closed-world subtree, got: %v", err)
	}
}

// TestClosedWorldDNATThen_RejectsTypo is the VALUE of the fix: a fat-fingered
// Junos action (`poool` for `pool`) is caught at commit rather than silently
// ignored — the operator learns the DNAT translation would never apply.
func TestClosedWorldDNATThen_RejectsTypo(t *testing.T) {
	tree := buildTree(t, dnatThenSet("poool dp"))
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("a typo'd DNAT then-action (poool) must be rejected at commit, not silently dropped")
	}
	if !strings.Contains(err.Error(), "poool") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the typo and the closed-world subtree, got: %v", err)
	}
}

// TestClosedWorldDNATThen_AcceptsValidActions proves no false-reject: every
// valid Junos DNAT then-action keyword still commits clean under closed-world.
func TestClosedWorldDNATThen_AcceptsValidActions(t *testing.T) {
	for _, action := range []string{"off", "pool dp"} {
		tree := buildTree(t, dnatThenSet(action))
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("valid destination-NAT then-action %q must commit clean under closed-world, got: %v", action, err)
		}
	}
}

// TestClosedWorldDNATThen_RejectsUnknownDirectlyUnderThen closes the top level
// too: an action keyword directly under `then` that is not `destination-nat`
// (the only valid one for a DNAT rule) is rejected.
func TestClosedWorldDNATThen_RejectsUnknownDirectlyUnderThen(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
		"set security nat destination rule-set rs1 rule r1 then bogus-action",
	})
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("an unknown action directly under a DNAT rule then must be rejected under closed-world")
	}
	if !strings.Contains(err.Error(), "bogus-action") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the keyword and the closed-world subtree, got: %v", err)
	}
}

// TestSourceNATThen_StillOpenWorld documents the deliberate asymmetry (#4313):
// the source-NAT rule then-action is NOT closed-world, because its packed runs
// collapse the rule-level persistent-nat tail onto Keys past the pool-name
// slot. Since #14626 that tail is MODELED and compiled per-rule, so this test
// now asserts SchemaValidate still accepts it (no false-reject) while the
// compiler gate owns its value validation. A bogus source-NAT action remains
// silently accepted at the schema layer (open-world) — the #10294 compiler
// gate, not SchemaValidate, rejects it.
func TestSourceNATThen_StillOpenWorld(t *testing.T) {
	// A valid-Junos rule-level persistent-nat must NOT be schema-rejected.
	persistent := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 192.0.2.10",
		"set security nat source rule-set rs1 from zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1 persistent-nat permit any-remote-host",
	})
	if err := SchemaValidate(persistent, nil); err != nil {
		t.Fatalf("rule-level `then source-nat pool <name> persistent-nat ...` is valid Junos and must NOT be rejected while source-NAT then is open-world (deferred #4313 subtree), got: %v", err)
	}
	// #14626: the tail now compiles — assert the compiled effect, not just
	// acceptance, so this test cannot pass on the old inert behavior.
	cfg, err := CompileConfig(persistent)
	if err != nil {
		t.Fatalf("CompileConfig(persistent tail): %v", err)
	}
	eff, ok := cfg.Security.NAT.Source[0].Rules[0].EffectivePersistentNAT(cfg)
	if !ok || eff.Permit != PersistentNATPermitAnyRemoteHost {
		t.Fatalf("rule-level tail inert (#14626): effective=%+v ok=%v", eff, ok)
	}

	// And an outright bogus source-NAT action is still silently accepted by
	// SchemaValidate (open-world) — the compiler gate owns that reject.
	bogus := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat bogus",
	})
	if err := SchemaValidate(bogus, nil); err != nil {
		t.Fatalf("source-NAT then is still open-world (deferred #4313 subtree); a bogus action must be silently accepted today, got: %v", err)
	}
}
