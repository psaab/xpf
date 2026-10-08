package config

import (
	"strings"
	"testing"
)

// #2187: a source/destination-NAT rule with `match application <name>` consumes
// the referenced app's port/proto (pkg/dataplane/userspace/nat.go
// appPortsFromSpec). #2142 (PR #2185) added strict commit-time validation of
// application specs, but scoped the reference walk to security POLICIES only —
// mirroring #2124's policy-only runtime gate. So a malformed user app referenced
// ONLY by a NAT rule (not by any policy) escaped both the commit gate and the
// runtime gate: appPortsFromSpec returns nil on the malformed spec → the NAT
// term silently never-matches (or over-matches), with no commit-time error.
//
// These tests drive the real strict commit path (CompileConfig) and the
// tolerant load path (CompileConfigLenient) through validateApplicationSpecsStrict
// for NAT-rule references. They FAIL on the pre-fix tree (the NAT walk was not
// part of applicationsToValidateStrict).
//
// All trees are built from flat `set` commands via flatTreeFromSets (defined in
// compiler_interfaces_unsupported_test.go) — the only correct way to exercise
// the flat-set AST shape.

// natRefBadApp_source wires a source-NAT rule whose `match application` names a
// malformed app (caller controls the bad destination-port). No security policy
// references BAD, so only the NAT walk can make this reject.
func natRefBadApp_source(destPort string) []string {
	return []string{
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port " + destPort,
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match application BAD",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
}

// natRefBadApp_dest wires a destination-NAT rule whose `match application` names
// a malformed app. No security policy references BAD.
func natRefBadApp_dest(destPort string) []string {
	return []string{
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port " + destPort,
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set rs1 rule r1 match application BAD",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
	}
}

func TestNATAppRef_SourceBadDestPort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, natRefBadApp_source("nope")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject source-nat rule referencing malformed application BAD")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name application BAD and destination-port", err.Error())
	}
}

func TestNATAppRef_SourceOutOfRangeDestPort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, natRefBadApp_source("99999")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject source-nat rule referencing application BAD with destination-port 99999")
	}
}

func TestNATAppRef_DestBadDestPort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, natRefBadApp_dest("nope")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject destination-nat rule referencing malformed application BAD")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name application BAD and destination-port", err.Error())
	}
}

func TestNATAppRef_DestUnknownProtocol_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol bogus",
		"set applications application BAD destination-port 80",
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set rs1 rule r1 match application BAD",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject destination-nat rule referencing application BAD with protocol bogus")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error %q must name application BAD and the bad protocol", err.Error())
	}
}

// Non-tautological companion: the SAME source-nat structure with a VALID
// destination-port must commit cleanly, proving the reject above is caused by
// the malformed spec and not the surrounding NAT rule.
func TestNATAppRef_SourceValid_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, natRefBadApp_source("8080-8090")...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("expected commit to accept source-nat rule referencing valid application BAD: %v", err)
	}
}

func TestNATAppRef_DestValid_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, natRefBadApp_dest("443")...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("expected commit to accept destination-nat rule referencing valid application BAD: %v", err)
	}
}

// A malformed application referenced by a NAT rule via an application-SET (the
// NAT rule names the set, not the app directly) must also reject at commit — the
// addRef closure expands sets identically for policy and NAT references.
func TestNATAppRef_DestViaSet_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		"set applications application-set SET application BAD",
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set rs1 rule r1 match application SET",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject NAT rule referencing application-set SET carrying malformed BAD")
	}
}

// Control: an UNREFERENCED malformed app with app-id disabled and NO NAT/policy
// reference stays a warning — the #2142 referenced-vs-unreferenced distinction is
// preserved (the NAT walk only ADDS references, it does not change the
// unreferenced behaviour). This test would also pass pre-fix; it pins that the
// fix did not over-reach into unreferenced apps.
func TestNATAppRef_Unreferenced_WarnsNotRejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol bogus",
		"set applications application BAD destination-port nope",
		// A source-nat rule exists but does NOT reference BAD.
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unreferenced bad app must not reject at commit: %v", err)
	}
	var warned bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("expected ValidateConfig to warn about unreferenced bad application BAD")
	}
}

// No-brick (#1960 / #2008 doctrine): a config persisted/synced with a NAT-rule
// reference to a malformed application must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning — so an upgraded node does
// not fail closed on boot. Same lenient wiring as the policy path; the runtime
// just gets nil ports for the NAT term (never-match), inert rather than a crash.
func TestNATAppRef_SourceBad_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, natRefBadApp_source("nope")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a NAT-referenced bad app must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record an application-spec downgrade warning, got %v", cfg.Warnings)
	}
}

func TestNATAppRef_DestSecondBadSpec_RejectsAtCommit12224(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application GOOD protocol tcp",
		"set applications application GOOD destination-port 443",
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set rs1 rule r1 match application [ GOOD BAD ]",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit with AppID disabled to reject malformed second app BAD")
	} else if !strings.Contains(err.Error(), "BAD") || !strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name second application BAD and its malformed destination-port", err.Error())
	}
}
