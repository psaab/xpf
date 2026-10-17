package config

import (
	"strings"
	"testing"
)

// #9140 (security, filter fail-open): `then routing-instance <x>` is a
// TERMINATING filter-based-forwarding action, so co-locating it with
// `then next term` is the same contradiction #5142 rejects for
// accept/discard/reject — reached through a different typed field.
//
// compileFilterThen records accept/reject/discard on term.TerminalActions but
// records the FBF steer on term.RoutingInstance, and the #5142 gate tested only
// `len(term.TerminalActions) > 0`. So
//
//	then { routing-instance mgmt-vrf; next term; }
//
// committed cleanly and then rendered a TERMINATING accept in BOTH runtimes
// (userspace-dp/src/filter/compiler.rs sets
// `continue_term: next_term && action.is_empty() && routing_instance.is_empty()` (#14632) and resolves
// the empty action to Accept; the kernel lo0 nft mirror emits `accept` — pinned
// by TestNftRuleFromTermRoutingInstanceTerminatesAccept in pkg/daemon). On lo0,
// the host control-plane filter, that makes every later deny term unreachable
// for the steer term's whole match set.
//
// The runtimes AGREE and are not the defect: changing either one alone would
// break the kernel/userspace mirror contract stated in
// pkg/daemon/daemon_nft_term_lower.go. The defect is that the operator could
// author the contradiction at all.
//
// FAIL-ON-REVERT: restore the gate to `term.NextTerm && len(term.TerminalActions) > 0`
// and TestFilterRoutingInstancePlusNextTerm_9140 goes RED — CompileConfig
// accepts the contradiction again.

// buildRIFilterTree defines the routing instance the filter steers into, so the
// term clears validateFilterRoutingInstanceReferenceStrict and the test is
// measuring the next-term gate rather than an undefined-instance rejection.
func buildRIFilterTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	all := append([]string{
		"set routing-instances mgmt-vrf instance-type virtual-router",
	}, cmds...)
	return buildFilterTree(t, all...)
}

func TestFilterRoutingInstancePlusNextTerm_9140(t *testing.T) {
	tree := buildRIFilterTree(t,
		"set firewall family inet filter lo0f term t1 from source-address 10.0.0.0/8",
		"set firewall family inet filter lo0f term t1 then routing-instance mgmt-vrf",
		"set firewall family inet filter lo0f term t1 then next term",
		"set firewall family inet filter lo0f term t2 from protocol tcp",
		"set firewall family inet filter lo0f term t2 from destination-port 22",
		"set firewall family inet filter lo0f term t2 then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with `then routing-instance` AND `then next term` must be " +
			"rejected at commit (#9140 — a routing-instance term terminates as " +
			"accept in both runtimes, so the later discard would be dead)")
	}
	if !strings.Contains(err.Error(), "routing-instance mgmt-vrf") ||
		!strings.Contains(err.Error(), "next term") {
		t.Fatalf("error %q must name the routing-instance action and `next term`", err)
	}
	if !strings.Contains(err.Error(), `filter "lo0f"`) ||
		!strings.Contains(err.Error(), `term "t1"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	// Tolerant load / peer-sync must not brick (#1960): the gate already runs
	// under lenientFilterTerminalConflict, so extending it inherits the
	// downgrade rather than turning an already-persisted config into a boot
	// failure.
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the routing-instance+next-term contradiction: %v", lerr)
	}
}

// inet6 must be gated identically (the validator walks both families).
func TestFilterRoutingInstancePlusNextTermV6_9140(t *testing.T) {
	tree := buildRIFilterTree(t,
		"set firewall family inet6 filter lo0f6 term t1 then routing-instance mgmt-vrf",
		"set firewall family inet6 filter lo0f6 term t1 then next term",
		"set firewall family inet6 filter lo0f6 term t2 then discard",
	)
	err := func() error { _, e := CompileConfig(tree); return e }()
	if err == nil {
		t.Fatal("inet6 routing-instance + next-term must be rejected (#9140)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// CONTROL 1: a bare `then routing-instance <x>` with NO next-term is the
// legitimate filter-based-forwarding case (#3427 M08) and must still commit.
// This is the cell that keeps the gate from being satisfied by levelling down —
// rejecting every routing-instance term would also make the cell above pass.
func TestFilterBareRoutingInstanceStillAllowed_9140(t *testing.T) {
	tree := buildRIFilterTree(t,
		"set firewall family inet filter ok term t1 from source-address 10.0.0.0/8",
		"set firewall family inet filter ok term t1 then routing-instance mgmt-vrf",
		"set firewall family inet filter ok term t2 then discard",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("bare `then routing-instance` (no next-term) is the legitimate FBF case and must compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["ok"].Terms[0]
	if term.RoutingInstance != "mgmt-vrf" || term.NextTerm || term.Action != "" {
		t.Fatalf("FBF term compiled wrong: RoutingInstance=%q NextTerm=%v Action=%q",
			term.RoutingInstance, term.NextTerm, term.Action)
	}
}

// CONTROL 2: `then routing-instance <x>` WITH `then accept` stays legal (#3308
// rejects only the discard/reject pairing), and adding next-term to it is
// already rejected by the #5142 half of the gate — so the two halves do not
// interfere.
func TestFilterRoutingInstanceAcceptStillAllowed_9140(t *testing.T) {
	tree := buildRIFilterTree(t,
		"set firewall family inet filter ok term t1 then routing-instance mgmt-vrf",
		"set firewall family inet filter ok term t1 then accept",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("`then routing-instance` + `then accept` must still compile (#3308 allows it): %v", err)
	}

	tree2 := buildRIFilterTree(t,
		"set firewall family inet filter bad term t1 then routing-instance mgmt-vrf",
		"set firewall family inet filter bad term t1 then accept",
		"set firewall family inet filter bad term t1 then next term",
	)
	_, err := CompileConfig(tree2)
	if err == nil {
		t.Fatal("routing-instance + accept + next-term must be rejected (#5142)")
	}
	// The explicit terminal is named first — the accept keyword is on
	// TerminalActions, so that arm reports it, not the routing-instance.
	if !strings.Contains(err.Error(), `"accept"`) {
		t.Fatalf("error %q must name the explicit accept terminal", err)
	}
}

// CONTROL 3: a modifier-only `then { count c; next term; }` fall-through — no
// terminating action and no routing-instance — is still a VALID fall-through
// (#2544/#3427) and must be untouched by the widened gate.
func TestFilterModifierOnlyNextTermStillAllowed_9140(t *testing.T) {
	tree := buildRIFilterTree(t,
		"set firewall family inet filter ok term t1 then count c1",
		"set firewall family inet filter ok term t1 then next term",
		"set firewall family inet filter ok term t2 then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("modifier-only `then next term` must still compile: %v", err)
	}
}
