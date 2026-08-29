package config

import (
	"strings"
	"testing"
)

// compiler_nat_then_packed_contradiction_7033_test.go — #7033.
//
// Two mutually-exclusive NAT actions PACKED onto one token run lower to a single
// field, so the resolved-field count sees `n == 1` and the contradiction commits
// under STRICT. Where `off` is the casualty the published behaviour is the
// INVERSE of what was authored: an exemption becomes a translation.
//
// THE PRESERVATION CASES ARE THE POINT OF THIS FILE, not an afterthought. Two
// rounds of #6820 tried to fix this by accumulating in the LOWERING and each was
// reverted for a regression in the ACCEPTING direction. Every one of those
// shapes is a cell here:
//
//   - `pool off` — a pool NAMED off must stay a pool.
//   - `pool P persistent-nat permit any-remote-host` — #4313's open-world tail
//     must still resolve to pool P, unchanged.
//   - `frobnicate { off; }` — must NOT become a fabricated exemption (round 6).
//   - `destination-nat interface pool PD` — must keep its ZERO-action message
//     (round 5's shape), which is what pins this check's placement AFTER the
//     resolved-field count.

func snat7033(then string) string {
	return `security { zones { security-zone trust; security-zone untrust; } nat { source {
  pool P { address 203.0.113.5; }
  pool off { address 203.0.113.9; }
  rule-set RS { from zone trust; to zone untrust;
    rule R1 { match { source-address 10.0.0.0/24; } ` + then + ` }
  } } } }`
}

func dnat7033(then string) string {
	return `security { zones { security-zone untrust; } nat { destination {
  pool PD { address 10.0.30.100; }
  rule-set RD { from zone untrust;
    rule R1 { match { destination-address 198.51.100.1/32; } ` + then + ` }
  } } } }`
}

func compileText7033(t *testing.T, txt string) error {
	t.Helper()
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("fixture did not parse: %v", perr)
	}
	_, err := CompileConfig(tree)
	return err
}

// TestPackedCrossModeContradictionRejected_7033 is the acceptance criterion: all
// six rows of the issue, across three AST shapes and BOTH token orders.
//
// Both orders are load-bearing rather than symmetry for its own sake. They
// resolve to DIFFERENT survivors — `off pool P` keeps the exemption, `pool P off`
// keeps the translation — so a fixture covering one order proves nothing about
// the other, and the rows where `off` is the casualty are the dangerous ones.
func TestPackedCrossModeContradictionRejected_7033(t *testing.T) {
	for _, tc := range []struct {
		name      string
		text      string
		modes     []string
		offDroppd bool
	}{
		{
			name: "root_packed_pool_then_off", text: snat7033("then { source-nat pool P off; }"),
			modes: []string{"pool", "off"}, offDroppd: true,
		},
		{
			name: "root_packed_off_then_pool", text: snat7033("then { source-nat off pool P; }"),
			modes: []string{"off", "pool"},
		},
		{
			name: "child_packed_pool_then_off", text: snat7033("then { source-nat { pool P off; } }"),
			modes: []string{"pool", "off"}, offDroppd: true,
		},
		{
			name: "root_packed_interface_then_pool", text: snat7033("then { source-nat interface pool P; }"),
			modes: []string{"interface", "pool"},
		},
		{
			name: "root_packed_pool_then_interface", text: snat7033("then { source-nat pool P interface; }"),
			modes: []string{"pool", "interface"},
		},
		{
			// POOL-LESS cross-mode packs. These are the rows the first draft of
			// the fix MISSED: the per-container record was ranked by distinct
			// POOLS, so a container naming no pool never beat the empty starting
			// record and its contradiction was never recorded. Every other row in
			// this table names a pool, so the table sampled the axis instead of
			// varying it and the whole class was invisible.
			name: "root_packed_interface_then_off", text: snat7033("then { source-nat interface off; }"),
			modes: []string{"interface", "off"}, offDroppd: true,
		},
		{
			name: "root_packed_off_then_interface", text: snat7033("then { source-nat off interface; }"),
			modes: []string{"off", "interface"},
		},
		{
			name: "child_packed_interface_then_off", text: snat7033("then { source-nat { interface off; } }"),
			modes: []string{"interface", "off"}, offDroppd: true,
		},
		{
			name: "dnat_child_packed_pool_then_off", text: dnat7033("then { destination-nat { pool PD off; } }"),
			modes: []string{"pool", "off"}, offDroppd: true,
		},
		{
			name: "dnat_root_packed_off_then_pool", text: dnat7033("then { destination-nat off pool PD; }"),
			modes: []string{"off", "pool"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := compileText7033(t, tc.text)
			if err == nil {
				t.Fatal("a `then` block packing two mutually-exclusive translation actions " +
					"committed under STRICT. Packed onto one run they lower to a single " +
					"field, so the resolved-action count sees one and nothing reports the " +
					"discarded action (#7033)")
			}
			msg := err.Error()
			for _, m := range tc.modes {
				if !strings.Contains(msg, m) {
					t.Fatalf("the rejection does not name authored mode %q: %q", m, msg)
				}
			}
			// The severe rows must SAY they are severe. A message that reported
			// only "two actions" would read as a tidiness complaint, when what
			// actually happens is that the firewall translates traffic the
			// operator exempted.
			said := strings.Contains(msg, "INVERSE")
			if said != tc.offDroppd {
				t.Fatalf("message says INVERSE = %v, want %v (off dropped = %v).\n"+
					"An `off` that loses to a pool is not a stylistic problem: the "+
					"dataplane enforces the opposite of the authored intent, and only "+
					"the rows where `off` is the casualty should say so.\nmessage: %s",
					said, tc.offDroppd, tc.offDroppd, msg)
			}
		})
	}
}

func TestFlatSetPackedContradictionRejected_7033(t *testing.T) {
	// Flat set is a THIRD shape, not a restatement: SetPath builds the run as a
	// child chain (`pool P` carrying `off` as its child), so a walk that reads
	// only sibling nodes or only packed Keys misses every row here.
	for _, tc := range []struct {
		name string
		then string
	}{
		{"flat_pool_then_off", "set security nat source rule-set RS rule R1 then source-nat pool P off"},
		{"flat_off_then_pool", "set security nat source rule-set RS rule R1 then source-nat off pool P"},
		{"flat_interface_then_pool", "set security nat source rule-set RS rule R1 then source-nat interface pool P"},
		// Pool-less, in the shape an operator types.
		{"flat_interface_then_off", "set security nat source rule-set RS rule R1 then source-nat interface off"},
		{"flat_off_then_interface", "set security nat source rule-set RS rule R1 then source-nat off interface"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source pool P address 203.0.113.5",
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				tc.then,
			})
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("a flat-set packed contradiction committed under STRICT (#7033)")
			}
		})
	}
}

// TestOpenWorldTrailingGrammarStillCommits_7033 pins #4313 bit-identically.
//
// It asserts the RESOLVED pool, not merely that the compile succeeded: the whole
// risk of this change is a scan that reads an open-world tail as actions, and a
// commit that succeeds with the wrong pool would satisfy an err == nil check.
func TestOpenWorldTrailingGrammarStillCommits_7033(t *testing.T) {
	txt := snat7033("then { source-nat pool P persistent-nat permit any-remote-host; }")
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("fixture did not parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("#4313's open-world trailing grammar must still commit, got: %v.\n"+
			"Everything after `persistent-nat` belongs to a sub-grammar the action "+
			"scan does not model; reading it as actions invents a contradiction in a "+
			"valid config", err)
	}
	if got := cfg.Security.NAT.Source[0].Rules[0].Then.PoolName; got != "P" {
		t.Fatalf("open-world tail changed the resolved pool to %q, want P", got)
	}
}

// TestOpenWorldTailContainingOffStillCommits_7033 is the adversarial version of
// the case above, and it is the one that actually bites.
//
// A realistic open-world tail (`persistent-nat permit any-remote-host`) contains
// no action keyword, so a scan that failed to stop would still record one mode
// and that fixture would pass anyway. Putting the token `off` IN the tail is the
// smallest shape where "stop at the first unrecognised token" changes an
// outcome: without the stop, this legal config is rejected as a contradiction
// the operator never wrote. #4313 makes the trailing grammar open-world, so the
// scan cannot assume a tail is free of words it recognises.
func TestOpenWorldTailContainingOffStillCommits_7033(t *testing.T) {
	txt := snat7033("then { source-nat pool P persistent-nat permit off; }")
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("fixture did not parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("an open-world tail that happens to contain the token `off` must still "+
			"commit, got: %v.\nEverything after `persistent-nat` belongs to a sub-grammar "+
			"the action scan does not model — reading it as actions invents a "+
			"contradiction in a valid config", err)
	}
	if got := cfg.Security.NAT.Source[0].Rules[0].Then; got.PoolName != "P" || got.Off {
		t.Fatalf("resolved Then={Off:%v PoolName:%q}, want {false P}", got.Off, got.PoolName)
	}
}

// TestPoolNamedOffIsAPoolNotAnExemption_7033: `pool` consumes exactly one value
// token, so a pool legitimately NAMED `off` resolves as a name.
//
// Without this, the obvious implementation — scan the run for the token `off` —
// turns a valid config into a rejected one, and does it to the operator whose
// pool naming was merely unlucky.
func TestPoolNamedOffIsAPoolNotAnExemption_7033(t *testing.T) {
	txt := snat7033("then { source-nat pool off; }")
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("fixture did not parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("`pool off` names a pool `off`; it must commit, got: %v", err)
	}
	then := cfg.Security.NAT.Source[0].Rules[0].Then
	if then.PoolName != "off" || then.Off {
		t.Fatalf("`pool off` resolved to {PoolName:%q Off:%v}, want {\"off\" false}",
			then.PoolName, then.Off)
	}
}

// TestRepeatedValuelessModeIsARedundancyNotAContradiction_7033 pins the
// asymmetry that decides what this check may report.
//
// `off` carries no value, so `off off` means the same exemption twice: nothing
// is discarded and it commits, the same way `pool P pool P` does under #7013.
// `off pool P` is a different matter — two modes packed onto one run lower to
// one field and the loser vanishes. "Carries no value" therefore justifies
// ignoring a REPEAT of a valueless mode; it never justified ignoring the mode.
//
// Without this cell, counting raw modes instead of distinct ones passes every
// other case in this file and rejects a config whose meaning is unambiguous.
func TestRepeatedValuelessModeIsARedundancyNotAContradiction_7033(t *testing.T) {
	for _, tc := range []struct{ name, then string }{
		{"off_twice", "then { source-nat off off; }"},
		{"interface_twice", "then { source-nat interface interface; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := compileText7033(t, snat7033(tc.then)); err != nil {
				t.Fatalf("%q repeats ONE valueless mode: both spellings mean the same "+
					"thing, nothing is discarded, and it must commit. Got: %v", tc.then, err)
			}
		})
	}
	// And the other half of the asymmetry, so the two live side by side: the
	// same `off`, packed against a pool, IS a contradiction.
	if err := compileText7033(t, snat7033("then { source-nat off pool P; }")); err == nil {
		t.Fatal("`off pool P` packs two DIFFERENT modes onto one run: one is discarded " +
			"with no diagnostic, and it must be rejected")
	}
}

// TestUnrecognisedContainerDoesNotFabricateAnExemption_7033 is #6820 round 6's
// reverted regression, kept as a standing cell.
//
// That round read an `off` out of a container it did not recognise and resolved
// the rule to `{Off:true}` — inventing an exemption the operator never authored,
// which is the same severity as dropping one. The walk must not descend past an
// unrecognised name, so this stays rejected as the ZERO-action rule it is.
func TestUnrecognisedContainerDoesNotFabricateAnExemption_7033(t *testing.T) {
	err := compileText7033(t, snat7033("then { source-nat { frobnicate { off; } } }"))
	if err == nil {
		t.Fatal("`then { source-nat { frobnicate { off; } } }` carries no recognised " +
			"action and must be rejected")
	}
	if !strings.Contains(err.Error(), "no translation action") {
		t.Fatalf("rejected for the WRONG REASON: %q.\nThis rule authors ZERO actions. "+
			"A packed-contradiction message here would mean the walk descended into "+
			"`frobnicate` and counted its `off` — the #6820 round 6 regression, which "+
			"in a rule that also named a pool would fabricate a contradiction", err)
	}
	// And directly: the walk records nothing from below an unrecognised name.
	node := &Node{Keys: []string{"then"}, Children: []*Node{
		{Keys: []string{"source-nat"}, Children: []*Node{
			{Keys: []string{"frobnicate"}, Children: []*Node{{Keys: []string{"off"}}}},
		}},
	}}
	if got := natThenAuthoredOccurrences(node, "source-nat"); len(got.Modes) != 0 {
		t.Fatalf("the walk recorded %v from below an unrecognised container; it must "+
			"record nothing", got.Modes)
	}
}

// TestRound5ShapeKeepsItsZeroActionMessage_7033 pins the ORDERING claim.
//
// `destination-nat interface pool PD` — #6820 round 5's regression shape — lowers
// no DNAT action at all, so it is rejected today by the zero-action branch. The
// packed check runs AFTER the resolved count precisely so configs that branch
// already handles keep their existing diagnostic. If this row ever reports a
// packed contradiction instead, the check has been moved ahead of the count and
// every currently-rejected config's message has changed with it.
func TestRound5ShapeKeepsItsZeroActionMessage_7033(t *testing.T) {
	err := compileText7033(t, dnat7033("then { destination-nat interface pool PD; }"))
	if err == nil {
		t.Fatal("round 5's shape must stay rejected")
	}
	if !strings.Contains(err.Error(), "no translation action") {
		t.Fatalf("expected the ZERO-action message, got: %q", err)
	}
}

// TestSingleActionsStillCommit_7033 is the negative control: without it every
// rejection above is satisfied by a gate that refuses all NAT.
func TestSingleActionsStillCommit_7033(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"snat_pool", snat7033("then { source-nat pool P; }")},
		{"snat_off", snat7033("then { source-nat off; }")},
		{"snat_interface", snat7033("then { source-nat interface; }")},
		{"dnat_pool", dnat7033("then { destination-nat pool PD; }")},
		{"dnat_off", dnat7033("then { destination-nat off; }")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := compileText7033(t, tc.text); err != nil {
				t.Fatalf("a single authored action must still commit, got: %v", err)
			}
		})
	}
}

// TestLenientNATOffendersMatchThePackedGate_7033 extends #7640's agreement to
// this class.
//
// #7640 binds the gate and the gauge to one predicate, but its rows build
// `NATThen` structs directly, so the authored record is empty and no packed row
// can reach it. Adding a rejection reason the gauge cannot see would leave an
// operator's annotation reporting a healthy node for a config a commit refuses —
// which is the exact failure #7640 exists to prevent, reintroduced one class
// over.
func TestLenientNATOffendersMatchThePackedGate_7033(t *testing.T) {
	for _, tc := range []struct {
		name     string
		text     string
		offender bool
	}{
		{"packed_pool_off", snat7033("then { source-nat pool P off; }"), true},
		{"packed_off_pool", snat7033("then { source-nat off pool P; }"), true},
		{"flat_open_world", snat7033("then { source-nat pool P persistent-nat permit any-remote-host; }"), false},
		{"pool_named_off", snat7033("then { source-nat pool off; }"), false},
		{"single_off", snat7033("then { source-nat off; }"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, perr := NewParser(tc.text).Parse()
			if len(perr) != 0 {
				t.Fatalf("fixture did not parse: %v", perr)
			}
			// The LENIENT compile is what makes this test possible: the strict
			// path returns a nil Config once the gate rejects, so there would be
			// nothing to hand the enumerator. Lenient lowers the same rules —
			// including the authored record — without the strict gates, so both
			// sides then read one identical *Config.
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient compile failed: %v", lerr)
			}
			gateRejects := validateNATTerminalActionCardinalityStrict(cfg) != nil
			found := len(natTerminalActionCardinalityOffenders(cfg)) > 0
			if gateRejects != tc.offender {
				t.Fatalf("gate rejects = %v, want %v", gateRejects, tc.offender)
			}
			if found != gateRejects {
				t.Fatalf("the enumerator and the gate DISAGREE (enumerator found=%v, "+
					"gate rejects=%v) for a PACKED contradiction. They must share one "+
					"predicate, or the gauge reports a healthy node for a config a "+
					"commit refuses", found, gateRejects)
			}
		})
	}
}

// TestPackedActionScanShapes_7033 drives the walk directly, so a shape it cannot
// see fails HERE by name instead of surfacing as one accepted row above.
func TestPackedActionScanShapes_7033(t *testing.T) {
	for _, tc := range []struct {
		name      string
		node      *Node
		wantModes []string
	}{
		{
			name:      "packed_on_the_then_node",
			node:      &Node{Keys: []string{"then", "source-nat", "pool", "P", "off"}},
			wantModes: []string{"pool", "off"},
		},
		{
			name: "packed_on_the_kind_child",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"source-nat", "off", "pool", "P"}},
			}},
			wantModes: []string{"off", "pool"},
		},
		{
			name: "flat_set_child_chain",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"source-nat"}, Children: []*Node{
					{Keys: []string{"pool", "P"}, Children: []*Node{{Keys: []string{"off"}}}},
				}},
			}},
			wantModes: []string{"pool", "off"},
		},
		{
			// `pool` consumes one value token, so the name `off` is a NAME.
			name:      "pool_named_off_is_one_mode",
			node:      &Node{Keys: []string{"then", "source-nat", "pool", "off"}},
			wantModes: []string{"pool"},
		},
		{
			// #4313 open-world tail: the scan stops at `persistent-nat`.
			name:      "open_world_tail_stops_the_scan",
			node:      &Node{Keys: []string{"then", "source-nat", "pool", "P", "persistent-nat", "permit", "off"}},
			wantModes: []string{"pool"},
		},
		{
			// No pool at all. The record must still be captured, or a pool-less
			// contradiction is invisible to the gate.
			name:      "pool_less_cross_mode_pack",
			node:      &Node{Keys: []string{"then", "source-nat", "interface", "off"}},
			wantModes: []string{"interface", "off"},
		},
		{
			name: "unrecognised_container_records_nothing",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"source-nat"}, Children: []*Node{
					{Keys: []string{"frobnicate"}, Children: []*Node{{Keys: []string{"off"}}}},
				}},
			}},
			wantModes: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := natThenAuthoredOccurrences(tc.node, "source-nat").Modes
			if strings.Join(got, ",") != strings.Join(tc.wantModes, ",") {
				t.Fatalf("recorded modes %v, want %v — the ORDER matters too: the first "+
					"authored mode is the one that takes effect, so the diagnostic names "+
					"the discarded action off the back of it", got, tc.wantModes)
			}
		})
	}
}
