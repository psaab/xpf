package config

import (
	"strings"
	"testing"
)

// #3850: a NAT rule or firewall filter term with DUPLICATE inner `match {}` /
// `then {}` / `from {}` blocks was read FIRST-BLOCK-ONLY. The Junos parser
// APPENDS a repeated hierarchical block as a SEPARATE sibling (parseStatements)
// rather than merging it, and `load merge` / `load override` can produce two
// such blocks under one rule/term. The old `FindChild("match"/"then"/"from")`
// first-block-only read silently DROPPED the second block's conditions (a
// fail-open widening of the match) or its action — the same class #3842 fixed
// for security policies and #3915 fixed for the nat SUB-blocks (source/
// destination/static). The fix iterates EVERY sibling block with FindChildren
// so all conditions AND-combine and all actions apply (Junos merge semantics).
//
// The flat-set path is INHERENTLY SAFE: SetPath merges duplicate containers
// into a single node (ast_edit.go container-descent), so two `set ... match X`
// / `set ... match Y` lines collapse onto ONE `match` node. The flat-set tests
// below therefore prove the merge reads all conditions (a regression guard),
// while the hierarchical tests go RED on revert (the compiler reads only the
// first sibling block).

// containsStr3850 reports whether xs contains s.
func containsStr3850(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// --- NAT SOURCE ------------------------------------------------------------

// TestNATSourceDupMatchBlocksMerge_3850 is the primary fail-open case: a source
// NAT rule with two `match {}` blocks, source-address in the first and
// destination-address in the second. Both constraints must compile. Reverting
// compileNATSource's match read to FindChild-first drops the second block's
// destination-address -> the rule matches a WIDER set of traffic than
// configured (a fail-open NAT widening) and this goes RED.
func TestNATSourceDupMatchBlocksMerge_3850(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS1 {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match {
                        source-address 10.0.0.0/24;
                    }
                    match {
                        destination-address 20.0.0.0/24;
                    }
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	rule := nat.FindChild("source").FindChild("rule-set").FindChild("rule")
	if n := len(rule.FindChildren("match")); n != 2 {
		t.Fatalf("precondition: expected 2 match blocks under the rule, got %d", n)
	}
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Source[0].Rules[0]
	if !containsStr3850(r.Match.SourceAddresses, "10.0.0.0/24") {
		t.Fatalf("first match block source-address dropped: %v", r.Match.SourceAddresses)
	}
	if !containsStr3850(r.Match.DestinationAddresses, "20.0.0.0/24") {
		t.Fatalf("SECOND match block destination-address DROPPED (first-block-only fail-open); "+
			"DestinationAddresses=%v", r.Match.DestinationAddresses)
	}
}

// TestNATSourceDupThenBlocksApplied_3850: two `then {}` blocks each naming a
// source-nat pool. A NAT rule has one translation action, so the second block
// resolves last-wins (Junos merges duplicate stanzas). Reverting the then read
// to FindChild-first keeps only the first pool -> RED.
func TestNATSourceDupThenBlocksApplied_3850(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS1 {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match {
                        source-address 10.0.0.0/24;
                    }
                    then {
                        source-nat pool poolA;
                    }
                    then {
                        source-nat pool poolB;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	rule := nat.FindChild("source").FindChild("rule-set").FindChild("rule")
	if n := len(rule.FindChildren("then")); n != 2 {
		t.Fatalf("precondition: expected 2 then blocks, got %d", n)
	}
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Source[0].Rules[0]
	if r.Then.PoolName != "poolB" {
		t.Fatalf("SECOND then block source-nat pool DROPPED (first-block-only); "+
			"PoolName=%q, want poolB (last-wins merge)", r.Then.PoolName)
	}
}

// TestNATSourceDupThenTypeSwitchResetsStaleField_3850 proves the per-block
// reset (#3850 review fold): a source NAT rule whose first `then` block sets
// `source-nat interface` and whose second sets `source-nat pool poolB` compiles
// to a POOL-ONLY spec (PoolName=poolB, Interface=false) — true last-wins across
// a translation-TYPE switch. Reverting the `rule.Then = NATThen{}` per-block
// reset leaves the first block's Interface=true set ALONGSIDE PoolName=poolB
// (both fields set, so the dataplane's field precedence decides, not true
// last-wins), so this goes RED.
func TestNATSourceDupThenTypeSwitchResetsStaleField_3850(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS1 {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match {
                        source-address 10.0.0.0/24;
                    }
                    then {
                        source-nat interface;
                    }
                    then {
                        source-nat pool poolB;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Source[0].Rules[0]
	if r.Then.PoolName != "poolB" {
		t.Fatalf("second then block pool not applied: PoolName=%q, want poolB", r.Then.PoolName)
	}
	if r.Then.Interface {
		t.Fatalf("STALE Interface=true from the first then block survived the translation-" +
			"type switch (per-block reset missing); want Interface=false (true last-wins)")
	}
}

// --- NAT DESTINATION -------------------------------------------------------

// TestNATDestinationDupMatchBlocksMerge_3850: two `match {}` blocks under a
// destination NAT rule (destination-address in one, source-address in the
// other). Both must compile; revert drops the second -> RED.
func TestNATDestinationDupMatchBlocksMerge_3850(t *testing.T) {
	cfgText := `
security {
    nat {
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD1 {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.1/32;
                    }
                    match {
                        source-address 203.0.113.0/24;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Destination.RuleSets[0].Rules[0]
	if !containsStr3850(r.Match.DestinationAddresses, "198.51.100.1/32") {
		t.Fatalf("first match block destination-address dropped: %v", r.Match.DestinationAddresses)
	}
	if !containsStr3850(r.Match.SourceAddresses, "203.0.113.0/24") {
		t.Fatalf("SECOND match block source-address DROPPED (first-block-only fail-open); "+
			"SourceAddresses=%v", r.Match.SourceAddresses)
	}
}

// --- NAT STATIC ------------------------------------------------------------

// TestNATStaticDupMatchBlocksMerge_3850: two `match {}` blocks under a static
// NAT rule (destination-address in one, source-address in the other). Both must
// compile; revert drops the second -> RED.
func TestNATStaticDupMatchBlocksMerge_3850(t *testing.T) {
	cfgText := `
security {
    nat {
        static {
            rule-set ST1 {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.10/32;
                    }
                    match {
                        source-address 203.0.113.0/24;
                    }
                    then {
                        static-nat prefix 10.0.1.10/32;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Static[0].Rules[0]
	if r.Match != "198.51.100.10/32" {
		t.Fatalf("first match block destination-address dropped: Match=%q", r.Match)
	}
	if !containsStr3850(r.SourceAddresses, "203.0.113.0/24") {
		t.Fatalf("SECOND match block source-address DROPPED (first-block-only fail-open); "+
			"SourceAddresses=%v", r.SourceAddresses)
	}
}

// --- FIREWALL FILTER TERM --------------------------------------------------

// firewallFromText parses cfgText and compiles the first `firewall` node.
func firewallFromText(t *testing.T, cfgText string) *FirewallConfig {
	t.Helper()
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	fwNode := tree.FindChild("firewall")
	if fwNode == nil {
		t.Fatalf("no firewall node parsed")
	}
	fw := &FirewallConfig{}
	if err := compileFirewall(fwNode, fw); err != nil {
		t.Fatalf("compileFirewall: %v", err)
	}
	return fw
}

// TestFilterTermDupFromBlocksMerge_3850 is the primary filter fail-open case: a
// term with two `from {}` blocks (source-address in one, destination-address in
// the other). Both must compile; revert to FindChild-first drops the second
// block's destination-address -> the term matches a WIDER set (fail-open) -> RED.
func TestFilterTermDupFromBlocksMerge_3850(t *testing.T) {
	cfgText := `
firewall {
    family inet {
        filter F1 {
            term T1 {
                from {
                    source-address 10.0.0.0/24;
                }
                from {
                    destination-address 20.0.0.0/24;
                }
                then {
                    accept;
                }
            }
        }
    }
}
`
	fw := firewallFromText(t, cfgText)
	term := fw.FiltersInet["F1"].Terms[0]
	if !containsStr3850(term.SourceAddresses, "10.0.0.0/24") {
		t.Fatalf("first from block source-address dropped: %v", term.SourceAddresses)
	}
	if !containsStr3850(term.DestAddresses, "20.0.0.0/24") {
		t.Fatalf("SECOND from block destination-address DROPPED (first-block-only fail-open); "+
			"DestAddresses=%v", term.DestAddresses)
	}
}

// TestFilterTermDupThenBlocksApplied_3850: two `then {}` blocks, a `count`
// modifier in the first and the terminal `accept` in the second. Both must
// apply; revert to FindChild-first keeps only the first (count, no terminal
// action) -> Action == "" -> RED.
func TestFilterTermDupThenBlocksApplied_3850(t *testing.T) {
	cfgText := `
firewall {
    family inet {
        filter F1 {
            term T1 {
                from {
                    source-address 10.0.0.0/24;
                }
                then {
                    count C1;
                }
                then {
                    accept;
                }
            }
        }
    }
}
`
	fw := firewallFromText(t, cfgText)
	term := fw.FiltersInet["F1"].Terms[0]
	if term.Count != "C1" {
		t.Fatalf("first then block count dropped: Count=%q", term.Count)
	}
	if term.Action != FilterActionAccept {
		t.Fatalf("SECOND then block terminal action DROPPED (first-block-only); "+
			"Action=%q, want accept", term.Action)
	}
}

// --- FLAT-SET (regression guard: SetPath merges duplicate containers) -------

// setPathTree builds a ConfigTree from flat `set` lines (the #2419 testing
// discipline: ParseSetCommand + SetPath, never NewParser for set syntax).
func setPathTree3850(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		toks, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%v): %v", toks, err)
		}
	}
	return tree
}

// TestNATSourceFlatSetSplitMatchMerges_3850 proves the flat-set shape is safe:
// two `set ... match ...` lines with different conditions MERGE onto one match
// node (SetPath container-descent), and the compiler reads BOTH. Green before
// and after the fix (documents that the fail-open is hierarchical-only).
func TestNATSourceFlatSetSplitMatchMerges_3850(t *testing.T) {
	tree := setPathTree3850(t, []string{
		"set security nat source rule-set RS1 from zone trust",
		"set security nat source rule-set RS1 to zone untrust",
		"set security nat source rule-set RS1 rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS1 rule R1 match destination-address 20.0.0.0/24",
		"set security nat source rule-set RS1 rule R1 then source-nat interface",
	})
	nat := tree.FindChild("security").FindChild("nat")
	rule := nat.FindChild("source").FindChild("rule-set").FindChild("rule")
	if n := len(rule.FindChildren("match")); n != 1 {
		t.Fatalf("flat-set should MERGE duplicate match containers into 1 node, got %d", n)
	}
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Source[0].Rules[0]
	if !containsStr3850(r.Match.SourceAddresses, "10.0.0.0/24") ||
		!containsStr3850(r.Match.DestinationAddresses, "20.0.0.0/24") {
		t.Fatalf("flat-set merged match lost a condition: src=%v dst=%v",
			r.Match.SourceAddresses, r.Match.DestinationAddresses)
	}
}

// TestFilterTermFlatSetSplitFromMerges_3850 is the firewall analogue.
func TestFilterTermFlatSetSplitFromMerges_3850(t *testing.T) {
	tree := setPathTree3850(t, []string{
		"set firewall family inet filter F1 term T1 from source-address 10.0.0.0/24",
		"set firewall family inet filter F1 term T1 from destination-address 20.0.0.0/24",
		"set firewall family inet filter F1 term T1 then accept",
	})
	fwNode := tree.FindChild("firewall")
	term := fwNode.FindChild("family").FindChild("filter").FindChild("term")
	if n := len(term.FindChildren("from")); n != 1 {
		t.Fatalf("flat-set should MERGE duplicate from containers into 1 node, got %d", n)
	}
	fw := &FirewallConfig{}
	if err := compileFirewall(fwNode, fw); err != nil {
		t.Fatalf("compileFirewall: %v", err)
	}
	tm := fw.FiltersInet["F1"].Terms[0]
	if !containsStr3850(tm.SourceAddresses, "10.0.0.0/24") ||
		!containsStr3850(tm.DestAddresses, "20.0.0.0/24") {
		t.Fatalf("flat-set merged from lost a condition: src=%v dst=%v",
			tm.SourceAddresses, tm.DestAddresses)
	}
}

// --- SINGLE-BLOCK REGRESSION GUARDS ----------------------------------------

// TestNATSingleMatchThenUnchanged_3850 pins bit-identical behaviour for the
// common single-block NAT rule after the FindChildren conversion.
func TestNATSingleMatchThenUnchanged_3850(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS1 {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match {
                        source-address 10.0.0.0/24;
                        destination-address 20.0.0.0/24;
                    }
                    then {
                        source-nat pool poolA;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	r := sec.NAT.Source[0].Rules[0]
	if !containsStr3850(r.Match.SourceAddresses, "10.0.0.0/24") ||
		!containsStr3850(r.Match.DestinationAddresses, "20.0.0.0/24") ||
		r.Then.PoolName != "poolA" {
		t.Fatalf("single-block NAT rule regressed: src=%v dst=%v pool=%q",
			r.Match.SourceAddresses, r.Match.DestinationAddresses, r.Then.PoolName)
	}
}

// TestFilterSingleFromThenUnchanged_3850 pins the single-block filter term.
func TestFilterSingleFromThenUnchanged_3850(t *testing.T) {
	cfgText := `
firewall {
    family inet {
        filter F1 {
            term T1 {
                from {
                    source-address 10.0.0.0/24;
                    destination-address 20.0.0.0/24;
                }
                then {
                    count C1;
                    accept;
                }
            }
        }
    }
}
`
	fw := firewallFromText(t, cfgText)
	term := fw.FiltersInet["F1"].Terms[0]
	if !containsStr3850(term.SourceAddresses, "10.0.0.0/24") ||
		!containsStr3850(term.DestAddresses, "20.0.0.0/24") ||
		term.Count != "C1" || term.Action != FilterActionAccept {
		t.Fatalf("single-block filter term regressed: src=%v dst=%v count=%q action=%q",
			term.SourceAddresses, term.DestAddresses, term.Count, term.Action)
	}
}

// --- pre-id-default-policy (minor, singleton then) -------------------------

// TestPreIDDefaultPolicyDupThenBlocks_3850: two `then {}` blocks under
// pre-id-default-policy, session-init in the first and session-close in the
// second. Both flags must set; revert to FindChild-first drops the second -> RED.
func TestPreIDDefaultPolicyDupThenBlocks_3850(t *testing.T) {
	cfgText := `
security {
    pre-id-default-policy {
        then {
            log {
                session-init;
            }
        }
        then {
            log {
                session-close;
            }
        }
    }
}
`
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	secNode := tree.FindChild("security")
	sec := &SecurityConfig{}
	if err := compileSecurity(secNode, sec); err != nil {
		t.Fatalf("compileSecurity: %v", err)
	}
	if sec.PreIDDefaultPolicy == nil {
		t.Fatalf("PreIDDefaultPolicy not compiled")
	}
	if !sec.PreIDDefaultPolicy.LogSessionInit {
		t.Fatalf("first then block session-init dropped")
	}
	if !sec.PreIDDefaultPolicy.LogSessionClose {
		t.Fatalf("SECOND then block session-close DROPPED (first-block-only)")
	}
}

// --- SECONDARY: identical terminal actions merge silently ------------------

// TestPolicyIdenticalPermitBlocksMerge_3850: two IDENTICAL `then { permit; }`
// blocks are NOT a conflict (Junos merges duplicate stanzas). The #3043
// conflicting-terminal-action gate must dedup by distinct value before the
// count, so this commits. Before the fix it over-rejected as "2 conflicting
// terminal actions (permit, permit)" -> reverting the dedup makes CompileConfig
// return that error and this goes RED.
func TestPolicyIdenticalPermitBlocksMerge_3850(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
                then {
                    permit;
                }
            }
        }
    }
}`
	p := NewParser(cfg)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected two IDENTICAL permit blocks (should merge "+
			"silently, Junos-faithful): %v", err)
	}
}

// TestPolicyConflictingTerminalStillRejected_3850 guards the secondary fix: a
// genuine permit + reject conflict (DIFFERENT actions) must STILL be rejected
// after the identical-action dedup.
func TestPolicyConflictingTerminalStillRejected_3850(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
                then {
                    reject;
                }
            }
        }
    }
}`
	p := NewParser(cfg)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted permit+reject conflict (should reject)")
	}
	if !strings.Contains(err.Error(), "conflicting terminal actions") {
		t.Fatalf("error = %q, want conflicting-terminal-actions rejection", err.Error())
	}
}
