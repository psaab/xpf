package config

import (
	"reflect"
	"strings"
	"testing"
)

// Tests for #6659 (fail-open half): compiler arms that read only ONE side of a
// dual-shape multi-value leaf, so a bracketed list or a packed statement
// silently compiled to one value — or to none.
//
// CLAUDE.md states the rule: "A compiler reading a multi-value leaf MUST read
// child.Keys[1:] AND child.Children and accumulate." These five arms did not.
// They are grouped here because each one is a FAIL-OPEN — the dropped value
// either widens what a rule matches, or escapes the commit gate that exists to
// reject it — as opposed to the pure value-drops tracked separately on #6659.
//
// THE ONE-SIDEDNESS RUNS IN BOTH DIRECTIONS. This is the property that makes the
// class recur, and it defeats the obvious fix strategy:
//
//   - some arms read Children and NEVER Keys[1:] — `attributes-match` and
//     `then change-configuration commands` here, which is why their PACKED-LEAF
//     spellings compiled to nothing while the block spellings worked;
//   - other arms read Keys[1:] and NEVER Children — the CoS `code-points`
//     collector (not in this PR) reads Keys plus the inline tail, so its
//     hierarchical BLOCK spelling loses the entire classifier.
//
// Anyone fixing this class by pattern-matching "looks like a nodeVal call" finds
// only the first direction and leaves the mirror image untouched. The check that
// actually works is per-shape: compile BOTH the bracketed/packed spelling AND the
// hierarchical block spelling and compare, which is what every test below does.
//
// Two distinct fail-open shapes appear below, do NOT conflate them:
//
//   - MATCH-WIDENING (attributes-match). Dropping the values makes the rule
//     match MORE than the operator wrote: an event policy with no
//     attributes-match fires on every occurrence of the event.
//   - GATE-ESCAPE (flow flag, static-NAT destination-address,
//     forwarding-table export). A commit-time validator walked the same one
//     side the compiler did, so an INVALID value in any slot but the first
//     committed CLEAN. Each of these has a paired "bogus value in slot 2"
//     assertion — that half is the actual defect, and a fix that only restores
//     the value without extending the gate would leave it open. What the escape
//     COSTS differs per site and is stated at each test rather than assumed
//     uniform: for static-NAT `match destination-address` it is a lost
//     DIAGNOSTIC, not a dataplane fail-open, because only the first prefix is
//     ever lowered (see
//     TestStaticNATMatchAddresses6659TolerantPathValidatesEveryPrefix).
//
// Per CLAUDE.md, every flat-set case is built with ParseSetCommand +
// tree.SetPath, never NewParser (which merges all set lines into one node).

func setTree6659(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
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

func hierTree6659(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func mustCompile6659(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// --- FAIL-OPEN 1: event-options attributes-match (MATCH-WIDENING) -----------

// TestEventAttributesMatch6659PackedLeaf pins the fail-open the issue calls out:
// a PACKED-LEAF `attributes-match <event>.<attr> matches <value>;` carries the
// whole expression on the node's own Keys with NO children, and the arm read
// only Children — so the policy compiled with ZERO match constraints and fired
// on every occurrence of the event rather than the narrower set authored.
//
// The block and flat-set spellings already worked; they are asserted alongside
// as GREEN CONTROLS so a regression in the packed path is distinguishable from
// a regression in the reader as a whole.
func TestEventAttributesMatch6659PackedLeaf(t *testing.T) {
	cfg := mustCompile6659(t, hierTree6659(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        attributes-match ping_test_failed.test-owner matches Comcast;
    }
}`))
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("expected 1 event policy, got %d", len(cfg.EventOptions))
	}
	want := []string{"ping_test_failed.test-owner matches Comcast"}
	if got := cfg.EventOptions[0].AttributesMatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("packed-leaf attributes-match = %q, want %q "+
			"(empty means the policy matches EVERY occurrence of the event — fail-open)", got, want)
	}
}

func TestEventAttributesMatch6659BlockAndFlatSetControls(t *testing.T) {
	want := []string{
		"ping_test_failed.test-owner matches Comcast",
		"ping_test_failed.test-name matches wan",
	}
	block := mustCompile6659(t, hierTree6659(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        attributes-match {
            ping_test_failed.test-owner matches Comcast;
            ping_test_failed.test-name matches wan;
        }
    }
}`))
	if got := block.EventOptions[0].AttributesMatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("block attributes-match = %q, want %q", got, want)
	}
	flat := mustCompile6659(t, setTree6659(t,
		"set event-options policy p1 events ping_test_failed",
		"set event-options policy p1 attributes-match ping_test_failed.test-owner matches Comcast",
		"set event-options policy p1 attributes-match ping_test_failed.test-name matches wan",
	))
	if got := flat.EventOptions[0].AttributesMatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("flat-set attributes-match = %q, want %q", got, want)
	}
}

// TestEventAttributesMatch6659PackedLeafReachesValidator is the GATE-ESCAPE half
// of the same arm. Because the packed leaf compiled to zero constraints,
// validateEventAttributesMatch had nothing to walk, so an expression naming an
// UNKNOWN attribute field committed CLEAN. Restoring the value must also restore
// the gate's reach.
func TestEventAttributesMatch6659PackedLeafReachesValidator(t *testing.T) {
	_, err := CompileConfig(hierTree6659(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        attributes-match ping_test_failed.NOSUCHFIELD matches Comcast;
    }
}`))
	if err == nil {
		t.Fatal("packed-leaf attributes-match with an unknown attribute field committed CLEAN; " +
			"the compiler dropped the expression so the validator never saw it (gate escape)")
	}
	// Assert the ATTRIBUTES-MATCH gate's wording, not just that something
	// rejected the config. No other gate rejects this config today, but "only
	// one gate can fire" is precisely the assumption that broke the
	// forwarding-table guard once a second gate was added alongside it — an
	// `err != nil` assertion silently stops binding the moment that happens.
	const wantMsg = "unknown field"
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("rejected, but not by the attributes-match field validator.\n  got: %v\n  want a message containing %q", err, wantMsg)
	}
}

// --- FAIL-OPEN 2: event-options then change-configuration commands ----------

// TestEventChangeConfigCommands6659 covers every broken command spelling.
// The packed form compiled ZERO remediation commands. The unquoted BLOCK form
// truncated a command to its first word (`set`) because the arm read
// child.Name() — Keys[0] — instead of joining the child's Keys; that shape is
// not in the issue's table and was found by dumping the parsed AST.
//
// #6673 fold: the table was HIERARCHICAL-ONLY, which is why it did not catch
// that the flat-set bracket list fused its members into one string. Which of
// the node's own tail / a child's Keys a bracket lands on is decided by WHICH
// PARSER RAN, so a table that drives only one parser cannot see the other's
// shape. Every spelling is now driven through both where both exist.
func TestEventChangeConfigCommands6659(t *testing.T) {
	const cmd1 = "set system host-name foo"
	const cmd2 = "delete interfaces ge-0/0/0"
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{
			"hier packed single quoted",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; then { change-configuration {
                commands "set system host-name foo";
            } } } }`),
			[]string{cmd1},
		},
		{
			"hier packed bracket list",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; then { change-configuration {
                commands [ "set system host-name foo" "delete interfaces ge-0/0/0" ];
            } } } }`),
			[]string{cmd1, cmd2},
		},
		{
			// Landed on the node's own tail with no children, and the tail was
			// read PER TOKEN unconditionally — so one command became four
			// bare words, none of which carries a `set `/`delete ` prefix.
			"hier packed unquoted (four bare words pre-fold)",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; then { change-configuration {
                commands set system host-name foo;
            } } } }`),
			[]string{cmd1},
		},
		{
			"hier block unquoted (truncated to `set` pre-#6659)",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; then { change-configuration { commands {
                set system host-name foo;
            } } } } }`),
			[]string{cmd1},
		},
		{
			"hier block quoted (GREEN CONTROL — worked pre-#6659)",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; then { change-configuration { commands {
                "set system host-name foo";
                "delete interfaces ge-0/0/0";
            } } } } }`),
			[]string{cmd1, cmd2},
		},
		{
			// THE #6673 FOLD CASE. ParseSetCommand + SetPath put the whole
			// bracket on ONE CHILD's Keys, and the children branch joined it:
			// ["set system host-name foo delete interfaces ge-0/0/0"], a single
			// string that classifyPlan turns into a garbage set path.
			"flat-set bracket list",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 then change-configuration commands [ "set system host-name foo" "delete interfaces ge-0/0/0" ]`),
			[]string{cmd1, cmd2},
		},
		{
			"flat-set single quoted (GREEN CONTROL)",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 then change-configuration commands "set system host-name foo"`),
			[]string{cmd1},
		},
		{
			"flat-set single unquoted (GREEN CONTROL)",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 then change-configuration commands set system host-name foo`),
			[]string{cmd1},
		},
		{
			"flat-set repeated statements (GREEN CONTROL)",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 then change-configuration commands "set system host-name foo"`,
				`set event-options policy p1 then change-configuration commands "delete interfaces ge-0/0/0"`),
			[]string{cmd1, cmd2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if got := cfg.EventOptions[0].ThenCommands; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ThenCommands = %q, want %q — a fused entry is not a "+
					"lost command, it is a DIFFERENT command: classifyPlan "+
					"accepts it as a set path and the remediation applies "+
					"garbage where it previously applied the first command",
					got, tc.want)
			}
		})
	}
}

// TestEventMultiValueLeaf6673TokenBoundaryBothParsers is the #6673 fold's
// discriminator guard, and the reason the fold did not take the obvious fix.
//
// The obvious fix for the fused flat-set bracket is to declare `commands` and
// `attributes-match` `multi: true` in setSchema, so SetPath absorbs the bracket
// onto the node's own tail the way the hierarchical parser already does. That
// is measurably wrong on three counts and none of them is visible from the
// bracket case alone:
//
//  1. `multi` makes SetPath append a bracket's members to the node's Keys, so
//     `commands set system host-name foo` — an unquoted command — also lands on
//     the tail, where the per-token read shatters it into four bare words.
//  2. `multi` makes REPEATED flat-set statements distinct SIBLING nodes rather
//     than merging into one node's children, and compileEventOptions reaches
//     `commands` through ccNode.FindChild (singular), so every sibling after
//     the first is silently dropped — worse than master.
//  3. It cannot repair a config ALREADY PERSISTED in the child shape: the
//     configstore deserializes Nodes straight from JSON and SetPath never runs,
//     so the fused read would survive a reload of the very configs the fold
//     exists to fix.
//
// So the boundary is decided in the READER, once, for both the tail and the
// children — and this table is what pins it. The last group is the over-reach
// guard: a quoted VALUE inside an otherwise unquoted statement must stay part
// of ONE value. That is what rules out the simpler "any token containing a
// space means the group is a list" discriminator.
func TestEventMultiValueLeaf6673TokenBoundaryBothParsers(t *testing.T) {
	cmdsOf := func(cfg *Config) []string { return cfg.EventOptions[0].ThenCommands }
	amOf := func(cfg *Config) []string { return cfg.EventOptions[0].AttributesMatch }

	for _, tc := range []struct {
		name string
		tree *ConfigTree
		get  func(*Config) []string
		want []string
	}{
		// --- attributes-match: the fused flat-set bracket (F2) -------------
		{
			"am/flat-set bracket splits per member",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 attributes-match [ "ping_test_failed.test-owner matches Comcast" "ping_test_failed.test-name matches wan" ]`),
			amOf,
			[]string{"ping_test_failed.test-owner matches Comcast", "ping_test_failed.test-name matches wan"},
		},
		{
			"am/hier bracket splits per member (GREEN CONTROL)",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed;
                attributes-match [ "ping_test_failed.test-owner matches Comcast" "ping_test_failed.test-name matches wan" ]; } }`),
			amOf,
			[]string{"ping_test_failed.test-owner matches Comcast", "ping_test_failed.test-name matches wan"},
		},
		{
			"am/hier block (GREEN CONTROL)",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; attributes-match {
                ping_test_failed.test-owner matches Comcast; ping_test_failed.test-name matches wan; } } }`),
			amOf,
			[]string{"ping_test_failed.test-owner matches Comcast", "ping_test_failed.test-name matches wan"},
		},

		// --- OVER-REACH GUARD: a quoted value inside a bare statement ------
		// Tokens are [ping_test_failed.test-owner, matches, "Comcast Business"]. This is ONE
		// constraint. A discriminator keyed on "any token has a space" would
		// emit three, two of which are malformed and one of which silently
		// narrows the policy to the literal owner "Comcast Business" only.
		{
			"am/hier quoted VALUE stays one expression",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed;
                attributes-match ping_test_failed.test-owner matches "Comcast Business"; } }`),
			amOf,
			[]string{"ping_test_failed.test-owner matches Comcast Business"},
		},
		{
			"am/flat-set quoted VALUE stays one expression",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 attributes-match ping_test_failed.test-owner matches "Comcast Business"`),
			amOf,
			[]string{"ping_test_failed.test-owner matches Comcast Business"},
		},
		{
			"cmd/hier quoted VALUE stays one command",
			hierTree6659(t, `event-options { policy p1 { events ping_test_failed; then { change-configuration {
                commands set system host-name "foo bar"; } } } }`),
			cmdsOf,
			[]string{"set system host-name foo bar"},
		},
		{
			"cmd/flat-set quoted VALUE stays one command",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 then change-configuration commands set system host-name "foo bar"`),
			cmdsOf,
			[]string{"set system host-name foo bar"},
		},

		// --- a mixed bracket must SPLIT, so the bare member fails alone ----
		// Joining would fuse `bogus` onto a valid command and hand
		// classifyPlan a plausible set path to apply. Split, `bogus` reaches
		// the prefix check on its own and rejects the whole batch.
		{
			"cmd/flat-set mixed bracket splits so the bare member fails alone",
			setTree6659(t,
				"set event-options policy p1 events ping_test_failed",
				`set event-options policy p1 then change-configuration commands [ "set system host-name foo" bogus ]`),
			cmdsOf,
			[]string{"set system host-name foo", "bogus"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if got := tc.get(cfg); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("compiled values = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- FAIL-OPEN 3: security flow traceoptions flag (GATE-ESCAPE) -------------

func TestFlowTraceFlags6659BothShapes(t *testing.T) {
	want := []string{"basic-datapath", "session"}
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set bracket", setTree6659(t,
			"set security flow traceoptions flag [ basic-datapath session ]")},
		{"hier block", hierTree6659(t, `
security { flow { traceoptions { flag { basic-datapath; session; } } } }`)},
		{"hier one-per-line (GREEN CONTROL)", hierTree6659(t, `
security { flow { traceoptions { flag basic-datapath; flag session; } } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if cfg.Security.Flow.Traceoptions == nil {
				t.Fatal("no traceoptions compiled")
			}
			if got := cfg.Security.Flow.Traceoptions.Flags; !reflect.DeepEqual(got, want) {
				t.Fatalf("Flags = %q, want %q", got, want)
			}
		})
	}
}

// TestFlowTraceFlags6659UnknownFlagInAnySlotRejected is the GATE-ESCAPE half.
// validateFlowTraceFlagsAndFiltersAST read the same nodeVal the compiler did, so an
// unknown flag anywhere but the FIRST slot committed clean. Both orderings must
// now be rejected; the first-slot case is the control that already worked.
func TestFlowTraceFlags6659UnknownFlagInAnySlotRejected(t *testing.T) {
	for _, tc := range []struct{ name, cmd string }{
		{"bogus in SECOND slot (the escape)",
			"set security flow traceoptions flag [ basic-datapath totally-bogus-flag ]"},
		{"bogus in THIRD slot",
			"set security flow traceoptions flag [ basic-datapath session totally-bogus-flag ]"},
		{"bogus in FIRST slot (control — already rejected)",
			"set security flow traceoptions flag [ totally-bogus-flag basic-datapath ]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6659(t, tc.cmd))
			if err == nil {
				t.Fatal("unknown flow trace flag committed CLEAN (gate escape)")
			}
			// Assert the UNKNOWN-FLAG gate's wording. Same reasoning as the
			// attributes-match guard: no competing gate rejects this config
			// today, but a bare `err != nil` stops binding the moment one is
			// added, which is exactly how the forwarding-table guard went blind.
			const wantMsg = "unknown flow trace flag"
			if !strings.Contains(err.Error(), wantMsg) {
				t.Fatalf("rejected, but not by the unknown-flag gate.\n  got: %v\n  want a message containing %q", err, wantMsg)
			}
		})
	}
}

// --- FAIL-OPEN 4: static NAT match destination-address (GATE-ESCAPE) --------

// TestStaticNATMatchAddresses6659MultiRejected pins that a multi-valued
// `match destination-address` is REJECTED rather than silently collapsing to the
// first prefix. Pre-#6659 nodeVal kept only the first, so the remaining prefixes
// were neither translated nor validated — a malformed prefix in slot 2 committed
// clean.
func TestStaticNATMatchAddresses6659MultiRejected(t *testing.T) {
	const multiMsg = "`match destination-address` prefixes"
	for _, tc := range []struct{ name, addrs string }{
		{"two well-formed prefixes", "[ 192.0.2.1/32 192.0.2.2/32 ]"},
		{"malformed prefix in SECOND slot", "[ 192.0.2.1/32 not-an-address ]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6659(t,
				"set security nat static rule-set rs1 from zone untrust",
				"set security nat static rule-set rs1 rule r1 match destination-address "+tc.addrs,
				"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			))
			if err == nil {
				t.Fatal("multi-valued static-NAT match destination-address committed CLEAN; " +
					"only the first prefix would translate and the rest are silently ignored")
			}
			// Assert WHICH gate fired. At strict commit the multi-value gate
			// runs first and MASKS the prefix validator, so the malformed-slot-2
			// case is expected to report the multi message here, not a prefix
			// error. Pinning that keeps this subtest honest: it is a second
			// instance of the multi rejection, NOT evidence that the prefix gate
			// sees slot 2. The prefix gate's multi-slot reach is asserted on the
			// tolerant path instead — see
			// TestStaticNATMatchAddresses6659TolerantPathValidatesEveryPrefix.
			if !strings.Contains(err.Error(), multiMsg) {
				t.Fatalf("rejected, but not by the multi-value gate.\n  got: %v\n  want a message containing %q", err, multiMsg)
			}
		})
	}
}

// TestStaticNATMatchAddresses6659TolerantPathValidatesEveryPrefix is the real
// gate-escape guard for site 6, and it has to run on the TOLERANT path.
//
// At strict commit the multi-value gate rejects the list outright and fires
// BEFORE the prefix validator, so a malformed slot-2 prefix is unreachable there
// — which means a strict-path test cannot distinguish "the prefix gate reads
// every value" from "the prefix gate reads only the first". On the tolerant load
// / peer-sync path the multi-value gate downgrades to a warning and the config
// LOADS, so the prefix validator is the only place a malformed tail prefix can
// still be named.
//
// WHAT THE ESCAPE COSTS, stated because the tempting version is FALSE: this is
// NOT a last line of defence in front of the Rust dataplane. Only the FIRST
// prefix is ever lowered — the userspace snapshot builder sets
// `ExternalIP: rule.Match` (pkg/dataplane/userspace/nat_static.go) and
// MatchAddresses has no consumer outside these validators — so a malformed slot
// 2 is dropped by the Go lowering and never reaches `parse_nat_prefix`. What is
// lost when the tail escapes is the DIAGNOSTIC: the tolerant-path warning tells
// the operator to split the list into one rule per external prefix, and without
// this loop they would discover slot 2 is malformed only on the commit AFTER
// they follow that advice.
//
// Before #6659 that validator read the scalar rule.Match — the FIRST value — so
// the tail escaped it entirely. It now walks MatchAddresses.
func TestStaticNATMatchAddresses6659TolerantPathValidatesEveryPrefix(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6659(t,
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address [ 192.0.2.1/32 not-an-address ]",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
	))
	if err != nil {
		t.Fatalf("tolerant path must LOAD (no-brick, #1960), got: %v", err)
	}
	// Assert the PREFIX gate's distinctive wording, NOT merely that the bad
	// value appears somewhere in the warnings.
	//
	// Asserting `Contains(warnings, "not-an-address")` is ATTRIBUTION-BLIND and
	// silently vacuous here: the multi-value gate's own warning echoes the whole
	// authored list — "...prefixes ([192.0.2.1/32 not-an-address])..." — so the
	// bad token appears whether or not the prefix validator ever looked at slot
	// 2. Written that way this test stayed GREEN when the prefix validator was
	// mutated back to a scalar-only read, i.e. it did not bind the fix it is
	// named for. That is the same defect the reviewer found in
	// TestForwardingTableExport6659DanglingRefInAnySlot, reproduced here while
	// fixing it: whenever two gates can both react to one probe config, any
	// assertion they can BOTH satisfy proves nothing about which one fired.
	const prefixMsg = "is not a valid IP address or CIDR prefix"
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, prefixMsg) {
		t.Fatalf("the malformed SLOT-2 prefix escaped the PREFIX validator on the tolerant "+
			"path — it is reading only the first value.\nwant a warning containing %q\nwarnings:\n%s",
			prefixMsg, joined)
	}
	if !strings.Contains(joined, "not-an-address") {
		t.Fatalf("prefix complaint present but does not name the offending value:\n%s", joined)
	}
	// Negative control on the same path: a well-formed list warns about the
	// multi-value collapse but must NOT produce a prefix complaint.
	okCfg, err := CompileConfigLenient(setTree6659(t,
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address [ 192.0.2.1/32 192.0.2.2/32 ]",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
	))
	if err != nil {
		t.Fatalf("tolerant path must LOAD, got: %v", err)
	}
	if strings.Contains(strings.Join(okCfg.Warnings, "\n"), "is not a valid IP address or CIDR prefix") {
		t.Fatalf("well-formed prefixes produced a prefix-validity complaint:\n%s",
			strings.Join(okCfg.Warnings, "\n"))
	}
}

// staticNAT6659Trees builds one static-NAT probe in BOTH parser shapes, because
// the bracketed list collapses onto Keys[1:] in either and a fix that reads only
// one shape passes half of them (CLAUDE.md, #2419). The flat-set arm goes
// through ParseSetCommand + SetPath, never NewParser.
func staticNAT6659Trees(t *testing.T, match, then string) map[string]*ConfigTree {
	t.Helper()
	return map[string]*ConfigTree{
		"flat-set": setTree6659(t,
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address "+match,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix "+then,
		),
		"hier block": hierTree6659(t, `
security { nat { static { rule-set rs1 {
    from zone untrust;
    rule r1 {
        match { destination-address `+match+`; }
        then { static-nat { prefix `+then+`; } }
    }
} } } }`),
	}
}

// TestStaticNATMatchAddresses6659TolerantPathHostMaskEverySlot is the
// SCOPE guard for the widened prefix loop above.
//
// Widening the parse-validity check without widening the HOST-ROUTE check left
// the fix scoped narrower than the claim it shipped under: read scalar, the
// host-route requirement classified the whole rule off slot 1, so
// `[ 192.0.2.1/32 198.51.100.0/24 ]` produced NO host-route complaint at all
// while `198.51.100.0/24` on its own DID. A non-host prefix is a different
// failure from an unparseable one — it parses fine, so the parse loop above
// never touches it — and it is the more likely operator typo of the two.
//
// Tolerant path for the same reason its sibling is: at strict commit the
// multi-value gate rejects the list first and the tail is unreachable.
func TestStaticNATMatchAddresses6659TolerantPathHostMaskEverySlot(t *testing.T) {
	// The host-route complaint NAMING the slot-2 address as its own operand.
	//
	// Asserting on the bare address would be attribution-blind and vacuous: the
	// multi-value gate's warning echoes the entire authored list, so
	// "198.51.100.0/24" appears in the warnings whether or not the host-route
	// check ever looked past slot 1. Only the check itself emits this phrase.
	const hostMsg = `match destination-address "198.51.100.0/24" must be a host route`

	for name, tree := range staticNAT6659Trees(t, "[ 192.0.2.1/32 198.51.100.0/24 ]", "10.0.0.1/32") {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant path must LOAD (no-brick, #1960), got: %v", err)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, hostMsg) {
				t.Fatalf("the non-host SLOT-2 prefix escaped the HOST-ROUTE check — it is "+
					"classifying the rule off slot 1 only.\nwant a warning containing %q\nwarnings:\n%s",
					hostMsg, joined)
			}
		})
	}

	// Negative control on the same path: an all-host list warns about the
	// multi-value collapse but must NOT produce a host-route complaint.
	for name, tree := range staticNAT6659Trees(t, "[ 192.0.2.1/32 192.0.2.2/32 ]", "10.0.0.1/32") {
		t.Run("all-host control/"+name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant path must LOAD, got: %v", err)
			}
			if joined := strings.Join(cfg.Warnings, "\n"); strings.Contains(joined, "must be a host route") {
				t.Fatalf("all-host prefixes produced a host-route complaint:\n%s", joined)
			}
		})
	}
}

// TestStaticNATMatchAddresses6659TolerantPathZeroLengthBlockInAnySlot covers the
// other consumer of the block-pair classification: #5658's `/0` identity-NAT
// rejection. It reads a MATCH address, so it moved to the same per-address
// classification — otherwise a `0.0.0.0/0` authored in the tail is classified
// against slot 1, lands in neither the block branch nor the host branch, and
// disappears.
func TestStaticNATMatchAddresses6659TolerantPathZeroLengthBlockInAnySlot(t *testing.T) {
	const zeroMsg = `zero-length (/0) prefix (match destination-address "0.0.0.0/0"`
	for name, tree := range staticNAT6659Trees(t, "[ 192.0.2.0/24 0.0.0.0/0 ]", "0.0.0.0/0") {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant path must LOAD, got: %v", err)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, zeroMsg) {
				t.Fatalf("the /0 block pair authored in SLOT 2 escaped the #5658 check.\n"+
					"want a warning containing %q\nwarnings:\n%s", zeroMsg, joined)
			}
		})
	}
}

// TestStaticNATMatchAddresses6659ThenSideKeepsInstalledPair is the guard on the
// OTHER edge of that widening — the one that says how far it must NOT go.
//
// The block-pair classification is what EXEMPTS a side from the host-route
// requirement, so hoisting it to "any authored match address pairs with the
// target" would have been the obvious way to widen it. That would be a
// FAIL-OPEN: only slot 1 is ever lowered (`ExternalIP: rule.Match`), so
// `match [ 192.0.2.1/32 198.51.100.0/24 ] then 10.0.0.0/24` installs a
// host-vs-block pair, and an "any" flag would exempt the target from the
// host-route complaint that catches it today because slot 2 happens to pair with
// it. Checks whose operand is a match address widen per-address; checks whose
// operand is the `then` prefix keep the pair that installs.
func TestStaticNATMatchAddresses6659ThenSideKeepsInstalledPair(t *testing.T) {
	const thenMsg = `then static-nat prefix "10.0.0.0/24" must be a host route`
	for name, tree := range staticNAT6659Trees(t, "[ 192.0.2.1/32 198.51.100.0/24 ]", "10.0.0.0/24") {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant path must LOAD, got: %v", err)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, thenMsg) {
				t.Fatalf("the target's host-route complaint was SUPPRESSED by a tail match "+
					"address that happens to pair with it — the installed pair is "+
					"(%q, %q) and it is host-vs-block.\nwant a warning containing %q\nwarnings:\n%s",
					"192.0.2.1/32", "10.0.0.0/24", thenMsg, joined)
			}
		})
	}
}

// TestStaticNATMatchAddresses6659SingleUnchanged is the GREEN CONTROL: the
// ordinary single-prefix rule must compile exactly as before, with Match still
// carrying the prefix the dataplane snapshot lowers to.
func TestStaticNATMatchAddresses6659SingleUnchanged(t *testing.T) {
	cfg := mustCompile6659(t, setTree6659(t,
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
	))
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Match != "192.0.2.1/32" {
		t.Fatalf("Match = %q, want %q", rule.Match, "192.0.2.1/32")
	}
	if want := []string{"192.0.2.1/32"}; !reflect.DeepEqual(rule.MatchAddresses, want) {
		t.Fatalf("MatchAddresses = %q, want %q", rule.MatchAddresses, want)
	}
}

// --- FAIL-OPEN 5: routing-options forwarding-table export (GATE-ESCAPE) -----

// TestForwardingTableExport6659DanglingRefInAnySlot is the GATE-ESCAPE half and
// the sharpest case in this file: the reference gate exists precisely to stop a
// dangling export policy from silently disabling ECMP, and it read the same
// nodeVal the compiler did — so an undefined policy in slot 2 committed clean on
// exactly the scenario the gate's own error message describes.
//
// IT MUST ASSERT ON THE ERROR TEXT, not merely on `err != nil`. Two independent
// gates reject `export [ p1 p2 ]`: the multi-policy gate
// (validateForwardingTableExportSingleStrict) and the dangling-reference loop
// this test is named for. A bare `err != nil` cannot attribute the rejection, so
// restoring the one-sided slot-1 read left this test GREEN — the multi gate was
// satisfying it and the actual site-14 fix had no guard at all. Caught by
// mutating the dangling loop back to slot 1 and observing nothing red.
//
// Why it matters even though strict commit is safe either way: at strict commit
// the multi gate rejects the list outright, so a dangling slot-2 ref cannot
// survive. But the TOLERANT load / peer-sync path downgrades that gate to a
// warning and the config loads, and there the multi-slot dangling read is the
// only thing between a dangling reference and silently-disabled ECMP.
func TestForwardingTableExport6659DanglingRefInAnySlot(t *testing.T) {
	// The dangling gate's distinctive wording. The multi-policy gate says
	// "declares N policies" instead, so requiring this substring pins WHICH gate
	// fired.
	const danglingMsg = "references undefined policy-statement"
	const multiMsg = "declares 2 policies"

	for _, tc := range []struct {
		name    string
		defined string
	}{
		{"p2 UNDEFINED (the escape)", "p1"},
		{"p1 UNDEFINED (control — already rejected)", "p2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6659(t,
				"set policy-options policy-statement "+tc.defined+" then accept",
				"set routing-options forwarding-table export [ p1 p2 ]",
			))
			if err == nil {
				t.Fatal("dangling forwarding-table export policy committed CLEAN (gate escape)")
			}
			if !strings.Contains(err.Error(), danglingMsg) {
				t.Fatalf("rejected, but NOT by the dangling-reference gate.\n"+
					"  got:  %v\n"+
					"  want a message containing %q.\n"+
					"If this is the %q message, the multi-policy gate is satisfying this "+
					"test and the multi-slot dangling read is UNGUARDED — that is the exact "+
					"defect this assertion exists to catch.", err, danglingMsg, multiMsg)
			}
		})
	}
}

// TestForwardingTableExport6659MultiRejected pins that a multi-policy chain is
// rejected rather than silently collapsing: the FRR renderer honours exactly one
// export policy (resolveECMP), so the rest had no effect and nothing said so.
//
// It asserts the MULTI gate's own wording, for the same reason its sibling
// TestForwardingTableExport6659DanglingRefInAnySlot asserts the dangling gate's:
// both policies here are DEFINED, so today only the multi gate can reject this
// config — but a bare `err != nil` would also be satisfied by any future gate
// that happens to reject a two-policy export for an unrelated reason, and the
// multi rejection this test is named for could then be deleted with nothing
// going red. Attribution-blind assertions are exactly what let the one-sided
// slot-1 read survive on the dangling test.
func TestForwardingTableExport6659MultiRejected(t *testing.T) {
	const multiMsg = "forwarding-table export declares 2 policies"
	_, err := CompileConfig(setTree6659(t,
		"set policy-options policy-statement p1 then accept",
		"set policy-options policy-statement p2 then accept",
		"set routing-options forwarding-table export [ p1 p2 ]",
	))
	if err == nil {
		t.Fatal("multi-policy forwarding-table export committed CLEAN; only the first " +
			"policy renders, so the rest are silently ignored")
	}
	if !strings.Contains(err.Error(), multiMsg) {
		t.Fatalf("rejected, but NOT by the multi-policy gate.\n  got:  %v\n"+
			"  want a message containing %q", err, multiMsg)
	}
}

// TestForwardingTableExport6659SingleUnchanged is the GREEN CONTROL: a single
// export policy still compiles and still lands in the scalar the FRR renderer
// reads, so ECMP rendering is untouched by this change.
func TestForwardingTableExport6659SingleUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set", setTree6659(t,
			"set policy-options policy-statement p1 then accept",
			"set routing-options forwarding-table export p1")},
		{"hier block", hierTree6659(t, `
policy-options { policy-statement p1 { then accept; } }
routing-options { forwarding-table { export p1; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if got := cfg.RoutingOptions.ForwardingTableExport; got != "p1" {
				t.Fatalf("ForwardingTableExport = %q, want %q", got, "p1")
			}
			if want := []string{"p1"}; !reflect.DeepEqual(cfg.RoutingOptions.ForwardingTableExports, want) {
				t.Fatalf("ForwardingTableExports = %q, want %q", cfg.RoutingOptions.ForwardingTableExports, want)
			}
		})
	}
}

// --- proxy-ARP address list (value-drop + the validator the widened read
// --- required) --------------------------------------------------------------

// TestProxyARPAddresses6659BothShapes pins the proxy-ARP list. The drop it
// guards is a PURE VALUE-DROP rather than a gate escape — the firewall answered
// ARP for one address of the authored set and stayed silent for the rest.
//
// The earlier revision of this comment claimed a malformed address in the FIRST
// slot "commits clean too (asserted below)". Nothing below asserted it, and the
// statement is no longer true either way: restoring the tail values means a
// malformed one now MATERIALISES into ProxyARPEntry.Addresses instead of being
// dropped at compile, so this PR had to add the missing commit-time validator in
// the same change. That validator, and the acceptance boundary it draws, are
// asserted for real in TestProxyARPAddresses6659MalformedRejected — including
// the first-slot case, which is the hole that predates #6659.
func TestProxyARPAddresses6659BothShapes(t *testing.T) {
	want := []string{"192.0.2.1/32", "192.0.2.2/32"}
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set bracket", setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address [ 192.0.2.1 192.0.2.2 ]")},
		{"hier block", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address { 192.0.2.1; 192.0.2.2; } } } } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if len(cfg.Security.NAT.ProxyARP) != 1 {
				t.Fatalf("expected 1 proxy-arp entry, got %d", len(cfg.Security.NAT.ProxyARP))
			}
			if got := cfg.Security.NAT.ProxyARP[0].Addresses; !reflect.DeepEqual(got, want) {
				t.Fatalf("Addresses = %q, want %q", got, want)
			}
		})
	}
}

// proxyARP6659Trees builds one proxy-ARP `address` probe in BOTH parser shapes.
func proxyARP6659Trees(t *testing.T, addrs ...string) map[string]*ConfigTree {
	t.Helper()
	bracket := "[ " + strings.Join(addrs, " ") + " ]"
	var block strings.Builder
	for _, a := range addrs {
		block.WriteString(a)
		block.WriteString("; ")
	}
	return map[string]*ConfigTree{
		"flat-set bracket": setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address "+bracket),
		"hier block": hierTree6659(t,
			"security { nat { proxy-arp { interface ge-0/0/0 { address { "+block.String()+"} } } } }"),
	}
}

// TestProxyARPAddresses6659MalformedRejected is the validator the widened read
// REQUIRED, and the assertion the previous revision of this file only claimed.
//
// Restoring the tail addresses changed what a malformed one does. It used to be
// discarded at compile (nodeVal kept slot 1); it now lands in
// ProxyARPEntry.Addresses, and pkg/dataplane/proxyarp.go parses each entry with
// netip.ParsePrefix, logs a bounded warning and SKIPS the failures — a
// silently-inert address that answers no ARP/ND, so inbound traffic to it is
// never drawn to this firewall. A widened read with an unwidened validator
// converts a value-drop into that inert entry, which is why the gate lands in
// the same change rather than as a follow-up.
//
// Both slots are covered. Slot 2 is the one #6659 exposed; slot 1 is the hole
// that predates it, because proxy-ARP addresses carried no commit-time
// validator at all.
func TestProxyARPAddresses6659MalformedRejected(t *testing.T) {
	// The gate's own wording, naming the offending value. Nothing else in the
	// compiler emits it, so a rejection carrying this phrase can only be this
	// gate — no other gate can satisfy the assertion on the operator's behalf.
	const gateMsg = `security nat proxy-arp interface "ge-0/0/0" address "bogus/32" is not a valid IP address or CIDR prefix`

	for _, slot := range []struct {
		name  string
		addrs []string
	}{
		{"malformed in SECOND slot (exposed by the widened read)", []string{"192.0.2.1", "bogus"}},
		{"malformed in FIRST slot (hole that predates #6659)", []string{"bogus", "192.0.2.1"}},
	} {
		for name, tree := range proxyARP6659Trees(t, slot.addrs...) {
			t.Run("strict/"+slot.name+"/"+name, func(t *testing.T) {
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatal("a malformed proxy-ARP address committed CLEAN; the installer " +
						"skips it, so the firewall answers no ARP/ND for it and nothing said so")
				}
				if !strings.Contains(err.Error(), gateMsg) {
					t.Fatalf("rejected, but NOT by the proxy-ARP address gate.\n  got:  %v\n"+
						"  want a message containing %q", err, gateMsg)
				}
			})
		}
	}

	// The TOLERANT load / peer-sync path must warn rather than reject (#1960
	// no-brick: an already-persisted config with a bad proxy-ARP address has to
	// keep booting). Covered separately from strict because a strict gate that
	// fires first can mask an unvalidated tolerant path entirely — the tolerant
	// path is where a downgrade that silently drops the diagnostic would hide.
	for name, tree := range proxyARP6659Trees(t, "192.0.2.1", "bogus") {
		t.Run("tolerant/"+name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant path must LOAD (no-brick, #1960), got: %v", err)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, gateMsg) {
				t.Fatalf("the malformed proxy-ARP address produced no gate warning on the "+
					"tolerant path.\nwant a warning containing %q\nwarnings:\n%s", gateMsg, joined)
			}
			// And the entry still loads, unchanged — the downgrade must not
			// quietly become a drop.
			if len(cfg.Security.NAT.ProxyARP) != 1 {
				t.Fatalf("expected 1 proxy-arp entry on the tolerant path, got %d",
					len(cfg.Security.NAT.ProxyARP))
			}
			if want := []string{"192.0.2.1/32", "bogus/32"}; !reflect.DeepEqual(
				cfg.Security.NAT.ProxyARP[0].Addresses, want) {
				t.Fatalf("tolerant Addresses = %q, want %q",
					cfg.Security.NAT.ProxyARP[0].Addresses, want)
			}
		})
	}

	// GREEN CONTROLS: the gate must not reject anything the installer accepts.
	// netip.ParsePrefix is the installer's own call, so these are the shapes
	// that reach it intact — a bare v4 address (compiler appends /32), an
	// explicit CIDR block, and a v6 address.
	//
	// #6559: the block is a /30 rather than the /24 this control used to carry,
	// and the expectation now names its two usable hosts. Before #6559 a block
	// passed through verbatim and installed ONE proxy neighbour for the address
	// as authored — for a canonical prefix that is the network address, which no
	// host ARPs for. This control therefore doubles as the positive assertion
	// that a multi-host prefix expands, with the network and broadcast addresses
	// excluded (198.51.100.0 and .3 are absent below by construction).
	for name, tree := range proxyARP6659Trees(t, "192.0.2.1", "198.51.100.0/30", "2001:db8::1/128") {
		t.Run("well-formed control/"+name, func(t *testing.T) {
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("well-formed proxy-ARP addresses rejected: %v", err)
			}
			want := []string{
				"192.0.2.1/32",
				"198.51.100.1/32", "198.51.100.2/32",
				"2001:db8::1/128",
			}
			if got := cfg.Security.NAT.ProxyARP[0].Addresses; !reflect.DeepEqual(got, want) {
				t.Fatalf("Addresses = %q, want %q", got, want)
			}
		})
	}
}

// --- aliasing audit (carried forward from #6391) ----------------------------

// TestMultiValueLeaf6659NoSharedBackingStore applies the #6391 aliasing hazard to
// three of the arms this PR touches.
//
// SCOPE, because an earlier revision of this comment claimed "every arm this PR
// touches" and the three subtests below do not cover that. Exercised:
// event-options `attributes-match` (compiler_services.go:1914), proxy-ARP
// `address` (compiler_nat_source.go:160) and static-NAT `match
// destination-address` (compiler_nat_static.go:750). NOT exercised:
// EventPolicy.ThenCommands, TraceOptions.Flags and
// RoutingOptionsConfig.ForwardingTableExports — the last two are single-instance
// leaves (one `traceoptions` block per section; one global `forwarding-table
// export`) so the two-sibling probe this test is built on cannot be written for
// them at all, but ThenCommands CAN have siblings and simply is not covered
// here. For all three the argument is the structural one below, unverified by a
// probe.
//
// On #6391 a fan that stored ONE parsed *HostInboundTraffic under N map keys
// aliased a single value across all of them, because mergeHostInbound returns
// src unchanged when dst is nil — so a later in-place merge on one key surfaced
// on the others. That hazard needs two ingredients: a shared STRUCT POINTER, and
// a mutator that writes through it.
//
// None of the six accumulation targets here has either. Each is a []string
// (EventPolicy.AttributesMatch / ThenCommands, TraceOptions.Flags,
// ProxyARPEntry.Addresses, StaticNATRule.MatchAddresses,
// RoutingOptionsConfig.ForwardingTableExports) filled by spread-appending a
// FRESHLY RETURNED slice, so `append` copies the elements and the strings are
// immutable; and the two scalars (Match, ForwardingTableExport) are string copies
// of index 0, not slice aliases. That is a structural argument, so this test
// pins the observable consequence instead of restating it: sibling instances that
// each author their own values stay independent, with no value bleeding across.
func TestMultiValueLeaf6659NoSharedBackingStore(t *testing.T) {
	t.Run("two event policies stay independent", func(t *testing.T) {
		cfg := mustCompile6659(t, hierTree6659(t, `
event-options {
    policy pA { events ping_test_failed; attributes-match ping_test_failed.test-owner matches Comcast; }
    policy pB { events ping_test_completed; attributes-match ping_test_completed.test-name matches wan; }
}`))
		if len(cfg.EventOptions) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(cfg.EventOptions))
		}
		byName := map[string][]string{}
		for _, p := range cfg.EventOptions {
			byName[p.Name] = p.AttributesMatch
		}
		if want := []string{"ping_test_failed.test-owner matches Comcast"}; !reflect.DeepEqual(byName["pA"], want) {
			t.Fatalf("pA AttributesMatch = %q, want %q", byName["pA"], want)
		}
		if want := []string{"ping_test_completed.test-name matches wan"}; !reflect.DeepEqual(byName["pB"], want) {
			t.Fatalf("pB AttributesMatch = %q, want %q", byName["pB"], want)
		}
	})

	t.Run("two proxy-arp interfaces stay independent", func(t *testing.T) {
		cfg := mustCompile6659(t, setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address [ 192.0.2.1 192.0.2.2 ]",
			"set security nat proxy-arp interface ge-0/0/1 address [ 198.51.100.1 198.51.100.2 ]",
		))
		got := map[string][]string{}
		for _, p := range cfg.Security.NAT.ProxyARP {
			got[p.Interface] = p.Addresses
		}
		if want := []string{"192.0.2.1/32", "192.0.2.2/32"}; !reflect.DeepEqual(got["ge-0/0/0"], want) {
			t.Fatalf("ge-0/0/0 = %q, want %q", got["ge-0/0/0"], want)
		}
		if want := []string{"198.51.100.1/32", "198.51.100.2/32"}; !reflect.DeepEqual(got["ge-0/0/1"], want) {
			t.Fatalf("ge-0/0/1 = %q, want %q", got["ge-0/0/1"], want)
		}
		// Pointer independence of the backing arrays, the assertion that would
		// have caught the #6391 shape on day one (value equality would not).
		a, b := cfg.Security.NAT.ProxyARP[0].Addresses, cfg.Security.NAT.ProxyARP[1].Addresses
		if len(a) > 0 && len(b) > 0 && &a[0] == &b[0] {
			t.Fatal("two proxy-arp entries share the SAME Addresses backing array")
		}
	})

	t.Run("two static NAT rules stay independent", func(t *testing.T) {
		cfg := mustCompile6659(t, setTree6659(t,
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r2 match destination-address 192.0.2.9/32",
			"set security nat static rule-set rs1 rule r2 then static-nat prefix 10.0.0.9/32",
		))
		rules := cfg.Security.NAT.Static[0].Rules
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}
		for _, tc := range []struct{ name, addr string }{{"r1", "192.0.2.1/32"}, {"r2", "192.0.2.9/32"}} {
			for _, r := range rules {
				if r.Name != tc.name {
					continue
				}
				if r.Match != tc.addr || !reflect.DeepEqual(r.MatchAddresses, []string{tc.addr}) {
					t.Fatalf("%s: Match=%q MatchAddresses=%q, want %q",
						tc.name, r.Match, r.MatchAddresses, tc.addr)
				}
			}
		}
		if a, b := rules[0].MatchAddresses, rules[1].MatchAddresses; len(a) > 0 && len(b) > 0 && &a[0] == &b[0] {
			t.Fatal("two static NAT rules share the SAME MatchAddresses backing array")
		}
	})
}

// TestProxyARPAddresses6659RangeStillExpands is the GREEN CONTROL that the list
// reader did not break the `address <low> to <high>` range spellings, which are
// handled by earlier branches and must keep expanding.
func TestProxyARPAddresses6659RangeStillExpands(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set range", setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address 192.0.2.1 to 192.0.2.3")},
		{"hier range", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address 192.0.2.1 to 192.0.2.3; } } } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			got := cfg.Security.NAT.ProxyARP[0].Addresses
			want := []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("range expansion = %q, want %q "+
					"(a bare list reader would emit the literal token \"to\" as an address)", got, want)
			}
		})
	}
}
