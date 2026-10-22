package config

import (
	"strings"
	"testing"
)

// #7216: a static-NAT rule whose SELECTED `match destination-address` is empty
// committed clean, and the dataplane dropped the WHOLE mapping.
//
// MEASURED AT 7230dcdcd, over nat7145Base — the same base config #7145 swept —
// with the explicitly quoted empty value `""`:
//
//	kind         leaf                  master     here
//	source       source-address        rejected   rejected   (#7145, untouched)
//	source       destination-address   rejected   rejected   (#7145, untouched)
//	destination  source-address        rejected   rejected   (#7145, untouched)
//	destination  destination-address   rejected   rejected   (#3228, untouched)
//	static       source-address        rejected   rejected   (#7145, untouched)
//	static       destination-address   ACCEPTED   rejected   <- #7216
//
// WHAT THE EMPTY VALUE MEANS HERE, established before rejecting it. #6673 gave
// an empty slot in MatchAddresses a deliberate meaning and this change does not
// touch it. That meaning is a COUNTING rule: multiLeafAuthoredValues keeps empty
// slots so the list always contains what nodeVal selected, and the cardinality
// gate must therefore count only NON-EMPTY values — `destination-address
// 192.0.2.1/32` followed by `destination-address [ ]` authors ONE prefix and
// blanks it, and counting the blank as a second prefix would invent a rejection
// that gate was never meant to make.
//
// That is a rule about the LIST. It says nothing about whether a blank
// SELECTION is a shippable rule, and #6673 itself already answers that the
// other way: its `rule.Match == ""` arm rejects the blank selection outright,
// wording it "the selected value is EMPTY, so NONE of them takes effect and the
// dataplane drops the rule". #6673 could only see that case when two or more
// prefixes were also listed, because the arm sits inside `len(addrs) > 1`.
// TestStaticNATBlankExternalPrefix7216PreservesTheCardinalityContract below is
// what holds #6673's half in place while this one closes the rest.
//
// WHY THE BLANK IS NOT INERT. compileNATStatic selects rule.Match from the
// authored value, buildStaticNATSnapshots lowers it as
// StaticNATRuleSnapshot.ExternalIP, and the Rust parse_nat_prefix returns None
// on an empty string, so from_snapshots `continue`s and drops the ENTIRE
// mapping, recorded only as a bounded NAT parse-error counter (#4718).
//
// Per CLAUDE.md every flat-set case is built with ParseSetCommand + SetPath,
// never NewParser (which merges all set lines into one node).

// nat7216StaticCmds builds a static-NAT corpus over nat7145Base: the rule-set
// scaffolding, a `then static-nat prefix` target, and whatever match statements
// the case authors.
func nat7216StaticCmds(extra ...string) []string {
	cmds := append([]string{}, nat7145Base...)
	cmds = append(cmds,
		"set security nat static rule-set RT from zone trust",
		"set security nat static rule-set RT rule R1 then static-nat prefix 10.0.1.5/32",
	)
	return append(cmds, extra...)
}

// TestStaticNATBlankExternalPrefix7216RejectsEverySlot is the ASYMMETRY guard:
// the issue's own 3x2 census with the quoted blank. Five cells are pre-existing
// gates asserted as CONTROLS so the table is a complete (kind x leaf) census
// rather than a list of the one cell this change touches, and so a regression
// that silently removed one of the older gates fails here too.
//
// RED-on-revert: drop the validateStaticNATSelectedMatchAddressStrict call from
// the NAT uniform-gates run and the static/destination-address cell fails at
// "committed CLEAN".
func TestStaticNATBlankExternalPrefix7216RejectsEverySlot(t *testing.T) {
	const blank = `""`
	for _, k := range nat7145Kinds() {
		for _, leaf := range []string{"source-address", "destination-address"} {
			t.Run(k.name+"/"+leaf, func(t *testing.T) {
				tree := nat7145Tree(t, nat7145Cmds(k, leaf, blank))
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("`security nat %s rule-set %s rule R1 match %s \"\"` committed "+
						"CLEAN. On static NAT that lowers ExternalIP as \"\" and the Rust "+
						"parse_nat_prefix drops the WHOLE mapping — the operator authored a "+
						"rule that does not exist at runtime, with no commit error and no "+
						"warning (#7216)", k.name, k.ruleSet, leaf)
				}
				if !strings.Contains(err.Error(), k.ruleSet) || !strings.Contains(err.Error(), "R1") {
					t.Errorf("the rejection must name the rule-set (%q) and rule (\"R1\") so the "+
						"operator can find it in a long rule-set; got: %v", k.ruleSet, err)
				}
			})
		}
	}
}

// TestStaticNATBlankExternalPrefix7216RejectsEveryAuthoringShape is the reason
// this gate binds the SELECTION rather than the keystrokes.
//
// Four shapes reach a surviving static-NAT rule with rule.Match == "". All four
// were measured committing clean at 7230dcdcd and all four are dropped
// identically by the dataplane. The issue names only the first. A gate that
// refused the quoted blank and passed the omitted leaf would be binding the
// authoring shape rather than the defect, and would sit one keystroke away from
// being defeated — so the property under test is "the selected external prefix
// is empty", not "the operator typed a pair of quotes".
//
// The message must distinguish the two REMEDIES, because they differ: a blank
// slot is filled in, an absent statement is added. Sending an operator to look
// for a line that is not there is its own defect.
func TestStaticNATBlankExternalPrefix7216RejectsEveryAuthoringShape(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extra      []string
		wantRemedy string
	}{
		{"quoted empty value", []string{
			`set security nat static rule-set RT rule R1 match destination-address ""`,
		}, "give the rule the external prefix it translates"},
		{"the leaf with no value at all", []string{
			"set security nat static rule-set RT rule R1 match destination-address ",
		}, "give the rule the external prefix it translates"},
		{"a valid prefix then a blank that re-selects", []string{
			"set security nat static rule-set RT rule R1 match destination-address 203.0.113.1/32",
			"set security nat static rule-set RT rule R1 match destination-address [ ]",
		}, "give the rule the external prefix it translates"},
		{"no match destination-address at all", nil,
			"add `match destination-address <prefix>` to the rule"},
		{"no match destination-address, but a source-address", []string{
			"set security nat static rule-set RT rule R1 match source-address 10.0.0.0/8",
		}, "add `match destination-address <prefix>` to the rule"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := nat7145Tree(t, nat7216StaticCmds(tc.extra...))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("committed CLEAN with an empty selected `match " +
					"destination-address`; the rule lowers ExternalIP as \"\" and the " +
					"dataplane drops the whole mapping, so it does not exist at runtime " +
					"(#7216)")
			}
			if !strings.Contains(err.Error(), tc.wantRemedy) {
				t.Errorf("the rejection must carry the remedy that fits the shape (%q) — a "+
					"blank slot is FILLED IN, an absent statement is ADDED, and sending the "+
					"operator to look for a line that is not there is its own defect; got: %v",
					tc.wantRemedy, err)
			}
			if !strings.Contains(err.Error(), "RT") || !strings.Contains(err.Error(), "R1") {
				t.Errorf("the rejection must name the rule-set and rule; got: %v", err)
			}
		})
	}
}

// TestStaticNATBlankExternalPrefix7216PreservesTheCardinalityContract is the
// #6673 half, asserted HERE rather than left to the older file, because #7216
// is exactly the change that could silently take it away.
//
// #6673's property is that an empty slot is a SELECTION and not a second
// prefix: the cardinality gate counts only non-empty, distinct values. If
// #7216's gate had been written as "reject any empty value in MatchAddresses"
// it would have looked identical on every fixture above and quietly re-invented
// the rejection #6673 removed. It reads rule.Match — the SELECTION — instead,
// and this is what says so.
func TestStaticNATBlankExternalPrefix7216PreservesTheCardinalityContract(t *testing.T) {
	// (a) A blank slot beside a prefix that IS selected must still commit. The
	//     blank is authored FIRST inside the bracket so nodeVal selects the
	//     prefix, not the blank.
	t.Run("blank slot, non-blank selection, still commits", func(t *testing.T) {
		tree := parseHierText(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 192.0.2.1/32 "" ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("#7216 must key on the SELECTED value, not on any empty slot in the "+
				"list. An empty slot beside a selected prefix is #6673's authored blank "+
				"selection artifact and has always committed; rejecting it re-invents the "+
				"rejection #6673 removed: %v", err)
		}
		if got := cfg.Security.NAT.Static[0].Rules[0].Match; got != "192.0.2.1/32" {
			t.Fatalf("Match = %q, want %q — the fixture must actually SELECT the prefix, "+
				"else this cell is vacuous", got, "192.0.2.1/32")
		}
	})

	// (b) A repeated identical prefix is ONE prefix, not a cardinality
	//     violation (#6673 fold) — still true with #7216 in place.
	t.Run("repeated identical prefix still commits", func(t *testing.T) {
		tree := parseHierText(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 192.0.2.1/32; destination-address 192.0.2.1/32; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("a repeated identical prefix authors ONE external prefix (#6673): %v", err)
		}
	})

	// (c) The 2+-prefix blank-selection shape must keep the CARDINALITY gate's
	//     richer message, which can name the prefixes being passed over. #7216
	//     runs after it precisely so this diagnosis is not replaced by a poorer
	//     one.
	t.Run("two prefixes with a blank selection keeps the #6659 message", func(t *testing.T) {
		tree := nat7145Tree(t, nat7216StaticCmds(
			`set security nat static rule-set RT rule R1 match destination-address [ "" 203.0.113.1/32 198.51.100.1/32 ]`))
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("a rule declaring two external prefixes with a BLANK selection must be " +
				"rejected (#6659/#6673)")
		}
		if !strings.Contains(err.Error(), "declares 2") {
			t.Fatalf("#7216 must run AFTER the cardinality gate so this shape keeps the "+
				"message that can name the prefixes being passed over; got: %v", err)
		}
	})
}

// TestStaticNATBlankExternalPrefix7216ExemptionsKeepTheirOwnGate pins the two
// exemptions, and pins them as ALREADY-COVERED rather than as holes.
//
// An exemption is only safe if something else refuses the same shape. Both were
// measured at 7230dcdcd before being exempted:
//
//   - NPTv6 lowers through buildNptv6Snapshots, not the static_nat table, and
//     its own gate already refuses an empty or absent match with a
//     family-specific message.
//   - `then static-nat inet` is refused outright by #5859 whether or not a
//     match is present.
//
// Both are asserted to still REJECT — the cell fails if an exemption ever turns
// into a hole — and to keep their OWN wording, since that is the whole reason
// for skipping them.
func TestStaticNATBlankExternalPrefix7216ExemptionsKeepTheirOwnGate(t *testing.T) {
	for _, tc := range []struct {
		name, wantMsg string
		then          string
		extra         []string
	}{
		{"nptv6, no match", "not a valid IPv6 prefix for nptv6-prefix translation",
			"set security nat static rule-set RT rule R1 then static-nat nptv6-prefix 2001:db8:1::/48", nil},
		{"nptv6, quoted blank match", "not a valid IPv6 prefix for nptv6-prefix translation",
			"set security nat static rule-set RT rule R1 then static-nat nptv6-prefix 2001:db8:1::/48",
			[]string{`set security nat static rule-set RT rule R1 match destination-address ""`}},
		{"inet (NAT64 keyword), no match", "#5859",
			"set security nat static rule-set RT rule R1 then static-nat inet", nil},
		{"inet (NAT64 keyword), quoted blank match", "#5859",
			"set security nat static rule-set RT rule R1 then static-nat inet",
			[]string{`set security nat static rule-set RT rule R1 match destination-address ""`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append([]string{}, nat7145Base...)
			cmds = append(cmds, "set security nat static rule-set RT from zone trust", tc.then)
			cmds = append(cmds, tc.extra...)
			_, err := CompileConfig(nat7145Tree(t, cmds))
			if err == nil {
				t.Fatalf("#7216 EXEMPTS this shape, so something else must refuse it — an " +
					"exemption whose sibling gate has gone away is a hole, not a scope " +
					"decision")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("the exempted shape must keep its OWN gate's message (%q) — that is "+
					"the entire reason #7216 skips it rather than firing first with a poorer "+
					"diagnosis; got: %v", tc.wantMsg, err)
			}
		})
	}
}

// TestStaticNATBlankExternalPrefix7216AcceptsValidRules is the OVER-REJECTION
// guard: a widened validator that refuses a rule the dataplane installs bricks
// the operator's next commit on a box that was translating correctly (#1960).
//
// Every shape here has a non-empty selected external prefix, so every one must
// still commit.
func TestStaticNATBlankExternalPrefix7216AcceptsValidRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"host prefix", []string{
			"set security nat static rule-set RT rule R1 match destination-address 203.0.113.1/32"}},
		{"bare host address", []string{
			"set security nat static rule-set RT rule R1 match destination-address 203.0.113.1"}},
		{"with a source-address too", []string{
			"set security nat static rule-set RT rule R1 match source-address 10.0.0.0/8",
			"set security nat static rule-set RT rule R1 match destination-address 203.0.113.1/32"}},
		{"blank first, prefix selected after", []string{
			`set security nat static rule-set RT rule R1 match destination-address ""`,
			"set security nat static rule-set RT rule R1 match destination-address 203.0.113.1/32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(nat7145Tree(t, nat7216StaticCmds(tc.extra...)))
			if err != nil {
				t.Fatalf("a static-NAT rule with a NON-EMPTY selected external prefix was "+
					"REJECTED; the dataplane installs it, so refusing it bricks the next "+
					"commit on a working box (#1960): %v", err)
			}
			if got := cfg.Security.NAT.Static[0].Rules[0].Match; got == "" {
				t.Fatalf("fixture is vacuous: it compiled with Match = \"\", which is the very " +
					"shape #7216 rejects — the cell proves nothing about over-rejection")
			}
		})
	}
}

// TestStaticNATBlankExternalPrefix7216LenientWarnsAndKeeps is the #1960
// no-brick half at the compiler: the tolerant path must WARN, not fail, and
// must leave rule.Match exactly as it was.
//
// Match is asserted unchanged because the dataplane's behaviour on a
// leniently-loaded config must be identical to what it was before this gate —
// it already drops the rule, so a tolerated load is no worse off. A tolerant
// path that "helpfully" substituted something for the blank would change what
// installs on a box that was only being warned at.
//
// RED-on-revert: remove the lenientFirewallRefs downgrade at the call site and
// this fails at "the tolerant path REJECTED".
func TestStaticNATBlankExternalPrefix7216LenientWarnsAndKeeps(t *testing.T) {
	tree := nat7145Tree(t, nat7216StaticCmds(
		`set security nat static rule-set RT rule R1 match destination-address ""`))

	// Precondition: the SAME corpus is refused by the strict path, else the
	// tolerant assertion below is vacuous.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("precondition: the strict path must REJECT this corpus")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path REJECTED a config carrying a blanked external prefix. "+
			"That value committed clean on every build before this gate, so boxes carrying "+
			"one exist by construction; failing the compile leaves ActiveConfig() nil and "+
			"drops the box into the bootstrap/lifeline state (#1960): %v", err)
	}
	if cfg == nil {
		t.Fatal("the tolerant path returned a nil config; a silent nil is the same brick " +
			"as an error")
	}
	var warn string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "RT") && strings.Contains(w, "#7216") {
			warn = w
			break
		}
	}
	if warn == "" {
		t.Fatalf("the tolerant path must WARN, naming the rule — a silent tolerate is the "+
			"pre-#7216 behaviour, which is exactly the defect. warnings: %v", cfg.Warnings)
	}
	if !strings.Contains(warn, "DROPPED ENTIRELY") {
		t.Errorf("the warning must say the rule is dropped ENTIRELY; an operator who reads "+
			"it as a narrowing will look for partial translation that does not exist: %s", warn)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].Match; got != "" {
		t.Fatalf("tolerant-path Match = %q, want \"\". The tolerant path must leave the "+
			"lowered value ALONE so behaviour is identical to before this gate existed; "+
			"substituting something for the blank would change what installs on a box that "+
			"is only being warned at", got)
	}
}
