package config

import (
	"strings"
	"testing"
)

// #5628 (codex-review-181 M16): a source- or destination-NAT rule's complete
// `then {}` block must carry EXACTLY ONE NAT-terminal translation action —
// SNAT: `source-nat interface` | `source-nat pool <p>` | `source-nat off`;
// DNAT: `destination-nat pool <p>` | `destination-nat off`. Before the fix the
// schema permitted a block with ZERO actions (actionless: the snapshot builder
// installs no translation and the rule does not stop evaluation, so an intended
// `off` exemption silently disappears and the traffic falls through —
// translated by a later broader rule if one matches, otherwise left
// untranslated) or TWO+ mutually-exclusive actions (the
// compiler silently picked one by packed-key / child order, so an exemption
// could publish as a translation — the inverse of the authored action).
//
// validateNATTerminalActionCardinalityStrict hard-rejects both at strict commit
// (CompileConfig); the tolerant load / peer-sync path (CompileConfigLenient)
// downgrades to a warning (#1960 no-brick). Duplicate `then` CONTAINERS remain
// #3850's intentional last-wins merge and must NOT be rejected.
//
// RED on revert: reverting the gate (validateNATTerminalActionCardinalityStrict
// + its runUniformGates call) makes CompileConfig ACCEPT the zero/two-action
// configs, so every "want reject" case fails; reverting the compiler_nat_source
// / compiler_nat_destination hierarchical setter change (independent `if`s back
// to the `else if` chain) makes a single-node `source-nat { interface; pool p }`
// resolve to one field again, so the hierarchical two-action cases fail.

// compileHier parses hierarchical Junos text and strict-compiles it.
func compileHier5628(t *testing.T, cfgText string) (*Config, error) {
	t.Helper()
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	return CompileConfig(tree)
}

// wantCardinalityReject asserts CompileConfig rejected with the #5628 message.
func wantCardinalityReject5628(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: CompileConfig ACCEPTED a malformed NAT `then` block; want a "+
			"#5628 terminal-action-cardinality rejection (RED on revert: pre-fix "+
			"accepted 0/2 actions)", name)
	}
	if !strings.Contains(err.Error(), "translation action") {
		t.Fatalf("%s: CompileConfig rejected with the wrong error %q; want the #5628 "+
			"terminal-action-cardinality message", name, err.Error())
	}
}

// TestNATTerminalActionMessageContent_6820 binds what the two rejection
// messages SAY, not merely that they fire.
//
// wantCardinalityReject5628 matches on "translation action", which both arities
// share and neither owns. That left the message bodies content-unbound: #6820
// rewrote the 2+-action text — it used to claim "the compiler would silently
// pick one by packed-key/child order, so an intended exemption can publish as a
// translation", a mechanism the compiler stopped using at #5628 and which the
// same file's CONTRADICTORY bullet already contradicted — and the whole edit
// landed with no test able to see it. These strings are operator-visible on
// BOTH paths: verbatim in the strict commit rejection, and wrapped into a
// cfg.Warnings entry on the tolerant load / peer-sync path
// (compiler_uniformgates_firewall_nat2.go), which is the only signal an
// operator gets there since `show` renders one selected action.
//
// Asserted per-arity and per-kind, because the mechanism sentence differs: the
// precedence clause is a parameter of the shared `check` closure, so a source
// rule must name the `interface`/`pool` ordering and a destination rule — which
// has no `interface` action at all — must not.
func TestNATTerminalActionMessageContent_6820(t *testing.T) {
	twoActionSNAT := buildTree(t, []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set security nat source rule-set RS rule R1 then source-nat off",
	})
	_, err := CompileConfig(twoActionSNAT)
	if err == nil {
		t.Fatal("CompileConfig ACCEPTED a two-action source-NAT rule")
	}
	// #7036: the WHOLE message, not a list of substrings.
	//
	// This used to assert ten substrings with strings.Contains. That binds the
	// presence of bytes, and two mutations were measured green against it:
	//
	//   M-A  append "THE PRECEDING SENTENCE IS FALSE: configuration order
	//        chooses the survivor." right after the survivor claim
	//   M-B  delete the clause "and never looking the pool up, and the
	//        dataplane applies the same " from the DNAT mechanism sentence
	//
	// Every asserted substring survives both. M-A is the one that matters: the
	// message asserts a claim and then explicitly denies it, and a guard whose
	// entire subject is whether this sentence is TRUE could not see it. An
	// addition is invisible to a containment check by construction, and a
	// deletion is invisible whenever the deleted text is not itself asserted —
	// which is most of the message.
	//
	// So the assertion is EQUALITY. The message is an operator-facing contract
	// that four rounds have already got wrong (#6820 r3 shipped a survivor
	// clause that was literally false for a 2-action rule; #7035 found the
	// unscoped form false in exactly the case that prints it; #7034 found the
	// parenthetical claiming a completeness it does not have), so pinning it
	// exactly is the point rather than a cost.
	//
	// Updating this golden is a DELIBERATE act. Classify the diff before you
	// regenerate: a reworded clause and a clause whose CLAIM changed look
	// identical in a diff that is merely accepted.
	//
	// What each clause is for, preserved from the rounds that put it there:
	//   - "every one of them is published to the dataplane" — the mechanism the
	//     compiler ACTUALLY uses (publish-all + dataplane precedence), not the
	//     pre-#5628 packed-key/child-order pick.
	//   - "WITHIN THIS BLOCK, the survivor is decided by that fixed precedence
	//     rather than by the order the actions were written" — the PRECISE form
	//     (#6820 r4). The loose paraphrase "not the one you configured first or
	//     last" is FALSE for a 2-action rule, where one action IS first and the
	//     other IS last. #7035 then scoped it: with duplicate `then` CONTAINERS
	//     the #3850 reset makes the LAST container supply the counted fields, so
	//     container order selects which contradiction you get.
	//   - "a contradiction whose tokens are PACKED onto one node" + "#7033" —
	//     #7034. The parenthetical used to end "this rejects contradictory
	//     actions inside one block", a completeness claim that is false for every
	//     token-packed spelling. #7033 then CLOSED that gap with a separate check
	//     that runs after this count, so the sentence no longer says the packed
	//     spelling is uncaught — it says which check catches it. The clause is
	//     still load-bearing: it is the only place the message admits that this
	//     count reads RESOLVED fields, which is why a packed contradiction is not
	//     its business.
	const wantSNAT = "source-nat rule-set \"RS\" rule \"R1\": `then` carries 2 mutually-exclusive translation actions (expected exactly one of `source-nat interface`, `source-nat pool <p>`, or `source-nat off`); every one of them is published to the dataplane, which resolves the rule by a fixed precedence — `off` wins over `interface`, and `interface` over `pool`, so all but one action is silently discarded and, WITHIN THIS BLOCK, the survivor is decided by that fixed precedence rather than by the order the actions were written. (Duplicate `then` CONTAINERS resolve last-wins per #3850, so a rule with several containers is counted on the LAST one — container order therefore does decide WHICH contradiction you get here. This gate counts the actions the rule RESOLVED to, so it catches a block that LOWERS two distinct actions; a contradiction whose tokens are PACKED onto one node, as in `pool <p> off`, lowers to a single action and is counted as one, so it is rejected by the packed-contradiction check that follows this one rather than here — #7033.)"
	assertExactMessage7036(t, "2+-action SNAT", err, wantSNAT)

	twoActionDNAT := buildTree(t, []string{
		"set security nat destination pool PD address 10.0.0.5",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool PD",
		"set security nat destination rule-set RD rule R1 then destination-nat off",
	})
	_, err = CompileConfig(twoActionDNAT)
	if err == nil {
		t.Fatal("CompileConfig ACCEPTED a two-action destination-NAT rule")
	}
	// The DNAT message is a DIFFERENT message, not the SNAT one with a word
	// changed, and that is the property the equality carries here. The DNAT
	// builder short-circuits on `isOff` and never resolves the pool
	// (pkg/dataplane/userspace/nat_destination.go), so "every one of them is
	// published to the dataplane" — true of SNAT — describes a path a DNAT rule
	// does not take. A sentence shared between the two kinds is necessarily
	// false for one of them. It must also not name `interface`, an action a
	// destination-NAT rule cannot carry.
	//
	// Under equality those three former Contains/NotContains checks are
	// consequences rather than separate assertions, and M-B — deleting "and
	// never looking the pool up, and the dataplane applies the same " from this
	// very sentence, measured GREEN against the substring form — now reds.
	const wantDNAT = "destination-nat rule-set \"RD\" rule \"R1\": `then` carries 2 mutually-exclusive translation actions (expected exactly one of `destination-nat pool <p>` or `destination-nat off`); the compiler resolves `off` itself, publishing a pool-less exemption and never looking the pool up, and the dataplane applies the same `off`-over-`pool` precedence to any entry that carries both, so all but one action is silently discarded and, WITHIN THIS BLOCK, the survivor is decided by that fixed precedence rather than by the order the actions were written. (Duplicate `then` CONTAINERS resolve last-wins per #3850, so a rule with several containers is counted on the LAST one — container order therefore does decide WHICH contradiction you get here. This gate counts the actions the rule RESOLVED to, so it catches a block that LOWERS two distinct actions; a contradiction whose tokens are PACKED onto one node, as in `pool <p> off`, lowers to a single action and is counted as one, so it is rejected by the packed-contradiction check that follows this one rather than here — #7033.)"
	assertExactMessage7036(t, "2+-action DNAT", err, wantDNAT)

	// The ZERO-action message was rewritten by this PR too ("falls through —
	// translated by a later broader rule if one matches, otherwise left
	// untranslated", replacing a claim that a later rule always exists). Bind
	// both halves of that disjunction so neither can silently return to the
	// single-outcome wording.
	zeroAction := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
	})
	_, err = CompileConfig(zeroAction)
	if err == nil {
		t.Fatal("CompileConfig ACCEPTED a zero-action source-NAT rule")
	}
	// BOTH halves of the fall-through disjunction, which is why equality matters
	// here too: the pre-#6820 wording claimed a later rule always exists, and a
	// substring check for the "translated by a later broader rule" half alone
	// would still hold if the "otherwise left untranslated" half were deleted —
	// restoring exactly the single-outcome claim #6820 removed.
	const wantZero = "source-nat rule-set \"RS\" rule \"R1\": `then` carries no translation action (expected exactly one of `source-nat interface`, `source-nat pool <p>`, or `source-nat off`); the rule would commit but installs no translation and does not stop rule evaluation, so matching traffic falls through — translated by a later broader rule if one matches, otherwise left untranslated — and an intended exemption silently disappears"
	assertExactMessage7036(t, "zero-action SNAT", err, wantZero)
}

// assertExactMessage7036 compares a rejection message to its golden EXACTLY,
// and on mismatch reports the first differing byte with context.
//
// #7036: the messages this pins are operator-facing contracts that four
// consecutive rounds got wrong, so the guard has to be able to see a sentence
// becoming FALSE. Containment cannot: an appended clause is invisible to it by
// construction, and a deleted clause is invisible whenever the deleted text was
// not itself one of the asserted substrings.
func assertExactMessage7036(t *testing.T, what string, err error, want string) {
	t.Helper()
	got := err.Error()
	if got == want {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	lo := i - 60
	if lo < 0 {
		lo = 0
	}
	t.Errorf("%s rejection does not match its golden.\n"+
		"  first difference at byte %d\n"+
		"  want ...%s\n"+
		"   got ...%s\n"+
		"Update this golden only DELIBERATELY, and classify the diff first: a\n"+
		"reworded clause and a clause whose CLAIM changed look identical in a\n"+
		"diff that is merely accepted (#7036).",
		what, i, clip7036(want[lo:]), clip7036(got[lo:]))
}

func clip7036(s string) string {
	if len(s) > 180 {
		return s[:180] + "..."
	}
	return s
}

// --- VALID single-action rules must COMPILE clean (flat + hierarchical) ------

func TestNATTerminalActionValidSingle_5628(t *testing.T) {
	// Flat SNAT: exactly one `source-nat interface`.
	flatSNAT := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat interface",
	})
	if _, err := CompileConfig(flatSNAT); err != nil {
		t.Fatalf("flat single-action SNAT rejected: %v", err)
	}

	// Flat DNAT: exactly one `destination-nat off`.
	flatDNAT := buildTree(t, []string{
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		"set security nat destination rule-set RD rule R1 then destination-nat off",
	})
	if _, err := CompileConfig(flatDNAT); err != nil {
		t.Fatalf("flat single-action DNAT rejected: %v", err)
	}

	// Hierarchical SNAT: exactly one `source-nat pool p`.
	if _, err := compileHier5628(t, `
security {
    nat {
        source {
            pool p { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat pool p; }
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical single-action SNAT rejected: %v", err)
	}

	// Hierarchical DNAT: exactly one `destination-nat pool p`.
	if _, err := compileHier5628(t, `
security {
    nat {
        destination {
            pool p { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p; }
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical single-action DNAT rejected: %v", err)
	}
}

// --- ZERO-action rules must be REJECTED (flat + hierarchical) ----------------

func TestNATTerminalActionZeroRejected_5628(t *testing.T) {
	// Flat SNAT: a rule with a match but NO `then` action.
	flatSNAT := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
	})
	_, err := CompileConfig(flatSNAT)
	wantCardinalityReject5628(t, "flat zero-action SNAT", err)

	// Flat DNAT: a rule with a match but NO `then` action.
	flatDNAT := buildTree(t, []string{
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
	})
	_, err = CompileConfig(flatDNAT)
	wantCardinalityReject5628(t, "flat zero-action DNAT", err)

	// Hierarchical SNAT: an empty `then {}` block.
	_, err = compileHier5628(t, `
security {
    nat {
        source {
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical zero-action SNAT", err)

	// Hierarchical DNAT: a rule with a match but no `then`.
	_, err = compileHier5628(t, `
security {
    nat {
        destination {
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical zero-action DNAT", err)
}

// --- TWO-action rules must be REJECTED (flat + hierarchical) -----------------

func TestNATTerminalActionTwoRejected_5628(t *testing.T) {
	// Flat SNAT: `source-nat interface` + `source-nat off` in one rule. SetPath
	// merges the two `then source-nat ...` lines into ONE source-nat node with
	// two children (interface, off) — a single complete then-block carrying two
	// mutually-exclusive actions.
	flatSNAT := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat interface",
		"set security nat source rule-set RS rule R1 then source-nat off",
	})
	_, err := CompileConfig(flatSNAT)
	wantCardinalityReject5628(t, "flat two-action SNAT (interface+off)", err)

	// Flat DNAT: `destination-nat off` + `destination-nat pool p1` in one rule.
	flatDNAT := buildTree(t, []string{
		"set security nat destination pool p1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		"set security nat destination rule-set RD rule R1 then destination-nat off",
		"set security nat destination rule-set RD rule R1 then destination-nat pool p1",
	})
	_, err = CompileConfig(flatDNAT)
	wantCardinalityReject5628(t, "flat two-action DNAT (off+pool)", err)

	// Hierarchical SNAT: a single `source-nat { interface; pool p; }` node. The
	// pre-#5628 else-if setter silently picked interface; the independent-if
	// setter now records both fields so the gate rejects.
	_, err = compileHier5628(t, `
security {
    nat {
        source {
            pool p { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; pool p; } }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical two-action SNAT (interface+pool one node)", err)

	// Hierarchical DNAT: a single `destination-nat { pool p; off; }` node.
	_, err = compileHier5628(t, `
security {
    nat {
        destination {
            pool p { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat { pool p; off; } }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical two-action DNAT (pool+off one node)", err)
}

// --- #3850 duplicate `then` CONTAINERS must NOT be false-rejected -----------

// TestNATTerminalActionDup3850LastWins_5628 pins that the cardinality gate does
// NOT reject a rule merely because it has two `then` CONTAINERS. Two `then`
// blocks each naming ONE source-nat action resolve last-wins (#3850): the
// compiler resets rule.Then per block, so the winning block carries exactly one
// action. This must compile AND resolve to the LAST block's pool.
func TestNATTerminalActionDup3850LastWins_5628(t *testing.T) {
	cfg, err := compileHier5628(t, `
security {
    nat {
        source {
            pool poolB { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat interface; }
                    then { source-nat pool poolB; }
                }
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("#3850 duplicate-then-container rule FALSE-REJECTED by the #5628 gate "+
			"(must be last-wins, not a conflict): %v", err)
	}
	if len(cfg.Security.NAT.Source) == 0 || len(cfg.Security.NAT.Source[0].Rules) == 0 {
		t.Fatalf("no source NAT rule compiled")
	}
	r := cfg.Security.NAT.Source[0].Rules[0]
	if r.Then.PoolName != "poolB" || r.Then.Interface {
		t.Fatalf("#3850 last-wins broken: Then={Interface:%v PoolName:%q}, want "+
			"{false poolB} (second then block wins, first block's interface cleared)",
			r.Then.Interface, r.Then.PoolName)
	}
}

// TestNATTerminalActionDupIdenticalPool3850_5628 pins that two `then` containers
// naming the SAME pool also commit (last-wins to that pool, count one).
func TestNATTerminalActionDupIdenticalPool3850_5628(t *testing.T) {
	cfg, err := compileHier5628(t, `
security {
    nat {
        destination {
            pool p1 { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p1; }
                    then { destination-nat pool p1; }
                }
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("#3850 duplicate identical-pool then-containers false-rejected: %v", err)
	}
	r := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if r.Then.PoolName != "p1" {
		t.Fatalf("duplicate identical-pool: PoolName=%q, want p1", r.Then.PoolName)
	}
}

// --- Tolerant load / peer-sync path WARNS, never bricks (#1960) --------------

func TestNATTerminalActionLenientWarns_5628(t *testing.T) {
	// A zero-action DNAT rule that strict-rejects must instead WARN-and-compile
	// on the tolerant path so an already-persisted / peer-synced config boots.
	flatDNAT := buildTree(t, []string{
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
	})
	// Strict rejects.
	if _, err := CompileConfig(flatDNAT); err == nil {
		t.Fatal("strict CompileConfig must reject the zero-action DNAT rule")
	}
	// Lenient warns and compiles.
	cfg, err := CompileConfigLenient(flatDNAT)
	if err != nil {
		t.Fatalf("tolerant CompileConfigLenient must NOT brick on a zero-action rule "+
			"(#1960 no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NAT terminal-action cardinality") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant path must record a NAT terminal-action-cardinality "+
			"downgrade warning; warnings=%v", cfg.Warnings)
	}
}

// TestNATSourceAndDestSupersededThenBlockResetsMetadata13211 pins #3850
// last-wins for diagnostic records as well as rule.Then. Malformed metadata in
// a superseded block must not poison a clean winning block, while defects in
// the winning block must still be rejected.
func TestNATSourceAndDestSupersededThenBlockResetsMetadata13211(t *testing.T) {
	t.Run("source packed contradiction superseded", func(t *testing.T) {
		cfg, err := compileHier5628(t, `
security {
    nat {
        source {
            pool p1 { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat pool p1 off; }
                    then { source-nat pool p1; }
                }
            }
        }
    }
}`)
		if err != nil {
			t.Fatalf("superseded packed-contradiction then block FALSE-REJECTED (#13211): %v", err)
		}
		r := cfg.Security.NAT.Source[0].Rules[0]
		if r.Then.PoolName != "p1" || r.Then.Off {
			t.Fatalf("winning Then = %+v, want pool p1 only", r.Then)
		}
	})
	t.Run("source unknown leaf superseded", func(t *testing.T) {
		cfgText := `
security {
    nat {
        source {
            pool p1 { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat typo; }
                    then { source-nat pool p1; }
                }
            }
        }
    }
}`
		cfg, err := compileHier5628(t, cfgText)
		if err != nil {
			t.Fatalf("superseded unknown-leaf then block FALSE-REJECTED (#13211): %v", err)
		}
		if got := cfg.Security.NAT.Source[0].Rules[0].unknownThenLeaves; len(got) != 0 {
			t.Fatalf("unknownThenLeaves = %v, want none from superseded block", got)
		}
		tree, perrs := NewParser(cfgText).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse for tolerant compile: %v", perrs)
		}
		lenient, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		for _, warning := range lenient.Warnings {
			if strings.Contains(warning, "#10294") {
				t.Fatalf("superseded unknown leaf produced false tolerant warning: %s", warning)
			}
		}
	})
	t.Run("destination multi-pool superseded", func(t *testing.T) {
		cfg, err := compileHier5628(t, `
security {
    nat {
        destination {
            pool p1 { address 10.0.30.100; }
            pool p2 { address 10.0.30.101; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p1 pool p2; }
                    then { destination-nat pool p1; }
                }
            }
        }
    }
}`)
		if err != nil {
			t.Fatalf("superseded multi-pool then block FALSE-REJECTED (#13211): %v", err)
		}
		if got := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Then.PoolName; got != "p1" {
			t.Fatalf("winning PoolName = %q, want p1", got)
		}
	})
	t.Run("destination packed contradiction superseded", func(t *testing.T) {
		_, err := compileHier5628(t, `
security {
    nat {
        destination {
            pool p1 { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p1 off; }
                    then { destination-nat pool p1; }
                }
            }
        }
    }
}`)
		if err != nil {
			t.Fatalf("superseded packed-contradiction then block FALSE-REJECTED (#13211): %v", err)
		}
	})
	t.Run("winning contradiction still rejects", func(t *testing.T) {
		for _, cfgText := range []string{`
security {
    nat {
        source {
            pool p1 { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat pool p1; }
                    then { source-nat pool p1 off; }
                }
            }
        }
    }
}`, `
security {
    nat {
        destination {
            pool p1 { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p1; }
                    then { destination-nat pool p1 off; }
                }
            }
        }
    }
}`} {
			if _, err := compileHier5628(t, cfgText); err == nil {
				t.Fatal("winning packed-contradiction block was ACCEPTED; gate must still fire")
			}
		}
	})
	t.Run("winning unknown leaf still rejects", func(t *testing.T) {
		_, err := compileHier5628(t, `
security {
    nat {
        source {
            pool p1 { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat pool p1; }
                    then { source-nat { pool p1; typo; } }
                }
            }
        }
    }
}`)
		if err == nil || !strings.Contains(err.Error(), "typo") {
			t.Fatalf("winning unknown-leaf block: err = %v, want rejection naming typo", err)
		}
	})
}
