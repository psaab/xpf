package config

import (
	"strings"
	"testing"
)

// #6483: a Junos static-NAT rule maps to EXACTLY ONE translation target — one of
// `prefix <ip>` | `prefix-name <name>` | `nptv6-prefix <p6>` | `inet`. A rule
// authoring two or more targets is invalid Junos, but compileNATStatic used to
// ACCEPT it: the child loop honors the FIRST target by a fixed priority
// (nptv6-prefix > prefix-name > prefix > inet) and drops the rest into the shared
// Then field (a later target overwrites an earlier one), so the rule compiled to
// one arbitrary target with no operator feedback. validateStaticNATSingleTarget-
// Strict now rejects a rule whose winning `then {}` block declares >1 target.
//
// PARENT-RED: neutralize the gate — guard `rule.ThenTargetCount > 1` to a
// constant false in validateStaticNATSingleTargetStrict (keep it compiling) — and
// every TestStaticNATMultiTarget6483_Reject* case goes clean-assertion RED
// (strict CompileConfig returns nil for a rule that must reject). The
// accept/residual cases stay green, proving the gate does not over-reject.

// mtBuildHier parses a full hierarchical config (its own prologue), optionally
// splicing extra flat-set lines (e.g. an address-book entry) on top.
func mtBuildHier(t *testing.T, hier string, extra ...string) *ConfigTree {
	t.Helper()
	tree := parseHierText(t, hier)
	for _, line := range extra {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// assertMultiTargetReject compiles the tree strict (must hard-reject naming the
// multi-target problem) and lenient (must NOT hard-error but must warn — the
// #1960 no-brick contract).
func assertMultiTargetReject(t *testing.T, build func() *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(build())
	if err == nil {
		t.Fatalf("strict CompileConfig must reject a multi-target static-nat rule")
	}
	if !strings.Contains(err.Error(), "translation targets") ||
		!strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("strict error must name the multi-target problem, got: %v", err)
	}
	cfg, errL := CompileConfigLenient(build())
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error (#1960 no-brick), got %v", errL)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "translation target") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("lenient path must warn about translation-target cardinality, got %v", cfg.Warnings)
	}
}

// assertSingleTargetAccept compiles strict, requires success, and asserts the
// rule resolved to EXACTLY ONE declared target (guards against over-rejection).
func assertSingleTargetAccept(t *testing.T, tree *ConfigTree) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig must accept a well-formed single-target rule, got %v", err)
	}
	if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) == 0 {
		t.Fatalf("expected a static NAT rule, got %#v", cfg.Security.NAT.Static)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].ThenTargetCount; got != 1 {
		t.Fatalf("ThenTargetCount = %d, want 1 (single well-formed target)", got)
	}
}

// --- multi-target REJECT (each authoring shape) -----------------------------

func TestStaticNATMultiTarget6483_RejectPrefixPlusPrefixName(t *testing.T) {
	// Flat-set: two target lines collapse onto ONE static-nat node with two target
	// children (prefix + prefix-name). On master this compiled clean, honoring
	// prefix-name and silently dropping the prefix.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name POOL")
	})
}

func TestStaticNATMultiTarget6483_RejectInetPlusPrefix(t *testing.T) {
	// Flat-set inet sibling + prefix sibling. On master the prefix (higher
	// priority) won Then, so the rule installed as a plain prefix rule and even
	// EVADED the #5859 inet reject — a doubly-silent accept.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat inet",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32")
	})
}

func TestStaticNATMultiTarget6483_RejectTwoPrefix(t *testing.T) {
	// Two mutually-exclusive prefix targets — last-wins on master, silently
	// dropping the first.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.2/32")
	})
}

func TestStaticNATMultiTarget6483_RejectHierTwoStaticNATBlocks(t *testing.T) {
	// Hierarchical `then { static-nat {…} static-nat {…} }` — one target per
	// sibling static-nat node.
	assertMultiTargetReject(t, func() *ConfigTree {
		return mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix 10.0.0.1/32; } static-nat { prefix-name POOL; } } } } } } }`,
			"set security address-book global address POOL 10.0.0.9/32")
	})
}

// --- #6479 residual: a malformed mapped-port on a DROPPED target ------------

func TestStaticNATMultiTarget6483_RejectClosesMappedPortResidual(t *testing.T) {
	// Hierarchical: an `inet` sibling carrying a malformed `mapped-port notaport`
	// FIRST, then a `prefix` sibling. On master this SILENT-ACCEPTS: the inet
	// branch never runs the mapped-port fold, so the bad token is dropped, and the
	// later prefix sibling overwrites Then to a valid host — the rule compiles
	// clean with the malformed port lost. That is the #6479/C179-038 residual.
	// Rejecting the multi-target rule (inet + prefix = 2 targets) closes it: the
	// rule never compiles, so the dropped-target mapped-port cannot slip.
	build := func() *ConfigTree {
		return mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { inet mapped-port notaport; } static-nat { prefix 10.0.0.1/32; } } } } } } }`)
	}
	assertMultiTargetReject(t, build)
}

// --- #6484 residual: two targets COLLAPSED onto one node/child --------------
//
// The reject cases above spread their targets across two SEPARATE set lines or
// two hierarchical static-nat siblings, so SetPath keeps two target children and
// the pre-#6484 first-pair read already counted 2. The cases below author both
// targets on ONE line (or as multiple values under one bare keyword), so they
// collapse onto a SINGLE child's Keys / a single keyword's grandchildren — where
// the first-pair read saw only the first target and counted 1, letting a genuine
// multi-target rule ESCAPE the >1 gate (the #6484 MAJOR). The grammar-role-aware
// FULL-TRAVERSAL counter registers every distinct target identity across the whole
// key stream + all children, so these now reject.

func TestStaticNATMultiTarget6484_RejectOneLinePrefixPlusPrefixName(t *testing.T) {
	// ONE set line: `prefix <ip> prefix-name POOL` collapses onto a single child
	// whose Keys are ["prefix","<ip>","prefix-name","POOL"]. The old counter read
	// only Keys[1]/Keys[2] (the prefix) and counted 1 → ACCEPT. Two distinct
	// targets now → reject. POOL is defined so no undefined-prefix-name gate fires
	// first; the multi-target gate must own the rejection.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 prefix-name POOL")
	})
}

func TestStaticNATMultiTarget6484_RejectOneLinePrefixPlusInet(t *testing.T) {
	// ONE line `prefix <ip> inet` → child Keys ["prefix","<ip>","inet"]. The old
	// read counted the prefix only (1) → ACCEPT, which ALSO evaded the #5859 inet
	// reject (the PR's own motivating case): the honored prefix installed a plain
	// rule and the dropped inet never reached its gate. Now 2 targets → reject.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 inet")
	})
}

func TestStaticNATMultiTarget6484_RejectOneLineTwoPrefix(t *testing.T) {
	// ONE line `prefix <ip> prefix <ip2>` → child Keys ["prefix","<ip>","prefix",
	// "<ip2>"]. Two DISTINCT prefix identities now → reject (old read: 1).
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 prefix 10.0.0.2/32")
	})
}

func TestStaticNATMultiTarget6484_RejectHierMultiValuePrefix(t *testing.T) {
	// Hierarchical `prefix { <ip>; <ip2>; }` → one bare `prefix` child (Keys
	// ["prefix"]) carrying TWO grandchild values. The old read took only
	// Children[0] (the first ip) and counted 1 → ACCEPT. Each grandchild is a
	// distinct prefix identity now → reject.
	assertMultiTargetReject(t, func() *ConfigTree {
		return mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix { 10.0.0.1/32; 10.0.0.2/32; } } } } } } } }`)
	})
}

func TestStaticNATMultiTarget6484_RejectPrefixPlusPrefixNameNamedMappedPort(t *testing.T) {
	// A prefix target plus a prefix-name whose pool is LITERALLY named
	// "mapped-port" (a legal address-book name, static_nat_mapped_port_canonical_
	// 6479_test.go establishes such names). SetPath keeps two children: prefix
	// ["prefix","<ip>"] and prefix-name ["prefix-name","mapped-port"]. The old
	// counter's add() pre-filtered a value slot equal to a modifier keyword and
	// DISCARDED the "prefix-name mapped-port" target → counted 1 → ACCEPT (the
	// Codex second finding). The name-valued walk registers "prefix-name\x00
	// mapped-port" as a genuine target now → 2 → reject. The address-book entry is
	// defined so prefix-name resolves and the multi-target gate owns the rejection.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security address-book global address mapped-port 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name mapped-port")
	})
}

// --- #6484 round-2: PACKED/BRACKETED multi-value target (Codex finding 1) ----
//
// A Junos bracketed list `prefix [ X Y ]` is collapsed by the lexer (#2419) onto
// ONE leaf's Keys ["prefix","X","Y"]; the same for prefix-name / nptv6-prefix. The
// round-1 counter consumed only the FIRST value after the keyword and let the rest
// fall through, so a genuine 2-target packed list counted 1 and ESCAPED the >1
// gate. The full-traversal walk now registers EVERY packed value as a distinct
// target identity, so these reject.
//
// PARENT-RED: revert the packed-value fix (restore the single-value read in
// staticNATCollectTargetIdentsFromKeys — count only keys[i+1] and advance i+=2)
// and each of these goes clean-assertion RED (strict CompileConfig returns nil for
// a rule that must reject: `prefix [ X Y ]` counts 1).

func TestStaticNATMultiTarget6484_RejectBracketedMultiPrefix(t *testing.T) {
	// `prefix [ 10.0.0.1/32 10.0.0.2/32 ]` → Keys ["prefix","10.0.0.1/32",
	// "10.0.0.2/32"]. Two distinct prefix identities → reject. Both /32 host masks
	// so the host-mask gate passes and the cardinality gate owns the rejection.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix [ 10.0.0.1/32 10.0.0.2/32 ]")
	})
}

func TestStaticNATMultiTarget6484_RejectBracketedMultiPrefixName(t *testing.T) {
	// `prefix-name [ POOL POOL2 ]` → Keys ["prefix-name","POOL","POOL2"]. The FIRST
	// token is the opaque name (always consumed), every FURTHER non-keyword token is
	// an additional packed name — two distinct prefix-name identities → reject. Both
	// pools are defined so no undefined-prefix-name gate fires first.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security address-book global address POOL2 10.0.0.8/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name [ POOL POOL2 ]")
	})
}

func TestStaticNATMultiTarget6484_RejectBracketedMultiNptv6(t *testing.T) {
	// `nptv6-prefix [ P6a P6b ]` → Keys ["nptv6-prefix","P6a","P6b"]. Two distinct
	// nptv6-prefix identities → reject. Built with a v6 match of EQUAL prefix length
	// (else the nptv6-length gate, not cardinality, would fire) and no mapped-port.
	assertMultiTargetReject(t, func() *ConfigTree {
		tree := &ConfigTree{}
		for _, line := range []string{
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix [ 2001:db8:2::/48 2001:db8:3::/48 ]",
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		return tree
	})
}

// --- #6484 round-2: hierarchical prefix-name + nested mapped-port (finding 2) -
//
// A bare hierarchical `prefix-name { POOL; mapped-port 8080; }` is ONE target
// (prefix-name POOL) plus a mapped-port MODIFIER — NOT two targets. The round-1
// grandchild walk registered EVERY grandchild of a name-valued bare keyword as a
// target, counting POOL and mapped-port as two, and FALSE-REJECTED a valid
// single-target rule that origin/master accepted. The grandchild walk now consumes
// only the FIRST grandchild as the opaque name and skips a later modifier
// grandchild, so this accepts (count 1).
//
// PARENT-RED: revert the grandchild-modifier-skip (drop the `gi == 0` guard so a
// name-valued keyword's modifier grandchild is registered as a target again) and
// this goes RED — the rule false-rejects with ThenTargetCount==2.

func TestStaticNATMultiTarget6484_AcceptHierPrefixNameNestedMappedPort(t *testing.T) {
	// `match destination-port 80` satisfies the #2769 with-mapped-port gate so the
	// well-formed 8080 is not caught there; POOL resolves so the empty-target gate
	// does not fire — the count-1 accept is genuine, not masked by an earlier gate.
	assertSingleTargetAccept(t, mtBuildHier(t,
		`security { zones { security-zone untrust; }
			nat { static { rule-set rs1 { from { zone untrust; }
				rule r1 { match { destination-address 203.0.113.1/32; destination-port 80; }
					then { static-nat { prefix-name { POOL; mapped-port 8080; } } } } } } } }`,
		"set security address-book global address POOL 10.0.0.9/32"))
}

// --- single-target ACCEPT (each of the four, collapsed + hierarchical) ------

func TestStaticNATMultiTarget6483_AcceptSingleTargets(t *testing.T) {
	t.Run("prefix_flat", func(t *testing.T) {
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32"))
	})
	t.Run("prefix_flat_with_mapped_port", func(t *testing.T) {
		// A modifier (mapped-port) on the single target must NOT read as a 2nd
		// target — it is the canonical single-target-plus-modifier form.
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 mapped-port 8080"))
	})
	t.Run("prefix_hier", func(t *testing.T) {
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix 10.0.0.1/32; } } } } } } }`))
	})
	t.Run("prefix_name_flat", func(t *testing.T) {
		assertSingleTargetAccept(t, buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name POOL"))
	})
	t.Run("prefix_name_hier", func(t *testing.T) {
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix-name POOL; } } } } } } }`,
			"set security address-book global address POOL 10.0.0.9/32"))
	})
	t.Run("nptv6_prefix_flat", func(t *testing.T) {
		// nptv6 needs a v6 match of EQUAL prefix length (else the nptv6-length
		// gate, not the cardinality gate, would fire). Build without natBaseZone.
		tree := &ConfigTree{}
		for _, line := range []string{
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:2::/48",
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		assertSingleTargetAccept(t, tree)
	})
	t.Run("nptv6_prefix_hier", func(t *testing.T) {
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 2001:db8:1::/48; }
						then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`))
	})
	t.Run("prefix_with_routing_instance", func(t *testing.T) {
		// A trailing target routing-instance (#4292) is a modifier, not a 2nd
		// target.
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 routing-instance FOO"))
	})
	t.Run("prefix_name_restate_mapped_port_idiom", func(t *testing.T) {
		// #5523 RESTATE idiom: the SAME prefix-name target authored twice, the
		// second restatement attaching a mapped-port. SetPath keeps two prefix-name
		// children (["prefix-name","POOL"] and ["prefix-name","POOL","mapped-port",
		// "8080"]); both map to identity "prefix-name\x00POOL" and collapse to ONE
		// target. Must NOT read as two (INVARIANT B).
		assertSingleTargetAccept(t, buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name POOL",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name POOL mapped-port 8080"))
	})
	t.Run("prefix_modifier_carrier_separate_line", func(t *testing.T) {
		// The canonical separate-set-line mapped-port form for a LITERAL prefix:
		// `prefix <ip>` on one line, `prefix mapped-port <p>` on another. SetPath
		// keeps two prefix children (["prefix","10.0.0.1/32"] and ["prefix",
		// "mapped-port","8080"]); the second is a MODIFIER CARRIER (the value slot
		// is a modifier keyword, and a prefix value can never be one), so it
		// registers no target — count 1. Must NOT read the carrier as a 2nd prefix.
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix mapped-port 8080"))
	})
	t.Run("prefix_hier_ip_with_nested_mapped_port", func(t *testing.T) {
		// Hierarchical `prefix <ip> { mapped-port P; }`: the value rides INLINE on
		// the prefix child's Keys (["prefix","<ip>"]) and mapped-port is a nested
		// grandchild modifier, not a second value — count 1.
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; destination-port 80; }
						then { static-nat { prefix 10.0.0.1/32 { mapped-port 8080; } } } } } } } }`))
	})
	t.Run("prefix_name_hier_sibling_mapped_port", func(t *testing.T) {
		// REAL Junos (#1 regression risk): `static-nat { prefix-name POOL;
		// mapped-port 8080; }` — mapped-port is a SIBLING child of the prefix-name
		// target, NOT a grandchild. The prefix-name child has Keys len 2 so it never
		// enters the grandchild loop; the mapped-port sibling is skipped by
		// staticNATCollectTargetIdentsFromKeys. Must stay ONE target.
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; destination-port 80; }
						then { static-nat { prefix-name POOL; mapped-port 8080; } } } } } } }`,
			"set security address-book global address POOL 10.0.0.9/32"))
	})
	t.Run("prefix_hier_sibling_mapped_port", func(t *testing.T) {
		// REAL Junos (#1 regression risk): `static-nat { prefix 10.0.0.1/32;
		// mapped-port 8080; }` — mapped-port sibling of the prefix target. Must stay
		// ONE target (the prefix child's Keys are len 2; the mapped-port sibling
		// registers no target).
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; destination-port 80; }
						then { static-nat { prefix 10.0.0.1/32; mapped-port 8080; } } } } } } }`))
	})
}

// TestStaticNATMultiTarget6483_SingleInetNotFlaggedMulti proves a lone `inet`
// target is NOT falsely rejected as multi-target: it counts ONE target and is
// rejected (if at all) only by the #5859 inet gate, never the cardinality gate.
func TestStaticNATMultiTarget6483_SingleInetNotFlaggedMulti(t *testing.T) {
	build := func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat inet")
	}
	// The lone inet counts exactly one target (lenient compile keeps the rule).
	cfg, errL := CompileConfigLenient(build())
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", errL)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].ThenTargetCount; got != 1 {
		t.Fatalf("lone inet ThenTargetCount = %d, want 1", got)
	}
	// Strict rejection is the #5859 inet reject, NOT the multi-target reject.
	_, err := CompileConfig(build())
	if err == nil {
		t.Fatalf("lone inet must still be rejected by the #5859 inet gate")
	}
	if strings.Contains(err.Error(), "translation targets") {
		t.Fatalf("lone inet must NOT be flagged multi-target, got: %v", err)
	}
	if !strings.Contains(err.Error(), "inet") {
		t.Fatalf("expected the #5859 inet reject, got: %v", err)
	}
}
