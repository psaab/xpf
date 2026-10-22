package config

import (
	"strings"
	"testing"
)

// This file closes the two residual #6479 silent-accepts the FINAL hostile
// review flagged, both attacked at the ROOT rather than shape-by-shape:
//
//   ROOT CAUSE (grammar role): staticNATMappedPortOperandsFromKeys used a
//     LEXEME-ONLY lookbehind — it skipped a `mapped-port` when the immediately
//     preceding TOKEN was a name-valued skip-keyword (prefix-name /
//     routing-instance). It could not tell whether that preceding token was the
//     KEYWORD or its VALUE, so a translation target whose NAME is literally
//     "prefix-name" / "routing-instance" shifted a real modifier into the skipped
//     slot and the malformed port was SILENTLY ACCEPTED:
//
//       then static-nat prefix-name prefix-name mapped-port notaport
//       keys [prefix-name(kw) prefix-name(value) mapped-port notaport]
//
//     The fix walks the key stream grammar-role-aware: a name-valued keyword
//     CONSUMES its next token as a value slot, and `mapped-port` is the modifier
//     ONLY in a keyword slot — closing the whole class (any target named after a
//     skip-keyword, in any position) convergently.
//
//   SECOND FINDING (collection gap): a modifier-only `static-nat` sibling
//     (`then { static-nat { mapped-port <p>; } static-nat { prefix <ip>; } }`)
//     matched NO target branch in compileNATStatic, so its mapped-port reached no
//     validator. The fix routes an unmatched static-nat node through the same
//     mergeMappedPortForNode accumulator so its malformed operand fails closed in
//     either sibling order, and even when the co-sibling is an nptv6 target.
//
// INVARIANT A (security, absolute): no shape may SILENTLY ACCEPT a present-but-
//   malformed mapped-port. INVARIANT B (no regression): a target legitimately
//   named "prefix-name"/"routing-instance"/"mapped-port" still compiles clean,
//   and a real modifier on such a target is still collected.

// --- ROOT CAUSE: translation target NAMED after a skip-keyword --------------

// TestStaticNATMappedPortTargetNamedSkipKeyword6479 pins the grammar-role fix: a
// prefix-name target whose resolved NAME is literally a name-valued skip-keyword
// ("prefix-name" or "routing-instance") must NOT let a trailing malformed
// mapped-port slip through. The address-book entry is defined so the TARGET
// resolves cleanly — the malformed mapped-port is then the ONLY defect, proving
// the reject is the mapped-port gate (not an unrelated empty-target rejection).
// No `match destination-port`, so this is the purest silent-accept probe: without
// the fix it compiles clean; with it, it fails closed naming the bad token.
//
// PARENT-RED: restoring the lexeme lookbehind (skip `mapped-port` when keys[i-1]
// is a name-valued keyword) makes every malformed case here go GREEN-compile =
// test RED — the malformed port is skipped and silently accepted.
func TestStaticNATMappedPortTargetNamedSkipKeyword6479(t *testing.T) {
	// targetName is the literal string the prefix-name reference resolves to; it
	// is chosen to equal a name-valued skip-keyword so it fools a lexeme lookbehind.
	for _, targetName := range []string{"prefix-name", "routing-instance"} {
		targetName := targetName
		t.Run("prefix-name-target-named-"+targetName, func(t *testing.T) {
			// Malformed mapped-port after a target NAMED like a skip-keyword.
			t.Run("malformed-rejects", func(t *testing.T) {
				assertMappedPortReject(t, func() *ConfigTree {
					return buildFlat(t,
						"set security address-book global address "+targetName+" 10.0.0.5/32",
						"set security nat static rule-set rs1 rule r1 then static-nat prefix-name "+targetName+" mapped-port notaport")
				}, `"notaport"`)
			})
			// INVARIANT B: the SAME target with a VALID mapped-port must still be
			// recovered (a matching match-port keeps the #2769 gate quiet).
			t.Run("valid-recovers-port", func(t *testing.T) {
				cfg, err := CompileConfig(buildFlat(t,
					"set security address-book global address "+targetName+" 10.0.0.5/32",
					"set security nat static rule-set rs1 rule r1 match destination-port 8080",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix-name "+targetName+" mapped-port 8080"))
				if err != nil {
					t.Fatalf("valid mapped-port on target named %q must accept, got %v", targetName, err)
				}
				rule := cfg.Security.NAT.Static[0].Rules[0]
				if rule.ThenPrefixName != targetName || rule.Then != "10.0.0.5/32" {
					t.Fatalf("target must resolve to %q/10.0.0.5/32, got name=%q then=%q", targetName, rule.ThenPrefixName, rule.Then)
				}
				if !rule.MappedPortPresent || rule.MappedPort != 8080 {
					t.Fatalf("valid mapped-port 8080 must be recovered (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
				}
			})
			// INVARIANT B: the SAME target with NO mapped-port must compile clean
			// and register NO modifier (the name is not a mapped-port).
			t.Run("no-modifier-clean", func(t *testing.T) {
				cfg, err := CompileConfig(buildFlat(t,
					"set security address-book global address "+targetName+" 10.0.0.5/32",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix-name "+targetName))
				if err != nil {
					t.Fatalf("target named %q with no mapped-port must compile clean, got %v", targetName, err)
				}
				rule := cfg.Security.NAT.Static[0].Rules[0]
				if rule.MappedPortPresent {
					t.Fatalf("target named %q must not register a phantom mapped-port (present=%v port=%d)", targetName, rule.MappedPortPresent, rule.MappedPort)
				}
			})
		})
	}
}

// TestStaticNATMappedPortRealModifierOnTargetNamedMappedPort6479 is the tightest
// INVARIANT B: a prefix-name target whose NAME is literally "mapped-port" AND
// which carries a REAL mapped-port modifier must recover the modifier — the name
// "mapped-port" is consumed as the target value, the SECOND `mapped-port` is the
// keyword-slot modifier. This proves the grammar-role scan does not conflate the
// name with the modifier in either direction.
func TestStaticNATMappedPortRealModifierOnTargetNamedMappedPort6479(t *testing.T) {
	cfg, err := CompileConfig(buildFlat(t,
		"set security address-book global address mapped-port 10.0.0.7/32",
		"set security nat static rule-set rs1 rule r1 match destination-port 8080",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix-name mapped-port mapped-port 8080"))
	if err != nil {
		t.Fatalf(`target named "mapped-port" + real modifier 8080 must accept, got %v`, err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.ThenPrefixName != "mapped-port" || rule.Then != "10.0.0.7/32" {
		t.Fatalf(`target must resolve to "mapped-port"/10.0.0.7/32, got name=%q then=%q`, rule.ThenPrefixName, rule.Then)
	}
	if !rule.MappedPortPresent || rule.MappedPort != 8080 {
		t.Fatalf("real modifier 8080 must be recovered past the name (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
	}
}

// --- SECOND FINDING: modifier-only static-nat sibling -----------------------

// TestStaticNATMappedPortModifierOnlySibling6479 pins the collection-gap fix: a
// `static-nat` sibling carrying ONLY a mapped-port modifier (no prefix /
// prefix-name / nptv6-prefix / inet target) is routed through the accumulator, so
// a malformed operand fails closed in EITHER sibling order and even when the
// co-sibling is an nptv6 target. hierRuleV4AB carries no match destination-port,
// so a malformed mapped-port is the only defect.
//
// PARENT-RED: deleting the `else { mergeMappedPortForNode(rule, t) }` branch in
// compileNATStatic makes the modifier-only sibling reach no validator — every
// malformed case here compiles clean = test RED.
func TestStaticNATMappedPortModifierOnlySibling6479(t *testing.T) {
	prefixCases := []struct {
		name  string
		inner string
	}{
		{
			// Modifier-only sibling FIRST, clean prefix second.
			name: "modifier-only-first-then-prefix",
			inner: `                        static-nat { mapped-port notaport; }
                        static-nat { prefix 10.0.0.5/32; }`,
		},
		{
			// Clean prefix FIRST, modifier-only sibling second (opposite order).
			name: "prefix-first-then-modifier-only",
			inner: `                        static-nat { prefix 10.0.0.5/32; }
                        static-nat { mapped-port notaport; }`,
		},
		{
			// Modifier-only sibling paired with a clean prefix-NAME target.
			name: "modifier-only-first-then-prefix-name",
			inner: `                        static-nat { mapped-port notaport; }
                        static-nat { prefix-name MP_TARGET; }`,
		},
	}
	for _, c := range prefixCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			assertMappedPortReject(t, func() *ConfigTree {
				return parseHierText(t, hierRuleV4AB(c.inner))
			}, `"notaport"`)
		})
	}

	// nptv6 co-sibling: the modifier-only mapped-port makes the (nptv6) rule carry
	// a mapped-port, which nptv6 rejects on presence regardless of the value. This
	// is the "also bypasses NPTv6 rejection" case the review flagged.
	nptv6Cases := []struct {
		name  string
		inner string
	}{
		{
			name: "modifier-only-first-then-nptv6",
			inner: `                        static-nat { mapped-port notaport; }
                        static-nat { nptv6-prefix 2001:db8:1::/64; }`,
		},
		{
			name: "nptv6-first-then-modifier-only",
			inner: `                        static-nat { nptv6-prefix 2001:db8:1::/64; }
                        static-nat { mapped-port notaport; }`,
		},
	}
	for _, c := range nptv6Cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			assertNPTv6MappedPortReject(t, func() *ConfigTree {
				body := `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 2001:db8:9::/64; }
                    then {
` + c.inner + `
                    }
                }
            }
        }
    }
}`
				return parseHierText(t, body)
			})
		})
	}
}

// TestStaticNATMappedPortModifierOnlySiblingAccept6479 is the INVARIANT B guard
// for the modifier-only sibling: a VALID mapped-port on a modifier-only sibling
// applies to the merged action and is recovered (with a matching match-port).
func TestStaticNATMappedPortModifierOnlySiblingAccept6479(t *testing.T) {
	tree := parseHierText(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.1/32; destination-port 8080; }
                    then {
                        static-nat { mapped-port 9090; }
                        static-nat { prefix 10.0.0.5/32; }
                    }
                }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("valid modifier-only sibling + clean prefix must accept, got %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "10.0.0.5/32" {
		t.Fatalf("target must resolve to the prefix sibling 10.0.0.5/32, got %q", rule.Then)
	}
	if !rule.MappedPortPresent || rule.MappedPort != 9090 {
		t.Fatalf("valid modifier-only mapped-port 9090 must be recovered (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
	}
	if !strings.Contains(rule.Then, "10.0.0.5") {
		t.Fatalf("sanity: prefix target lost, got %q", rule.Then)
	}
}
