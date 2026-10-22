package config

import (
	"strings"
	"testing"
)

// This file closes the #6479 hostile-review shape-completeness findings for
// static-NAT `then static-nat ... mapped-port`. Round after round of the
// C179-038 work fixed the shape it was looking at and missed another; the final
// review round flagged five more authoring shapes. Each is pinned here against
// two bounded, checkable invariants:
//
//   INVARIANT A (security, absolute): in NO authoring shape may a present-but-
//     malformed mapped-port be SILENTLY ACCEPTED (compile clean, MappedPort==0,
//     no error and no lenient warning). Every shape that carries a malformed
//     operand fails closed (strict error / lenient warning), and no shape ever
//     installs a bogus NON-zero port.
//   INVARIANT B (no regression vs origin/master): a config master compiled clean
//     is not newly false-rejected, and a valid mapped-port's resolved value is
//     unchanged — EXCEPT where master itself had the C179-038 silent-accept bug.
//
// The five shapes, and their resolution:
//
//   S1  prefix-name separate-set-line: `prefix-name N` then `prefix-name
//       mapped-port P` (name NOT restated). The lexer parses `prefix-name
//       mapped-port P` as prefix-name="mapped-port" + a trailing token — a
//       name-slot collision, not a modifier — so the port is NOT recovered and
//       MappedPort stays 0 (a plain prefix-name 1:1, no bogus port). The
//       SUPPORTED separate-line form restates the name (`prefix-name N
//       mapped-port P`), which DOES recover + gate the port. Matches master.
//   S2  hierarchical `prefix-name N { mapped-port P; }`: the nested mapped-port
//       is collected + gated (valid accepts with P, malformed rejects).
//   S3  modifier-first ordering `prefix mapped-port P` before `prefix <ip>`: the
//       modifier line's `prefix` keyword takes the value "mapped-port", so the
//       target resolves to the literal "mapped-port" — an invalid IP — and the
//       rule fails closed on the target. Never a silent accept. Matches master.
//   S4  port range / trailing tokens: a range operand (`mapped-port 8080-8090`)
//       is a single non-numeric token → rejected. A valid single port followed
//       by a legitimate trailing modifier (`mapped-port 8080 routing-instance
//       X`) accepts with the port AND captures the modifier — the mapped-port
//       operand is the single immediately-following token.
//   S5  NPTv6 + mapped-port: NPTv6 (RFC 6296) translates the address prefix and
//       has no port concept. A mapped-port in ANY nptv6 shape is rejected on
//       PRESENCE (the value is irrelevant). This closes both the malformed
//       silent-accept and the valid silent-ignore that master left open (the
//       host-mask loop skips nptv6 rules entirely).

// natBaseZoneV6Tree is the shared IPv6 flat-set prologue for NPTv6 shapes: a
// zone + a static rule-set whose rule matches an internal IPv6 /64. The NPTv6
// external prefix length must equal the match length, and /64 is a supported
// nptv6 length, so a mapped-port is the ONLY defect — the nptv6-no-mapped-port
// gate is not masked by a length-mismatch or unsupported-length error.
func natBaseZoneV6Tree(t *testing.T, extra ...string) *ConfigTree {
	t.Helper()
	base := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:9::/64",
	}
	tree := &ConfigTree{}
	for _, line := range append(append([]string{}, base...), extra...) {
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

// assertNPTv6MappedPortReject asserts the #5523/#6479 nptv6-no-mapped-port gate:
// strict hard-errors with the nptv6 message; lenient warns; and — critically —
// the compiled rule stays IsNPTv6 with MappedPort==0 (no bogus port reaches the
// port-less nptv6 dataplane path; the prefix translation itself still applies).
func assertNPTv6MappedPortReject(t *testing.T, build func() *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(build())
	if err == nil {
		t.Fatalf("strict CompileConfig must reject nptv6 + mapped-port")
	}
	if !strings.Contains(err.Error(), "nptv6-prefix does not support mapped-port") {
		t.Fatalf("strict error must be the nptv6-no-mapped-port message, got %v", err)
	}
	cfg, errL := CompileConfigLenient(build())
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", errL)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nptv6-prefix does not support mapped-port") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("lenient path must warn nptv6-no-mapped-port, got %v", cfg.Warnings)
	}
	if len(cfg.Security.NAT.Static) == 1 && len(cfg.Security.NAT.Static[0].Rules) == 1 {
		r := cfg.Security.NAT.Static[0].Rules[0]
		if !r.IsNPTv6 {
			t.Fatalf("nptv6 rule must remain nptv6 on the lenient path")
		}
		if r.MappedPort != 0 {
			t.Fatalf("nptv6 rule must keep MappedPort==0 (no bogus port), got %d", r.MappedPort)
		}
	}
}

// --- S1: prefix-name separate-set-line -------------------------------------

// TestStaticNATMappedPortPrefixNameSeparateLine5523 pins both the SUPPORTED
// separate-line form (name restated → port recovered + gated) and the ambiguous
// name-NOT-restated form (port not recovered, target resolved, no bogus port).
func TestStaticNATMappedPortPrefixNameSeparateLine5523(t *testing.T) {
	// Supported: the name is RESTATED on the mapped-port line, so `mapped-port`
	// is NOT in name-slot position (it follows the NAME value MP_TARGET) and the
	// port is recovered + gated.
	t.Run("name-restated-recovers-port", func(t *testing.T) {
		cfg, err := CompileConfig(buildFlat(t,
			"set security address-book global address MP_TARGET 10.0.0.5/32",
			"set security nat static rule-set rs1 rule r1 match destination-port 8080",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name MP_TARGET",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name MP_TARGET mapped-port 8080"))
		if err != nil {
			t.Fatalf("name-restated separate-line form must accept a valid port, got %v", err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.ThenPrefixName != "MP_TARGET" || rule.Then != "10.0.0.5/32" {
			t.Fatalf("target must resolve to MP_TARGET/10.0.0.5/32, got name=%q then=%q", rule.ThenPrefixName, rule.Then)
		}
		if !rule.MappedPortPresent || rule.MappedPort != 8080 {
			t.Fatalf("restated form must recover mapped-port 8080 (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
		}
	})

	// Supported form, MALFORMED port → fail closed naming the token.
	t.Run("name-restated-malformed-rejects", func(t *testing.T) {
		assertMappedPortReject(t, func() *ConfigTree {
			return buildFlat(t,
				"set security address-book global address MP_TARGET 10.0.0.5/32",
				"set security nat static rule-set rs1 rule r1 match destination-port 8080",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix-name MP_TARGET",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix-name MP_TARGET mapped-port notaport")
		}, `"notaport"`)
	})

	// Ambiguous name-NOT-restated form: `prefix-name mapped-port P` parses
	// prefix-name="mapped-port" + trailing P. The target resolves from the FIRST
	// child (MP_TARGET) and NO mapped-port is recovered — MappedPort stays 0 (a
	// plain prefix-name 1:1). No malformed port is ever installed (INVARIANT A).
	// This is the pre-existing == master behaviour: the ambiguous name-slot form
	// is not a supported way to attach a port; the restated form above is.
	for _, p := range []string{"8080", "notaport", "0"} {
		p := p
		t.Run("name-not-restated-installs-no-bogus-port-P="+p, func(t *testing.T) {
			// WITHOUT a match destination-port so nothing external forces a
			// reject: this is the purest silent-accept probe. It must compile
			// clean AND install NO port (MappedPort==0) — never a bogus port.
			cfg, err := CompileConfigLenient(buildFlat(t,
				"set security address-book global address MP_TARGET 10.0.0.5/32",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix-name MP_TARGET",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix-name mapped-port "+p))
			if err != nil {
				t.Fatalf("lenient compile must not hard-error, got %v", err)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.ThenPrefixName != "MP_TARGET" {
				t.Fatalf("target must resolve from the first child (MP_TARGET), got %q", rule.ThenPrefixName)
			}
			if rule.MappedPort != 0 {
				t.Fatalf("INVARIANT A: the ambiguous name-slot form must install NO port (MappedPort==0), got %d", rule.MappedPort)
			}
		})
	}
}

// --- S2: hierarchical prefix-name with a nested mapped-port ----------------

// TestStaticNATMappedPortHierPrefixName5523 covers `prefix-name N { mapped-port
// P; }` — a valid nested port accepts and resolves; a malformed one fails closed
// naming the token. The nested mapped-port is collected via the target-child's
// grandchild scan in staticNATMappedPortForNode.
func TestStaticNATMappedPortHierPrefixName5523(t *testing.T) {
	build := func(op string) *ConfigTree {
		return parseHierText(t, `security {
    zones { security-zone untrust; }
    address-book { global { address MP_TARGET 10.0.0.5/32; } }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.1/32; destination-port 8080; }
                    then { static-nat { prefix-name MP_TARGET { mapped-port `+op+`; } } }
                }
            }
        }
    }
}`)
	}
	t.Run("valid-accepts", func(t *testing.T) {
		cfg, err := CompileConfig(build("8080"))
		if err != nil {
			t.Fatalf("hier prefix-name { mapped-port 8080 } must accept, got %v", err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.Then != "10.0.0.5/32" || rule.MappedPort != 8080 {
			t.Fatalf("want then=10.0.0.5/32 port=8080, got then=%q port=%d", rule.Then, rule.MappedPort)
		}
	})
	for _, m := range []struct{ op, token string }{
		{"notaport", `"notaport"`},
		{"0", `"0"`},
		{"70000", `"70000"`},
	} {
		m := m
		t.Run("malformed-"+m.op+"-rejects", func(t *testing.T) {
			assertMappedPortReject(t, func() *ConfigTree { return build(m.op) }, m.token)
		})
	}
}

// --- S3: modifier-first ordering -------------------------------------------

// TestStaticNATMappedPortModifierFirst5523 covers the `prefix mapped-port P` set
// line authored BEFORE the `prefix <ip>` line. The modifier line's `prefix`
// keyword takes the value "mapped-port" (a distinct prefix child), so FindChild
// resolves the target to the literal "mapped-port" — an invalid IP — and the
// rule FAILS CLOSED on the target in EVERY case (the whole rule is dropped by
// the dataplane, so any port it carries never installs). Never a silent accept.
// Matches origin/master (which also resolves the target to "mapped-port" and
// rejects on it). The port operand itself may be valid (8080) or malformed
// (notaport); it is the TARGET that is unrecoverable in this ordering, so the
// fail-closed proof is the invalid-target rejection, not the port value.
func TestStaticNATMappedPortModifierFirst5523(t *testing.T) {
	build := func(op string) *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 match destination-port 8080",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix mapped-port "+op,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32")
	}
	for _, op := range []string{"8080", "notaport", "0"} {
		op := op
		t.Run("rejects-invalid-target-P="+op, func(t *testing.T) {
			_, err := CompileConfig(build(op))
			if err == nil {
				t.Fatalf("modifier-first ordering must fail closed (invalid target), P=%s", op)
			}
			// The target resolved to the literal "mapped-port" (not an IP), so
			// the rule is rejected on the target in strict mode.
			if !strings.Contains(err.Error(), `prefix "mapped-port"`) {
				t.Fatalf("strict error must name the invalid target prefix \"mapped-port\", got %v", err)
			}
			// On the lenient path the rule survives but carries the invalid
			// target Then=="mapped-port", so the dataplane drops the WHOLE rule
			// (parse_nat_prefix returns None) — whatever port it carries never
			// installs. This is the fail-closed mechanism for this shape.
			cfg, errL := CompileConfigLenient(build(op))
			if errL != nil {
				t.Fatalf("lenient compile must not hard-error, got %v", errL)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.Then != "mapped-port" {
				t.Fatalf("lenient rule must carry the invalid target Then==\"mapped-port\" (dataplane drops the whole rule), got %q", rule.Then)
			}
		})
	}
}

// --- S4: port range / trailing tokens --------------------------------------

// TestStaticNATMappedPortRangeAndTrailing5523 covers shape 4. A RANGE operand is
// a single non-numeric token → rejected (a static-NAT mapped-port is a single
// port, not a range). A valid single port followed by a legitimate trailing
// modifier accepts with the port AND captures the modifier — proving the
// mapped-port operand is the single immediately-following token, and a non-
// numeric FIRST operand (a range) fails closed.
func TestStaticNATMappedPortRangeAndTrailing5523(t *testing.T) {
	// A range as the mapped-port operand fails closed, naming the token.
	t.Run("range-rejects", func(t *testing.T) {
		assertMappedPortReject(t, func() *ConfigTree {
			return buildFlat(t,
				"set security nat static rule-set rs1 rule r1 match destination-port 8080",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 8080-8090")
		}, `"8080-8090"`)
	})

	// A valid single port followed by a legitimate `routing-instance` modifier:
	// the port is recovered (8080) AND the routing-instance is captured. The
	// mapped-port operand is the single token after `mapped-port`; a trailing
	// modifier is NOT folded into the port (so it is not a bogus-truncation).
	t.Run("valid-port-plus-trailing-modifier-accepts", func(t *testing.T) {
		cfg, err := CompileConfig(buildFlat(t,
			"set security nat static rule-set rs1 rule r1 match destination-port 8080",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 8080 routing-instance blue"))
		if err != nil {
			t.Fatalf("valid mapped-port + trailing routing-instance must accept, got %v", err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.MappedPort != 8080 {
			t.Fatalf("mapped-port operand must be the single token 8080, got %d", rule.MappedPort)
		}
		if rule.ThenRoutingInstance != "blue" {
			t.Fatalf("trailing routing-instance must be captured as blue, got %q", rule.ThenRoutingInstance)
		}
	})

	// A non-numeric FIRST operand fails closed even when a numeric token trails
	// it (`mapped-port notaport 8080` must NOT silently pick up 8080).
	t.Run("non-numeric-first-operand-rejects", func(t *testing.T) {
		assertMappedPortReject(t, func() *ConfigTree {
			return buildFlat(t,
				"set security nat static rule-set rs1 rule r1 match destination-port 8080",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port notaport 8080")
		}, `"notaport"`)
	})
}

// --- S5: NPTv6 + mapped-port ------------------------------------------------

// TestStaticNATMappedPortNPTv65523 covers shape 5 across every nptv6 authoring
// shape: a mapped-port on an nptv6 rule is rejected on PRESENCE (the value is
// irrelevant — nptv6 has no ports). This closes BOTH the malformed silent-accept
// (INVARIANT A) and the valid silent-ignore that origin/master left open (the
// host-mask loop `continue`s past every nptv6 rule). A clean nptv6 rule (no
// mapped-port) still compiles — no false reject (INVARIANT B).
func TestStaticNATMappedPortNPTv65523(t *testing.T) {
	// Collapsed single-line: nptv6-prefix + mapped-port on one leaf.
	t.Run("collapsed-valid-rejects", func(t *testing.T) {
		assertNPTv6MappedPortReject(t, func() *ConfigTree {
			return natBaseZoneV6Tree(t,
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64 mapped-port 8080")
		})
	})
	t.Run("collapsed-malformed-rejects", func(t *testing.T) {
		assertNPTv6MappedPortReject(t, func() *ConfigTree {
			return natBaseZoneV6Tree(t,
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64 mapped-port notaport")
		})
	})
	// Sibling: nptv6-prefix and mapped-port as two `then static-nat` set lines.
	t.Run("sibling-malformed-rejects", func(t *testing.T) {
		assertNPTv6MappedPortReject(t, func() *ConfigTree {
			return natBaseZoneV6Tree(t,
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64",
				"set security nat static rule-set rs1 rule r1 then static-nat mapped-port notaport")
		})
	})
	// Canonical separate-set-line: the nptv6-prefix keyword is RESTATED on the
	// mapped-port line (`nptv6-prefix <p6>` + `nptv6-prefix mapped-port <port>`).
	// SetPath merges both lines onto one static-nat node with two nptv6-prefix
	// children, the second being Keys=["nptv6-prefix","mapped-port","<port>"] — so
	// `mapped-port` immediately follows the literal `nptv6-prefix` keyword. This
	// was the LAST residual C179-038 silent-accept: while `nptv6-prefix` sat in the
	// name-valued skip set the modifier was discarded before it reached
	// recordNPTv6MappedPortPresence, so validateNPTv6Strict never fired and BOTH a
	// malformed and a well-formed port were silently accepted. It is the exact
	// sibling of the round-5 `prefix mapped-port` fix; both must now reject on
	// presence. Parent-RED: re-adding "nptv6-prefix" to mappedPortNameValuedKeywords
	// makes these two subtests go RED (the silent-accept returns).
	t.Run("canonical-separate-valid-rejects", func(t *testing.T) {
		assertNPTv6MappedPortReject(t, func() *ConfigTree {
			return natBaseZoneV6Tree(t,
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64",
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix mapped-port 8080")
		})
	})
	t.Run("canonical-separate-malformed-rejects", func(t *testing.T) {
		assertNPTv6MappedPortReject(t, func() *ConfigTree {
			return natBaseZoneV6Tree(t,
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64",
				"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix mapped-port notaport")
		})
	})
	// Hierarchical: nptv6-prefix block with a nested mapped-port.
	t.Run("hierarchical-valid-rejects", func(t *testing.T) {
		assertNPTv6MappedPortReject(t, func() *ConfigTree {
			return parseHierText(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 2001:db8:9::/64; }
                    then { static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port 8080; } } }
                }
            }
        }
    }
}`)
		})
	})
	// A clean nptv6 rule (no mapped-port) still compiles — no false reject.
	t.Run("clean-nptv6-accepts", func(t *testing.T) {
		cfg, err := CompileConfig(natBaseZoneV6Tree(t,
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64"))
		if err != nil {
			t.Fatalf("a clean nptv6 rule (no mapped-port) must accept, got %v", err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if !rule.IsNPTv6 || rule.MappedPortPresent {
			t.Fatalf("clean nptv6 rule: want IsNPTv6 && !MappedPortPresent, got nptv6=%v present=%v", rule.IsNPTv6, rule.MappedPortPresent)
		}
	})
}
