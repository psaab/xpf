package config

import (
	"strings"
	"testing"
)

// TestStaticNATMappedPortShapeMatrix6479 is the comprehensive #6479 shape
// matrix. Every prior round of the C179-038 mapped-port work fixed the shape it
// was looking at and missed another; this matrix pins the behaviour across
// EVERY Junos AST shape a `then static-nat ... mapped-port` can take, so a
// future grammar-position or collection change that regresses one shape goes RED
// here.
//
// The regression this guards: round-4 added `prefix` to the grammar-position
// skip in staticNATMappedPortOperandsFromKeys, which dropped the mapped-port of
// the CANONICAL Junos separate-set-line form
//
//	set ... then static-nat prefix 10.0.0.5/32
//	set ... then static-nat prefix mapped-port 8080
//
// (SetPath collapses the second line to Keys ["prefix","mapped-port","8080"], so
// the mapped-port immediately follows the literal `prefix` keyword). A prefix
// value is always an IP and can never be the string "mapped-port", so the token
// is ALWAYS the genuine modifier — skipping it both false-rejected the clean
// canonical rule (it looked like a match-port with no mapped-port) AND reopened
// the C179-038 fail-open for a canonical malformed value.
//
// For each shape: a valid in-range port with a matching `match destination-port`
// ACCEPTS with the resolved MappedPort asserted; a malformed operand REJECTS
// strict (naming the token) and WARNS lenient with MappedPort==0 (fail-closed to
// a plain 1:1, no bogus port at the dataplane).

// natBaseZone is the shared flat-set prologue: a zone + a static rule-set whose
// rule matches a host destination. matchPort adds the `match destination-port`
// so a valid mapped-port is not caught by the #2769 without-match gate.
func natBaseZone() []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
	}
}

func buildFlat(t *testing.T, extra ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range append(natBaseZone(), extra...) {
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

// assertMappedPortAccept compiles tree in strict mode, requires success, and
// asserts the resolved MappedPort equals want.
func assertMappedPortAccept(t *testing.T, tree *ConfigTree, want int) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig must accept, got %v", err)
	}
	if len(cfg.Security.NAT.Static) != 1 || len(cfg.Security.NAT.Static[0].Rules) != 1 {
		t.Fatalf("expected exactly 1 static NAT rule, got %#v", cfg.Security.NAT.Static)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].MappedPort; got != want {
		t.Fatalf("MappedPort = %d, want %d", got, want)
	}
}

// assertMappedPortReject compiles tree in both strict and lenient modes: strict
// must hard-error naming the bad token; lenient must warn (naming the token) and
// keep MappedPort==0 (no bogus port reaches the dataplane).
func assertMappedPortReject(t *testing.T, buildTree func() *ConfigTree, wantToken string) {
	t.Helper()
	_, err := CompileConfig(buildTree())
	if err == nil {
		t.Fatalf("strict CompileConfig must reject the malformed mapped-port")
	}
	if !strings.Contains(err.Error(), "mapped-port") || !strings.Contains(err.Error(), wantToken) {
		t.Fatalf("strict error must name mapped-port + %q, got %v", wantToken, err)
	}
	cfg, errL := CompileConfigLenient(buildTree())
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", errL)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "mapped-port") && strings.Contains(w, wantToken) {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("lenient path must warn naming %q, got %v", wantToken, cfg.Warnings)
	}
	if len(cfg.Security.NAT.Static) == 1 && len(cfg.Security.NAT.Static[0].Rules) == 1 {
		if got := cfg.Security.NAT.Static[0].Rules[0].MappedPort; got != 0 {
			t.Fatalf("lenient path must keep MappedPort==0 (no bogus port), got %d", got)
		}
	}
}

func TestStaticNATMappedPortShapeMatrix6479(t *testing.T) {
	// Each shape builds a rule expressing prefix 10.0.0.5/32 + mapped-port <op>
	// plus a matching `match destination-port 8080`, in a distinct AST shape.
	type shape struct {
		name string
		// build returns the tree for a given mapped-port operand string.
		build func(t *testing.T, op string) *ConfigTree
	}

	shapes := []shape{
		{
			// Collapsed single-line: mapped-port rides on the prefix leaf's Keys
			// AFTER the IP value (Keys=["prefix","<ip>","mapped-port","<op>"]).
			name: "collapsed-one-line",
			build: func(t *testing.T, op string) *ConfigTree {
				return buildFlat(t,
					"set security nat static rule-set rs1 rule r1 match destination-port 8080",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port "+op)
			},
		},
		{
			// THE REGRESSION: canonical separate-set-line. The second set line
			// collapses to a distinct prefix leaf Keys=["prefix","mapped-port",
			// "<op>"] — mapped-port immediately follows the literal `prefix`.
			name: "canonical-separate-set-line",
			build: func(t *testing.T, op string) *ConfigTree {
				return buildFlat(t,
					"set security nat static rule-set rs1 rule r1 match destination-port 8080",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix mapped-port "+op)
			},
		},
		{
			// Canonical HIERARCHICAL nested-under-prefix-value: mapped-port is a
			// child of the prefix node, prefix VALUE carried on the prefix Keys.
			name: "hier-nested-under-prefix-value",
			build: func(t *testing.T, op string) *ConfigTree {
				return parseHierText(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.1/32;
                        destination-port 8080;
                    }
                    then {
                        static-nat {
                            prefix 10.0.0.5/32 {
                                mapped-port `+op+`;
                            }
                        }
                    }
                }
            }
        }
    }
}`)
			},
		},
		{
			// Canonical HIERARCHICAL nested value-as-child: the prefix node is a
			// block carrying BOTH the IP value and the mapped-port as children.
			name: "hier-nested-value-as-child",
			build: func(t *testing.T, op string) *ConfigTree {
				return parseHierText(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.1/32;
                        destination-port 8080;
                    }
                    then {
                        static-nat {
                            prefix {
                                10.0.0.5/32;
                                mapped-port `+op+`;
                            }
                        }
                    }
                }
            }
        }
    }
}`)
			},
		},
		{
			// prefix-name target with a collapsed mapped-port. The prefix-name
			// resolves to a global address-book entry; mapped-port follows the
			// NAME value (Keys=["prefix-name","MP_TARGET","mapped-port","<op>"]).
			name: "prefix-name-collapsed",
			build: func(t *testing.T, op string) *ConfigTree {
				return buildFlat(t,
					"set security address-book global address MP_TARGET 10.0.0.5/32",
					"set security nat static rule-set rs1 rule r1 match destination-port 8080",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix-name MP_TARGET mapped-port "+op)
			},
		},
		{
			// Sibling: prefix and mapped-port authored as two `then static-nat`
			// set lines -> distinct children of the static-nat node.
			name: "sibling",
			build: func(t *testing.T, op string) *ConfigTree {
				return buildFlat(t,
					"set security nat static rule-set rs1 rule r1 match destination-port 8080",
					"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
					"set security nat static rule-set rs1 rule r1 then static-nat mapped-port "+op)
			},
		},
	}

	// Malformed operands common to every single-value shape.
	malformed := []struct{ op, token string }{
		{"notaport", `"notaport"`},
		{"0", `"0"`},
		{"70000", `"70000"`},
	}

	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			// Valid in-range port accepts with the resolved MappedPort asserted.
			t.Run("valid-8080-accepts", func(t *testing.T) {
				assertMappedPortAccept(t, s.build(t, "8080"), 8080)
			})
			for _, m := range malformed {
				t.Run("malformed-"+m.op+"-rejects", func(t *testing.T) {
					assertMappedPortReject(t, func() *ConfigTree { return s.build(t, m.op) }, m.token)
				})
			}
		})
	}
}

// TestStaticNATMappedPortDuplicateShapes6479 covers the duplicate-across-nodes
// shapes: two mapped-port operands must fold through ONE combine (last-wins when
// both valid, fail-closed when either malformed), never first-wins.
func TestStaticNATMappedPortDuplicateShapes6479(t *testing.T) {
	// crossNode: two `then static-nat prefix <ip> mapped-port <op>` set lines.
	crossNode := func(t *testing.T, a, b string, withMatch bool) *ConfigTree {
		extra := []string{}
		if withMatch {
			extra = append(extra, "set security nat static rule-set rs1 rule r1 match destination-port 8080")
		}
		extra = append(extra,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port "+a,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port "+b)
		return buildFlat(t, extra...)
	}
	// packedSibling: one `mapped-port a mapped-port b` sibling child (the packed
	// duplicate that rides on a single mapped-port leaf's Keys).
	packedSibling := func(t *testing.T, a, b string, withMatch bool) *ConfigTree {
		extra := []string{}
		if withMatch {
			extra = append(extra, "set security nat static rule-set rs1 rule r1 match destination-port 8080")
		}
		extra = append(extra,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
			"set security nat static rule-set rs1 rule r1 then static-nat mapped-port "+a+" mapped-port "+b)
		return buildFlat(t, extra...)
	}

	dupShapes := []struct {
		name  string
		build func(t *testing.T, a, b string, withMatch bool) *ConfigTree
	}{
		{"cross-node", crossNode},
		{"packed-sibling", packedSibling},
	}

	for _, s := range dupShapes {
		t.Run(s.name, func(t *testing.T) {
			// Both valid -> accept, last-wins (9090).
			t.Run("both-valid-last-wins", func(t *testing.T) {
				assertMappedPortAccept(t, s.build(t, "8080", "9090", true), 9090)
			})
			// Valid then malformed -> fail closed, naming the bad token (the
			// exact first-wins fail-open this guards: 8080 must NOT win).
			t.Run("valid-then-malformed-rejects", func(t *testing.T) {
				assertMappedPortReject(t, func() *ConfigTree { return s.build(t, "8080", "notaport", true) }, `"notaport"`)
			})
			// Malformed first -> order-independent fail closed.
			t.Run("malformed-first-rejects", func(t *testing.T) {
				assertMappedPortReject(t, func() *ConfigTree { return s.build(t, "notaport", "8080", true) }, `"notaport"`)
			})
		})
	}
}

// TestStaticNATMappedPortNameValuedSkip6479 confirms the grammar-position skip:
// a `mapped-port` that is the VALUE of a NAME-valued keyword (routing-instance /
// prefix-name) is NOT a modifier — the rule carries no mapped-port and compiles
// clean. This is the false-reject the round-4 skip protected against; the fix
// keeps it while restoring the `prefix mapped-port` recovery.
func TestStaticNATMappedPortNameValuedSkip6479(t *testing.T) {
	// A translation-target routing-instance NAMED "mapped-port".
	t.Run("routing-instance-named-mapped-port-clean", func(t *testing.T) {
		cfg, err := CompileConfig(buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 routing-instance mapped-port"))
		if err != nil {
			t.Fatalf(`routing-instance named "mapped-port" must compile clean, got %v`, err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.MappedPortPresent {
			t.Fatalf("routing-instance value \"mapped-port\" must not register a mapped-port modifier (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
		}
		if rule.ThenRoutingInstance != "mapped-port" {
			t.Fatalf("routing-instance target must be \"mapped-port\", got %q", rule.ThenRoutingInstance)
		}
	})

	// A prefix-name address-book entry NAMED "mapped-port".
	t.Run("prefix-name-named-mapped-port-clean", func(t *testing.T) {
		cfg, err := CompileConfig(buildFlat(t,
			"set security address-book global address mapped-port 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name mapped-port"))
		if err != nil {
			t.Fatalf(`prefix-name entry named "mapped-port" must compile clean, got %v`, err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.MappedPortPresent {
			t.Fatalf("prefix-name value \"mapped-port\" must not register a mapped-port modifier (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
		}
		if rule.ThenPrefixName != "mapped-port" {
			t.Fatalf("prefix-name target must be \"mapped-port\", got %q", rule.ThenPrefixName)
		}
		if rule.Then != "10.0.0.9/32" {
			t.Fatalf("prefix-name must resolve to 10.0.0.9/32, got %q", rule.Then)
		}
	})

	// A REAL mapped-port alongside a routing-instance named "mapped-port": the
	// real port survives, the RI name does not poison it.
	t.Run("real-mapped-port-plus-ri-named-mapped-port", func(t *testing.T) {
		cfg, err := CompileConfig(buildFlat(t,
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 8080",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 routing-instance mapped-port"))
		if err != nil {
			t.Fatalf(`real mapped-port 8080 + RI named "mapped-port" must compile clean, got %v`, err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if !rule.MappedPortPresent || rule.MappedPort != 8080 {
			t.Fatalf("real mapped-port 8080 must survive (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
		}
	})
}
