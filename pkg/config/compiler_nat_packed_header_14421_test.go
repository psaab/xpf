package config

import (
	"strings"
	"testing"
)

// Tests for #14421: a NAT rule-set whose `from` / `to` clause is PACKED onto
// the rule-set header line (`rule-set RS from zone trust { rule ... }`)
// compiled with the header tail invisible to collectNATScopes and all three
// NAT scope gates, so the rule-set installed with match-any scope
// (FromZone/ToZone/... all empty, stamped match-any).
//
// Braced control: `rule-set RS { from zone trust; rule ... }`.
// Packed spelling: `rule-set RS from zone trust { rule ... }`.
// Both must compile (strict, no error; lenient, no scope warning) to typed
// rule-sets with identical scope fields. The gate cells prove the three AST
// gates (mixed-kind #4881, empty-scope #7525, DNAT-`to` #3444) see the same
// packed tail the compiler now captures, in strict (reject) and lenient
// (warn; DNAT rule-set omitted) modes.
//
// RED on origin/master: every packed cell compiled match-any (scope fields
// empty) with no error/warning; the gate cells were silently accepted.
// Fail-on-revert: returning collectNATScopes / the gates to Children-only
// reads turns every assertion below RED.

func buildPackedNATTree14421(t *testing.T, cfgText string) *ConfigTree {
	t.Helper()
	cfgText = injectHierNATZones15001(cfgText)
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	return tree
}

// source NAT packed vs braced
func sourceText14421(packed bool, clause, kindVal string) string {
	// clause: from/to, kindVal: "zone trust" etc
	if packed {
		if clause == "from" {
			return `
security {
    nat {
        source {
            rule-set RS ` + clause + ` ` + kindVal + ` {
                rule r1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}
`
		}
		return `
security {
    nat {
        source {
            rule-set RS ` + clause + ` ` + kindVal + ` {
                from zone trust;
                rule r1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}
`
	}
	if clause == "from" {
		return `
security {
    nat {
        source {
            rule-set RS {
                from ` + kindVal + `;
                rule r1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}
`
	}
	return `
security {
    nat {
        source {
            rule-set RS {
                from zone trust;
                to ` + kindVal + `;
                rule r1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}
`
}

func destText14421(packed bool, kindVal string) string {
	if packed {
		return `
security {
    nat {
        destination {
            pool P1 { address 10.0.30.100; }
            rule-set RS from ` + kindVal + ` {
                rule r1 {
                    match { destination-address 198.51.100.5/32; }
                    then { destination-nat pool P1; }
                }
            }
        }
    }
}
`
	}
	return `
security {
    nat {
        destination {
            pool P1 { address 10.0.30.100; }
            rule-set RS {
                from ` + kindVal + `;
                rule r1 {
                    match { destination-address 198.51.100.5/32; }
                    then { destination-nat pool P1; }
                }
            }
        }
    }
}
`
}

func staticText14421(packed bool, kindVal string) string {
	if packed {
		return `
security {
    nat {
        static {
            rule-set RS from ` + kindVal + ` {
                rule r1 {
                    match { destination-address 198.51.100.5/32; }
                    then { static-nat prefix 10.0.0.5/32; }
                }
            }
        }
    }
}
`
	}
	return `
security {
    nat {
        static {
            rule-set RS {
                from ` + kindVal + `;
                rule r1 {
                    match { destination-address 198.51.100.5/32; }
                    then { static-nat prefix 10.0.0.5/32; }
                }
            }
        }
    }
}
`
}

func TestPackedNATRuleSetHeader14421(t *testing.T) {
	scopes := []struct{ kv, kind, val string }{
		{"zone trust", "zone", "trust"},
		{"interface ge-0/0/1.0", "interface", "ge-0/0/1.0"},
		{"routing-instance red", "routing-instance", "red"},
	}
	for _, sc := range scopes {
		// source from
		t.Run("source from "+sc.kv, func(t *testing.T) {
			braced, err := CompileConfig(buildPackedNATTree14421(t, sourceText14421(false, "from", sc.kv)))
			if err != nil {
				t.Fatalf("braced CompileConfig: %v", err)
			}
			packed, err := CompileConfig(buildPackedNATTree14421(t, sourceText14421(true, "from", sc.kv)))
			if err != nil {
				t.Fatalf("packed CompileConfig: %v", err)
			}
			if len(braced.Security.NAT.Source) != 1 || len(packed.Security.NAT.Source) != 1 {
				t.Fatalf("counts braced=%d packed=%d", len(braced.Security.NAT.Source), len(packed.Security.NAT.Source))
			}
			b, p := braced.Security.NAT.Source[0], packed.Security.NAT.Source[0]
			if !(b.FromZone == p.FromZone && b.FromInterface == p.FromInterface && b.FromRoutingInstance == p.FromRoutingInstance && b.ToZone == p.ToZone && b.ToInterface == p.ToInterface && b.ToRoutingInstance == p.ToRoutingInstance) {
				t.Fatalf("packed source-from %s = %+v, braced = %+v", sc.kv, p, b)
			}
			// explicit field check
			var got string
			switch sc.kind {
			case "zone":
				got = p.FromZone
			case "interface":
				got = p.FromInterface
			default:
				got = p.FromRoutingInstance
			}
			if got != sc.val {
				t.Fatalf("packed field = %q want %q (rs=%+v)", got, sc.val, p)
			}
		})
		// source to
		t.Run("source to "+sc.kv, func(t *testing.T) {
			braced, err := CompileConfig(buildPackedNATTree14421(t, sourceText14421(false, "to", sc.kv)))
			if err != nil {
				t.Fatalf("braced: %v", err)
			}
			packed, err := CompileConfig(buildPackedNATTree14421(t, sourceText14421(true, "to", sc.kv)))
			if err != nil {
				t.Fatalf("packed: %v", err)
			}
			b, p := braced.Security.NAT.Source[0], packed.Security.NAT.Source[0]
			var got string
			switch sc.kind {
			case "zone":
				got = p.ToZone
			case "interface":
				got = p.ToInterface
			default:
				got = p.ToRoutingInstance
			}
			if got != sc.val {
				t.Fatalf("packed to field = %q want %q braced=%+v packed=%+v", got, sc.val, b, p)
			}
		})
		// destination from
		t.Run("destination from "+sc.kv, func(t *testing.T) {
			braced, err := CompileConfig(buildPackedNATTree14421(t, destText14421(false, sc.kv)))
			if err != nil {
				t.Fatalf("braced: %v", err)
			}
			packed, err := CompileConfig(buildPackedNATTree14421(t, destText14421(true, sc.kv)))
			if err != nil {
				t.Fatalf("packed: %v", err)
			}
			b := braced.Security.NAT.Destination.RuleSets[0]
			p := packed.Security.NAT.Destination.RuleSets[0]
			var got string
			switch sc.kind {
			case "zone":
				got = p.FromZone
			case "interface":
				got = p.FromInterface
			default:
				got = p.FromRoutingInstance
			}
			if got != sc.val {
				t.Fatalf("packed dest field = %q want %q braced=%+v packed=%+v", got, sc.val, b, p)
			}
		})
		// static from
		t.Run("static from "+sc.kv, func(t *testing.T) {
			braced, err := CompileConfig(buildPackedNATTree14421(t, staticText14421(false, sc.kv)))
			if err != nil {
				t.Fatalf("braced: %v", err)
			}
			packed, err := CompileConfig(buildPackedNATTree14421(t, staticText14421(true, sc.kv)))
			if err != nil {
				t.Fatalf("packed: %v", err)
			}
			b := braced.Security.NAT.Static[0]
			p := packed.Security.NAT.Static[0]
			var got string
			switch sc.kind {
			case "zone":
				got = p.FromZone
			case "interface":
				got = p.FromInterface
			default:
				got = p.FromRoutingInstance
			}
			if got != sc.val {
				t.Fatalf("packed static field = %q want %q braced=%+v packed=%+v", got, sc.val, b, p)
			}
		})
	}
	// packed from+to pair
	t.Run("source packed from+to pair", func(t *testing.T) {
		text := `
security { nat { source {
  rule-set RS from zone trust to zone untrust {
    rule r1 { match { source-address 10.0.0.0/24; } then { source-nat { interface; } } }
  }
} } }
`
		cfg, err := CompileConfig(buildPackedNATTree14421(t, text))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if len(cfg.Security.NAT.Source) != 1 {
			t.Fatalf("count %d", len(cfg.Security.NAT.Source))
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.FromZone != "trust" || rs.ToZone != "untrust" {
			t.Fatalf("pair = %+v", rs)
		}
	})
	// lenient also captures, no warning about scope
	t.Run("lenient packed source from", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildPackedNATTree14421(t, sourceText14421(true, "from", "zone trust")))
		if err != nil {
			t.Fatalf("lenient: %v", err)
		}
		if len(cfg.Security.NAT.Source) != 1 || cfg.Security.NAT.Source[0].FromZone != "trust" {
			t.Fatalf("lenient packed = %+v warnings=%v", cfg.Security.NAT.Source, cfg.Warnings)
		}
	})
}

// TestPackedNATRuleSetHeaderGates14421 proves the three NAT scope gates see
// the packed header tail: mixed-kind (strict reject / lenient warn),
// empty-scope (strict reject / lenient warn, #7525), and DNAT `to`
// packed+braced-mixed (strict reject / lenient warn + omit, #3444/#14391).
func TestPackedNATRuleSetHeaderGates14421(t *testing.T) {
	mk := func(body string) *ConfigTree {
		return buildPackedNATTree14421(t, "security { nat { "+body+" } }")
	}
	srcRule := `rule r1 { match { source-address 10.0.0.0/24; } then { source-nat { interface; } } }`
	dstRule := `rule r1 { match { destination-address 198.51.100.5/32; } then { destination-nat pool P1; } }`
	stRule := `rule r1 { match { destination-address 198.51.100.5/32; } then { static-nat prefix 10.0.0.5/32; } }`

	cases := []struct {
		name string
		body string
		want string // substring in strict error / lenient warning
	}{
		{"mixed source from packed+child", "source { rule-set RS from zone trust { from interface ge-0/0/1.0; " + srcRule + " } }", "#4881"},
		{"mixed source to packed+child", "source { rule-set RS to zone untrust { from zone trust; to interface ge-0/0/2.0; " + srcRule + " } }", "#4881"},
		{"mixed destination from packed+child", "destination { pool P1 { address 10.0.30.100; } rule-set RS from zone untrust { from interface ge-0/0/1.0; " + dstRule + " } }", "#4881"},
		{"mixed static from packed+child", "static { rule-set RS from zone untrust { from interface ge-0/0/1.0; " + stRule + " } }", "#4881"},
		{"empty source from packed", "source { rule-set RS from zone [ ] { " + srcRule + " } }", "#7525"},
		{"empty source to packed", "source { rule-set RS to zone [ ] { from zone trust; " + srcRule + " } }", "#7525"},
		{"empty destination from packed", "destination { pool P1 { address 10.0.30.100; } rule-set RS from zone [ ] { " + dstRule + " } }", "#7525"},
		{"empty static from packed", "static { rule-set RS from zone [ ] { " + stRule + " } }", "#7525"},
		{"dnat to packed+from braced", "destination { pool P1 { address 10.0.30.100; } rule-set RS to zone trust { from zone untrust; " + dstRule + " } }", "#3444"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" strict", func(t *testing.T) {
			if _, err := CompileConfig(mk(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict CompileConfig err = %v, want containing %s", err, tc.want)
			}
		})
		t.Run(tc.name+" lenient warns", func(t *testing.T) {
			cfg, err := CompileConfigLenient(mk(tc.body))
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.want) && strings.Contains(w, `"RS"`) {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient warnings %v, want one containing %s naming RS", cfg.Warnings, tc.want)
			}
			// DNAT-to lenient must also omit the rule-set (#14391 posture).
			if tc.want == "#3444" && cfg.Security.NAT.Destination != nil {
				for _, rs := range cfg.Security.NAT.Destination.RuleSets {
					if rs.Name == "RS" {
						t.Fatalf("lenient installed DNAT rule-set RS despite packed to: %+v", rs)
					}
				}
			}
		})
	}
}
