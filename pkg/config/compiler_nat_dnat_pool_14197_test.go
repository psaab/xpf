package config

import (
	"strings"
	"testing"
)

// #14197: two `address` statements inside ONE hierarchical DNAT pool block
// (or across repeated pool blocks) previously compiled last-wins: a valid
// second statement silently cleared an invalid first statement's
// AddressInvalidSpec, and two valid hosts silently kept only the last.
// Hierarchical duplicate address statements now record
// DuplicateAddressStatements, fail strict commit, and fail closed
// (excluded, not last-wins) on the tolerant path. Flat-set re-`set`
// replaces in the tree before compile and is unaffected (#10289).
func TestDNATPoolDuplicateAddressStatements14197(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "invalid-then-valid",
			body: "address 10.1.0.1 to 10.1.0.9; address 10.2.0.1;",
		},
		{
			name: "valid-then-valid",
			body: "address 10.0.0.1; address 10.0.0.2;",
		},
		{
			name: "valid-then-invalid",
			body: "address 10.3.0.1; address 10.3.0.1 to 10.3.0.9;",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgText := `
security {
    nat {
        destination {
            pool P1 {
                ` + tc.body + `
            }
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat pool P1; }
                }
            }
        }
    }
    zones { security-zone untrust; }
}
`
			p := NewParser(cfgText)
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("Parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "duplicate address statements") {
				t.Fatalf("CompileConfig = %v, want duplicate address statements rejection", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			pool := cfg.Security.NAT.Destination.Pools["P1"]
			if pool == nil || pool.DuplicateAddressStatements == "" {
				t.Fatalf("lenient pool = %+v, want DuplicateAddressStatements recorded", pool)
			}
			foundWarn := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "duplicate address statements") {
					foundWarn = true
				}
			}
			if !foundWarn {
				t.Fatalf("lenient warnings = %v, want duplicate address statements", cfg.Warnings)
			}
			rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
			if reason := DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rule); !strings.Contains(reason, "duplicate address statements") {
				t.Fatalf("excluded reason = %q, want duplicate address statements fail-closed", reason)
			}
		})
	}
}

// A single address statement plus a port-only statement is not a duplicate.
func TestDNATPoolSingleAddressPlusPortOnlyNotDuplicate14197(t *testing.T) {
	nat := natNodeFromText(t, `
security {
    nat {
        destination {
            pool P1 {
                address 10.0.0.1;
                address port 8080;
            }
        }
    }
}
`)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	pool := sec.NAT.Destination.Pools["P1"]
	if pool.DuplicateAddressStatements != "" || pool.Address != "10.0.0.1" || pool.Port != 8080 {
		t.Fatalf("pool = addr %q port %d dup %q, want single host + port, no duplicate",
			pool.Address, pool.Port, pool.DuplicateAddressStatements)
	}
}
