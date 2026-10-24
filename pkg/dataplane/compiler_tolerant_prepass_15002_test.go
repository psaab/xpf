package dataplane

// #15002 (A08-03) / #16422: shapes that pkg/config's strict gates reject
// and the tolerant load / HA peer-sync path (CompileConfigLenient)
// downgrades to a warning must warn-and-skip on BOTH the #4960 validation
// pre-pass and the production real pass. The userspace snapshot builders
// already drop or disarm exactly these objects (DNAT via
// DestinationNATRuleExcludedReason, SNAT via the missing_pool/unusable-pool
// marker, NAT64 via the Rust scoped skip, static NAT via the Rust per-rule
// drop, policies via the #9410 whole-snapshot fail-closed rejection), so
// neither pass may abort the apply — otherwise a tolerated config compiles
// no dataplane snapshot after Phase 2 has mutated the host (#16422).
// Strict rejection stays in pkg/config.
//
// The acceptance shape: for each shape, CompileConfigLenient succeeds AND
// validateBeforeMutate returns nil AND the production shim compile returns
// nil, and strict config compile still rejects.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// tolerantCfg15002 parses + lenient-compiles a hierarchical config that the
// strict path rejects, asserting the tolerant path keeps it (the #1960
// no-brick precondition every fixture below relies on).
func tolerantCfg15002(t *testing.T, body string) *config.Config {
	t.Helper()
	p := config.NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must keep the fixture (#1960): %v", err)
	}
	return cfg
}

func strictRejects15002(t *testing.T, body string) {
	t.Helper()
	p := config.NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict commit must still reject this shape")
	}
}

const zones15002 = `
    zones {
        security-zone trust;
        security-zone untrust;
    }
`

// NAT64 prefix that is not /96 (also covers the /+96 normaliser spelling on
// the strict side: strict rejects, tolerant keeps, pre-pass must not abort).
func TestTolerantNAT64BadPrefixPrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        source {
            pool p64 {
                address 198.51.100.1/32;
            }
        }
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/64;
                source-pool p64;
            }
        }
    }
}
`
	strictRejects15002(t, body)
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant NAT64 /64 prefix must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// NAT64 rule-set referencing a source pool that does not exist. Since
// #15000 landed, strict config compile rejects this reference and the
// dataplane warn-skips it on BOTH passes; this cell keeps the #15002
// acceptance shape (lenient keeps it, pre-pass must not abort) pinned
// alongside the #15000 cells, and exercises the #15002 validation-pass
// arm that runs before the #15000 unconditional skip.
func TestTolerantNAT64MissingPoolPrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/96;
                source-pool no-such-pool;
            }
        }
    }
}
`
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant NAT64 missing source pool must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// Source NAT rule referencing a pool that does not exist. The userspace
// builder ships the rule with pool_unusable=missing_pool (fail-closed), so
// the pre-pass must not abort the whole apply.
func TestTolerantSNATMissingPoolPrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address 10.0.0.0/8;
                    }
                    then {
                        source-nat {
                            pool no-such-pool;
                        }
                    }
                }
            }
        }
    }
}
`
	strictRejects15002(t, body)
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant SNAT missing pool must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// Destination NAT rule referencing a pool that does not exist.
func TestTolerantDNATMissingPoolPrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        destination {
            rule-set rd1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.10/32;
                    }
                    then {
                        destination-nat {
                            pool no-such-pool;
                        }
                    }
                }
            }
        }
    }
}
`
	strictRejects15002(t, body)
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant DNAT missing pool must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// Destination NAT pool whose address is a network prefix, not a host.
func TestTolerantDNATNetworkPoolPrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        destination {
            pool dp1 {
                address 10.0.0.0/24;
            }
            rule-set rd1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.10/32;
                    }
                    then {
                        destination-nat {
                            pool dp1;
                        }
                    }
                }
            }
        }
    }
}
`
	strictRejects15002(t, body)
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant DNAT network pool must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// Static NAT rule mixing address families (v4 external, v6 internal).
func TestTolerantStaticMixedFamilyPrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        static {
            rule-set ss1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.5/32;
                    }
                    then {
                        static-nat {
                            prefix 2001:db8::5/128;
                        }
                    }
                }
            }
        }
    }
}
`
	strictRejects15002(t, body)
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant static mixed-family rule must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// Security policy naming an undefined zone. The tolerant config path
// downgrades the zone-reference gate to a warning; the userspace helper
// rejects such a snapshot whole (fail-closed, previous-good retained), so
// the Go pre-pass must not abort the apply either.
func TestTolerantPolicyUndefinedZonePrePass15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    policies {
        from-zone trust to-zone no-such-zone {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`
	strictRejects15002(t, body)
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("tolerant policy undefined zone must warn-and-skip in the pre-pass, got: %v", err)
	}
}

// Control: a fully valid NAT + policy config still validates clean, and a
// valid NAT64 /96 rule-set is untouched by the tolerant arms.
func TestTolerantPrePassValidControl15002(t *testing.T) {
	body := `
security {
` + zones15002 + `
    nat {
        source {
            pool p1 {
                address 198.51.100.1/32;
            }
            pool p64 {
                address 198.51.100.9/32;
            }
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address 10.0.0.0/8;
                    }
                    then {
                        source-nat {
                            pool p1;
                        }
                    }
                }
            }
        }
        destination {
            pool dp1 {
                address 10.0.0.5/32;
            }
            rule-set rd1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.10/32;
                    }
                    then {
                        destination-nat {
                            pool dp1;
                        }
                    }
                }
            }
        }
        static {
            rule-set ss1 {
                from zone untrust;
                rule r1 {
                    match {
                        destination-address 203.0.113.5/32;
                    }
                    then {
                        static-nat {
                            prefix 10.0.0.5/32;
                        }
                    }
                }
            }
        }
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/96;
                source-pool p64;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`
	cfg := tolerantCfg15002(t, body)
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("valid control config must validate clean, got: %v", err)
	}
	// #16422: the real (non-validation) pass also warn-and-skips: driving
	// the same compiler with an unmarked dp must ACCEPT the bad shape, so
	// a tolerated config compiles a snapshot instead of aborting after
	// Phase 2. Strict rejection stays in pkg/config (strictRejects15002).
	bad := tolerantCfg15002(t, `
security {
`+zones15002+`
    nat {
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/64;
                source-pool no-such-pool;
            }
        }
    }
}
`)
	result := newValidationResult()
	assignZoneIDs(result, bad)
	if err := compileNAT64(&natWriteTripwireDP{validationPass: false}, bad, result); err != nil {
		t.Fatalf("real pass must warn-and-skip the bad NAT64 prefix (#16422), got: %v", err)
	}
}

// TestCompileConfigTolerantNATShapesDoNotAbortPostZonePhase is the
// #16422 regression named by #15943 §6: for each of the six tolerated
// shapes, the production real pass (CompileConfig against
// userspaceShimCompileDataplane, the exact dp CompileUserspaceShim
// uses) must return nil instead of aborting after Phase 2, and strict
// pkg/config compile must still reject. The zones carry no interfaces,
// so compileZones completes without touching real links (the probe's
// stated limit). NAT64 missing-pool is already warn-skip on both
// passes via #15000; it is included as a guard.
func TestCompileConfigTolerantNATShapesDoNotAbortPostZonePhase(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"snat-missing-pool", `
security {
` + zones15002 + `
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match { source-address 10.0.0.0/8; }
                    then { source-nat { pool no-such-pool; } }
                }
            }
        }
    }
}
`},
		{"dnat-missing-pool", `
security {
` + zones15002 + `
    nat {
        destination {
            rule-set rd1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat { pool no-such-pool; } }
                }
            }
        }
    }
}
`},
		{"dnat-network-pool", `
security {
` + zones15002 + `
    nat {
        destination {
            pool dp1 { address 10.0.0.0/24; }
            rule-set rd1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat { pool dp1; } }
                }
            }
        }
    }
}
`},
		{"static-mixed-family", `
security {
` + zones15002 + `
    nat {
        static {
            rule-set ss1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.5/32; }
                    then { static-nat { prefix 2001:db8::5/128; } }
                }
            }
        }
    }
}
`},
		{"nat64-bad-prefix", `
security {
` + zones15002 + `
    nat {
        source { pool p64 { address 198.51.100.1/32; } }
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/64;
                source-pool p64;
            }
        }
    }
}
`},
		{"nat64-missing-pool", `
security {
` + zones15002 + `
    nat {
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/96;
                source-pool no-such-pool;
            }
        }
    }
}
`},
		{"nat64-unusable-pool", `
security {
` + zones15002 + `
    nat {
        source { pool p64 { address 2001:db8::1/128; } }
        nat64 {
            rule-set rs64 {
                prefix 64:ff9b::/96;
                source-pool p64;
            }
        }
    }
}
`},
		{"policy-undefined-zone", `
security {
` + zones15002 + `
    policies {
        from-zone trust to-zone no-such-zone {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strictRejects15002(t, tc.body)
			cfg := tolerantCfg15002(t, tc.body)
			if err := validateBeforeMutate(cfg); err != nil {
				t.Fatalf("pre-pass must warn-and-skip, got: %v", err)
			}
			m := New()
			m.loaded.Store(true)
			result, err := CompileConfig(userspaceShimCompileDataplane{Manager: m}, cfg, false)
			if err != nil {
				t.Fatalf("production real pass must warn-and-skip (#16422), got: %v", err)
			}
			if result == nil {
				t.Fatal("production real pass returned nil result")
			}
		})
	}
	// Positive control: the pool-defined twin of the SNAT shape still
	// compiles clean on the production path.
	t.Run("snat-defined-pool-control", func(t *testing.T) {
		body := `
security {
` + zones15002 + `
    nat {
        source {
            pool p1 { address 198.51.100.1/32; }
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match { source-address 10.0.0.0/8; }
                    then { source-nat { pool p1; } }
                }
            }
        }
    }
}
`
		cfg := tolerantCfg15002(t, body)
		m := New()
		m.loaded.Store(true)
		if _, err := CompileConfig(userspaceShimCompileDataplane{Manager: m}, cfg, false); err != nil {
			t.Fatalf("pool-defined control must compile clean, got: %v", err)
		}
	})
}
