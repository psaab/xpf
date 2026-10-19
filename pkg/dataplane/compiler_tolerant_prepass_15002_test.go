package dataplane

// #15002 (A08-03): shapes that pkg/config's strict gates reject and the
// tolerant load / HA peer-sync path (CompileConfigLenient) downgrades to a
// warning still hard-failed the whole Go dataplane pre-pass
// (validateBeforeMutate). The userspace snapshot builders already drop or
// disarm exactly these objects (DNAT via DestinationNATRuleExcludedReason,
// SNAT via the missing_pool/unusable-pool marker, NAT64 via the Rust scoped
// skip, static NAT via the Rust per-rule drop, policies via the #9410
// whole-snapshot fail-closed rejection), so the pre-pass must warn-and-skip
// the offending rule / rule-set on the validation pass instead of aborting
// the apply before any host mutation — while the real (non-validation)
// pass keeps its hard rejection so a strict caller never applies silently.
//
// The acceptance shape per issue #15002: for each shape,
// CompileConfigLenient succeeds AND validateBeforeMutate returns nil, and
// strict config compile still rejects.

import (
	"strings"
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
	// The real (non-validation) pass keeps the hard rejections: driving the
	// same compilers with an unmarked dp must still error on a bad shape,
	// so the tolerant arms cannot leak into a strict apply.
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
	if err := compileNAT64(&natWriteTripwireDP{validationPass: false}, bad, result); err == nil ||
		!strings.Contains(err.Error(), "rs64") {
		t.Fatalf("real pass must keep rejecting the bad NAT64 prefix, got: %v", err)
	}
}
