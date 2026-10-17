package config

import (
	"reflect"
	"testing"
)

// #14430 (DR17-H1): two same-name `security ipsec policy` blocks under two
// DIFFERENT `ipsec` containers wholesale-replaced each other. The first
// container's strong proposal list and PFS were silently lost because
// compileIPsec built a fresh IPsecPolicyDef per block and unconditionally
// assigned it, while the #9023 duplicate fold only spans a single parent.
// The merged policy must preserve STRONG + PFS.

func parseHier14430(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

const proposals14430 = `
        proposal STRONG {
            protocol esp;
            authentication-algorithm hmac-sha-256-128;
            encryption-algorithm aes-256-cbc;
        }
        proposal WEAK {
            protocol esp;
            authentication-algorithm hmac-md5-96;
            encryption-algorithm des-cbc;
        }
`

func assertMerged14430(t *testing.T, cfg *Config) {
	t.Helper()
	pol := cfg.Security.IPsec.Policies["P"]
	if pol == nil {
		t.Fatal("ipsec policy P missing after compile")
	}
	if got, want := pol.Proposals, []string{"STRONG", "WEAK"}; !reflect.DeepEqual(got, want) {
		t.Errorf("policy P Proposals = %v, want %v (merged across containers; STRONG must not be replaced by WEAK)", got, want)
	}
	if pol.PFSGroup != 19 {
		t.Errorf("policy P PFSGroup = %d, want 19 (perfect-forward-secrecy from first container must survive)", pol.PFSGroup)
	}
}

func TestIPsecPolicyCrossContainerDuplicateMerges14430(t *testing.T) {
	src := `security {
    ipsec {` + proposals14430 + `
        policy P {
            proposals [ STRONG ];
            perfect-forward-secrecy {
                keys group19;
            }
        }
    }
    ipsec {
        policy P {
            proposals [ WEAK ];
        }
    }
    ipsec {
        vpn V1 {
            bind-interface st0.0;
            pre-shared-key fixture-secret;
            ike {
                gateway 192.0.2.1;
                ipsec-policy P;
            }
        }
    }
}`
	cfg, err := CompileConfig(parseHier14430(t, src))
	if err != nil {
		t.Fatalf("CompileConfig (strict, cross-container duplicate policy): %v", err)
	}
	assertMerged14430(t, cfg)

	// Lenient path shares compileIPsec; it must merge identically.
	cfgL, err := CompileConfigLenient(parseHier14430(t, src))
	if err != nil {
		t.Fatalf("CompileConfigLenient (cross-container duplicate policy): %v", err)
	}
	assertMerged14430(t, cfgL)
}

func TestIPsecPolicyCrossSecurityRootDuplicateMerges14430(t *testing.T) {
	src := `security {
    ipsec {` + proposals14430 + `
        policy P {
            proposals [ STRONG ];
            perfect-forward-secrecy {
                keys group19;
            }
        }
    }
}
security {
    ipsec {
        policy P {
            proposals [ WEAK ];
        }
    }
}`
	cfg, err := CompileConfig(parseHier14430(t, src))
	if err != nil {
		t.Fatalf("CompileConfig (strict, two security roots): %v", err)
	}
	assertMerged14430(t, cfg)
}

func TestIPsecPolicySameParentDuplicateStillMerges14430(t *testing.T) {
	// Control: same-parent duplicates were already folded by #9023 and
	// must keep merging (no double-merge / no regression).
	src := `security {
    ipsec {` + proposals14430 + `
        policy P {
            proposals [ STRONG ];
        }
        policy P {
            proposals [ WEAK ];
            perfect-forward-secrecy {
                keys group19;
            }
        }
    }
}`
	cfg, err := CompileConfig(parseHier14430(t, src))
	if err != nil {
		t.Fatalf("CompileConfig (strict, same-parent duplicate policy): %v", err)
	}
	assertMerged14430(t, cfg)
}

func TestIPsecPolicySingleContainerUnchanged14430(t *testing.T) {
	src := `security {
    ipsec {` + proposals14430 + `
        policy P {
            proposals [ STRONG ];
            perfect-forward-secrecy {
                keys group19;
            }
        }
    }
}`
	cfg, err := CompileConfig(parseHier14430(t, src))
	if err != nil {
		t.Fatalf("CompileConfig (strict, single policy): %v", err)
	}
	pol := cfg.Security.IPsec.Policies["P"]
	if pol == nil {
		t.Fatal("ipsec policy P missing after compile")
	}
	if got, want := pol.Proposals, []string{"STRONG"}; !reflect.DeepEqual(got, want) {
		t.Errorf("single-container policy P Proposals = %v, want %v", got, want)
	}
	if pol.PFSGroup != 19 {
		t.Errorf("single-container policy P PFSGroup = %d, want 19", pol.PFSGroup)
	}
}

func TestIPsecPolicyCrossContainerDuplicateProposalNotDuplicated14430(t *testing.T) {
	// Both containers listing the same proposal must not mint a duplicate
	// entry (rendered twice on the esp_proposals line).
	src := `security {
    ipsec {` + proposals14430 + `
        policy P {
            proposals [ STRONG ];
            perfect-forward-secrecy {
                keys group19;
            }
        }
    }
    ipsec {
        policy P {
            proposals [ STRONG ];
        }
    }
}`
	cfg, err := CompileConfig(parseHier14430(t, src))
	if err != nil {
		t.Fatalf("CompileConfig (strict, repeated proposal across containers): %v", err)
	}
	pol := cfg.Security.IPsec.Policies["P"]
	if pol == nil {
		t.Fatal("ipsec policy P missing after compile")
	}
	if got, want := pol.Proposals, []string{"STRONG"}; !reflect.DeepEqual(got, want) {
		t.Errorf("policy P Proposals = %v, want %v (no duplicate on cross-container merge)", got, want)
	}
	if pol.PFSGroup != 19 {
		t.Errorf("policy P PFSGroup = %d, want 19", pol.PFSGroup)
	}
}
