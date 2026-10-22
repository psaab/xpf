package config

import (
	"strings"
	"testing"
)

// #4296 (fable-review-167 F-1 residual): #4287 dual-compiles a `family any`
// firewall filter into BOTH the inet (v4) and inet6 (v6) pools. A
// family-specific match under `family any` (a v4/v6 source/destination-address
// literal, or a per-family icmp-type/icmp-code) is then dual-compiled VERBATIM
// and can never match the other family — an imperfect v6 under-block (the term
// falls through to the implicit ACCEPT for v6, degrading to the pre-#4287
// state). validateFirewallFilterFamilyAnyMatchesAST rejects such a term at
// strict commit (pointing the operator at family inet/inet6) and warns on the
// tolerant load / peer-sync path.
//
// These configs are non-Junos and reach compileFirewall's structured path only
// via a HIERARCHICAL config-file / peer-synced AST (the flat `set` schema does
// not model `family any`), so the fixtures use parseHierText.

// RED-on-revert: a `family any` filter carrying a v4 source-address literal must
// be REJECTED at strict commit. On revert of the #4296 gate this goes RED — the
// term is silently dual-compiled into the v6 pool where the v4 literal never
// matches (fail-open v6 under-block).
func TestFirewallFilterFamilyAnySourceAddressRejected(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family any {
        filter blockNet {
            term t {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                }
                then {
                    discard;
                }
            }
        }
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a family-specific source-address under family any, got nil")
	}
	if !strings.Contains(err.Error(), "blockNet") || !strings.Contains(err.Error(), "family any") ||
		!strings.Contains(err.Error(), "#4296") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// A symbolic icmp-type under `family any` resolves via the ICMPv4 table
// (af=="any" is not inet6) and is therefore family-specific — rejected.
func TestFirewallFilterFamilyAnyICMPTypeRejected(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family any {
        filter noPing {
            term t {
                from {
                    icmp-type echo-request;
                }
                then {
                    discard;
                }
            }
        }
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a per-family icmp-type under family any, got nil")
	}
	if !strings.Contains(err.Error(), "noPing") || !strings.Contains(err.Error(), "#4296") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Lenient (load / peer-sync): the family-any specific-match downgrades to a
// warning so an already-persisted or peer-synced config still boots — the
// dual-compile behavior is preserved (the v6 arm merely never matches).
func TestFirewallFilterFamilyAnySpecificMatchLenientWarns(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family any {
        filter blockNet {
            term t {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                }
                then {
                    discard;
                }
            }
        }
    }
}
`)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: family-any specific match must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "blockNet") && strings.Contains(w, "#4296") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #4296 family-any specific-match warning on the lenient path, got: %v", cfg.Warnings)
	}
}

// A `family any` filter using only family-AGNOSTIC matches (protocol, which
// maps to a family-independent L4 protocol number) commits cleanly — the gate
// must not over-reject the legitimate #4287 dual-family case.
func TestFirewallFilterFamilyAnyAgnosticMatchCommits(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family any {
        filter dropTCP {
            term t {
                from {
                    protocol tcp;
                }
                then {
                    discard;
                }
            }
        }
    }
}
`)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: family any with a family-agnostic protocol match must commit, got error: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4296") {
			t.Fatalf("unexpected #4296 warning on a valid family-agnostic family any config: %q", w)
		}
	}
	if cfg.Firewall.FiltersInet["dropTCP"] == nil || cfg.Firewall.FiltersInet6["dropTCP"] == nil {
		t.Fatal("family any dropTCP must land in both pools (#4287)")
	}
}

// A family-specific match under a normal single-family filter (family inet with
// a v4 source-address, family inet6 with a v6 source-address) is legitimate and
// must NOT be flagged — the gate is scoped to `family any` only.
func TestFirewallFilterSingleFamilyAddressNotFlagged(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet {
        filter v4 {
            term t {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                }
                then {
                    discard;
                }
            }
        }
    }
    family inet6 {
        filter v6 {
            term t {
                from {
                    source-address {
                        2001:db8::/32;
                    }
                }
                then {
                    discard;
                }
            }
        }
    }
}
`)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: single-family filters with address literals must commit, got error: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4296") {
			t.Fatalf("unexpected #4296 warning on a valid single-family config: %q", w)
		}
	}
}
