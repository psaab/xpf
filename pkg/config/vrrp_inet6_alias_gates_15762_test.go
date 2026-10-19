package config

import (
	"strings"
	"testing"
)

// #15762 — the Junos `vrrp-inet6-group` alias bypassed four AST gates that
// keyed only on `vrrp-group`: validateVRRPTrackInterfaceAST,
// validateVRRPAuthenticationAST, collectVRRPGroups, and (via the collector)
// vrrpMisplacedAuth. parseVRRPGroups compiles both spellings, so an inet6
// group carrying authentication or duplicate track-interface statements
// committed clean and activated unauthenticated / with last-wins tracking.
// These tests pin the inet6 spelling to the same strict-reject /
// lenient-drop behaviour as its vrrp-group twin. Helpers
// (replaySetLines, parseHier, firstVRRPGroupWithVIP, hasWarningContaining)
// are defined in sibling test files in this package.

const vrrpInet6VIP15762 = "2001:db8::1/64"

// Strict: authentication under vrrp-inet6-group must reject like vrrp-group.
func TestVRRPInet6AuthStrictReject15762(t *testing.T) {
	flat := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address " + vrrpInet6VIP15762,
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 authentication-type md5",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 authentication-key secret15762",
	})
	if _, err := CompileConfig(flat); err == nil {
		t.Fatal("flat-set: vrrp-inet6-group authentication must strict-reject")
	} else if !strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "secret15762") {
		t.Fatalf("flat-set: error must name authentication without leaking the key, got: %v", err)
	}

	hier := `interfaces {
    reth0 {
        unit 0 {
            family inet6 {
                address 2001:db8::10/64 {
                    vrrp-inet6-group 1 {
                        virtual-inet6-address ` + vrrpInet6VIP15762 + `;
                        authentication-type md5;
                        authentication-key secret15762;
                    }
                }
            }
        }
    }
}`
	if _, err := CompileConfig(parseHier(t, hier)); err == nil {
		t.Fatal("hierarchical: vrrp-inet6-group authentication must strict-reject")
	} else if !strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "secret15762") {
		t.Fatalf("hierarchical: error must name authentication without leaking the key, got: %v", err)
	}
}

// Lenient: the auth-carrying inet6 group is dropped (fail-closed), warned,
// and the base address survives — exactly as for vrrp-group (#5834 posture).
func TestVRRPInet6AuthLenientDropsGroup15762(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address " + vrrpInet6VIP15762,
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 authentication-key secret15762",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "authentication") {
		t.Fatalf("lenient must warn on inet6 authentication, got: %v", cfg.Warnings)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "secret15762") {
			t.Fatalf("warning leaked the authentication key: %q", w)
		}
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, vrrpInet6VIP15762); vg != nil {
		t.Fatalf("lenient left auth-carrying vrrp-inet6-group ACTIVE: %+v", vg)
	}
	if ifc := cfg.Interfaces.Interfaces["reth0"]; ifc == nil || len(ifc.Units) == 0 {
		t.Fatal("base interface/unit must survive the lenient drop")
	}
}

const vrrpInet6MisplacedHier15762 = `interfaces {
    reth0 {
        unit 0 {
            family inet6 {
                address 2001:db8::10/64 {
                    authentication-key secret15762;
                    vrrp-inet6-group 1 {
                        virtual-inet6-address ` + vrrpInet6VIP15762 + `;
                    }
                }
            }
        }
    }
}`

// Misplaced auth (leaf on the address ancestor) with only an inet6 group in
// its subtree must reject strict / drop lenient — this exercises
// collectVRRPGroups and vrrpMisplacedAuth, which also keyed on vrrp-group.
func TestVRRPInet6MisplacedAuth15762(t *testing.T) {
	if _, err := CompileConfig(parseHier(t, vrrpInet6MisplacedHier15762)); err == nil {
		t.Fatal("strict: misplaced auth above vrrp-inet6-group must reject")
	} else if !strings.Contains(err.Error(), "authentication-key") || strings.Contains(err.Error(), "secret15762") {
		t.Fatalf("strict: error must name authentication-key without leaking it, got: %v", err)
	}
	cfg, err := CompileConfigLenient(parseHier(t, vrrpInet6MisplacedHier15762))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "authentication-key") {
		t.Fatalf("lenient must warn on misplaced auth, got: %v", cfg.Warnings)
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, vrrpInet6VIP15762); vg != nil {
		t.Fatalf("lenient left misplaced-auth vrrp-inet6-group ACTIVE: %+v", vg)
	}
}

// The inet6 group node itself is a group, not a misplaced carrier: auth as a
// direct child must hit the group arm, and a clean inet6 group must commit.
func TestVRRPInet6CleanGroupCommits15762(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address " + vrrpInet6VIP15762,
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 priority 150",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("clean vrrp-inet6-group must commit: %v", err)
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, vrrpInet6VIP15762); vg == nil || vg.Priority != 150 {
		t.Fatalf("clean vrrp-inet6-group compiled wrong: %+v", vg)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication") {
			t.Fatalf("clean group must not warn on authentication: %v", cfg.Warnings)
		}
	}
}

const vrrpInet6DupTrackHier15762 = `interfaces {
    reth0 {
        unit 0 {
            family inet6 {
                address 2001:db8::10/64 {
                    vrrp-inet6-group 1 {
                        virtual-inet6-address ` + vrrpInet6VIP15762 + `;
                        priority 200;
                        track-interface ge-0/0/1 {
                            priority-cost 20;
                        }
                        track-interface ge-0/0/2 {
                            priority-cost 40;
                        }
                    }
                }
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet6 {
                address 2001:db8:1::1/64;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet6 {
                address 2001:db8:2::1/64;
            }
        }
    }
}`

// Strict: duplicate track-interface under vrrp-inet6-group rejects.
// Lenient: first track-interface wins with a warning, as for vrrp-group.
func TestVRRPInet6DuplicateTrack15762(t *testing.T) {
	if _, err := CompileConfig(parseHier(t, vrrpInet6DupTrackHier15762)); err == nil {
		t.Fatal("strict: duplicate track-interface under vrrp-inet6-group must reject")
	} else if !strings.Contains(err.Error(), "track-interface") {
		t.Fatalf("strict: error must mention track-interface, got: %v", err)
	}
	cfg, err := CompileConfigLenient(parseHier(t, vrrpInet6DupTrackHier15762))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, vrrpInet6VIP15762)
	if vg == nil {
		t.Fatal("lenient: vrrp-inet6-group must still compile")
	}
	if vg.TrackInterface != "ge-0/0/1" || vg.TrackPriorityDelta != 20 {
		t.Fatalf("lenient first-wins wrong: track=%q cost=%d", vg.TrackInterface, vg.TrackPriorityDelta)
	}
	if !hasWarningContaining(cfg.Warnings, "keeping the first") {
		t.Fatalf("lenient must warn first-wins, got: %v", cfg.Warnings)
	}
}

// Unit-pin the shared predicate the four gates now use.
func TestIsVRRPGroupNodeName15762(t *testing.T) {
	for name, want := range map[string]bool{
		"vrrp-group":       true,
		"vrrp-inet6-group": true,
		"vrrp":             false,
		"track-interface":  false,
		"":                 false,
	} {
		if got := isVRRPGroupNodeName(name); got != want {
			t.Errorf("isVRRPGroupNodeName(%q) = %v, want %v", name, got, want)
		}
	}
}
