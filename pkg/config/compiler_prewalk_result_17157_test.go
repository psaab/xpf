package config

import (
	"strings"
	"testing"
)

// #17157: runPreWalkGates must return both collision sets in
// preWalkResult (the single result channel), and compileExpanded must
// stamp them from that return value — never through the deleted
// compileOpts pointer out-parameters
// (opts.applicationNameCollisions / opts.firewallFilterCollisions),
// which a caller could silently drop by leaving the pointer nil.
//
// These tests drive the FULL public compile paths (CompileConfigLenient
// and CompileConfigForNodeLenient) rather than colluding with the
// pre-walk wiring: if compileExpanded read the collision sets from
// anywhere other than preWalkResult, the lenient quarantines below
// would not be stamped (the pointers are gone, so nothing else CAN
// carry them — this test pins that the return value is the live one).
//
// FAIL-ON-REVERT: revert compileExpanded to installing pointer
// out-parameters on compileOpts and runPreWalkGates to writing through
// them, and these tests stay green (behavior is transport-independent)
// — the structural pins are TestCompileOptsShape17157 (no
// pointer-to-map fields survive) and the acceptance grep for
// `applicationNameCollisions` / `firewallFilterCollisions` as
// compileOpts fields. What THIS test kills is the half-revert where
// the struct fields are gone but compileExpanded reads an empty set:
// both quarantines below would vanish.

// TestPreWalkResultCollisionsViaPreWalkResult17157 proves both
// collision sets reach the compiled Config through preWalkResult on
// the generic lenient path: the #3339 application name lands in
// Applications.CollidingNames and the #3884/#15997 firewall name lands
// in Firewall.CollidingNames AND is omitted from both filter pools.
func TestPreWalkResultCollisionsViaPreWalkResult17157(t *testing.T) {
	tree := parseHierText(t, `
applications {
    application web {
        protocol tcp;
        destination-port 80;
    }
    application-set web {
        application junos-https;
    }
}
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
    family any {
        filter blockX {
            term t1 {
                then {
                    accept;
                }
            }
        }
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: both collisions must downgrade to warnings, got error: %v", err)
	}
	if _, ok := cfg.Applications.CollidingNames["web"]; !ok {
		t.Fatalf("application collision set not stamped from preWalkResult: Applications.CollidingNames=%v", cfg.Applications.CollidingNames)
	}
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; !ok {
		t.Fatalf("firewall collision set not stamped from preWalkResult: Firewall.CollidingNames=%v", cfg.Firewall.CollidingNames)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; ok {
		t.Fatal("quarantined blockX must be omitted from FiltersInet (#15997)")
	}
	if _, ok := cfg.Firewall.FiltersInet6["blockX"]; ok {
		t.Fatal("quarantined blockX must be omitted from FiltersInet6 (#15997)")
	}
	found3339, found3884 := false, false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "web") && strings.Contains(w, "#3339") {
			found3339 = true
		}
		if strings.Contains(w, "blockX") && strings.Contains(w, "#3884") {
			found3884 = true
		}
	}
	if !found3339 || !found3884 {
		t.Fatalf("expected #3339 and #3884 warnings, got: %v", cfg.Warnings)
	}
}

// TestPreWalkResultCollisionsNodeLenient17157 is the node-aware twin:
// CompileConfigForNodeLenient must stamp the identical collision sets
// (same pre-walk, same preWalkResult channel).
func TestPreWalkResultCollisionsNodeLenient17157(t *testing.T) {
	tree := parseHierText(t, `
applications {
    application web {
        protocol tcp;
        destination-port 80;
    }
    application-set web {
        application junos-https;
    }
}
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
    family any {
        filter blockX {
            term t1 {
                then {
                    accept;
                }
            }
        }
    }
}
`)
	cfg, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient: both collisions must downgrade to warnings, got error: %v", err)
	}
	if _, ok := cfg.Applications.CollidingNames["web"]; !ok {
		t.Fatalf("node lenient: application collision set not stamped: %v", cfg.Applications.CollidingNames)
	}
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; !ok {
		t.Fatalf("node lenient: firewall collision set not stamped: %v", cfg.Firewall.CollidingNames)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; ok {
		t.Fatal("node lenient: quarantined blockX must be omitted from FiltersInet (#15997)")
	}
}
