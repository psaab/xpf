package config

import (
	"strings"
	"testing"
)

// #1814 — VRRP track-interface: nested priority-cost parse + warnings.
//
// Covers both AST shapes (hierarchical NewParser text and flat-set
// ParseSetCommand + SetPath replay — NEVER NewParser on set lines, see
// CLAUDE.md), the legacy flat sibling spelling, nested-wins precedence
// in both node orders, the strict/lenient duplicate gate, and the
// compile warnings that keep tracking misconfigurations loud.

// trackTestVRRPGroup compiles cfg and returns the single vrrp-group of
// reth1 unit 0.
func trackTestVRRPGroup(t *testing.T, cfg *Config) *VRRPGroup {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["reth1"]
	if ifc == nil {
		t.Fatal("reth1 not compiled")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("reth1 unit 0 not compiled")
	}
	if len(unit.VRRPGroups) != 1 {
		t.Fatalf("expected 1 vrrp-group, got %d", len(unit.VRRPGroups))
	}
	for _, vg := range unit.VRRPGroups {
		return vg
	}
	return nil
}

// parseHier parses hierarchical config text, failing the test on errors.
func parseHier(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

// replaySetLines builds a tree by replaying flat-set lines through
// ParseSetCommand + SetPath (the only valid way to test set syntax).
func replaySetLines(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
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

func hasWarningContaining(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

const trackNestedHier = `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/1 {
                            priority-cost 20;
                        }
                    }
                }
            }
        }
    }
}`

func TestVRRPTrackInterface_NestedHierarchical(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, trackNestedHier))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" {
		t.Errorf("TrackInterface = %q, want ge-0/0/1", vg.TrackInterface)
	}
	if vg.TrackPriorityDelta != 20 {
		t.Errorf("TrackPriorityDelta = %d, want 20", vg.TrackPriorityDelta)
	}
	if hasWarningContaining(cfg.Warnings, "track") {
		t.Errorf("unexpected track warning: %v", cfg.Warnings)
	}
}

func TestVRRPTrackInterface_NestedFlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.61.3",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 priority 200",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 track-interface ge-0/0/1 priority-cost 20",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" {
		t.Errorf("TrackInterface = %q, want ge-0/0/1", vg.TrackInterface)
	}
	if vg.TrackPriorityDelta != 20 {
		t.Errorf("TrackPriorityDelta = %d, want 20", vg.TrackPriorityDelta)
	}
}

func TestVRRPTrackInterface_LegacySiblingHierarchical(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/1;
                        track-priority-cost 30;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" {
		t.Errorf("TrackInterface = %q, want ge-0/0/1", vg.TrackInterface)
	}
	if vg.TrackPriorityDelta != 30 {
		t.Errorf("TrackPriorityDelta = %d, want 30", vg.TrackPriorityDelta)
	}
}

func TestVRRPTrackInterface_LegacySiblingFlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.61.3",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 track-interface ge-0/0/1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 track-priority-cost 30",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" {
		t.Errorf("TrackInterface = %q, want ge-0/0/1", vg.TrackInterface)
	}
	if vg.TrackPriorityDelta != 30 {
		t.Errorf("TrackPriorityDelta = %d, want 30", vg.TrackPriorityDelta)
	}
}

// Nested priority-cost must win over the legacy sibling regardless of
// statement order (#1814 — the child walk is source-order based, so the
// compiler gathers both and applies nested last).
func TestVRRPTrackInterface_NestedWinsOverSibling_BothOrders(t *testing.T) {
	cases := map[string]string{
		"nested-first": `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/1 {
                            priority-cost 20;
                        }
                        track-priority-cost 30;
                    }
                }
            }
        }
    }
}`,
		"sibling-first": `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-priority-cost 30;
                        track-interface ge-0/0/1 {
                            priority-cost 20;
                        }
                    }
                }
            }
        }
    }
}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfig(parseHier(t, text))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			vg := trackTestVRRPGroup(t, cfg)
			if vg.TrackPriorityDelta != 20 {
				t.Errorf("TrackPriorityDelta = %d, want 20 (nested wins)", vg.TrackPriorityDelta)
			}
			if !hasWarningContaining(cfg.Warnings, "nested priority-cost wins") {
				t.Errorf("expected nested-wins warning, got %v", cfg.Warnings)
			}
		})
	}
}

const trackDuplicateHier = `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
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
}`

func TestVRRPTrackInterface_MultipleStrictError(t *testing.T) {
	_, err := CompileConfig(parseHier(t, trackDuplicateHier))
	if err == nil {
		t.Fatal("expected strict compile error for duplicate track-interface")
	}
	if !strings.Contains(err.Error(), "track-interface") {
		t.Errorf("error %q does not mention track-interface", err)
	}
}

func TestVRRPTrackInterface_MultipleLenientFirstWins(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHier(t, trackDuplicateHier))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" {
		t.Errorf("TrackInterface = %q, want ge-0/0/1 (first wins)", vg.TrackInterface)
	}
	if vg.TrackPriorityDelta != 20 {
		t.Errorf("TrackPriorityDelta = %d, want 20 (first wins)", vg.TrackPriorityDelta)
	}
	if !hasWarningContaining(cfg.Warnings, "keeping the first") {
		t.Errorf("expected first-wins warning, got %v", cfg.Warnings)
	}
}

func TestVRRPTrackInterface_MissingCostWarning(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/1;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" || vg.TrackPriorityDelta != 0 {
		t.Errorf("unexpected track fields: %q/%d", vg.TrackInterface, vg.TrackPriorityDelta)
	}
	if !hasWarningContaining(cfg.Warnings, "without priority-cost has no effect") {
		t.Errorf("expected missing-cost warning, got %v", cfg.Warnings)
	}
}

func TestVRRPTrackInterface_OrphanSiblingCostWarning(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-priority-cost 30;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "track-priority-cost without track-interface has no effect") {
		t.Errorf("expected orphan-cost warning, got %v", cfg.Warnings)
	}
}

func TestVRRPTrackInterface_OrphanPriorityCostChildWarning(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        priority-cost 20;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "only valid nested under track-interface") {
		t.Errorf("expected orphan priority-cost warning, got %v", cfg.Warnings)
	}
}

func TestVRRPTrackInterface_OwnerPriority255Warning(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 255;
                        track-interface ge-0/0/1 {
                            priority-cost 20;
                        }
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "ignored for the address owner") {
		t.Errorf("expected owner-255 warning, got %v", cfg.Warnings)
	}
}

// FormatSet must render the nested child as a flat-set line that
// replays back into an identically-compiling tree.
func TestVRRPTrackInterface_FormatSetRoundTrip(t *testing.T) {
	hierTree := parseHier(t, trackNestedHier)
	setText := hierTree.FormatSet()
	if !strings.Contains(setText, "track-interface ge-0/0/1 priority-cost 20") {
		t.Fatalf("FormatSet did not render the nested priority-cost:\n%s", setText)
	}

	var lines []string
	for _, line := range strings.Split(setText, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	flatTree := replaySetLines(t, lines)
	cfg, err := CompileConfig(flatTree)
	if err != nil {
		t.Fatalf("CompileConfig(replayed): %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" || vg.TrackPriorityDelta != 20 {
		t.Errorf("round-trip track fields = %q/%d, want ge-0/0/1/20",
			vg.TrackInterface, vg.TrackPriorityDelta)
	}
}

// TestVRRPTrackInterface_KeysPackedDuplicateStrictReject pins the
// Codex finding on PR #1821: the compact hierarchical leaf packs
// duplicate track-interface statements into the vrrp-group node's own
// Keys, bypassing a child-node-only count. Strict commit must reject;
// lenient must first-wins.
func TestVRRPTrackInterface_KeysPackedDuplicateStrictReject(t *testing.T) {
	const text = `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 virtual-address 10.0.61.3 track-interface ge-0/0/2 track-interface ge-0/0/3;
                }
            }
        }
    }
}`
	if _, err := CompileConfig(parseHier(t, text)); err == nil {
		t.Fatal("strict compile should reject Keys-packed duplicate track-interface")
	}
	cfg, err := CompileConfigLenient(parseHier(t, text))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/2" {
		t.Fatalf("lenient first-wins: TrackInterface = %q, want ge-0/0/2", vg.TrackInterface)
	}
	if !hasWarningContaining(cfg.Warnings, "track-interface statements") {
		t.Fatalf("missing duplicate warning: %v", cfg.Warnings)
	}
}

// TestVRRPTrackInterface_CostRangeValidation pins the second Codex
// finding on PR #1821: priority-cost outside 1..254 (notably NEGATIVE,
// which would RAISE priority on link-down) must be rejected on strict
// commit and neutralized (cost 0 + warning) on lenient load.
func TestVRRPTrackInterface_CostRangeValidation(t *testing.T) {
	for _, val := range []string{"-50", "0", "255", "9999"} {
		text := `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/2 {
                            priority-cost ` + val + `;
                        }
                    }
                }
            }
        }
    }
}`
		if _, err := CompileConfig(parseHier(t, text)); err == nil {
			t.Fatalf("strict compile should reject priority-cost %s", val)
		}
		cfg, err := CompileConfigLenient(parseHier(t, text))
		if err != nil {
			t.Fatalf("lenient compile (%s): %v", val, err)
		}
		vg := trackTestVRRPGroup(t, cfg)
		if vg.TrackPriorityDelta != 0 {
			t.Fatalf("lenient cost %s: TrackPriorityDelta = %d, want 0 (neutralized)", val, vg.TrackPriorityDelta)
		}
		if !hasWarningContaining(cfg.Warnings, "out of range") {
			t.Fatalf("lenient cost %s: missing out-of-range warning (warnings: %v)", val, cfg.Warnings)
		}
	}
}

// TestVRRPTrackInterface_DuplicateCostChildValidated pins the Codex
// confirm-round finding on PR #1821: a duplicate priority-cost child
// where only the SECOND is invalid must still strict-reject (FindChild
// validated only the first occurrence).
func TestVRRPTrackInterface_DuplicateCostChildValidated(t *testing.T) {
	tree := parseHier(t, `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/2 {
                            priority-cost 20;
                            priority-cost -50;
                        }
                    }
                }
            }
        }
    }
}`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile should reject the invalid duplicate priority-cost child")
	}
}
