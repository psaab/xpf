package config

import (
	"strings"
	"testing"
)

// Hierarchical trees are built via parseHierText (#16139 kit, NewParser) —
// the correct tool for hierarchical blocks (flat `set` lines must use
// ParseSetCommand/SetPath instead; see docs/config-schema.md).

// setTree5180 builds a ConfigTree from flat `set` commands via
// ParseSetCommand + SetPath (never NewParser).
func setTree5180(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestDuplicateNamedBlockRejected is the #5180 RED-on-revert proof.
//
// A repeated hierarchical named block under groups / interfaces / screen
// ids-option was silently reduced to last-writer-wins, dropping the earlier
// block's config (fail-open — an authored enforcement/deny block could vanish).
// Strict commit now rejects the duplicate; the equivalent flat `set` form
// MERGES (SetPath collapses the repeats onto one node) and compiles clean — so
// the two AST shapes agree that no authored block silently disappears.
//
// Reverting validateDuplicateNamedBlockAST turns every "hierarchical … rejected"
// sub-test RED (the duplicate compiles clean).
func TestDuplicateNamedBlockRejected(t *testing.T) {
	// --- interfaces ---------------------------------------------------------
	t.Run("hierarchical duplicate interface rejected", func(t *testing.T) {
		tree := parseHierText(t, `interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    eth0 {
        unit 1 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig must reject a duplicate hierarchical interface block")
		}
		if !strings.Contains(err.Error(), "interface") || !strings.Contains(err.Error(), "eth0") {
			t.Fatalf("error should name the duplicate interface, got: %v", err)
		}
		if !strings.Contains(err.Error(), "5180") {
			t.Fatalf("error should reference #5180, got: %v", err)
		}
	})

	t.Run("flat-set repeated interface merges (dual-AST equivalence)", func(t *testing.T) {
		tree := setTree5180(t, []string{
			"set interfaces eth0 unit 0 family inet address 10.0.1.1/24",
			"set interfaces eth0 unit 1 family inet address 10.0.2.1/24",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("flat-set repeated interface statements must MERGE and compile, got: %v", err)
		}
		ifc := cfg.Interfaces.Interfaces["eth0"]
		if ifc == nil {
			t.Fatal("interface eth0 missing after merge")
		}
		// Both units must survive — proof the flat shape merges rather than
		// dropping one (the fail-open the hierarchical shape suffered).
		if _, ok := ifc.Units[0]; !ok {
			t.Errorf("unit 0 dropped; units = %v", ifc.Units)
		}
		if _, ok := ifc.Units[1]; !ok {
			t.Errorf("unit 1 dropped; units = %v", ifc.Units)
		}
	})

	// --- groups -------------------------------------------------------------
	t.Run("hierarchical duplicate group rejected", func(t *testing.T) {
		tree := parseHierText(t, `groups {
    g1 {
        system {
            host-name a;
        }
    }
    g1 {
        system {
            domain-name example.com;
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig must reject a duplicate hierarchical group definition")
		}
		if !strings.Contains(err.Error(), "group") || !strings.Contains(err.Error(), "g1") {
			t.Fatalf("error should name the duplicate group, got: %v", err)
		}
	})

	// --- screen ids-option --------------------------------------------------
	t.Run("hierarchical duplicate ids-option rejected", func(t *testing.T) {
		tree := parseHierText(t, `security {
    screen {
        ids-option myscreen {
            tcp {
                land;
            }
        }
        ids-option myscreen {
            icmp {
                ping-death;
            }
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig must reject a duplicate hierarchical ids-option block")
		}
		if !strings.Contains(err.Error(), "ids-option") || !strings.Contains(err.Error(), "myscreen") {
			t.Fatalf("error should name the duplicate ids-option, got: %v", err)
		}
	})

	t.Run("hierarchical duplicate screen family within one ids-option rejected", func(t *testing.T) {
		tree := parseHierText(t, `security {
    screen {
        ids-option myscreen {
            icmp {
                ping-death;
            }
            icmp {
                fragment;
            }
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig must reject a duplicate same-family block inside one ids-option")
		}
		if !strings.Contains(err.Error(), "family") || !strings.Contains(err.Error(), "icmp") {
			t.Fatalf("error should name the duplicate screen family, got: %v", err)
		}
	})

	t.Run("flat-set repeated ids-option merges", func(t *testing.T) {
		tree := setTree5180(t, []string{
			"set security screen ids-option myscreen tcp land",
			"set security screen ids-option myscreen icmp ping-death",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("flat-set repeated ids-option statements must MERGE and compile, got: %v", err)
		}
	})

	// --- tolerant load downgrades to a warning (#1960 no-brick) --------------
	t.Run("tolerant load warns instead of rejecting", func(t *testing.T) {
		tree := parseHierText(t, `interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    eth0 {
        unit 1 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}`)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must NOT reject a duplicate block (warn, not brick): %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "eth0") && strings.Contains(w, "5180") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tolerant load should surface a duplicate-block warning, got warnings: %v", cfg.Warnings)
		}
	})

	// --- no false positive on a normal single block -------------------------
	t.Run("single interface block compiles clean", func(t *testing.T) {
		tree := parseHierText(t, `interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    eth1 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}`)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("distinct interface blocks must compile clean, got: %v", err)
		}
	})
}
