package config

import (
	"strings"
	"testing"
)

// #14443 (DR18-H7, #8445 residual): merged policer / three-color-policer
// `then { discard; loss-priority high; }` must strict-reject AND
// lenient-poison to discard. Before the fix the lenient arm only warned and
// the last-wins ThenAction ("loss-priority high") metered and forwarded
// excess traffic (DiscardExcess=false in the snapshot).

const policerGroupMerged14443 = `
groups {
    G {
        firewall {
            policer P {
                then {
                    loss-priority high;
                }
            }
        }
    }
}
firewall {
    policer P {
        apply-groups G;
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 15k;
        }
        then {
            discard;
        }
    }
}
`

const threeColorGroupMerged14443 = `
groups {
    G {
        firewall {
            three-color-policer P {
                then {
                    loss-priority high;
                }
            }
        }
    }
}
firewall {
    three-color-policer P {
        apply-groups G;
        single-rate {
            committed-information-rate 1m;
            committed-burst-size 15k;
            excess-burst-size 15k;
        }
        then {
            discard;
        }
    }
}
`

func TestPolicerThenConflictGroupMergedLenientPoison14443(t *testing.T) {
	tree := hierTree(t, policerGroupMerged14443)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile must reject merged discard+loss-priority (#8445)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatalf("lenient compile must warn about policer then conflict")
	}
	pol := cfg.Firewall.Policers["P"]
	if pol == nil {
		t.Fatalf("policer P not compiled: %+v", cfg.Firewall.Policers)
	}
	// ThenActions preserves authored conflict.
	foundDiscard, foundLP := false, false
	for _, a := range pol.ThenActions {
		if a == "discard" {
			foundDiscard = true
		}
		if a == "loss-priority" {
			foundLP = true
		}
	}
	if !foundDiscard || !foundLP {
		t.Fatalf("ThenActions = %v, want both discard and loss-priority", pol.ThenActions)
	}
	if pol.ThenAction != "discard" {
		t.Fatalf("lenient ThenAction = %q, want %q (fail-closed poison; DiscardExcess must be true)", pol.ThenAction, "discard")
	}
}

func TestThreeColorPolicerThenConflictGroupMergedLenientPoison14443(t *testing.T) {
	tree := hierTree(t, threeColorGroupMerged14443)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile must reject merged three-color discard+loss-priority (#8445)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	tcp := cfg.Firewall.ThreeColorPolicers["P"]
	if tcp == nil {
		t.Fatalf("three-color-policer P not compiled: %+v", cfg.Firewall.ThreeColorPolicers)
	}
	if tcp.ThenAction != "discard" {
		t.Fatalf("lenient ThenAction = %q, want %q (fail-closed poison)", tcp.ThenAction, "discard")
	}
}

func TestPolicerThenConflictDuplicateRootsLenientPoison14443(t *testing.T) {
	src := `
firewall {
    policer P {
        if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; }
        then { discard; }
    }
}
firewall {
    policer P {
        then { loss-priority high; }
    }
}
`
	tree := hierTree(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile must reject duplicate-root discard+loss-priority")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	pol := cfg.Firewall.Policers["P"]
	if pol == nil {
		t.Fatalf("policer P not compiled")
	}
	if pol.ThenAction != "discard" {
		t.Fatalf("lenient ThenAction = %q, want discard", pol.ThenAction)
	}
}

// Both authored orders in a single container must poison to discard leniently.
func TestPolicerThenConflictBothOrdersLenientPoison14443(t *testing.T) {
	for _, thenBody := range []string{
		"discard; loss-priority high;",
		"loss-priority high; discard;",
		"discard; forwarding-class af11;",
		"forwarding-class af11; discard;",
	} {
		src := `firewall { policer P { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then { ` + thenBody + ` } } }`
		tree := hierTree(t, src)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("strict must reject then { %s }", thenBody)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient (%s): %v", thenBody, err)
		}
		pol := cfg.Firewall.Policers["P"]
		if pol == nil || pol.ThenAction != "discard" {
			t.Fatalf("then { %s }: lenient ThenAction = %v, want discard", thenBody, pol)
		}
		if !strings.Contains(strings.Join(cfg.Warnings, " "), "policer") {
			t.Fatalf("then { %s }: warnings = %v, want policer conflict warning", thenBody, cfg.Warnings)
		}
	}
}

func TestPolicerThenSingleActionUnchanged14443(t *testing.T) {
	for _, tc := range []struct{ name, thenBody, want string }{
		{"discard alone", "discard;", "discard"},
		{"loss-priority alone", "loss-priority high;", "loss-priority high"},
		{"forwarding-class alone", "forwarding-class af11;", "forwarding-class af11"},
		{"discard repeated", "discard; discard;", "discard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `firewall { policer P { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then { ` + tc.thenBody + ` } } }`
			for _, compile := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{{"strict", CompileConfig}, {"lenient", CompileConfigLenient}} {
				cfg, err := compile.fn(hierTree(t, src))
				if err != nil {
					t.Fatalf("%s compile (%s): %v", compile.name, tc.thenBody, err)
				}
				pol := cfg.Firewall.Policers["P"]
				if pol == nil || pol.ThenAction != tc.want {
					t.Fatalf("%s then { %s }: ThenAction = %v, want %q", compile.name, tc.thenBody, pol, tc.want)
				}
			}
		})
	}
}
