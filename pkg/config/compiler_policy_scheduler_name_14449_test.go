package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dupSchedulerConfig14449(zonePair bool, first, second string, action string) string {
	policy := func(sched string) string {
		if sched == "" {
			return ""
		}
		return "                scheduler-name " + sched + ";\n"
	}
	body := "                match {\n" +
		"                    source-address any;\n" +
		"                    destination-address any;\n" +
		"                    application any;\n" +
		"                }\n" +
		"                then { " + action + "; }\n" +
		policy(first) + policy(second)
	if second != "" && first == "" {
		// single-value control is expressed via first only; keep shape simple
		_ = body
	}
	head := `schedulers {
    scheduler wide {
        daily { start-time 00:00; stop-time 23:59; }
    }
    scheduler narrow {
        daily { start-time 09:00; stop-time 17:00; }
    }
}
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
`
	if zonePair {
		return head + `        from-zone trust to-zone untrust {
            policy p1 {
` + body + `            }
        }
    }
}
`
	}
	return head + `        global {
            policy p1 {
` + body + `            }
        }
    }
}
`
}

func parseTree14449(t *testing.T, input string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func findPolicy14449(t *testing.T, cfg *config.Config, global bool) *config.Policy {
	t.Helper()
	if global {
		if len(cfg.Security.GlobalPolicies) != 1 {
			t.Fatalf("global policies = %d, want 1", len(cfg.Security.GlobalPolicies))
		}
		return cfg.Security.GlobalPolicies[0]
	}
	for _, zp := range cfg.Security.Policies {
		for _, p := range zp.Policies {
			if p.Name == "p1" {
				return p
			}
		}
	}
	t.Fatalf("policy p1 not found")
	return nil
}

func TestDuplicatePolicySchedulerNameStrictReject14449(t *testing.T) {
	for _, tc := range []struct {
		name   string
		global bool
		first  string
		second string
	}{
		{name: "zone-pair wide-then-narrow", first: "wide", second: "narrow"},
		{name: "zone-pair narrow-then-wide", first: "narrow", second: "wide"},
		{name: "global wide-then-narrow", global: true, first: "wide", second: "narrow"},
		{name: "global narrow-then-wide", global: true, first: "narrow", second: "wide"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := dupSchedulerConfig14449(!tc.global, tc.first, tc.second, "permit")
			_, err := config.CompileConfig(parseTree14449(t, input))
			if err == nil {
				t.Fatalf("CompileConfig succeeded, want strict reject for duplicate scheduler-name %q/%q", tc.first, tc.second)
			}
			for _, want := range []string{"scheduler-name", tc.first, tc.second, "p1", "#14449"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}

func TestDuplicatePolicySchedulerNameLenient14449(t *testing.T) {
	for _, tc := range []struct {
		name   string
		global bool
		first  string
		second string
		action string
	}{
		{name: "zone-pair permit wide-then-narrow", first: "wide", second: "narrow", action: "permit"},
		{name: "zone-pair permit narrow-then-wide", first: "narrow", second: "wide", action: "permit"},
		{name: "global permit wide-then-narrow", global: true, first: "wide", second: "narrow", action: "permit"},
		{name: "zone-pair deny wide-then-narrow", first: "wide", second: "narrow", action: "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := dupSchedulerConfig14449(!tc.global, tc.first, tc.second, tc.action)
			cfg, err := config.CompileConfigLenient(parseTree14449(t, input))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			pol := findPolicy14449(t, cfg, tc.global)
			if pol.SchedulerName != tc.second {
				t.Errorf("SchedulerName = %q, want last-wins %q", pol.SchedulerName, tc.second)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, "scheduler-name") || !strings.Contains(joined, "#14449") {
				t.Errorf("warnings do not name duplicate scheduler-name (#14449): %v", cfg.Warnings)
			}
			if tc.action == "permit" && !pol.LenientContentDropped {
				t.Errorf("conflicting permit policy not poisoned (LenientContentDropped=false)")
			}
			if tc.action == "deny" && pol.LenientContentDropped {
				t.Errorf("conflicting deny policy poisoned; refusing a deny would fail open")
			}
		})
	}
}

func TestSingleAndIdenticalSchedulerNameUnchanged14449(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  string
		second string
		want   string
	}{
		{name: "single narrow", first: "narrow", want: "narrow"},
		{name: "single wide", first: "wide", want: "wide"},
		{name: "identical narrow repeat", first: "narrow", second: "narrow", want: "narrow"},
		{name: "identical wide repeat", first: "wide", second: "wide", want: "wide"},
		{name: "no scheduler", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := dupSchedulerConfig14449(true, tc.first, tc.second, "permit")
			for _, lenient := range []bool{false, true} {
				cfg, err := func() (*config.Config, error) {
					if lenient {
						return config.CompileConfigLenient(parseTree14449(t, input))
					}
					return config.CompileConfig(parseTree14449(t, input))
				}()
				if err != nil {
					t.Fatalf("compile lenient=%v: %v", lenient, err)
				}
				pol := findPolicy14449(t, cfg, false)
				if pol.SchedulerName != tc.want {
					t.Errorf("lenient=%v SchedulerName = %q, want %q", lenient, pol.SchedulerName, tc.want)
				}
				if pol.LenientContentDropped {
					t.Errorf("lenient=%v single/identical scheduler poisoned", lenient)
				}
				if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#14449") {
					t.Errorf("lenient=%v unexpected #14449 warning: %v", lenient, cfg.Warnings)
				}
			}
		})
	}
}

// Load-merge spelling: two `policy p1` statements (the #8752 tolerant
// fold shape) each carrying one scheduler-name must fold into one
// policy whose schedulerNames conflict — strict rejects the equivalent
// single-statement duplicate above, and the folded policy must warn +
// poison on the tolerant path. (A repeated flat `set ... scheduler-name`
// line is idempotent Junos set semantics — SetPath replaces the single-
// value leaf — so it can never author a duplicate; hierarchical text
// and load-merge are the duplicate spellings.)
func TestDuplicatePolicySchedulerNameFoldedStatements14449(t *testing.T) {
	input := `schedulers {
    scheduler wide {
        daily { start-time 00:00; stop-time 23:59; }
    }
    scheduler narrow {
        daily { start-time 09:00; stop-time 17:00; }
    }
}
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                scheduler-name wide;
            }
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                scheduler-name narrow;
            }
        }
    }
}
`
	cfg, err := config.CompileConfigLenient(parseTree14449(t, input))
	if err != nil {
		t.Fatalf("CompileConfigLenient folded: %v", err)
	}
	pol := findPolicy14449(t, cfg, false)
	if pol.SchedulerName != "narrow" {
		t.Errorf("folded lenient SchedulerName = %q, want last-wins narrow", pol.SchedulerName)
	}
	if !pol.LenientContentDropped {
		t.Errorf("folded lenient conflicting permit not poisoned")
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#14449") {
		t.Errorf("folded lenient warnings do not name #14449: %v", cfg.Warnings)
	}
}
