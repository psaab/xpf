package config

import "testing"

// TestSchedulerNameIsNotDroppedAtEitherSpelling8690 is the executable form of
// the `no-drop-measured` entries in the #8690 permanent-exclusion register.
//
// The register briefly carried the opposite claim: that a packed
// `policy <p> scheduler-name <s>` silently drops the scheduler, leaving a
// PERMANENTLY-ACTIVE security policy, and that normalizing it was a correct fix
// owing a failover smoke. That was reasoned, not measured, and it is false. The
// argument was built on a spelling nobody writes.
//
// This cell measures both spellings that are actually reachable. It exists so
// the register's claim cannot rot back into prose: if someone changes the
// normalizer such that scheduler-name IS dropped, or such that the pass starts
// mattering here at all, this reds.
func TestSchedulerNameIsNotDroppedAtEitherSpelling8690(t *testing.T) {
	base := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	}
	const schedulerDef = "set schedulers scheduler S daily start-time 09:00:00 stop-time 17:00:00"
	const schedulerRef = "set security policies from-zone trust to-zone untrust policy p1 scheduler-name S"

	build := func(t *testing.T, cmds []string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			path, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		return tree
	}

	policySchedulerName := func(cfg *Config) string {
		for _, zpp := range cfg.Security.Policies {
			if zpp == nil {
				continue
			}
			for _, pol := range zpp.Policies {
				if pol != nil && pol.Name == "p1" {
					return pol.SchedulerName
				}
			}
		}
		return "<no policy p1>"
	}

	// The flat `set` spelling is the one operators write, and it is the only
	// correct way to exercise a packed form (CLAUDE.md: never NewParser here).
	// Every case is run with the brace-elision pass BOTH enabled and disabled:
	// the pass must not be load-bearing at this site in either direction.
	for _, skipNormalize := range []bool{false, true} {
		t.Run(map[bool]string{false: "passEnabled", true: "passDisabled"}[skipNormalize], func(t *testing.T) {
			opts8690 := strictCompileOpts()
			opts8690.skipCompactNormalize = skipNormalize
			// 1. scheduler defined -> reference is HONOURED, not dropped.
			cfg, err := compileTree(build(t, append(append([]string{}, base...), schedulerRef, schedulerDef)),
				opts8690, nil)
			if err != nil {
				t.Fatalf("defined scheduler: want clean compile, got %v", err)
			}
			if got := policySchedulerName(cfg); got != "S" {
				t.Errorf("defined scheduler: policy p1 scheduler-name = %q, want %q — the packed spelling DROPPED it", got, "S")
			}

			// 2. scheduler NOT defined -> strict commit REJECTS. The validator is
			// live at this spelling; it is not a vacuous gate.
			_, err = compileTree(build(t, append(append([]string{}, base...), schedulerRef)),
				opts8690, nil)
			if err == nil {
				t.Error("undefined scheduler: want rejection, got clean compile — the reference validator is not reached at the packed spelling")
			}

			// 3. Control: with no scheduler-name at all the field is empty and the
			// config still compiles. Without this, case 1 could pass on a config
			// that carries "S" for some unrelated reason.
			cfg, err = compileTree(build(t, append(append([]string{}, base...), schedulerDef)),
				opts8690, nil)
			if err != nil {
				t.Fatalf("no scheduler-name: want clean compile, got %v", err)
			}
			if got := policySchedulerName(cfg); got != "" {
				t.Errorf("no scheduler-name: policy p1 scheduler-name = %q, want empty", got)
			}
		})
	}
}

// TestSchedulerNameHierarchicalSiblingIsRejected8690 measures the OTHER
// reachable spelling — the one the #8690 census synthesizes: a from-zone block
// holding a fully-defined `policy p1` AND a sibling brace-elided
// `policy p1 scheduler-name S;`.
//
// A repeated policy block does NOT merge into the first; it replaces it, losing
// both the match and the terminal action. THREE independent gates reject the
// result, established by disarming them one at a time and reading which message
// surfaced next:
//
//	#3044 missing required match criterion   (fires first)
//	  -> disarmed: "no terminal action" (validatePolicyTerminalActionStrict)
//	    -> disarmed: "duplicate policy name \"p1\"" (#3473)
//
// The assertion here is only that the config is REJECTED, which is all this
// cell can observe — it deliberately does not name a gate, because disarming
// any one of the three leaves it green. #3473 is the most accurate description
// of the shape: the elided sibling is a duplicate policy, not a partial one.
//
// Why that matters for #8690: normalizing this site would have to decide
// merge-vs-replace, and only merge is safe. Today three gates stand between a
// replace and a compiled config, and the innermost one names the real defect.
func TestSchedulerNameHierarchicalSiblingIsRejected8690(t *testing.T) {
	const body = `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.2.1/24; } } }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/1.0; } }
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
            policy p1 scheduler-name S;
        }
    }
}
`
	const sched = "\nschedulers { scheduler S { daily { start-time 09:00:00 stop-time 17:00:00; } } }\n"
	for _, withScheduler := range []bool{true, false} {
		for _, skipNormalize := range []bool{false, true} {
			text := body
			if withScheduler {
				text += sched
			}
			err := compileStrict8690(t, text, skipNormalize)
			if err == nil {
				t.Errorf("schedulerDefined=%v skipNormalize=%v: want rejection of the sibling-elided policy, got clean compile — a match-less policy reached the compiled config",
					withScheduler, skipNormalize)
			}
		}
	}
}
