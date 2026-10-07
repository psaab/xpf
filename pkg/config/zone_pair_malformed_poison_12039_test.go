package config

import (
	"strings"
	"testing"
)

// zone_pair_malformed_poison_12039_test.go pins the #12039 fail-closed fix for
// a multizone `to-zone [ B C ]` context on the TOLERANT path (Store.Load /
// peer sync, CompileConfigLenient).
//
// THE DEFECT. #11366 records such a context in MalformedZonePairs and SKIPS it
// before any of its policies compile — including an authored `then deny` —
// while the tolerant uniform-gates path only WARNS. Nothing poisons the
// snapshot, so with a configured global permit (or `default-policy
// permit-all`) the A->B / A->C traffic the dropped context used to deny falls
// through to a PERMIT. The #9246 quarantine ("warn + skip the context") is not
// fail-closed when the skipped content is a restriction.
//
// THE FIX. The tolerant uniform-gates path does not expand the malformed
// context into guessed zone-pair rules. Instead it appends one synthetic global
// policy flagged LenientContentDropped. The existing userspace snapshot builder
// lowers that flag to the __unsupported__ application sentinel, so the helper
// integrity preflight rejects the WHOLE snapshot (previous-good retained;
// fresh-boot default-deny) — the same wire outcome as other #5575-family
// poison. Strict still rejects; clean configs are untouched.
//
// The grouped fixture mirrors groupedPolicyZoneTree11366 but carries `then
// deny` (the dropped-restriction direction #11366 never varied) plus a global
// permit and `default-policy permit-all` (the fall-through the defect armed).

func malformedPoisonTree12039(t *testing.T, action string) *ConfigTree {
	t.Helper()
	return groupedSetTree11366(t, []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone A to-zone [ B C ] policy p1 match source-address any",
		"set security policies from-zone A to-zone [ B C ] policy p1 match destination-address any",
		"set security policies from-zone A to-zone [ B C ] policy p1 match application any",
		"set security policies from-zone A to-zone [ B C ] policy p1 then " + action,
		"set security policies global policy g-permit match source-address any",
		"set security policies global policy g-permit match destination-address any",
		"set security policies global policy g-permit match application any",
		"set security policies global policy g-permit then permit",
		"set security policies default-policy permit-all",
	})
}

// The tolerant compile must still BOOT (#1960 no-brick) but must leave a
// poisoned global carrier behind so the snapshot builder refuses the whole
// snapshot — not an empty rulebase that falls through to the global permit.
func TestMalformedZonePairTolerantCompilePoisonsSnapshot12039(t *testing.T) {
	for _, action := range []string{"deny", "permit"} {
		t.Run("then "+action, func(t *testing.T) {
			cfg, err := CompileConfigLenient(malformedPoisonTree12039(t, action))
			if err != nil {
				t.Fatalf("tolerant load must remain bootable: %v", err)
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatalf("then %s: tolerant compile of a multizone context left NO poisoned "+
					"policy carrier — the dropped context's rules are unenforced and nothing "+
					"refuses the snapshot, so A->B/A->C fall through to the global permit (#12039)", action)
			}
		})
	}
}

// The tolerant warning must say the context is NOT ENFORCED. The old text
// ("the compiler would ignore every listed zone after B") described a
// partial-enforcement outcome that is not what happens: the whole context is
// absent, and now the snapshot is refused.
func TestMalformedZonePairWarningStatesNotEnforced12039(t *testing.T) {
	cfg, err := CompileConfigLenient(malformedPoisonTree12039(t, "deny"))
	if err != nil {
		t.Fatalf("tolerant load must remain bootable: %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "bracketed") || !strings.Contains(joined, "to-zone") {
		t.Fatalf("tolerant warning must still name the bracketed to-zone list: %v", cfg.Warnings)
	}
	if !strings.Contains(joined, "not enforced") {
		t.Fatalf("tolerant warning must state the malformed context is not enforced: %v", cfg.Warnings)
	}
}

// STRICT-COMMIT GUARD. The fix only adds a tolerant-path synthesis; the commit
// path must keep hard-rejecting the multizone spelling.
func TestMalformedZonePairStrictStillRejects12039(t *testing.T) {
	_, err := CompileConfig(malformedPoisonTree12039(t, "deny"))
	if err == nil {
		t.Fatal("strict commit must keep rejecting a bracketed to-zone list")
	}
	if !strings.Contains(err.Error(), "to-zone") || !strings.Contains(err.Error(), "bracketed") {
		t.Fatalf("strict error must identify the invalid list, got %v", err)
	}
}

// OVER-POISON GUARD. A clean two-context config must compile with no poison
// flag, no malformed-pair warning, and both contexts intact.
func TestMalformedZonePairCleanConfigUnpoisoned12039(t *testing.T) {
	tree := groupedSetTree11366(t, []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone A to-zone B policy p1 match source-address any",
		"set security policies from-zone A to-zone B policy p1 match destination-address any",
		"set security policies from-zone A to-zone B policy p1 match application any",
		"set security policies from-zone A to-zone B policy p1 then deny",
		"set security policies from-zone A to-zone C policy p2 match source-address any",
		"set security policies from-zone A to-zone C policy p2 match destination-address any",
		"set security policies from-zone A to-zone C policy p2 match application any",
		"set security policies from-zone A to-zone C policy p2 then permit",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("clean tolerant compile failed: %v", err)
	}
	if got := LenientDroppedPolicyLocator(cfg); got != "" {
		t.Fatalf("clean config was poisoned (%q) — over-rejection refuses a healthy snapshot", got)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bracketed") {
			t.Fatalf("clean config carries a malformed-pair warning: %q", w)
		}
	}
	if len(cfg.Security.Policies) != 2 {
		t.Fatalf("clean config compiled %d contexts, want 2", len(cfg.Security.Policies))
	}
}

// SHAPE-INDEPENDENCE. The poison keys on MalformedZonePairs, which every
// malformed shape feeds — the hierarchical spelling must poison too, not just
// the grouped one.
func TestMalformedZonePairHierarchicalTolerantCompilePoisons12039(t *testing.T) {
	const text = `security {
    zones {
        security-zone A;
        security-zone B;
        security-zone C;
    }
    policies {
        from-zone A to-zone [ B C ] {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
}`
	tree, parseErrs := NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse errors: %v", parseErrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must remain bootable: %v", err)
	}
	if got := LenientDroppedPolicyLocator(cfg); got == "" {
		t.Fatal("hierarchical multizone context left NO poisoned policy on the tolerant path (#12039)")
	}
}
