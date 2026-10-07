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

// FROM-LIST BYPASS. Grouped `from-zone [ A C ] to-zone B` collapses the OTHER
// way from the to-zone list: the keys shift so Keys[3] becomes the literal
// string "to-zone" (["from-zone","A","C","to-zone"] with A/C bracketed), while
// the real to-zone is absorbed into a non-policy child. The #9246 detector
// keys on Keys[2]=="to-zone", so this shape escapes MalformedZonePairs
// entirely; the pair builder then reads Keys[1]/Keys[3] as A/"to-zone" and
// compiles a phantom A->`to-zone` pair with zero policies, and the tolerant
// path only warns — the dropped deny falls through to the global permit.
// All three cells below are RED pre-fix and GREEN once the shape is recorded
// and flows into the existing synthetic-global-poison path.
func malformedFromListTree12039(t *testing.T) *ConfigTree {
	t.Helper()
	return groupedSetTree11366(t, []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone [ A C ] to-zone B policy p1 match source-address any",
		"set security policies from-zone [ A C ] to-zone B policy p1 match destination-address any",
		"set security policies from-zone [ A C ] to-zone B policy p1 match application any",
		"set security policies from-zone [ A C ] to-zone B policy p1 then deny",
		"set security policies global policy g-permit match source-address any",
		"set security policies global policy g-permit match destination-address any",
		"set security policies global policy g-permit match application any",
		"set security policies global policy g-permit then permit",
		"set security policies default-policy permit-all",
	})
}

func TestMalformedFromListZonePairIsRecorded12039(t *testing.T) {
	cfg, err := CompileConfigLenient(malformedFromListTree12039(t))
	if err != nil {
		t.Fatalf("tolerant load must remain bootable: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) == 0 {
		t.Fatal("grouped from-zone list recorded NOTHING in MalformedZonePairs — the bypass shape escapes the #9246 detector (Keys[3]==\"to-zone\") and its dropped deny is unenforced (#12039)")
	}
	joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
	if !strings.Contains(joined, "from-zone") || !strings.Contains(joined, "bracketed") {
		t.Fatalf("recorded diagnostic must name the bracketed from-zone list, got %q", joined)
	}
}

func TestMalformedFromListZonePairLeavesNoPhantomPair12039(t *testing.T) {
	cfg, err := CompileConfigLenient(malformedFromListTree12039(t))
	if err != nil {
		t.Fatalf("tolerant load must remain bootable: %v", err)
	}
	for _, zp := range cfg.Security.Policies {
		t.Errorf("tolerant path built phantom context %s->%s with %d policies from a grouped from-zone list it must refuse. The operator sees a zone pair they never wrote (to-zone literally \"to-zone\"), carrying none of the rule they did write (#12039)",
			zp.FromZone, zp.ToZone, len(zp.Policies))
	}
}

func TestSingleFromZoneBracketStillCompiles12039(t *testing.T) {
	prefix := "set security policies from-zone [ A ] to-zone B policy p1 "
	tree := groupedSetTree11366(t, []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		prefix + "match source-address any",
		prefix + "match destination-address any",
		prefix + "match application any",
		prefix + "then deny",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a single bracketed from-zone value is still one zone pair: %v", err)
	}
	if len(cfg.Security.Policies) != 1 ||
		cfg.Security.Policies[0].FromZone != "A" ||
		cfg.Security.Policies[0].ToZone != "B" ||
		len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("single bracketed from-zone did not compile as A->B with its policy: %+v", cfg.Security.Policies)
	}
}

func TestMalformedFromListDetectorScansPastKeys3_12039(t *testing.T) {
	n := &Node{Keys: []string{"from-zone", "A", "C", "D", "to-zone"}}
	if got := malformedZonePairShape9246(n); !strings.Contains(got, "from-zone [ A C D ]") {
		t.Fatalf("a source list with more than two members must detect the shifted to-zone key at Keys[4], got %q", got)
	}
}

// PLACEHOLDER CONTROL. The #2419 compact/block census synthesizes the
// `security policies from-zone xpfarg xpfarg xpfarg policy xpfarg` path. Its
// parser-shaped placeholder keys are all bare `xpfarg` values; a shape with
// the fixed `to-zone` token after those values is also an explicit exclusion
// control for the widened index scan. Neither may be recorded as malformed.
func TestMalformedFromListDetectorExemptsCensusPlaceholders12039(t *testing.T) {
	cases := []*Node{
		{Keys: []string{"from-zone", "xpfarg", "xpfarg", "xpfarg"}},
		{Keys: []string{"from-zone", "xpfarg", "xpfarg", "to-zone", "xpfarg"}},
	}
	for _, n := range cases {
		if got := malformedZonePairShape9246(n); got != "" {
			t.Fatalf("census placeholder shape %q was flagged malformed: %q — the from-list widening over-reaches into #2419 synthetic paths",
				n.Keys, got)
		}
	}
	const censusPlaceholder = `security {
    zones { security-zone xpfarg; }
    policies {
        from-zone xpfarg xpfarg xpfarg policy xpfarg {
            match {
                source-address any;
                destination-address any;
                application any;
            }
            then { deny; }
        }
    }
}`
	tree, parseErrs := NewParser(censusPlaceholder).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse the #2419 census placeholder: %v", parseErrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile the #2419 census placeholder: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 0 {
		t.Fatalf("the #2419 census placeholder was recorded as malformed: %q", cfg.Security.MalformedZonePairs)
	}
}
