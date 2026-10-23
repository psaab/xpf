package config

import (
	"os"
	"strings"
	"testing"
)

// #9415 members 2 and 5: commit errors that taught a runtime consequence the
// code no longer has.

// Member 2: an undefined screen-profile reference said the zone "silently runs
// with NO screen protection (the dataplane fails open for a missing profile)".
// Since #7168 the dataplane substitutes the conservative default for such a
// zone.
func TestUndefinedScreenProfileErrorDescribesSubstitutedDefault_9415(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set security screen ids-option wan-screen tcp land",
		"set security zones security-zone untrust screen wan-scren",
	}))
	if err == nil {
		t.Fatal("precondition: an undefined screen profile must still fail strict commit")
	}
	msg := err.Error()
	for _, stale := range []string{"fails open", "NO screen protection"} {
		if strings.Contains(msg, stale) {
			t.Errorf("error still teaches the pre-#7168 model (%q): %s", stale, msg)
		}
	}
	for _, want := range []string{`undefined screen profile "wan-scren"`, "set security screen ids-option wan-scren", "substituted conservative default"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q: %s", want, msg)
		}
	}
}

// #16005 (A3-M2): the strict error above is pinned, but the tolerant leg and
// the gate-site comments were not. The tolerant warning must name the actual
// residual — loss of flood/scan/session-limit thresholds under the substituted
// conservative default — not the pre-#7168 fail-open, and strict must still
// reject the same config.
func TestDanglingScreenProfileThresholdLoss16005(t *testing.T) {
	lines := []string{
		"set security screen ids-option wan-screen tcp land",
		"set security zones security-zone untrust screen wan-scren",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict commit must reject a dangling screen profile reference")
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile must boot a dangling screen reference (#1960): %v", err)
	}
	var warn string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone screen profile reference") {
			warn = w
			break
		}
	}
	if warn == "" {
		t.Fatalf("tolerant compile must warn on dangling screen reference, got %v", cfg.Warnings)
	}
	for _, want := range []string{"substituted conservative default", "no flood, scan or session-limit thresholds"} {
		if !strings.Contains(warn, want) {
			t.Errorf("tolerant warning must name threshold loss (%q): %s", want, warn)
		}
	}
	for _, stale := range []string{"fails open", "fails OPEN", "NO screen protection", "silently skipping every screen"} {
		if strings.Contains(warn, stale) {
			t.Errorf("tolerant warning still teaches pre-#7168 fail-open (%q): %s", stale, warn)
		}
	}
}

// #16005: the comments at the exact gate sites a maintainer reads before
// touching this gate must not assert the pre-#7168 fail-open. Source-scan
// those files (the established pattern for cross-language posture claims);
// restoring any stale claim reds this test.
func TestScreenGateCommentsDoNotClaimFailOpen16005(t *testing.T) {
	files := []struct {
		path  string
		stale []string
	}{
		{"compiler_opts.go", []string{
			"dataplane fails OPEN (screen/mod.rs returns ScreenVerdict::Pass",
			"a missing profile fails open",
			"NOT independently safe on the lenient path",
		}},
		{"compiler_uniformgates_screen.go", []string{
			"dataplane fails OPEN for a missing profile",
		}},
		{"screen_profile_ref_test.go", []string{
			"ScreenVerdict::Pass for a missing profile), silently skipping",
		}},
		{"../dataplane/userspace/screens.go", []string{
			"the verdict stays Pass (the fail-closed posture is deferred)",
			"returns ScreenVerdict::Pass on the None",
		}},
		{"../../userspace-dp/src/screen/mod.rs", []string{
			"still Pass in BOTH cases",
			"lenient/HA-sync fail-open",
			"the fail-closed-vs-pass posture is the deferred #3082",
		}},
	}
	for _, f := range files {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}
		for _, stale := range f.stale {
			if strings.Contains(string(b), stale) {
				t.Errorf("%s still asserts stale fail-open %q (#16005)", f.path, stale)
			}
		}
		if !strings.Contains(string(b), "conservative_default") {
			t.Errorf("%s must describe the #7168 conservative_default substitution (#16005)", f.path)
		}
	}
}

// Member 5: an undefined zone in a zone-pair or a global-policy match said the
// rule is "silently never matched". Since #3402 the helper refuses the whole
// policy snapshot on the tolerant path, so none of the config's policies is
// enforced. All four literals are covered: both zone-pair sides and both
// global-match sides.
func TestUndefinedPolicyZoneErrorDescribesWholeSnapshotRefusal_9415(t *testing.T) {
	policy := func(prefix string) []string {
		return []string{
			prefix + " match source-address any",
			prefix + " match destination-address any",
			prefix + " match application any",
			prefix + " then deny",
		}
	}
	cases := []struct {
		name string
		cmds []string
	}{
		{"zone_pair_from_zone", append([]string{"set security zones security-zone trust"},
			policy("set security policies from-zone typo-zone to-zone trust policy p")...)},
		{"zone_pair_to_zone", append([]string{"set security zones security-zone trust"},
			policy("set security policies from-zone trust to-zone typo-zone policy p")...)},
		{"global_from_zone", append([]string{"set security zones security-zone trust"},
			append(policy("set security policies global policy g1"),
				"set security policies global policy g1 match from-zone typo-zone")...)},
		{"global_to_zone", append([]string{"set security zones security-zone trust"},
			append(policy("set security policies global policy g1"),
				"set security policies global policy g1 match to-zone typo-zone")...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, c.cmds))
			if err == nil {
				t.Fatal("precondition: an undefined policy zone must still fail strict commit")
			}
			msg := err.Error()
			if !strings.Contains(msg, "typo-zone") || !strings.Contains(msg, "references undefined") {
				t.Fatalf("precondition: this must be the undefined-zone error: %s", msg)
			}
			for _, stale := range []string{"silently never matched", "falls through to the default policy", "fails closed for an unknown match zone"} {
				if strings.Contains(msg, stale) {
					t.Errorf("error still teaches the pre-#3402 model (%q): %s", stale, msg)
				}
			}
			for _, want := range []string{"define `set security zones security-zone typo-zone`", "WHOLE policy snapshot", "none of the config's policies is enforced"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error missing %q: %s", want, msg)
				}
			}
		})
	}
}

func TestEmptyUndefinedZonePairWarningDoesNotClaimSnapshotRefusal9415(t *testing.T) {
	for _, tc := range []struct {
		side   string
		prefix string
	}{
		{"from", "set security policies from-zone typo-zone to-zone trust"},
		{"to", "set security policies from-zone trust to-zone typo-zone"},
	} {
		t.Run(tc.side, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, []string{
				"set security zones security-zone trust",
				tc.prefix,
			}))
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable: %v", err)
			}
			for _, warning := range cfg.Warnings {
				if !strings.Contains(warning, "references undefined "+tc.side+"-zone") {
					continue
				}
				if strings.Contains(warning, "refuses the WHOLE policy snapshot") {
					t.Fatalf("the warning claims the helper refuses the snapshot, but the malformed empty pair compiles no rule for the helper to inspect: %s", warning)
				}
				if !strings.Contains(warning, "no compiled policies") {
					t.Fatalf("the warning must explain that the undefined empty pair sends no rule to the helper: %s", warning)
				}
				return
			}
			t.Fatalf("tolerant compile emitted no undefined-%s-zone warning: %v", tc.side, cfg.Warnings)
		})
	}
}
