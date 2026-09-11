package config

import (
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
