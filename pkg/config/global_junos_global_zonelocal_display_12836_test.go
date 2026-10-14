package config

import (
	"strings"
	"testing"
)

// #12836 (D2-14): a global policy whose match from-zone/to-zone is the
// reserved `junos-global` token falls through to the generic undefined-zone
// text, which instructs the operator to `define set security zones
// security-zone junos-global` — the exact definition #3055 rejects. The
// zone-pair loop already names the reserved global-policy context (#9570);
// the global loop must do the same instead of emitting the self-contradictory
// remediation. Fail-on-revert: removing the global-loop junos-global arm
// restores the "define ... junos-global" text and turns these RED.
func TestGlobalPolicyJunosGlobalNamesReservedContext12836(t *testing.T) {
	for _, tc := range []struct{ name, side string }{
		{"from-zone", "from-zone"},
		{"to-zone", "to-zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust",
				"set security policies global policy g match " + tc.name + " junos-global",
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g then permit",
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict commit accepted a global policy scoping %s to junos-global", tc.name)
			}
			msg := err.Error()
			for _, want := range []string{`"junos-global"`, "reserved global-policy context", "security policies global", tc.side} {
				if !strings.Contains(msg, want) {
					t.Errorf("strict error does not contain %q: %s", want, msg)
				}
			}
			for _, bad := range []string{
				"define `set security zones security-zone junos-global`",
				"references undefined zone",
			} {
				if strings.Contains(msg, bad) {
					t.Errorf("strict error still carries the self-contradictory advice %q: %s", bad, msg)
				}
			}
			// Tolerant load preserves legacy configuration; the dataplane's
			// snapshot integrity preflight remains the fail-closed boundary.
			if _, lerr := CompileConfigLenient(tree); lerr != nil {
				t.Fatalf("tolerant compile must preserve bootability, got %v", lerr)
			}
		})
	}
}

// Control: an ordinary typo zone in a global policy keeps the ordinary
// undefined-zone remediation (the junos-global arm must not swallow it), and
// a defined-zone scope still commits.
func TestGlobalPolicyTypoZoneKeepsUndefinedZoneText12836(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security policies global policy g match from-zone typo-zone",
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g then permit",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit accepted a global policy scoping to an undefined typo zone")
	}
	if !strings.Contains(err.Error(), "references undefined zone") ||
		!strings.Contains(err.Error(), "define `set security zones security-zone typo-zone`") {
		t.Fatalf("typo-zone control lost the ordinary undefined-zone text: %s", err)
	}

	ok := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security policies global policy g match from-zone trust",
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g then permit",
	})
	if _, err := CompileConfig(ok); err != nil {
		t.Fatalf("strict commit rejected a defined-zone global policy: %v", err)
	}
}

// #12836 (D2-14): a policy referencing a DEFINED-BUT-EMPTY zone-local
// address-set is rewritten by the fold to the synthetic
// `zone-local/<zone>/<name>` key before strict validation; the #3149 reject
// then leaks that internal key in both the named token and the inner cause.
// The diagnostic must name what the operator wrote — `S (security-zone
// trust)` — like the #12243/#9490 display convention. Fail-on-revert:
// removing the display mapping restores the synthetic key and turns this RED.
func TestZoneLocalEmptySetPolicyErrorNamesAuthoredSet12836(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone trust address-book address-set S",
		"set security policies from-zone trust to-zone untrust policy p match source-address S",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit accepted a policy referencing an empty zone-local address-set")
	}
	msg := err.Error()
	if strings.Contains(msg, "zone-local/") {
		t.Fatalf("CompileConfig error %q leaks the synthetic zone-local key", msg)
	}
	if !strings.Contains(msg, `match source-address "S (security-zone trust)"`) {
		t.Fatalf("CompileConfig error %q does not name the authored set with its zone", msg)
	}
	if !strings.Contains(msg, "is empty") {
		t.Fatalf("CompileConfig error %q lost the empty-set cause", msg)
	}
}
