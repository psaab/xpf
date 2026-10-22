package config

import (
	"strings"
	"testing"
)

// #3896 — IKE gateway `version`, IKE policy `mode`, and gateway
// `nat-traversal` were untyped free-form leaves (args:1, no validator), so a
// typo committed CLEAN and was then silently mis-mapped by the strongSwan
// generator: `version v2-onyl` dropped the v2-only pin (the gateway then
// accepts legacy IKEv1 — a downgrade); `mode agressive` fell back to main
// mode; a typo'd `nat-traversal` value was ignored. The setSchema leaves are
// now typed with ValidateEnum, matching EXACTLY the value sets the generator
// recognizes:
//
//	version       ∈ {v1-only, v2-only}  (pkg/ipsec/policy.go — version = 1/2)
//	mode          ∈ {main, aggressive}  (pkg/ipsec/ike.go — Mode=="aggressive")
//	nat-traversal ∈ {enable, disable, force} (pkg/ipsec/policy.go — encap switch)
//
// FAIL-ON-REVERT: reverting the three leaves in schema_security.go back to
// untyped (args:1 with no validator) makes every reject case below return nil
// and go RED — a typo would commit clean and silently weaken negotiation.
func TestIKEEnumSchemaGate_3896(t *testing.T) {
	reject := func(set, badVal string) {
		t.Helper()
		tree := flatTreeFromSets(t, set)
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("%q: expected SchemaValidate to REJECT typo, got nil (silent mis-map)", set)
		}
		// The error must name the offending value so the operator can fix it.
		if !strings.Contains(err.Error(), badVal) {
			t.Fatalf("%q: reject error %q should name the bad value %q", set, err, badVal)
		}
	}
	accept := func(set string) {
		t.Helper()
		tree := flatTreeFromSets(t, set)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("%q: expected SchemaValidate to ACCEPT valid value, got %v", set, err)
		}
	}

	// --- Typos are rejected (fail-closed, error names the bad value) ---
	reject("set security ike gateway G version v2-onyl", "v2-onyl")     // → would accept IKEv1
	reject("set security ike gateway G version v3-only", "v3-only")     // unsupported version
	reject("set security ike policy P mode agressive", "agressive")     // → would fall back to main
	reject("set security ike policy P mode passive", "passive")         // unhandled mode
	reject("set security ike gateway G nat-traversal enabel", "enabel") // → NAT-T not as intended
	reject("set security ike gateway G nat-traversal on", "on")         // unhandled NAT-T value
	// The `ipsec gateway` alias carries the same version/nat-traversal leaves.
	reject("set security ipsec gateway G version v2-onyl", "v2-onyl")
	reject("set security ipsec gateway G nat-traversal enabel", "enabel")

	// --- Every value the generator handles must still commit (no false reject) ---
	for _, v := range []string{"v1-only", "v2-only"} {
		accept("set security ike gateway G version " + v)
		accept("set security ipsec gateway G version " + v)
	}
	for _, m := range []string{"main", "aggressive"} {
		accept("set security ike policy P mode " + m)
	}
	for _, n := range []string{"enable", "disable", "force"} {
		accept("set security ike gateway G nat-traversal " + n)
		accept("set security ipsec gateway G nat-traversal " + n)
	}
}
