package config

import (
	"strings"
	"testing"
)

// #12060: FRR staticd's distance operand accepts 1..255, but zebra treats 255
// as DISTANCE_INFINITY and never installs the route. Strict commit therefore
// limits route-level preference to the usable range 1..254.
//
// FAIL-ON-REVERT: allowing preference 256 through makes FRR accept an unusable
// route or reject a discard route during reload.
func TestStaticRoutePreference_SchemaGate(t *testing.T) {
	reject := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 preference "+val)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("preference %q: expected SchemaValidate to reject, got nil", val)
		}
	}
	accept := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 preference "+val)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("preference %q: expected SchemaValidate to accept, got %v", val, err)
		}
	}
	// Zero, negative, non-numeric, i32-overflow, and non-installable reject.
	for _, val := range []string{"0", "-1", "-2147483648", "notanumber", "2147483648", "4294967295", "255", "256", "2147483647"} {
		reject(val)
	}
	// Preference 1 is accepted explicitly; 254 is the maximum installable.
	for _, val := range []string{"1", "5", "100", "254"} {
		accept(val)
	}
}

// #3771 (L1): the reject error names the offending value so the operator sees
// which preference was out of range.
func TestStaticRoutePreference_NegativeErrorMentionsRange(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route ::/0 preference -5")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected a negative route preference to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "-5") {
		t.Fatalf("error %q must name the out-of-range value -5", err.Error())
	}
}

func TestStaticRoutePreference_AboveFRRMaximumNamesLeaf12060(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 0.0.0.0/0 preference 256")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected route preference 256 to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "preference") {
		t.Fatalf("error %q must name the preference leaf", err.Error())
	}
}
