package config

import (
	"strings"
	"testing"
)

// #3771/#11454: the route `preference` leaf is a typed integer bounded to
// [1, 2147483647] at the Go commit boundary. FRR defaults an omitted static
// distance to 1 while the Rust FIB preserves preference 0, so accepting 0
// would silently change the route's meaning at render time. Reject it at
// commit, uniformly with the qualified-next-hop preference leaf.
//
// FAIL-ON-REVERT: dropping the `valueType: ValueInteger, validator:
// ValidateInteger(1, maxWireI32)` on the schema `preference` leaf lets
// preference 0 through, diverging from FRR's default distance 1.
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
	// Zero, negative, non-numeric, and i32-overflow reject.
	for _, val := range []string{"0", "-1", "-2147483648", "notanumber", "2147483648", "4294967295"} {
		reject(val)
	}
	// Preference 1 is accepted explicitly and remains a Rust value of 1.
	for _, val := range []string{"1", "5", "100", "2147483647"} {
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
