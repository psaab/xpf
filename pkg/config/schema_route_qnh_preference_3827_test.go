package config

import (
	"strings"
	"testing"
)

// #12060: FRR staticd accepts distances through 255, but zebra treats 255 as
// DISTANCE_INFINITY and never installs the route. Strict commit limits
// qualified-next-hop preference to the usable range 1..254.
//
// FAIL-ON-REVERT: allowing preference 256 through makes the floating backup
// silently unusable.
func TestStaticRouteQualifiedNextHopPreference_SchemaGate(t *testing.T) {
	reject := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference "+val)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("qualified-next-hop preference %q: expected SchemaValidate to reject, got nil", val)
		}
	}
	accept := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference "+val)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("qualified-next-hop preference %q: expected SchemaValidate to accept, got %v", val, err)
		}
	}
	// Zero, negative, non-numeric, i32-overflow, and non-installable reject.
	for _, val := range []string{"0", "-1", "-2147483648", "notanumber", "2147483648", "4294967295", "255", "256", "2147483647"} {
		reject(val)
	}
	// Preference 1 is the minimum; 254 is the maximum installable distance.
	for _, val := range []string{"1", "5", "100", "254"} {
		accept(val)
	}
}

// #3827: the reject error names the offending value so the operator sees which
// qualified-next-hop preference was out of range (commit-time diagnostic, not
// the opaque Rust snapshot rejection).
func TestStaticRouteQualifiedNextHopPreference_NegativeErrorMentionsValue(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route ::/0 qualified-next-hop 2001:db8::1 preference -7")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected a negative qualified-next-hop preference to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "-7") {
		t.Fatalf("error %q must name the out-of-range value -7", err.Error())
	}
}

func TestStaticRouteQualifiedNextHopPreference_AboveFRRMaximumNamesLeaf12060(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference 256")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected qualified-next-hop preference 256 to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "preference") {
		t.Fatalf("error %q must name the preference leaf", err.Error())
	}
}

// #3827: a valid qualified-next-hop preference (with interface + metric
// siblings) still commits — the typing tightens the value slot without
// breaking the surrounding qualified-next-hop grammar.
func TestStaticRouteQualifiedNextHopPreference_ValidCommits(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 preference 10",
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 metric 20",
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 interface ge-0-0-0")
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("valid qualified-next-hop preference/metric/interface: SchemaValidate rejected: %v", err)
	}
}
