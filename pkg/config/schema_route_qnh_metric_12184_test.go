package config

import (
	"strings"
	"testing"
)

// #12184: the qualified-next-hop metric leaf was untyped, so `metric -1`,
// `metric 4294967296` and `metric abc` committed clean while the tier code
// collapsed them to tier 0 (static_next_hop_tiers.go) and the FRR export
// skipped them (qnh_metric_11447.go) — the authored backup silently joined
// the primary as equal-cost ECMP. Strict commit gates the leaf at 0..2^32-1,
// the range every consumer honors.
//
// FAIL-ON-REVERT: untyping the leaf (or widening the range) re-admits the
// invalid values below on a clean commit.
func TestStaticRouteQualifiedNextHopMetric_SchemaGate12184(t *testing.T) {
	flat := func(val string) *ConfigTree {
		return flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 metric "+val)
	}
	// SetPath supports a single command with several QNH modifiers. These
	// spellings form a nested flat-run chain, which the compiler hoists
	// before reading; strict validation must inspect the same metric leaf.
	flatChain := func(val string) *ConfigTree {
		return flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 interface ge-0/0/1.0 metric "+val)
	}
	braced := func(val string) *ConfigTree {
		return hierTree(t, `routing-options {
	static {
		route 0.0.0.0/0 {
			qualified-next-hop 192.168.1.1 {
				interface ge-0/0/1.0;
				metric `+val+`;
			}
		}
	}
}`)
	}
	// Brace-elided hierarchical spelling; validation normalizes the same
	// (qualified-next-hop, metric) pair as the compiler.
	packed := func(val string) *ConfigTree {
		return hierTree(t, `routing-options {
	static {
		route 0.0.0.0/0 {
			qualified-next-hop 192.168.1.1 metric `+val+`;
		}
	}
}`)
	}
	spellings := []struct {
		name string
		tree func(string) *ConfigTree
	}{
		{"flat", flat},
		{"flat-interface-chain", flatChain},
		{"braced", braced},
		{"packed", packed},
	}
	// Negative, out-of-u32, and non-numeric reject on EVERY spelling.
	for _, val := range []string{"-1", "4294967296", "abc"} {
		for _, sp := range spellings {
			t.Run("reject/"+sp.name+"/"+val, func(t *testing.T) {
				if err := SchemaValidate(sp.tree(val), nil); err == nil {
					t.Fatalf("qualified-next-hop metric %q (%s): expected SchemaValidate to reject, got nil", val, sp.name)
				}
			})
		}
	}
	// 0 is the primary tier and u32max the ceiling; both commit on every spelling.
	for _, val := range []string{"0", "100", "4294967295"} {
		for _, sp := range spellings {
			t.Run("accept/"+sp.name+"/"+val, func(t *testing.T) {
				if err := SchemaValidate(sp.tree(val), nil); err != nil {
					t.Fatalf("qualified-next-hop metric %q (%s): expected SchemaValidate to accept, got %v", val, sp.name, err)
				}
			})
		}
	}
}

// #12184: the reject error names the leaf and the offending value, as the
// sibling preference gate does (#3827).
func TestStaticRouteQualifiedNextHopMetric_RejectNamesLeafAndValue12184(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route ::/0 qualified-next-hop 2001:db8::1 metric -7")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected a negative qualified-next-hop metric to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "-7") {
		t.Fatalf("error %q must name the out-of-range value -7", err.Error())
	}
	if !strings.Contains(err.Error(), "metric") {
		t.Fatalf("error %q must name the metric leaf", err.Error())
	}
}

// #12184: a valid qualified-next-hop (with preference + interface siblings)
// still commits — typing the leaf tightens the value slot without breaking
// the surrounding grammar. Covers the rib and routing-instance parents,
// which share staticRouteNode().
func TestStaticRouteQualifiedNextHopMetric_ValidCommits12184(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 preference 10",
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 metric 20",
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 interface ge-0-0-0",
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("valid qualified-next-hop metric/preference/interface: SchemaValidate rejected: %v", err)
	}
	cfg := assertCommitAccepts(t, tree)
	found := false
	for _, r := range cfg.RoutingOptions.StaticRoutes {
		for _, nh := range r.NextHops {
			if nh.HasMetric && nh.Metric == 20 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected compiled static route with metric 20, got %v", cfg.RoutingOptions.StaticRoutes)
	}

	// staticRouteNode() is also used under routing-options rib and
	// routing-instances; confirm the typed leaf is active at both parents.
	for _, set := range []string{
		"set routing-options rib v4-static static route 10.1.0.0/24 qualified-next-hop 192.168.2.1 metric 0",
		"set routing-instances VRF-A routing-options static route 10.2.0.0/24 qualified-next-hop 192.168.3.1 metric 4294967295",
	} {
		if err := SchemaValidate(flatTreeFromSets(t, set), nil); err != nil {
			t.Errorf("valid metric at shared staticRouteNode parent for %q: %v", set, err)
		}
	}
}
