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

	flatMetricInterface := func(val string) *ConfigTree {
		return flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 metric "+val+
				" interface ge-0/0/1.0")
	}
	flatMetricPreference := func(val string) *ConfigTree {
		return flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 metric "+val+
				" preference 5")
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

	// The parser keeps these same-statement modifier runs packed. The compiler
	// reads the metric, so commit validation must read it too.
	bracedFused := func(val string) *ConfigTree {
		return hierTree(t, `routing-options {
	static {
		route 0.0.0.0/0 {
			qualified-next-hop 192.168.1.1 {
				interface ge-0/0/1.0 metric `+val+`;
			}
		}
	}
}`)
	}
	packedMulti := func(val string) *ConfigTree {
		return hierTree(t, `routing-options {
	static {
		route 0.0.0.0/0 {
			qualified-next-hop 192.168.1.1 interface ge-0/0/1.0 preference 5 metric `+val+`;
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
		{"F05-flat-metric-first-interface", flatMetricInterface},
		{"F06-flat-metric-first-preference", flatMetricPreference},
		{"braced", braced},
		{"packed", packed},
		{"braced-fused-child", bracedFused},
		{"packed-multi-modifier", packedMulti},
	}
	// Negative, out-of-u32, and non-numeric reject on EVERY spelling.
	for _, val := range []string{"-1", "4294967296", "abc"} {
		for _, sp := range spellings {
			t.Run("reject/"+sp.name+"/"+val, func(t *testing.T) {
				if err := SchemaValidate(sp.tree(val)); err == nil {
					t.Fatalf("qualified-next-hop metric %q (%s): expected SchemaValidate to reject, got nil", val, sp.name)
				}
			})
		}
	}
	// Zero, an interior value, and u32max are valid on every spelling.
	for _, val := range []string{"0", "100", "4294967295"} {
		for _, sp := range spellings {
			t.Run("accept/"+sp.name+"/"+val, func(t *testing.T) {
				if err := SchemaValidate(sp.tree(val)); err != nil {
					t.Fatalf("qualified-next-hop metric %q (%s): expected SchemaValidate to accept, got %v", val, sp.name, err)
				}
			})
		}
	}
	for _, sp := range []struct {
		name string
		tree func(string) *ConfigTree
	}{
		{"braced-fused-child", bracedFused},
		{"packed-multi-modifier", packedMulti},
	} {
		t.Run("compile/"+sp.name, func(t *testing.T) {
			cfg := assertCommitAccepts(t, sp.tree("100"))
			found := false
			for _, route := range cfg.RoutingOptions.StaticRoutes {
				for _, nh := range route.NextHops {
					if nh.HasMetric && nh.Metric == 100 && nh.Interface == "ge-0/0/1.0" {
						found = true
						if sp.name == "packed-multi-modifier" &&
							(!nh.HasPreference || nh.Preference != 5) {
							t.Errorf("packed spelling lost preference: %+v", nh)
						}
					}
				}
			}
			if !found {
				t.Fatalf("accepted %s but compiler did not preserve its metric/interface: %+v",
					sp.name, cfg.RoutingOptions.StaticRoutes)
			}
		})
	}
}

// #12184: the reject error names the leaf and the offending value, as the
// sibling preference gate does (#3827).
func TestStaticRouteQualifiedNextHopMetric_RejectNamesLeafAndValue12184(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route ::/0 qualified-next-hop 2001:db8::1 metric -7")
	err := SchemaValidate(tree)
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
	if err := SchemaValidate(tree); err != nil {
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

	// These valid-value controls pin that the shared staticRouteNode schema
	// accepts a metric under both parents; they do not exercise rejection.
	for _, set := range []string{
		"set routing-options rib v4-static static route 10.1.0.0/24 qualified-next-hop 192.168.2.1 metric 0",
		"set routing-instances VRF-A routing-options static route 10.2.0.0/24 qualified-next-hop 192.168.3.1 metric 4294967295",
	} {
		if err := SchemaValidate(flatTreeFromSets(t, set)); err != nil {
			t.Errorf("valid metric at shared staticRouteNode parent for %q: %v", set, err)
		}
	}
}

// #12184: expanding flat QNH runs also exposes the existing typed preference
// leaf (1..254). These flat chains used to bypass that gate.
func TestStaticRouteQualifiedNextHopPreferenceFlatChains12184(t *testing.T) {
	spellings := []struct {
		name string
		tree func(string) *ConfigTree
	}{
		{
			name: "interface-chain",
			tree: func(value string) *ConfigTree {
				return flatTreeFromSets(t,
					"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 interface ge-0/0/1.0 preference "+value)
			},
		},
		{
			name: "metric-chain",
			tree: func(value string) *ConfigTree {
				return flatTreeFromSets(t,
					"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 metric 100 preference "+value)
			},
		},
	}
	for _, value := range []string{"0", "255", "abc"} {
		for _, spelling := range spellings {
			t.Run("reject/"+spelling.name+"/"+value, func(t *testing.T) {
				err := SchemaValidate(spelling.tree(value))
				if err == nil {
					t.Fatalf("expected invalid preference %q in %s to be rejected", value, spelling.name)
				}
				if !strings.Contains(err.Error(), "preference") || !strings.Contains(err.Error(), value) {
					t.Fatalf("error %q must name preference and offending value %q", err, value)
				}
			})
		}
	}
	for _, spelling := range spellings {
		t.Run("accept/"+spelling.name+"/5", func(t *testing.T) {
			assertCommitAccepts(t, spelling.tree("5"))
		})
	}
}
