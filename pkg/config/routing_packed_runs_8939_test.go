package config

import (
	"reflect"
	"testing"
)

func buildRouting8939(t *testing.T, lines ...string) *Config {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// Global selector fixtures use tolerant compilation because strict commit
	// rejects that unsupported shape (#11311); per-instance cases remain valid.
	c, err := CompileConfigLenient(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// #8939 at `routing-options interface-routes rib-group`: a packed run set only
// the FIRST family.
//
//	rib-group inet RG inet6 RG  ->  v4="RG"  v6=""
//
// The consequence is an inter-VRF route leak the operator configured that
// silently does not happen for one address family — and a HALF-configured leak
// is harder to notice than an absent one, because v4 works.
func TestInterfaceRoutesRibGroupPackedRun8939(t *testing.T) {
	const pre = "set routing-options rib-groups RG import-rib inet.0"
	split := buildRouting8939(t, pre,
		"set routing-options interface-routes rib-group inet RG",
		"set routing-options interface-routes rib-group inet6 RG")
	// REFERENCE ARM: the split spelling must set BOTH, or the comparison is
	// between two broken results.
	if split.RoutingOptions.InterfaceRoutesRibGroup == "" ||
		split.RoutingOptions.InterfaceRoutesRibGroupV6 == "" {
		t.Fatalf("the SPLIT control set v4=%q v6=%q — the comparison would prove nothing",
			split.RoutingOptions.InterfaceRoutesRibGroup, split.RoutingOptions.InterfaceRoutesRibGroupV6)
	}
	packed := buildRouting8939(t, pre,
		"set routing-options interface-routes rib-group inet RG inet6 RG")
	if !reflect.DeepEqual(packed, split) {
		t.Errorf("packed v4=%q v6=%q, split v4=%q v6=%q",
			packed.RoutingOptions.InterfaceRoutesRibGroup, packed.RoutingOptions.InterfaceRoutesRibGroupV6,
			split.RoutingOptions.InterfaceRoutesRibGroup, split.RoutingOptions.InterfaceRoutesRibGroupV6)
	}

	// NARROWNESS: one family alone must still set only that family. A fix that
	// set both from any rib-group statement would satisfy the row above and
	// leak a family the operator did not name.
	only := buildRouting8939(t, pre, "set routing-options interface-routes rib-group inet RG")
	if only.RoutingOptions.InterfaceRoutesRibGroupV6 != "" {
		t.Errorf("`rib-group inet RG` alone set the v6 rib-group to %q",
			only.RoutingOptions.InterfaceRoutesRibGroupV6)
	}
}

// TestInterfaceRoutesRibGroupTwinIsFixedToo8939 pins the routing-instance twin.
// The global site and the per-instance site are separate loops with identical
// bodies, and fixing one and not the other is how this class keeps coming back.
func TestInterfaceRoutesRibGroupTwinIsFixedToo8939(t *testing.T) {
	pre := []string{
		"set routing-options rib-groups RG import-rib inet.0",
		"set routing-instances BLUE instance-type virtual-router",
	}
	split := buildRouting8939(t, append(append([]string{}, pre...),
		"set routing-instances BLUE routing-options interface-routes rib-group inet RG",
		"set routing-instances BLUE routing-options interface-routes rib-group inet6 RG")...)
	packed := buildRouting8939(t, append(append([]string{}, pre...),
		"set routing-instances BLUE routing-options interface-routes rib-group inet RG inet6 RG")...)

	find := func(c *Config) (string, string) {
		for _, ri := range c.RoutingInstances {
			if ri.Name == "BLUE" {
				return ri.InterfaceRoutesRibGroup, ri.InterfaceRoutesRibGroupV6
			}
		}
		return "", ""
	}
	sv4, sv6 := find(split)
	if sv4 == "" || sv6 == "" {
		t.Fatalf("the SPLIT control on the instance set v4=%q v6=%q", sv4, sv6)
	}
	pv4, pv6 := find(packed)
	if pv4 != sv4 || pv6 != sv6 {
		t.Errorf("routing-instance twin: packed v4=%q v6=%q, split v4=%q v6=%q", pv4, pv6, sv4, sv6)
	}
}

// #8939 at `routing-options generate route`: a packed run LOST THE POLICY.
//
//	generate route 10.0.0.0/8 discard policy P  ->  Discard=true  Policy=""
//
// The direction matters: a generate route's POLICY selects its contributing
// routes, so losing it leaves the contributor set UNCONSTRAINED rather than
// empty — the aggregate generates on contributions the operator meant to
// exclude.
func TestGenerateRoutePackedRun8939(t *testing.T) {
	const pol = "set policy-options policy-statement P then accept"
	split := buildRouting8939(t, pol,
		"set routing-options generate route 10.0.0.0/8 discard",
		"set routing-options generate route 10.0.0.0/8 policy P")
	if len(split.RoutingOptions.GenerateRoutes) != 1 ||
		split.RoutingOptions.GenerateRoutes[0].Policy == "" ||
		!split.RoutingOptions.GenerateRoutes[0].Discard {
		t.Fatalf("the SPLIT control did not set both: %+v", split.RoutingOptions.GenerateRoutes)
	}
	packed := buildRouting8939(t, pol,
		"set routing-options generate route 10.0.0.0/8 discard policy P")
	if !reflect.DeepEqual(packed, split) {
		t.Errorf("packed %+v\nsplit  %+v",
			packed.RoutingOptions.GenerateRoutes, split.RoutingOptions.GenerateRoutes)
	}

	// NARROWNESS: `discard` alone must not invent a policy.
	only := buildRouting8939(t, pol, "set routing-options generate route 10.0.0.0/8 discard")
	if len(only.RoutingOptions.GenerateRoutes) != 1 || only.RoutingOptions.GenerateRoutes[0].Policy != "" {
		t.Errorf("`generate route <p> discard` alone produced a policy: %+v",
			only.RoutingOptions.GenerateRoutes)
	}
}
