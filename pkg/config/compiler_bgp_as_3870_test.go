package config

import "testing"

func compileSets3870(t *testing.T, cmds []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// The canonical vSRX placement sets the BGP AS at routing-options
// autonomous-system, with NO `protocols bgp local-as`. The FRR renderer gates
// `router bgp` on BGPConfig.LocalAS > 0, so this must resolve LocalAS from the
// global autonomous-system. RED-on-revert: LocalAS stays 0 → no `router bgp`
// block renders at all (#3870).
func TestBGPAutonomousSystemFeedsLocalAS_3870(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options autonomous-system 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2 peer-as 65002",
	})
	if c.Protocols.BGP == nil {
		t.Fatal("Protocols.BGP is nil; expected a compiled BGP block")
	}
	if got := c.Protocols.BGP.LocalAS; got != 65001 {
		t.Fatalf("BGP LocalAS = %d, want 65001 (resolved from routing-options autonomous-system)", got)
	}
}

// `protocols bgp local-as` is the more specific override and MUST win over the
// global routing-options autonomous-system (Junos precedence).
func TestBGPLocalASOverridesAutonomousSystem_3870(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options autonomous-system 65001",
		"set protocols bgp local-as 65099",
		"set protocols bgp group G neighbor 10.0.0.2 peer-as 65002",
	})
	if c.Protocols.BGP == nil {
		t.Fatal("Protocols.BGP is nil")
	}
	if got := c.Protocols.BGP.LocalAS; got != 65099 {
		t.Fatalf("BGP LocalAS = %d, want 65099 (local-as overrides autonomous-system)", got)
	}
}

// Per-instance BGP inherits the global routing-options autonomous-system;
// instance routing-options overrides it, and protocols bgp local-as overrides
// both at that instance's scope.
func TestBGPInstanceInheritsAutonomousSystem_3870(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options autonomous-system 65001",
		"set routing-instances RED instance-type virtual-router",
		"set routing-instances RED protocols bgp group G peer-as 65010",
		"set routing-instances RED protocols bgp group G neighbor 10.1.0.2",
		"set routing-instances BLUE instance-type virtual-router",
		"set routing-instances BLUE routing-options autonomous-system 65055",
		"set routing-instances BLUE protocols bgp group G peer-as 65020",
		"set routing-instances BLUE protocols bgp group G neighbor 10.2.0.2",
		"set routing-instances GREEN instance-type virtual-router",
		"set routing-instances GREEN routing-options autonomous-system 65056",
		"set routing-instances GREEN protocols bgp local-as 65099",
		"set routing-instances GREEN protocols bgp group G neighbor 10.3.0.2 peer-as 65030",
	})
	var red, blue, green *RoutingInstanceConfig
	for _, ri := range c.RoutingInstances {
		switch ri.Name {
		case "RED":
			red = ri
		case "BLUE":
			blue = ri
		case "GREEN":
			green = ri
		}
	}
	if red == nil || red.BGP == nil {
		t.Fatal("instance RED BGP not compiled")
	}
	if got := red.BGP.LocalAS; got != 65001 {
		t.Fatalf("RED BGP LocalAS = %d, want 65001 (inherited from global autonomous-system)", got)
	}
	if blue == nil || blue.BGP == nil {
		t.Fatal("instance BLUE BGP not compiled")
	}
	if got := blue.BGP.LocalAS; got != 65055 {
		t.Fatalf("BLUE BGP LocalAS = %d, want 65055 (instance-level autonomous-system override)", got)
	}
	if green == nil || green.BGP == nil {
		t.Fatal("instance GREEN BGP not compiled")
	}
	if got := green.BGP.LocalAS; got != 65099 {
		t.Fatalf("GREEN BGP LocalAS = %d, want 65099 (instance protocols bgp local-as overrides routing-options)", got)
	}
}
