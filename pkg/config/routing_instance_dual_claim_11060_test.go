package config

import (
	"strings"
	"testing"
)

// FAIL-ON-REVERT: removing the #11060 gate or its uniform-gate dispatch lets
// both instances claim the same interface and makes their kernel/dataplane
// membership disagree. The strict error must name the interface and both RIs.
func TestRIDualClaimRejectedAndToleratedWithWarning11060(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/7 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/7.0",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface ge-0/0/7.0",
	}

	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict commit accepted ge-0/0/7.0 claimed by routing-instances blue and red")
	} else {
		for _, want := range []string{"ge-0/0/7.0", "blue", "red", "#11060"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("dual-claim error %q does not name %q", err, want)
			}
		}
	}

	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant load must keep booting a legacy dual-claim config: %v", err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "routing-instance interface membership (downgraded to warning on tolerant path)") &&
			strings.Contains(warning, "blue") && strings.Contains(warning, "red") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a dual-RI warning naming both instances, got %v", cfg.Warnings)
	}
}

// A bare member claims its configured units, so it conflicts with another
// instance that lists one of those units explicitly.
func TestRIBareAndUnitClaimRejectedAcrossInstances11060(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/7 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue interface ge-0/0/7",
		"set routing-instances red interface ge-0/0/7.0",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil ||
		!strings.Contains(err.Error(), "blue") || !strings.Contains(err.Error(), "red") {
		t.Fatalf("bare/unit dual claim must be rejected naming both RIs, got %v", err)
	}
}

// Two distinct logical units are independent routing keys and remain valid
// when split between instances (the ordinary VLAN-subinterface case).
func TestRIDualClaimDistinctUnitsRemainValid11060(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/7": {Name: "ge-0/0/7", Units: map[int]*InterfaceUnit{
				0: {Number: 0, VlanID: 100},
				1: {Number: 1, VlanID: 200},
			}}},
		},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7.0"}},
			{Name: "red", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7.1"}},
		},
	}
	if err := validateRIDualClaimStrict11060(cfg); err != nil {
		t.Fatalf("distinct units in different instances are a valid split: %v", err)
	}
}

func TestRIDualClaimSameInstanceRepeatIsHarmless11060(t *testing.T) {
	cfg := &Config{RoutingInstances: []*RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7.0", "ge-0/0/7.0"},
	}}}
	if err := validateRIDualClaimStrict11060(cfg); err != nil {
		t.Fatalf("repeated member within one instance must not conflict: %v", err)
	}
}
