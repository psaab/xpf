package config

import (
	"strings"
	"testing"
)

func TestNativeVLANWithoutMatchingUnitWarns12248(t *testing.T) {
	cfg, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 native-vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "interfaces ge-0/0/0") &&
			strings.Contains(warning, "native-vlan-id 100") &&
			strings.Contains(warning, "unique matching unit") {
			return
		}
	}
	t.Fatalf("no native VLAN binding advisory in warnings: %v", cfg.Warnings)
}

func TestNativeVLANWithUniqueMatchingUnitStaysSilent12248(t *testing.T) {
	cfg, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 native-vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "native-vlan-id") {
			t.Fatalf("unexpected native VLAN advisory for unique matching unit: %q", warning)
		}
	}
}

func TestNativeVLANWithAmbiguousMatchingUnitsWarns12248(t *testing.T) {
	warning := nativeVLANBindingWarning("ge-0/0/0", &InterfaceConfig{
		NativeVlanID: 100,
		Units: map[int]*InterfaceUnit{
			100: {Number: 100, VlanID: 100},
			200: {Number: 200, VlanID: 100},
		},
	})
	if !strings.Contains(warning, "interfaces ge-0/0/0") ||
		!strings.Contains(warning, "native-vlan-id 100") ||
		!strings.Contains(warning, "no unique matching unit") {
		t.Fatalf("ambiguous native VLAN binding warning = %q", warning)
	}
}
