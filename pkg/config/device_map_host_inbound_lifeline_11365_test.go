package config

import (
	"fmt"
	"strings"
	"testing"
)

func deviceMapLifelineWarnings11365(names ...string) []string {
	entries := make([]DeviceMapEntry, 0, len(names))
	interfaces := make(map[string]*InterfaceConfig, len(names))
	for i, name := range names {
		entries = append(entries, DeviceMapEntry{
			LogicalName: name,
			PCIAddr:     fmt.Sprintf("0000:%02x:00.0", i+1),
		})
		interfaces[name] = &InterfaceConfig{Name: name}
	}
	cfg := &Config{Chassis: ChassisConfig{
		DeviceMap: &DeviceMapConfig{Entries: entries},
	}}
	cfg.Interfaces.Interfaces = interfaces
	return ValidateConfig(cfg)
}

func TestDeviceMapManagementClassesWarnWhenNotLifelineExempt11365(t *testing.T) {
	for _, name := range []string{"em1", "emu0", "fab0", "fabric0", "fxp1"} {
		t.Run(name, func(t *testing.T) {
			var got string
			for _, warning := range deviceMapLifelineWarnings11365(name) {
				if strings.Contains(warning, "#11365") && strings.Contains(warning, name) {
					got = warning
					break
				}
			}
			if got == "" {
				t.Fatalf("device-map management-class NIC %q was not diagnosed as non-lifeline-exempt", name)
			}
			for _, want := range []string{"device-map", "vrf-mgmt", "lifeline-exempt"} {
				if !strings.Contains(got, want) {
					t.Errorf("diagnostic %q omits %q", got, want)
				}
			}
		})
	}
}

func TestDeviceMapLifelineWarningsRespectRealLifelineAndOtherNames11365(t *testing.T) {
	if got := deviceMapLifelineWarnings11365("fxp0", "ge-0/0/1"); hasDeviceMapLifelineWarning11365(got) {
		t.Fatalf("default fxp0 lifeline or ordinary interface should not draw a mismatch warning: %v", got)
	}

	cfg := &Config{Chassis: ChassisConfig{
		Cluster: &ClusterConfig{ControlInterface: "em1", FabricInterface: "fab0", Fabric1Interface: "fxp1"},
		DeviceMap: &DeviceMapConfig{Entries: []DeviceMapEntry{
			{LogicalName: "em1", PCIAddr: "0000:01:00.0"},
			{LogicalName: "fab0", PCIAddr: "0000:02:00.0"},
			{LogicalName: "fxp1", PCIAddr: "0000:03:00.0"},
		}},
	}}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"em1":  {Name: "em1"},
		"fab0": {Name: "fab0"},
		"fxp1": {Name: "fxp1"},
	}
	if got := ValidateConfig(cfg); hasDeviceMapLifelineWarning11365(got) {
		t.Fatalf("explicitly configured cluster lifelines should be reconciled without warning: %v", got)
	}
}

func hasDeviceMapLifelineWarning11365(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#11365") {
			return true
		}
	}
	return false
}
func TestDeviceMapManagementClassWarningIsReturnedOnCommit11365(t *testing.T) {
	for _, name := range []string{"em1", "fab0", "fxp1"} {
		t.Run(name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set interfaces " + name + " unit 0 family inet address 192.0.2.1/24",
				"set chassis device-map interface " + name + " pci 0000:01:00.0",
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("valid device-map entry failed commit: %v", err)
			}
			if !hasDeviceMapLifelineWarning11365(cfg.Warnings) {
				t.Fatalf("commit result omitted the name-class/lifeline mismatch diagnostic: %v", cfg.Warnings)
			}
		})
	}
}

func TestDeviceMapWarningRequiresAConfiguredManagementInterface11365(t *testing.T) {
	cfg := &Config{Chassis: ChassisConfig{DeviceMap: &DeviceMapConfig{
		Entries: []DeviceMapEntry{{LogicalName: "em1", PCIAddr: "0000:01:00.0"}},
	}}}
	if got := ValidateConfig(cfg); hasDeviceMapLifelineWarning11365(got) {
		t.Fatalf("unconfigured device-map entry was warned as vrf-mgmt-enslaved: %v", got)
	}
}
