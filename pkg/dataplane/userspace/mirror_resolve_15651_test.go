package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15651: buildMirrorConfigSnapshots indexed only iface.Name / iface.LinuxName.
// A unit row's LinuxName is the parent kernel device (unit 0 collapses) or a
// VLAN child, so a Linux unit spelling `ge-0-0-0.0` never matched either key
// and the mirror silently disappeared; Junos/VLAN/RETH spellings needed
// ResolveKernelIfName against cfg.Interfaces.
func mirrorCfg15651() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{1: {Number: 1, VlanID: 100}}},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0", Units: map[int]*config.InterfaceUnit{}},
		"reth0":    {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"linux-unit": {Name: "linux-unit", Input: []string{"ge-0-0-0.0"}, Output: "ge-0-0-9.0"},
			"vlan-unit":  {Name: "vlan-unit", Input: []string{"ge-0/0/1.1"}, Output: "ge-0/0/9.0"},
			"reth-unit":  {Name: "reth-unit", Input: []string{"reth0.0"}, Output: "ge-0/0/9.0"},
		},
	}
	return cfg
}

func TestBuildMirrorConfigSnapshotsResolvesUnitSpellings15651(t *testing.T) {
	cfg := mirrorCfg15651()
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/0", LinuxName: "ge-0-0-0", Ifindex: 11},
		{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0", Ifindex: 11, IsUnit: true, VLANID: 0},
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Ifindex: 12},
		{Name: "ge-0/0/1.1", LinuxName: "ge-0-0-1.100", Ifindex: 12100, IsUnit: true, VLANID: 100, ParentIfindex: 12},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Ifindex: 13},
		{Name: "reth0", LinuxName: "ge-0-0-2", Ifindex: 13},
		{Name: "reth0.0", LinuxName: "ge-0-0-2", Ifindex: 13, IsUnit: true, VLANID: 0},
		{Name: "ge-0/0/9", LinuxName: "ge-0-0-9", Ifindex: 22},
		{Name: "ge-0/0/9.0", LinuxName: "ge-0-0-9", Ifindex: 22, IsUnit: true, VLANID: 0},
	}
	got, excl := buildMirrorConfigSnapshots(cfg, interfaces)
	// Sorted instances: linux-unit, reth-unit, vlan-unit. The RETH unit and
	// the Linux unit-0 both resolve via ResolveKernelIfName; the VLAN unit
	// resolves to its VLAN child. Note reth0.0 and ge-0/0/2 share ifindex 13
	// but only reth-unit claims it here.
	want := []MirrorConfigSnapshot{
		{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: true},
		{IngressIfindex: 13, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: true},
		{IngressIfindex: 12100, OutputIfindex: 22, IngressVLANID: 100, UnitScoped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v excl=%+v, want %+v", got, excl, want)
	}
	if len(excl) != 0 {
		t.Fatalf("exclusions = %+v, want none", excl)
	}
}

// The scoped-key contract (#15113) must survive ResolveKernelIfName
// fallback: a bare `ge-0/0/0` and unit-0 `ge-0-0-0.0` on the same ifindex
// remain distinct rows, not a blanket duplicate drop.
func TestBuildMirrorConfigSnapshotsBareVsUnit0ViaResolve15651(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"bare":  {Name: "bare", Input: []string{"ge-0/0/0"}, Output: "ge-0/0/9.0"},
			"unit0": {Name: "unit0", Input: []string{"ge-0-0-0.0"}, Output: "ge-0/0/9.0"},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/0", LinuxName: "ge-0-0-0", Ifindex: 11},
		{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0", Ifindex: 11, IsUnit: true},
		{Name: "ge-0/0/9.0", LinuxName: "ge-0-0-9", Ifindex: 22, IsUnit: true},
	}
	got, _ := buildMirrorConfigSnapshots(cfg, interfaces)
	want := []MirrorConfigSnapshot{
		{IngressIfindex: 11, OutputIfindex: 22, UnitScoped: false},
		{IngressIfindex: 11, OutputIfindex: 22, UnitScoped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v, want bare+unit0 distinct %+v", got, want)
	}
}
