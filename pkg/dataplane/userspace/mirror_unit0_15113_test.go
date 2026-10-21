package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15113 (A75-01): a port-mirroring input naming untagged unit 0
// (ge-0/0/1.0, VLANID 0, sharing the base netdev/ifindex 11) must carry
// its unit scope so the Rust resolver matches only VID 0 / native VID,
// not every tagged sibling on the same bind port. A bare physical
// input (ge-0/0/1, no unit) keeps the all-units fallback (UnitScoped
// false, IngressVLANID 0).
func TestBuildMirrorConfigSnapshotsUnit0VsBarePhysical15113(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span-unit0": {
				Name:   "span-unit0",
				Input:  []string{"ge-0/0/1.0"},
				Output: "ge-0/0/9.0",
			},
			"span-bare": {
				Name:   "span-bare",
				Input:  []string{"ge-0/0/2"},
				Output: "ge-0/0/9.0",
			},
			"span-tagged": {
				Name:   "span-tagged",
				Input:  []string{"ge-0/0/3.1"},
				Output: "ge-0/0/9.0",
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Ifindex: 11},
		{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1", Ifindex: 11, IsUnit: true, VLANID: 0},
		{Name: "ge-0/0/1.1", LinuxName: "ge-0-0-1.100", Ifindex: 11100, IsUnit: true, VLANID: 100, ParentIfindex: 11},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Ifindex: 12},
		{Name: "ge-0/0/3", LinuxName: "ge-0-0-3", Ifindex: 13},
		{Name: "ge-0/0/3.1", LinuxName: "ge-0-0-3.100", Ifindex: 13100, IsUnit: true, VLANID: 100, ParentIfindex: 13},
		{Name: "ge-0/0/9.0", LinuxName: "ge-0-0-9.0", Ifindex: 22},
	}

	got, _ := buildMirrorConfigSnapshots(cfg, interfaces)
	// Sorted instance order: span-bare, span-tagged, span-unit0.
	want := []MirrorConfigSnapshot{
		{IngressIfindex: 12, OutputIfindex: 22, Rate: 0, IngressVLANID: 0, UnitScoped: false},
		{IngressIfindex: 13100, OutputIfindex: 22, Rate: 0, IngressVLANID: 100, UnitScoped: true, IngressUnit: 1},
		{IngressIfindex: 11, OutputIfindex: 22, Rate: 0, IngressVLANID: 0, UnitScoped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v, want distinct unit-scoped rows %+v", got, want)
	}
}

// #16063 (SI-5): wg0.0 and wg0.1 share the wg0 netdev (ifindex 42) and
// both carry VLANID 0 — the VID cannot tell tunnel units apart, and the
// packet metadata at every mirror callsite is (ifindex, VID) only
// (decap rebinds to the tunnel's single logical ifindex), so no
// per-packet unit identity exists. A mirror input naming wg0.1 only
// must therefore be REFUSED (not installed): installing it on
// (ifindex 42, VID 0) would mirror wg0.0 inner packets to the analyzer.
// Production shape: base + both units all on ifindex 42.
func TestBuildMirrorConfigSnapshotsTunnelUnitScope16063(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {Name: "wg0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span-wg1": {
				Name:   "span-wg1",
				Input:  []string{"wg0.1"},
				Output: "ge-0/0/9.0",
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "wg0", LinuxName: "wg0", Ifindex: 42},
		{Name: "wg0.0", LinuxName: "wg0", Ifindex: 42, IsUnit: true, VLANID: 0},
		{Name: "wg0.1", LinuxName: "wg0", Ifindex: 42, IsUnit: true, VLANID: 0},
		{Name: "ge-0/0/9.0", LinuxName: "ge-0-0-9.0", Ifindex: 22},
	}
	got, excl := buildMirrorConfigSnapshots(cfg, interfaces)
	if len(got) != 0 {
		t.Fatalf("mirror snapshots = %+v, want none: wg0.1 on shared ifindex 42 must be refused, not keyed on (42, VID 0)", got)
	}
	if len(excl) != 1 || excl[0].Instance != "span-wg1" || excl[0].Input != "wg0.1" ||
		excl[0].Reason != config.TunnelUnitSharedIfindexMirrorReason("wg0.1") {
		t.Fatalf("exclusions = %+v, want one wg0.1 shared-ifindex refusal", excl)
	}
	// Control: mirroring the bare wg0 device (all units, operator's
	// explicit whole-device intent) still installs unscoped.
	cfg.ForwardingOptions.PortMirroring.Instances["span-wg1"].Input = []string{"wg0"}
	got, excl = buildMirrorConfigSnapshots(cfg, interfaces)
	want := []MirrorConfigSnapshot{
		{IngressIfindex: 42, OutputIfindex: 22, Rate: 0, IngressVLANID: 0, UnitScoped: false},
	}
	if !reflect.DeepEqual(got, want) || len(excl) != 0 {
		t.Fatalf("bare wg0 mirror = %+v excl=%+v, want unscoped row %+v", got, excl, want)
	}
}
