package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestResolveKernelIfName_DriftGuardVsSnapshotLinuxName asserts that the
// public (*config.Config).ResolveKernelIfName helper and the private
// snapshotLinuxName helper produce identical output for shared input
// shapes. The two implementations have intentional scope deltas
// (snapshotLinuxName does not implement IRB), but for every other
// case they must match. See #1565.
func TestResolveKernelIfName_DriftGuardVsSnapshotLinuxName(t *testing.T) {
	// Construct a Config that exercises every branch of
	// snapshotLinuxName:
	//   - iface == nil path (bare ref, no cfg entry).
	//   - bare reth (reth0 only, no unit).
	//   - bare non-reth (em0, ge-0/0/0).
	//   - tunnel-map hit (gr-0/0/0.0 with interface-level tunnel).
	//   - tunnel-map hit where the map DISAGREES with the fallback
	//     (gr-0/0/0.1 — nonzero unit sharing the interface tunnel device;
	//     #6861 F3, without which the map lookup is unobservable).
	//   - VLAN positive (reth0.50 with vlan-id 50; ge-0/0/0.80 with
	//     vlan-id 180).
	//   - reth unit 0 (reth0.0 with no vlan).
	//   - reth nonzero no-VLAN unit (synthetic).
	//   - non-reth unit 0 (ge-0/0/0.0).
	//   - non-reth nonzero no-VLAN unit (synthetic).
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0}},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"em0": {Name: "em0"},
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, VlanID: 0},
					3:  {Number: 3, VlanID: 0}, // non-reth nonzero no-VLAN
					80: {Number: 80, VlanID: 180},
				}},
				"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, VlanID: 0},
					5:  {Number: 5, VlanID: 0}, // reth nonzero no-VLAN
					50: {Number: 50, VlanID: 50},
				}},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				// #6861 F3: unit 0 alone does NOT exercise the tunnel-map
				// lookup. For a unit-0 ref the map answer ("gr-0-0-0") and
				// ResolveKernelIfName's fallback (unit.Number == 0 ->
				// kernelBase) are the SAME string, so deleting the
				// TunnelNameMap() block from ResolveKernelIfName left this
				// guard green — the fallback silently supplied the right
				// answer and the lookup was unobservable.
				//
				// A NONZERO unit under an interface-level tunnel splits them:
				// the map (and snapshotLinuxName, and the runtime) say
				// "gr-0-0-0" because the unit shares the interface's tunnel
				// device, while the fallback would synthesize "gr-0-0-0.1".
				// That is the only shape in this config where the lookup is
				// load-bearing, which is why it has to be here.
				"gr-0/0/0": {
					Name:   "gr-0/0/0",
					Tunnel: &config.TunnelConfig{Source: "10.0.0.1"},
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0},
						1: {Number: 1},
					},
				},
			},
		},
	}

	type tcase struct {
		ifName string
		iface  *config.InterfaceConfig
		unit   *config.InterfaceUnit
	}

	// Collect cases by walking the config so the parity check matches
	// real snapshot iteration shape.
	var cases []tcase
	for name, ifc := range cfg.Interfaces.Interfaces {
		// iface, no unit (snapshotLinuxName's no-unit branch).
		cases = append(cases, tcase{ifName: name, iface: ifc, unit: nil})
		for _, u := range ifc.Units {
			cases = append(cases, tcase{ifName: name, iface: ifc, unit: u})
		}
	}
	// iface == nil branch.
	cases = append(cases, tcase{ifName: "lo", iface: nil, unit: nil})
	cases = append(cases, tcase{ifName: "fxp0", iface: nil, unit: nil})

	for _, tc := range cases {
		var ref string
		if tc.unit == nil {
			ref = tc.ifName
		} else {
			ref = fmt.Sprintf("%s.%d", tc.ifName, tc.unit.Number)
		}
		got := cfg.ResolveKernelIfName(ref)
		want := snapshotLinuxName(cfg, tc.ifName, tc.iface, tc.unit)
		if got != want {
			t.Errorf("drift: ref %q (ifName=%q, unit=%+v) got %q, want %q",
				ref, tc.ifName, tc.unit, got, want)
		}
	}
}

// #12646: pin base-before-unit snapshot emission for a unit 0 sharing the
// base's live netdev ifindex. Rust enforces the unit's host-inbound precedence
// independently of input order; this producer-order assertion prevents an
// accidental wire-contract change. Fail-on-revert: moving the base append below
// the unit loop flips the two row names.
func TestBuildInterfaceSnapshotsEmitsBaseBeforeUnitRows_12646(t *testing.T) {
	prev := buildLinkSnapshot
	defer func() { buildLinkSnapshot = prev }()
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-9" {
			return 9009, 1500, "02:00:00:00:00:09", nil
		}
		return 0, 0, "", nil
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/9": {
			Name: "ge-0/0/9",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
			},
		},
	}

	snapshots := buildInterfaceSnapshots(cfg)
	if len(snapshots) < 2 {
		t.Fatalf("snapshots = %+v, want base and unit-0 rows", snapshots)
	}
	if got, want := []string{snapshots[0].Name, snapshots[1].Name},
		[]string{"ge-0/0/9", "ge-0/0/9.0"}; !equalStrings(got, want) {
		t.Fatalf("first base/unit rows = %v, want %v", got, want)
	}
	if snapshots[0].Ifindex <= 0 || snapshots[0].Ifindex != snapshots[1].Ifindex {
		t.Fatalf("base/unit ifindexes = %d/%d, want same positive live ifindex",
			snapshots[0].Ifindex, snapshots[1].Ifindex)
	}
}
