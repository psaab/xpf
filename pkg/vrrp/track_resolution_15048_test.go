package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15048 (A25-01): CollectInstances resolved the instance interface via the
// SSOT cfg.ResolveKernelIfName but TrackInterface via the slash-to-dash-only
// config.LinuxIfName. A track ref naming a unit (`ge-0/0/1.0`), a VLAN unit,
// or a reth therefore stored a kernel name that is not the tracked device:
// `ge-0/0/1.0` stayed `ge-0-0-1.0` only by accident for unit 0, while a VLAN
// unit (`ge-0/0/1` unit 100 vlan-id 100) must become `ge-0-0-1.100` and a
// reth must become its physical member. The unresolvable spelling matched
// no netdev, seedTrackState treated it as down for the life of the config,
// and real link events (matched by exact kernel name) never arrived.
//
// FAIL-ON-REVERT: restore config.LinuxIfName(vg.TrackInterface) in
// CollectInstances and the VLAN/reth cells below red (they yield
// "ge-0-0-1" / "reth1" instead of the SSOT device). The unit-0 and bare
// controls stay green either way — they pin no behaviour change outside
// the cited mechanism.

func track15048Cfg(track string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number: 0,
							VRRPGroups: map[string]*config.VRRPGroup{
								"10.0.0.1/24_grp1": {
									ID:                 1,
									Priority:           200,
									VirtualAddresses:   []string{"10.0.0.3/24"},
									TrackInterface:     track,
									TrackPriorityDelta: 20,
								},
							},
						},
					},
				},
				"ge-0/0/1": {
					Name:        "ge-0/0/1",
					VlanTagging: true,
					Units: map[int]*config.InterfaceUnit{
						0:   {Number: 0},
						100: {Number: 100, VlanID: 100},
					},
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 1,
					Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
				},
				"ge-0/0/2": {
					Name:            "ge-0/0/2",
					RedundantParent: "reth1",
					Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
				},
			},
		},
	}
}

func TestCollectInstances_TrackInterfaceResolvesViaSSOT15048(t *testing.T) {
	cases := []struct {
		name  string
		track string
		want  string
	}{
		// Controls: spellings LinuxIfName already handled — must not change.
		{"bare", "ge-0/0/1", "ge-0-0-1"},
		{"unit-zero", "ge-0/0/1.0", "ge-0-0-1"},
		// The defect legs: only ResolveKernelIfName yields the real device.
		{"vlan-unit", "ge-0/0/1.100", "ge-0-0-1.100"},
		{"reth", "reth1", "ge-0-0-2"},
		{"reth-unit", "reth1.0", "ge-0-0-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := track15048Cfg(tc.track)
			// Oracle: the expectation must agree with the SSOT itself.
			if ssot := cfg.ResolveKernelIfName(tc.track); ssot != tc.want {
				t.Fatalf("fixture precondition: ResolveKernelIfName(%q) = %q, want %q", tc.track, ssot, tc.want)
			}
			insts := CollectInstances(cfg)
			if len(insts) != 1 {
				t.Fatalf("expected 1 instance, got %d", len(insts))
			}
			if insts[0].TrackInterface != tc.want {
				t.Errorf("TrackInterface for %q = %q, want SSOT device %q", tc.track, insts[0].TrackInterface, tc.want)
			}
		})
	}
}

// Undeclared tracked names still collect (the config gate in pkg/config is
// what rejects them at commit; the lenient path must stay usable). The
// collector resolves them through the same SSOT fallback as any other ref.
func TestCollectInstances_TrackInterfaceUndeclaredFallsBack15048(t *testing.T) {
	cfg := track15048Cfg("ge-0/0/9")
	insts := CollectInstances(cfg)
	if len(insts) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(insts))
	}
	if want := cfg.ResolveKernelIfName("ge-0/0/9"); insts[0].TrackInterface != want {
		t.Errorf("TrackInterface = %q, want SSOT fallback %q", insts[0].TrackInterface, want)
	}
}
