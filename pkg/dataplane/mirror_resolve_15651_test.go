package dataplane

import (
	"net"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type mirrorDP15651 struct {
	discardingDataPlane
	calls [][3]int // ingress, output, rate
}

func (*mirrorDP15651) ClearMirrorConfigs() error { return nil }
func (m *mirrorDP15651) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error {
	m.calls = append(m.calls, [3]int{ifindex, mirrorIfindex, int(rate)})
	return nil
}

// #15651: the legacy compiler resolved mirror refs with LinuxIfName only,
// so a Junos unit ref (`ge-0/0/0.0`) named no kernel device. It must go
// through resolveInterfaceRef/ResolveKernelIfName and program the row.
func TestCompilePortMirroringResolvesJunosUnitRef15651(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"lo": {Name: "lo", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {Name: "span1", Input: []string{"lo.0"}, Output: "lo.0", InputRate: 7},
		},
	}
	result := &CompileResult{ifCache: map[string]*net.Interface{"lo": lo}}
	dp := &mirrorDP15651{}
	if err := compilePortMirroring(dp, cfg, result); err != nil {
		t.Fatalf("compilePortMirroring: %v", err)
	}
	want := [][3]int{{lo.Index, lo.Index, 7}}
	if !reflect.DeepEqual(dp.calls, want) {
		t.Fatalf("SetMirrorConfig calls = %v, want %v (Junos unit ref lo.0 must resolve to lo)", dp.calls, want)
	}
}

func TestMirrorKernelName15651(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{1: {Number: 1, VlanID: 100}}},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"reth0":    {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cases := map[string]string{
		"ge-0/0/0.0": "ge-0-0-0",
		"ge-0/0/0":   "ge-0-0-0",
		"ge-0/0/3.1": "ge-0-0-3.100",
		"reth0.0":    "ge-0-0-2",
		"reth0":      "ge-0-0-2",
	}
	for ref, want := range cases {
		if got := mirrorKernelName(cfg, ref); got != want {
			t.Errorf("mirrorKernelName(%q) = %q, want %q", ref, got, want)
		}
	}
}
