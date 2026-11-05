package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAssembleFRRConfigBuildsTunnelNameMapOnce18984 pins the interface-hint
// walk's cost contract while checking that RETH, VLAN, and tunnel names
// remain canonical in the assembled FRR interface hints.
func TestAssembleFRRConfigBuildsTunnelNameMapOnce18984(t *testing.T) {
	cfg := interfaceSettingsConfig14138()
	cfg.Interfaces.Interfaces["gr-0/0/1"] = &config.InterfaceConfig{
		Name:      "gr-0/0/1",
		Bandwidth: 250_000_000,
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, PointToPoint: true, Tunnel: &config.TunnelConfig{Name: "gre-unit0"}},
		},
	}

	orig := frrTunnelNameMapFn
	builds := 0
	frrTunnelNameMapFn = func(c *config.Config) map[string]string {
		builds++
		return orig(c)
	}
	t.Cleanup(func() { frrTunnelNameMapFn = orig })

	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
	for dev, want := range map[string]uint64{
		"ge-0-0-1": 1_000_000_000,
		"ge-0-0-3": 100_000_000,
		"gr-0-0-1": 250_000_000,
	} {
		if got := fc.InterfaceBandwidths[dev]; got != want {
			t.Errorf("InterfaceBandwidths[%q] = %d, want %d; all=%v", dev, got, want, fc.InterfaceBandwidths)
		}
	}
	for _, dev := range []string{"ge-0-0-1.50", "ge-0-0-3.60", "gre-unit0"} {
		if !fc.InterfacePointToPoint[dev] {
			t.Errorf("InterfacePointToPoint missing %q; all=%v", dev, fc.InterfacePointToPoint)
		}
	}
	if len(fc.InterfacePointToPoint) != 3 {
		t.Errorf("InterfacePointToPoint = %v, want exactly three resolved p2p devices", fc.InterfacePointToPoint)
	}
	if builds != 1 {
		t.Errorf("built the tunnel-name map %d times across interface and p2p-unit refs, want exactly 1", builds)
	}

	builds = 0
	(&Daemon{}).assembleFRRConfig(&config.Config{}, nil)
	if builds != 0 {
		t.Errorf("nil interface-map shape built the tunnel-name map %d times, want 0", builds)
	}

	builds = 0
	empty := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"nil":   nil,
		"empty": {Name: "empty", Units: map[int]*config.InterfaceUnit{}},
	}}}
	(&Daemon{}).assembleFRRConfig(empty, nil)
	if builds != 0 {
		t.Errorf("nil/empty interface shapes built the tunnel-name map %d times, want 0", builds)
	}
}
