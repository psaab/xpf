package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestApplyTunnelHostInboundPreservesScreenProfileAndSupportsIP6GRE is the
// #15765 regression: applyTunnelHostInbound must not overwrite the
// ZoneConfig installed by programZoneMaps (ZoneID/ScreenProfileID zeroed by a
// fresh ZoneConfig{HostInbound: merged} + full UpdateAny), must honour
// ip6gre, and must not resurrect a DroppedEnforcementChild-poisoned zone.
func TestApplyTunnelHostInboundPreservesScreenProfileAndSupportsIP6GRE(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0, Addresses: []string{"2001:db8::1/64"}},
					},
				},
				"ge-0/0/1": {
					Name: "ge-0/0/1",
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0, Addresses: []string{"2001:db8::1/64"}},
					},
				},
				"gr-0/0/0": {
					Name: "gr-0/0/0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number: 0,
							Tunnel: &config.TunnelConfig{
								Mode:        "ip6gre",
								Source:      "2001:db8::1",
								Destination: "2001:db8::2",
							},
						},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			Screen: map[string]*config.ScreenProfile{
				"untrust-screen": {Name: "untrust-screen"},
			},
			Zones: map[string]*config.ZoneConfig{
				"untrust": {
					Name:          "untrust",
					ScreenProfile: "untrust-screen",
					Interfaces:    []string{"ge-0/0/0.0"},
					TCPRst:        true,
					HostInboundTraffic: &config.HostInboundTraffic{
						SystemServices: []string{"ssh"},
					},
				},
				// Poisoned zone carrying the same transport address: must
				// never be programmed (programZoneMaps skips it).
				"poisoned": {
					Name:                    "poisoned",
					ScreenProfile:           "untrust-screen",
					Interfaces:              []string{"ge-0/0/1.0"},
					DroppedEnforcementChild: true,
				},
			},
		},
	}
	result := &CompileResult{
		ZoneIDs:   map[string]uint16{"untrust": 7, "poisoned": 8},
		ScreenIDs: map[string]uint16{"untrust-screen": 3},
	}
	dp := &tunnelHostInboundTestDP{}
	applyTunnelHostInbound(dp, cfg, result)

	zc, ok := dp.zoneCfgs[7]
	if !ok {
		t.Fatalf("expected SetZoneConfig for untrust (id 7) for ip6gre tunnel; got %#v", dp.zoneCfgs)
	}
	if zc.HostInbound&HostInboundGRE == 0 {
		t.Errorf("HostInbound = %#x, missing HostInboundGRE for ip6gre", zc.HostInbound)
	}
	if zc.HostInbound&HostInboundSSH == 0 {
		t.Errorf("HostInbound = %#x, missing pre-existing ssh flag", zc.HostInbound)
	}
	if zc.ZoneID != 7 {
		t.Errorf("ZoneID = %d, want 7 (preserved, not zeroed)", zc.ZoneID)
	}
	if zc.ScreenProfileID != 3 {
		t.Errorf("ScreenProfileID = %d, want 3 (preserved, not zeroed)", zc.ScreenProfileID)
	}
	if zc.TCPRst != 1 {
		t.Errorf("TCPRst = %d, want 1 (preserved)", zc.TCPRst)
	}
	if _, ok := dp.zoneCfgs[8]; ok {
		t.Errorf("poisoned zone (id 8) must not be configured, got %#v", dp.zoneCfgs[8])
	}
}
