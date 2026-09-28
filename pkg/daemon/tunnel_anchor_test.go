package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestCollectAppliedTunnelsUsesAnchorModeForUserspace(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeUserspace
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:db8::1",
				Destination: "2001:db8::2",
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1", len(tunnels))
	}
	if !tunnels[0].AnchorOnly {
		t.Fatal("userspace tunnel should be anchor-only")
	}
}

func TestCollectAppliedTunnelsUsesAnchorModeForDefaultDataplane(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:db8::1",
				Destination: "2001:db8::2",
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1", len(tunnels))
	}
	if !tunnels[0].AnchorOnly {
		t.Fatal("default userspace tunnel should be anchor-only")
	}
}

func TestCollectAppliedTunnelsKeepsKernelModeForLegacyDataplane(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeEBPF
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:db8::1",
				Destination: "2001:db8::2",
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1", len(tunnels))
	}
	if tunnels[0].AnchorOnly {
		t.Fatal("legacy dataplane tunnel should not be anchor-only")
	}
}

// #1736 S2b regression: a WireGuard tunnel has no GRE-style `source`,
// and the Source!="" screen in collectAppliedTunnels must not drop it —
// otherwise the persistent wgN TUN is never created and the userspace
// WG control thread cannot attach (found live during S2b bring-up).
func TestCollectAppliedTunnelsKeepsWireguardWithoutSource(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeUserspace
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Tunnel: &config.TunnelConfig{
				Name:         "wg0",
				Mode:         "wireguard",
				WgListenPort: 51820,
				WgPeers: []config.WgPeerConfig{{
					PublicKeyHex: "b0202020202020202020202020202020202020202020202020202020202020b2",
				}},
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1 (wireguard tunnel without source was dropped)", len(tunnels))
	}
	if tunnels[0].Mode != "wireguard" || tunnels[0].Name != "wg0" {
		t.Fatalf("unexpected tunnel collected: %+v", tunnels[0])
	}
	// A GRE stanza with no source must STILL be screened out — the
	// wireguard exemption must not weaken the half-configured-GRE gate.
	cfg.Interfaces.Interfaces["gr-0/0/0"] = &config.InterfaceConfig{
		Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", Mode: "gre"},
	}
	if got := len(collectAppliedTunnels(cfg)); got != 1 {
		t.Fatalf("len(tunnels) = %d, want 1 (sourceless GRE must stay screened)", got)
	}
}

// #1884: collectAppliedTunnels must plumb the config-desired MTU
// (unit-level overrides interface-level) and the routing-instance
// LIST membership (step-0a normalization) into each TunnelConfig.
func TestCollectAppliedTunnelsPopulatesMTUAndRIListMember(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeUserspace
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			MTU: 9000,
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "192.0.2.1",
				Destination: "192.0.2.2",
			},
		},
		"gr-0/0/1": {
			MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				0: {
					MTU: 1400, // unit overrides interface
					Tunnel: &config.TunnelConfig{
						Name:        "gr-0-0-1",
						Mode:        "gre",
						Source:      "192.0.2.3",
						Destination: "192.0.2.4",
					},
				},
				1: {
					Tunnel: &config.TunnelConfig{
						Name:        "gr-0-0-1u1", // compiler uN scheme
						Mode:        "gre",
						Source:      "192.0.2.5",
						Destination: "192.0.2.6",
					},
				},
			},
		},
	}
	// Keep the forwarding-instance skip check on a separate device: forwarding
	// ownership otherwise conflicts with the VRF member under #11060.
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "fwd", InstanceType: "forwarding", Interfaces: []string{"ge-0/0/0"}},
		{Name: "red", InstanceType: "vrf", Interfaces: []string{"gr-0/0/0.0"}},
		{Name: "blue", InstanceType: "vrf", Interfaces: []string{"gr-0/0/1.1"}},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 3 {
		t.Fatalf("len(tunnels) = %d, want 3", len(tunnels))
	}
	byName := map[string]*config.TunnelConfig{}
	for _, tc := range tunnels {
		byName[tc.Name] = tc
	}
	if got := byName["gr-0-0-0"].MTU; got != 9000 {
		t.Errorf("interface-level MTU = %d, want 9000", got)
	}
	if got := byName["gr-0-0-1"].MTU; got != 1400 {
		t.Errorf("unit-level MTU = %d, want 1400 (unit overrides interface)", got)
	}
	// `gr-0/0/0.0` normalizes to gr-0-0-0 (the 0a transform);
	// forwarding-type instances are skipped exactly as 0a skips them.
	if got := byName["gr-0-0-0"].RIListMember; got != "red" {
		t.Errorf("RIListMember = %q, want red", got)
	}
	if got := byName["gr-0-0-1"].RIListMember; got != "" {
		t.Errorf("RIListMember = %q for unlisted tunnel, want empty", got)
	}
	// #1904: a unit>0 list entry (gr-0/0/1.1) resolves to the real
	// per-unit "uN" device name, so the veto now covers unit>0 tunnels.
	if got := byName["gr-0-0-1u1"].RIListMember; got != "blue" {
		t.Errorf("unit>0 RIListMember = %q, want blue", got)
	}
}

// #1904 (supersedes the #1884 r5 parity pin, whose comment said "the
// shared helper guarantees both move together when 0a is fixed"): a
// unit>0 tunnel entry like gr-0/0/0.1 resolves through tunMap to the
// real per-unit "uN" device name (gr-0-0-0u1) — the compiler-assigned
// TunnelConfig.Name that ApplyTunnels actually creates. Non-tunnel
// refs keep the literal pre-#1904 transform byte-identically.
func TestRIMemberLinuxNameResolvesPerUnitTunnels(t *testing.T) {
	tunMap := map[string]string{
		"gr-0/0/0.0": "gr-0-0-0",
		"gr-0/0/0.1": "gr-0-0-0u1",
	}
	cases := map[string]string{
		"gr-0/0/0.0": "gr-0-0-0",
		"gr-0/0/0":   "gr-0-0-0",   // bare ref: literal transform
		"gr-0/0/0.1": "gr-0-0-0u1", // #1904: real uN device, not gr-0-0-0.1
		"ge-0/0/1.0": "ge-0-0-1",   // non-tunnel: literal unit-0 collapse
		"ge-0/0/1.5": "ge-0-0-1.5", // non-tunnel unit>0: literal, unchanged
	}
	for in, want := range cases {
		if got := riMemberLinuxName(nil, tunMap, in); got != want {
			t.Errorf("riMemberLinuxName(%q) = %q, want %q", in, got, want)
		}
	}
	// Nil/empty map (no tunnels configured): literal transform only.
	if got := riMemberLinuxName(nil, nil, "gr-0/0/0.1"); got != "gr-0-0-0.1" {
		t.Errorf("riMemberLinuxName(nil, gr-0/0/0.1) = %q, want gr-0-0-0.1", got)
	}
}
