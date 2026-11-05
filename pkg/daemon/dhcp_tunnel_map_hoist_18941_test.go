package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestResolveDHCPRethInterfacesBuildsTunnelNameMapOnce18941 pins the daemon
// resolver's cost contract across multiple DHCP groups and both families.
// Its expected names also ensure supplying a shared map does not change the
// canonical resolver's RETH/VLAN/tunnel results.
func TestResolveDHCPRethInterfacesBuildsTunnelNameMapOnce18941(t *testing.T) {
	cfg := keaCfg9407(t)
	cfg.Interfaces.Interfaces["gr-0/0/1"] = &config.InterfaceConfig{
		Name: "gr-0/0/1",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Tunnel: &config.TunnelConfig{Name: "gr-0-0-1"}},
		},
	}
	cfg.System.DHCPServer.DHCPLocalServer.Groups["tunnel"] = &config.DHCPServerGroup{
		Name: "tunnel", Interfaces: []string{"gr-0/0/1.0"},
	}
	cfg.System.DHCPServer.DHCPv6LocalServer.Groups["tunnel6"] = &config.DHCPServerGroup{
		Name: "tunnel6", Interfaces: []string{"gr-0/0/1.0"},
	}

	orig := dhcpTunnelNameMapFn
	builds := 0
	dhcpTunnelNameMapFn = func(c *config.Config) map[string]string {
		builds++
		return orig(c)
	}
	t.Cleanup(func() { dhcpTunnelNameMapFn = orig })

	out := resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)
	for _, tc := range []struct {
		family string
		local  *config.DHCPLocalServerConfig
		group  string
		want   string
	}{
		{"v4", out.DHCPLocalServer, "untagged", "ge-0-0-1"},
		{"v4", out.DHCPLocalServer, "tagged", "ge-0-0-1.180"},
		{"v4", out.DHCPLocalServer, "tunnel", "gr-0-0-1"},
		{"v6", out.DHCPv6LocalServer, "untagged6", "ge-0-0-1"},
		{"v6", out.DHCPv6LocalServer, "tunnel6", "gr-0-0-1"},
	} {
		if tc.local == nil || tc.local.Groups[tc.group] == nil || len(tc.local.Groups[tc.group].Interfaces) != 1 {
			t.Fatalf("%s group %q missing or malformed", tc.family, tc.group)
		}
		if got := tc.local.Groups[tc.group].Interfaces[0]; got != tc.want {
			t.Errorf("%s group %q resolved to %q, want %q", tc.family, tc.group, got, tc.want)
		}
	}
	if builds != 1 {
		t.Errorf("built the tunnel-name map %d times across groups in both families, want exactly 1", builds)
	}

	builds = 0
	resolveDHCPRethInterfaces(config.DHCPServerConfig{}, nil)
	if builds != 0 {
		t.Errorf("nil DHCP/config shapes built the tunnel-name map %d times, want 0", builds)
	}

	builds = 0
	empty := config.DHCPServerConfig{
		DHCPLocalServer:   &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{}},
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{},
	}
	resolveDHCPRethInterfaces(empty, &config.Config{})
	if builds != 0 {
		t.Errorf("empty DHCP groups built the tunnel-name map %d times, want 0", builds)
	}
}
