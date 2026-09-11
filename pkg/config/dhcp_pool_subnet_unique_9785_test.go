package config

import (
	"strings"
	"testing"
)

// dupSubnetTree9785 builds a tree from flat set lines the way the CLI does
// (ParseSetCommand + SetPath).
func dupSubnetTree9785(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range lines {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// dhcpPool9785 returns the set lines declaring one pool of one group.
func dhcpPool9785(server, group, pool, subnet, low, high string) []string {
	p := "set system services " + server + " group " + group
	return []string{
		p + " interface ge-0-0-1",
		p + " pool " + pool + " subnet " + subnet,
		p + " pool " + pool + " address-range low " + low + " high " + high,
	}
}

func joinLines9785(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// TestDuplicateDHCPPoolSubnetIsRefusedAtCommit9785 binds the commit gate. Two
// pools of one DHCP server with the same subnet render two Kea subnet entries
// for one prefix; Kea refuses the whole config and stops serving every pool on
// the node, while the commit used to print `commit complete`.
func TestDuplicateDHCPPoolSubnetIsRefusedAtCommit9785(t *testing.T) {
	const v4, v6 = "dhcp-local-server", "dhcpv6-local-server"
	lan := dhcpPool9785(v4, "lan-pool", "lan-range", "10.0.61.0/24", "10.0.61.100", "10.0.61.199")
	cases := []struct {
		name  string
		lines []string
		want  []string // substrings of the refusal; nil means the config must commit
	}{
		{
			name:  "the #9785 shape: a second group for the same v4 subnet",
			lines: joinLines9785(lan, dhcpPool9785(v4, "g9729", "p9729", "10.0.61.0/24", "10.0.61.150", "10.0.61.199")),
			want:  []string{v4, `group "lan-pool" pool "lan-range"`, `group "g9729" pool "p9729"`, "10.0.61.0/24", "duplicates"},
		},
		{
			name:  "two pools with one subnet in the same v4 group",
			lines: joinLines9785(lan, dhcpPool9785(v4, "lan-pool", "second", "10.0.61.0/24", "10.0.61.200", "10.0.61.220")),
			want:  []string{`pool "lan-range"`, `pool "second"`, "duplicates"},
		},
		{
			name:  "a host-bit spelling of the same v4 network",
			lines: joinLines9785(lan, dhcpPool9785(v4, "other", "o", "10.0.61.1/24", "10.0.61.150", "10.0.61.199")),
			want:  []string{"subnet 10.0.61.1/24", "prefix 10.0.61.0/24", "duplicates"},
		},
		{
			name: "two v6 groups with one subnet",
			lines: joinLines9785(
				dhcpPool9785(v6, "a6", "p", "2001:db8:61::/64", "2001:db8:61::10", "2001:db8:61::20"),
				dhcpPool9785(v6, "b6", "p", "2001:db8:61::/64", "2001:db8:61::30", "2001:db8:61::40")),
			want: []string{v6, `group "a6"`, `group "b6"`, "2001:db8:61::/64", "duplicates"},
		},
		{
			name:  "control: distinct v4 subnets commit",
			lines: joinLines9785(lan, dhcpPool9785(v4, "other", "o", "10.0.62.0/24", "10.0.62.100", "10.0.62.199")),
		},
		{
			name:  "control: nested v4 prefixes are left to the ambiguity warning",
			lines: joinLines9785(lan, dhcpPool9785(v4, "other", "o", "10.0.61.0/25", "10.0.61.10", "10.0.61.20")),
		},
		{
			name: "control: v4 and v6 servers are separate scopes",
			lines: joinLines9785(lan,
				dhcpPool9785(v6, "a6", "p", "2001:db8:61::/64", "2001:db8:61::10", "2001:db8:61::20")),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(dupSubnetTree9785(t, tc.lines...))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CONTROL BROKE: want the config to commit, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want the duplicate subnet refused at commit, got a clean compile")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not contain %q", err, w)
				}
			}
		})
	}
}

// TestDuplicateDHCPPoolSubnetLenientGate9785 binds the tolerant side. The load
// and peer-sync paths must warn and keep both pools, so a persisted config
// still boots (#1960); the Kea renderer then skips the later pool
// (claimPoolSubnet in pkg/dhcpserver).
func TestDuplicateDHCPPoolSubnetLenientGate9785(t *testing.T) {
	lines := joinLines9785(
		dhcpPool9785("dhcp-local-server", "lan-pool", "lan-range", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
		dhcpPool9785("dhcp-local-server", "g9729", "p9729", "10.0.61.0/24", "10.0.61.150", "10.0.61.199"))
	if _, err := CompileConfig(dupSubnetTree9785(t, lines...)); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("CompileConfig: want the duplicate refused, got %v", err)
	}
	const warn = "DHCP pool subnet (downgraded to warning on tolerant path)"
	cfg, err := CompileConfigLenient(dupSubnetTree9785(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: want a warning, not an error: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, warn) {
		t.Fatalf("CompileConfigLenient: want %q, got %+v", warn, cfg.Warnings)
	}
	if got := len(cfg.System.DHCPServer.DHCPLocalServer.Groups); got != 2 {
		t.Fatalf("CompileConfigLenient: want both groups kept for the renderer to arbitrate, got %d", got)
	}
	cfgN, errN := CompileConfigForNodeLenient(dupSubnetTree9785(t, lines...), 0)
	if errN != nil {
		t.Fatalf("CompileConfigForNodeLenient: want a warning, not an error: %v", errN)
	}
	if !hasWarningContaining(cfgN.Warnings, warn) {
		t.Fatalf("CompileConfigForNodeLenient: want %q, got %+v", warn, cfgN.Warnings)
	}
}
