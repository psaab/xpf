package config

import (
	"strings"
	"testing"
)

// dupIfaceTree15028 builds a tree from flat set lines the way the CLI does.
func dupIfaceTree15028(t *testing.T, lines ...string) *ConfigTree {
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

func joinLines15028(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// TestDuplicateDHCPGroupInterfaceIsRefusedAtCommit15028 binds the #15028
// commit gate. Two group interface refs of one family that resolve to one
// kernel device render twice into Kea's interfaces-config list; Kea
// refuses the duplicate and stops serving every pool of the family, while
// the commit used to print success.
func TestDuplicateDHCPGroupInterfaceIsRefusedAtCommit15028(t *testing.T) {
	const v4, v6 = "dhcp-local-server", "dhcpv6-local-server"
	// The reth fixture: reth1's member is ge-0/0/1, so reth1.0 and
	// ge-0/0/1.0 both resolve to the kernel device ge-0-0-1.
	cluster := []string{
		"set chassis cluster authentication-key test-cluster-psk-15028",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
	}
	grp := func(server, group, iface, subnet, low, high string) []string {
		p := "set system services " + server + " group " + group
		return []string{
			p + " interface " + iface,
			p + " pool p1 subnet " + subnet,
			p + " pool p1 address-range low " + low + " high " + high,
		}
	}
	cases := []struct {
		name  string
		lines []string
		want  []string // substrings of the refusal; nil means the config must commit
	}{
		{
			name: "C1: reth ref and its member ref in two v4 groups resolve to one device",
			lines: joinLines15028(cluster,
				grp(v4, "g1", "reth1.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
				grp(v4, "g2", "ge-0/0/1.0", "10.0.62.0/24", "10.0.62.100", "10.0.62.199")),
			want: []string{v4, `group "g1" interface "reth1.0"`, `group "g2" interface "ge-0/0/1.0"`, `"ge-0-0-1"`, "duplicates"},
		},
		{
			name: "C1b: bare reth ref and unit ref in two v4 groups (unit-0 collapse)",
			lines: joinLines15028(cluster,
				grp(v4, "g1", "reth1.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
				grp(v4, "g2", "reth1", "10.0.62.0/24", "10.0.62.100", "10.0.62.199")),
			want: []string{`group "g1" interface "reth1.0"`, `group "g2" interface "reth1"`, `"ge-0-0-1"`, "duplicates"},
		},
		{
			name: "C2: v6 twin — reth ref and member ref in two v6 groups",
			lines: joinLines15028(cluster,
				grp(v6, "g1", "reth1.0", "2001:db8:61::/64", "2001:db8:61::10", "2001:db8:61::20"),
				grp(v6, "g2", "ge-0/0/1.0", "2001:db8:62::/64", "2001:db8:62::10", "2001:db8:62::20")),
			want: []string{v6, `group "g1" interface "reth1.0"`, `group "g2" interface "ge-0/0/1.0"`, `"ge-0-0-1"`, "duplicates"},
		},
		{
			// A repeated `set ... interface reth1.0` line is the same
			// statement and the tree keeps it once, so the within-group
			// duplicate reaches the compiler as one bracketed statement.
			name: "C6: one ref repeated within a single v4 group (bracketed)",
			lines: joinLines15028(cluster, []string{
				"set system services " + v4 + " group g1 interface [ reth1.0 reth1.0 ]",
				"set system services " + v4 + " group g1 pool p1 subnet 10.0.61.0/24",
				"set system services " + v4 + " group g1 pool p1 address-range low 10.0.61.100 high 10.0.61.199",
			}),
			want: []string{`group "g1" interface "reth1.0"`, "duplicates"},
		},
		{
			name: "C6b: unit-0 and bare refs within a single non-reth v4 group",
			lines: joinLines15028([]string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			}, grp(v4, "g1", "ge-0/0/0.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
				[]string{"set system services " + v4 + " group g1 interface ge-0/0/0"}),
			want: []string{`group "g1"`, `"ge-0-0-0"`, "duplicates"},
		},
		{
			name: "C0 control: reth ref plus a distinct physical interface commits",
			lines: joinLines15028(cluster,
				grp(v4, "g1", "reth1.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
				grp(v4, "g2", "ge-0/0/2.0", "10.0.62.0/24", "10.0.62.100", "10.0.62.199")),
		},
		{
			name: "C0 control: same device in v4 and v6 families is separate scope",
			lines: joinLines15028(cluster,
				grp(v4, "g1", "reth1.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
				grp(v6, "g1", "reth1.0", "2001:db8:61::/64", "2001:db8:61::10", "2001:db8:61::20")),
		},
		{
			name: "C0 control: two distinct devices in one group commit",
			lines: joinLines15028(cluster, []string{
				"set system services " + v4 + " group g1 interface reth1.0",
				"set system services " + v4 + " group g1 interface ge-0/0/2.0",
				"set system services " + v4 + " group g1 pool p1 subnet 10.0.61.0/24",
				"set system services " + v4 + " group g1 pool p1 address-range low 10.0.61.100 high 10.0.61.199",
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(dupIfaceTree15028(t, tc.lines...))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CONTROL BROKE: want the config to commit, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want the duplicate resolved interface refused at commit, got a clean compile")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not contain %q", err, w)
				}
			}
		})
	}
}

// TestDuplicateDHCPGroupInterfaceLenientGate15028 binds the tolerant side.
// The load and peer-sync paths must warn and keep both groups, so a
// persisted config still boots (#1960); the Kea renderer then
// de-duplicates the interfaces list (dedupKeaInterfaces).
func TestDuplicateDHCPGroupInterfaceLenientGate15028(t *testing.T) {
	lines := joinLines15028(
		[]string{
			"set chassis cluster authentication-key test-cluster-psk-15028",
			"set chassis cluster reth-count 2",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 1 priority 100",
			"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
			"set interfaces reth1 redundant-ether-options redundancy-group 1",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		},
		[]string{
			"set system services dhcp-local-server group g1 interface reth1.0",
			"set system services dhcp-local-server group g1 pool p1 subnet 10.0.61.0/24",
			"set system services dhcp-local-server group g1 pool p1 address-range low 10.0.61.100 high 10.0.61.199",
			"set system services dhcp-local-server group g2 interface ge-0/0/1.0",
			"set system services dhcp-local-server group g2 pool p1 subnet 10.0.62.0/24",
			"set system services dhcp-local-server group g2 pool p1 address-range low 10.0.62.100 high 10.0.62.199",
		})
	if _, err := CompileConfig(dupIfaceTree15028(t, lines...)); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("CompileConfig: want the duplicate refused, got %v", err)
	}
	const warn = "DHCP group interface (downgraded to warning on tolerant path)"
	cfg, err := CompileConfigLenient(dupIfaceTree15028(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: want a warning, not an error: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, warn) {
		t.Fatalf("CompileConfigLenient: want %q, got %+v", warn, cfg.Warnings)
	}
	if got := len(cfg.System.DHCPServer.DHCPLocalServer.Groups); got != 2 {
		t.Fatalf("CompileConfigLenient: want both groups kept for the renderer to arbitrate, got %d", got)
	}
	cfgN, errN := CompileConfigForNodeLenient(dupIfaceTree15028(t, lines...), 0)
	if errN != nil {
		t.Fatalf("CompileConfigForNodeLenient: want a warning, not an error: %v", errN)
	}
	if !hasWarningContaining(cfgN.Warnings, warn) {
		t.Fatalf("CompileConfigForNodeLenient: want %q, got %+v", warn, cfgN.Warnings)
	}
}
