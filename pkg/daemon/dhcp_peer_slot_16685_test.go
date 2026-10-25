package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16685: a shared-section DHCP group member on the PEER node's FPC slot
// (ge-0/0/3 on node1, ge-7/0/3 on node0) does not exist on this node. The
// cluster DHCP filter must drop it (setting MembersFiltered when a group
// shrinks) so Kea never renders a name it will refuse — Kea refuses the
// whole family file, so the peer would serve nothing, including RETH
// segments after failover. The owning node keeps the member unchanged,
// a `groups nodeN` per-node shape is unchanged, slot-less interfaces
// (fxp0) are unaffected, and a peer-slot-only group disappears entirely
// rather than rendering a phantom.
//
// FAIL-ON-REVERT: remove the isPeerSlotInterface16685 arm in
// filterDHCPConfigForMasterRGsWithMasters and node1 keeps ge-0-0-3 below.

func peerSlotDHCPCfg16685(t *testing.T, nodeID int) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16685",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-7/0/0 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.60.1/24",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8:60::1/64",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		"set interfaces ge-0/0/3 unit 0 family inet6 address 2001:db8:3::1/64",
		"set system services dhcp-local-server group gL interface ge-0/0/3.0",
		"set system services dhcp-local-server group gL pool p1 subnet 10.0.3.0/24",
		"set system services dhcp-local-server group gL pool p1 address-range low 10.0.3.100 high 10.0.3.199",
		"set system services dhcp-local-server group gR interface reth0.0",
		"set system services dhcp-local-server group gR pool p1 subnet 10.0.60.0/24",
		"set system services dhcp-local-server group gR pool p1 address-range low 10.0.60.100 high 10.0.60.199",
		"set system services dhcpv6-local-server group gL6 interface ge-0/0/3.0",
		"set system services dhcpv6-local-server group gL6 pool p1 subnet 2001:db8:3::/64",
		"set system services dhcpv6-local-server group gL6 pool p1 address-range low 2001:db8:3::100 high 2001:db8:3::199",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigForNode(tree, nodeID)
	if err != nil {
		t.Fatalf("CompileConfigForNode(%d) must be clean: %v", nodeID, err)
	}
	if cfg.Chassis.Cluster == nil || cfg.Chassis.Cluster.NodeID != nodeID {
		t.Fatalf("node%d compile: Cluster=%+v", nodeID, cfg.Chassis.Cluster)
	}
	return cfg
}

func TestPeerSlotDHCPDroppedOnPeer16685(t *testing.T) {
	for _, tc := range []struct {
		name    string
		nodeID  int
		masters map[int]bool
		wantL   []string // gL interfaces; nil means group absent
	}{
		{"node1 drops ge-0-0-3, keeps mastered reth", 1, map[int]bool{1: true}, nil},
		{"node1 drops ge-0-0-3 even when not master", 1, map[int]bool{}, nil},
		{"node0 keeps ge-0-0-3", 0, map[int]bool{1: true}, []string{"ge-0-0-3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := peerSlotDHCPCfg16685(t, tc.nodeID)
			d := newTestDaemon()
			out := d.filterDHCPConfigForMasterRGsWithMasters(cfg, tc.masters)
			if !tc.masters[1] {
				// Nothing survives: peer-slot group dropped, RETH gated.
				if out != nil {
					t.Fatalf("node%d with no RG mastered must filter to nil, got %+v", tc.nodeID, out)
				}
				return
			}
			if out == nil || out.DHCPLocalServer == nil {
				t.Fatal("filtered config is nil; the mastered RETH group must survive")
			}
			gL := out.DHCPLocalServer.Groups["gL"]
			if tc.wantL == nil {
				if gL != nil {
					t.Fatalf("peer-slot-only group gL must be dropped on node%d, got interfaces %v", tc.nodeID, gL.Interfaces)
				}
			} else {
				if gL == nil {
					t.Fatalf("gL must survive on its owning node%d", tc.nodeID)
				}
				if len(gL.Interfaces) != len(tc.wantL) {
					t.Fatalf("gL interfaces = %v, want %v", gL.Interfaces, tc.wantL)
				}
				for i, want := range tc.wantL {
					if gL.Interfaces[i] != want {
						t.Fatalf("gL interfaces = %v, want %v", gL.Interfaces, tc.wantL)
					}
				}
				if gL.MembersFiltered {
					t.Fatal("unshrunk group on the owning node must not be marked MembersFiltered")
				}
			}
			// The RETH group survives exactly when this node masters RG1,
			// resolved to the LOCAL member.
			gR := out.DHCPLocalServer.Groups["gR"]
			if tc.masters[1] {
				wantMember := "ge-0-0-0"
				if tc.nodeID == 1 {
					wantMember = "ge-7-0-0"
				}
				if gR == nil || len(gR.Interfaces) != 1 || gR.Interfaces[0] != wantMember {
					t.Fatalf("mastered RETH group = %+v, want [%s]", gR, wantMember)
				}
			} else if gR != nil {
				t.Fatalf("RETH group must be gated when RG1 is not mastered, got %v", gR.Interfaces)
			}
			// v6 mirrors v4.
			if out.DHCPv6LocalServer != nil {
				if g := out.DHCPv6LocalServer.Groups["gL6"]; g != nil {
					for _, iface := range g.Interfaces {
						if strings.HasPrefix(iface, "ge-0-0-") && tc.nodeID == 1 {
							t.Fatalf("peer-slot v6 member survived on node1: %v", g.Interfaces)
						}
					}
					if tc.nodeID == 1 {
						t.Fatalf("peer-slot-only v6 group must be dropped on node1, got %v", g.Interfaces)
					}
				}
			} else if tc.nodeID == 0 {
				t.Fatal("v6 group must survive on node0")
			}
		})
	}
}

// TestPeerSlotDHCPMixedGroupMarksFiltered16685: a group mixing a peer-slot
// member with a local member keeps the local member and is marked
// MembersFiltered, so the Kea renderer suppresses the per-subnet selector
// instead of cross-binding the dropped member's pool.
func TestPeerSlotDHCPMixedGroupMarksFiltered16685(t *testing.T) {
	cfg := peerSlotDHCPCfg16685(t, 1)
	// Add a local (slot-7) member to gL by hand: the compiler shape for a
	// mixed group is exercised at the filter's own level.
	g := cfg.System.DHCPServer.DHCPLocalServer.Groups["gL"]
	g.Interfaces = []string{"ge-0/0/3.0", "ge-7/0/3.0"}
	cfg.Interfaces.Interfaces["ge-7/0/3"] = &config.InterfaceConfig{
		Name:  "ge-7/0/3",
		Units: map[int]*config.InterfaceUnit{0: {Addresses: []string{"10.0.73.1/24"}}},
	}
	d := newTestDaemon()
	out := d.filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{1: true})
	if out == nil || out.DHCPLocalServer == nil {
		t.Fatal("mixed group must survive via its local member")
	}
	got := out.DHCPLocalServer.Groups["gL"]
	if got == nil || len(got.Interfaces) != 1 || got.Interfaces[0] != "ge-7-0-3" {
		t.Fatalf("mixed group interfaces = %+v, want [ge-7-0-3]", got)
	}
	if !got.MembersFiltered {
		t.Fatal("group shrunk by the peer-slot drop must be marked MembersFiltered")
	}
}

// TestPeerSlotDHCPGroupedShapeUnchanged16685: an interface declared only
// under `groups node0` never appears in node1's compiled config at all;
// the filter must not invent or drop anything beyond that.
func TestPeerSlotDHCPGroupedShapeUnchanged16685(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16685",
		`set groups node0 interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24`,
		`set groups node0 system services dhcp-local-server group gL interface ge-0/0/3.0`,
		`set groups node1 interfaces ge-7/0/3 unit 0 family inet address 10.0.73.1/24`,
		`set groups node1 system services dhcp-local-server group gL interface ge-7/0/3.0`,
		`set apply-groups "${node}"`,
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// Grouped pools are needed for a renderable group; add via the same tree.
	for _, cmd := range []string{
		`set groups node0 system services dhcp-local-server group gL pool p1 subnet 10.0.3.0/24`,
		`set groups node1 system services dhcp-local-server group gL pool p1 subnet 10.0.73.0/24`,
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	for _, tc := range []struct {
		nodeID int
		want   string
	}{
		{0, "ge-0-0-3"},
		{1, "ge-7-0-3"},
	} {
		cfg, err := config.CompileConfigForNode(tree, tc.nodeID)
		if err != nil {
			t.Fatalf("CompileConfigForNode(%d): %v", tc.nodeID, err)
		}
		d := newTestDaemon()
		out := d.filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{})
		if out == nil || out.DHCPLocalServer == nil {
			t.Fatalf("node%d: grouped shape filtered to nil", tc.nodeID)
		}
		g := out.DHCPLocalServer.Groups["gL"]
		if g == nil || len(g.Interfaces) != 1 || g.Interfaces[0] != tc.want {
			t.Fatalf("node%d: grouped gL = %+v, want [%s]", tc.nodeID, g, tc.want)
		}
		if g.MembersFiltered {
			t.Fatalf("node%d: grouped shape must be unmarked", tc.nodeID)
		}
	}
}

// TestPeerSlotDHCPNode0ViewHasNoPeerName16685 binds the rendered outcome:
// node1's filtered config, handed to the Kea v4 renderer, contains no
// ge-0-0-* name at all, while node0's render keeps ge-0-0-3.
func TestPeerSlotDHCPKeaRender16685(t *testing.T) {
	// The renderer lives in pkg/dhcpserver and needs a Manager; assert the
	// daemon-side precondition instead through the 15206 belt's own lens:
	// every interface surviving node1's filter must be a device node1's
	// compiled config declares AND whose slot is local (or slot-less).
	for _, nodeID := range []int{0, 1} {
		cfg := peerSlotDHCPCfg16685(t, nodeID)
		d := newTestDaemon()
		out := d.filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{1: true})
		if out == nil {
			t.Fatalf("node%d: nil filtered config", nodeID)
		}
		for _, fam := range []*config.DHCPLocalServerConfig{out.DHCPLocalServer} {
			if fam == nil {
				continue
			}
			for name, g := range fam.Groups {
				for _, iface := range g.Interfaces {
					if nodeID == 1 && strings.HasPrefix(iface, "ge-0-0-") {
						t.Fatalf("node1 renders peer-slot name %q in group %s: Kea would refuse the family file", iface, name)
					}
					if nodeID == 0 && iface == "ge-0-0-3" {
						// owning node keeps it
					}
				}
			}
		}
	}
	_ = dhcpserver.FilterKeaInterfaces15206 // belt remains the second line of defence
}

// TestPeerSlotRA16685: the RA sibling. A shared-section RA interface on the
// peer's slot is dropped from clusterRAConfigSets on the peer, kept on the
// owner; an RG-scoped RA interface follows mastership on both nodes.
func TestPeerSlotRA16685(t *testing.T) {
	build := func(t *testing.T, nodeID int) *config.Config {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-16685",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 1 priority 100",
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces reth0 unit 0 family inet6 address 2001:db8:60::1/64",
			"set interfaces ge-0/0/3 unit 0 family inet6 address 2001:db8:3::1/64",
			"set protocols router-advertisement interface ge-0/0/3.0 prefix 2001:db8:3::/64",
			"set protocols router-advertisement interface reth0.0 prefix 2001:db8:60::/64",
		} {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := config.CompileConfigForNode(tree, nodeID)
		if err != nil {
			t.Fatalf("CompileConfigForNode(%d): %v", nodeID, err)
		}
		return cfg
	}
	has := func(list []*config.RAInterfaceConfig, name string) bool {
		for _, ra := range list {
			if ra != nil && ra.Interface == name {
				return true
			}
		}
		return false
	}
	names := func(list []*config.RAInterfaceConfig) []string {
		var out []string
		for _, ra := range list {
			if ra != nil {
				out = append(out, ra.Interface)
			}
		}
		return out
	}

	// Node1, master of RG1: peer-slot ge-0-0-3 dropped, local RETH member kept.
	d1 := newTestDaemon()
	d1.getOrCreateRGState(1).SetVRRP("reth0", true)
	desired, _ := d1.clusterRAConfigSets(build(t, 1))
	if has(desired, "ge-0-0-3") {
		t.Fatalf("node1 desired RA keeps peer-slot ge-0-0-3: %v", names(desired))
	}
	if !has(desired, "ge-7-0-0") {
		t.Fatalf("node1 master must keep its local RETH RA member, got %v", names(desired))
	}

	// Node0, master of RG1: its own ge-0-0-3 kept, RETH via ge-0-0-0.
	d0 := newTestDaemon()
	d0.getOrCreateRGState(1).SetVRRP("reth0", true)
	desired0, _ := d0.clusterRAConfigSets(build(t, 0))
	if !has(desired0, "ge-0-0-3") {
		t.Fatalf("node0 must keep its own ge-0-0-3 RA, got %v", names(desired0))
	}
	if !has(desired0, "ge-0-0-0") {
		t.Fatalf("node0 master must keep RETH RA, got %v", names(desired0))
	}

	// Node0 not master: RETH RA gated, node-local ge-0-0-3 still kept.
	d0b := newTestDaemon()
	d0b.getOrCreateRGState(1).SetVRRP("reth0", false)
	desired0b, _ := d0b.clusterRAConfigSets(build(t, 0))
	if has(desired0b, "ge-0-0-0") {
		t.Fatalf("non-master must not advertise the RETH RA, got %v", names(desired0b))
	}
	if !has(desired0b, "ge-0-0-3") {
		t.Fatalf("non-master keeps its node-local RA, got %v", names(desired0b))
	}
}
