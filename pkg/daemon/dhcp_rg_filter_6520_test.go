package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6520: the cluster DHCP master-RG filter.
//
// (a) Mastership scoping must apply only to RG-scoped members. A node-local
// interface — the fxp0 management lifeline, or any plain interface with no
// redundant peer — has no redundancy group to master, so removing it from
// every group on both nodes silently kills the DHCP service configured on it.
//
// (b) When the filter DOES narrow a group, it must record that
// (DHCPServerGroup.MembersFiltered) so the Kea renderer suppresses its
// per-subnet interface selector. This file asserts the PRODUCER side of that
// agreement; pkg/dhcpserver asserts the consumer honours the flag. Each side
// names itself so a failure says which one broke.

// dhcpClusterMixedConfig builds a two-RG HA config: reth1 (RG1, member
// ge-0/0/1) and reth2 (RG2, member ge-0/0/2), plus one dhcp-local-server group
// over the supplied interface refs.
func dhcpClusterMixedConfig(groupIfaces ...string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 1,
					Units:           map[int]*config.InterfaceUnit{0: {}},
				},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
				"reth2": {
					Name:            "reth2",
					RedundancyGroup: 2,
					Units:           map[int]*config.InterfaceUnit{0: {}},
				},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth2"},
				"fxp0":     {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {}}},
			},
		},
		System: config.SystemConfig{
			DHCPServer: config.DHCPServerConfig{
				DHCPLocalServer: &config.DHCPLocalServerConfig{
					Groups: map[string]*config.DHCPServerGroup{
						"g1": {Name: "g1", Interfaces: append([]string(nil), groupIfaces...)},
					},
				},
			},
		},
	}
}

// TestFilterDHCPConfigForMasterRGs_NodeLocalMemberKeptOnMaster_6520 is the
// #6520 (a) regression: a group mixing the fxp0 lifeline with a mastered RETH
// member must keep BOTH members. Before the fix the keep-set was built only
// from RETH members of master RGs, so fxp0 was dropped even here.
func TestFilterDHCPConfigForMasterRGs_NodeLocalMemberKeptOnMaster_6520(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterMixedConfig("fxp0.0", "reth1.0")
	d.getOrCreateRGState(1).SetVRRP("reth1", true)

	got := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())
	if got == nil || got.DHCPLocalServer == nil {
		t.Fatal("group with a mastered RETH member must survive the filter; got nil")
	}
	g := got.DHCPLocalServer.Groups["g1"]
	if g == nil {
		t.Fatal("group g1 dropped by the master-RG filter")
	}
	if len(g.Interfaces) != 2 || !contains6520(g.Interfaces, "fxp0") || !contains6520(g.Interfaces, "ge-0-0-1") {
		t.Fatalf("#6520(a) RED: node-local fxp0 must be kept alongside the mastered RETH member; kept %v, want both [fxp0 ge-0-0-1]", g.Interfaces)
	}
}

// TestFilterDHCPConfigForMasterRGs_NodeLocalOnlyGroupSurvivesOnBackup_6520 is
// the sharper half of #6520 (a): a group made only of node-local members must
// survive on a node that masters NOTHING. Before the fix the whole group — and
// with it the DHCP service on the management segment — disappeared on every
// node that was not the RG master, i.e. permanently on the backup.
func TestFilterDHCPConfigForMasterRGs_NodeLocalOnlyGroupSurvivesOnBackup_6520(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterMixedConfig("fxp0.0")
	d.getOrCreateRGState(1).SetVRRP("reth1", false)
	d.getOrCreateRGState(2).SetVRRP("reth2", false)

	got := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())
	if got == nil || got.DHCPLocalServer == nil {
		t.Fatal("#6520(a) RED: a node-local-only DHCP group must survive on a node that masters no RG; the whole config was filtered to nil")
	}
	g := got.DHCPLocalServer.Groups["g1"]
	if g == nil || len(g.Interfaces) != 1 || g.Interfaces[0] != "fxp0" {
		t.Fatalf("#6520(a) RED: expected the node-local member kept as [fxp0], got %+v", g)
	}
}

// TestFilterDHCPConfigForMasterRGs_RGScopedMemberStillGated_6520 pins the
// property #6520 must NOT weaken: an RG-scoped member is still removed while
// this node does not master its RG. Without this, "keep what is not mastered"
// would degenerate into keeping everything and both nodes would serve DHCP on
// the same redundant segment.
func TestFilterDHCPConfigForMasterRGs_RGScopedMemberStillGated_6520(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterMixedConfig("reth1.0", "reth2.0")
	d.getOrCreateRGState(1).SetVRRP("reth1", true)
	d.getOrCreateRGState(2).SetVRRP("reth2", false)

	got := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())
	if got == nil || got.DHCPLocalServer == nil {
		t.Fatal("group with a mastered RETH member must survive the filter; got nil")
	}
	g := got.DHCPLocalServer.Groups["g1"]
	if g == nil || len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0-0-1" {
		t.Fatalf("an RG-scoped member of a BACKUP RG must still be removed; kept %+v, want only [ge-0-0-1]", g)
	}
}

// TestFilterDHCPConfigForMasterRGs_MarksShrunkGroup_6520 is the PRODUCER half
// of the #6520 (b) agreement: the active/active mixed-RG group above really
// does shrink to a singleton, and the filter must record that so the renderer
// stops emitting a per-subnet selector. Asserting the flag here (rather than
// only the rendered Kea file) localises a break to the filter.
func TestFilterDHCPConfigForMasterRGs_MarksShrunkGroup_6520(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterMixedConfig("reth1.0", "reth2.0")
	d.getOrCreateRGState(1).SetVRRP("reth1", true)
	d.getOrCreateRGState(2).SetVRRP("reth2", false)

	g := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState()).DHCPLocalServer.Groups["g1"]
	if !g.MembersFiltered {
		t.Fatal("#6520(b) RED (producer side): the filter narrowed g1 from 2 members to 1 but did not set MembersFiltered, so dhcpserver.subnetInterface will cross-bind the removed member's pool onto the survivor")
	}
}

// TestFilterDHCPConfigForMasterRGs_UnshrunkGroupNotMarked_6520 is its control:
// a group the filter did not narrow must NOT be marked, or every
// operator-authored singleton group would lose the #1778 explicit binding.
func TestFilterDHCPConfigForMasterRGs_UnshrunkGroupNotMarked_6520(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterMixedConfig("reth1.0")
	d.getOrCreateRGState(1).SetVRRP("reth1", true)

	g := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState()).DHCPLocalServer.Groups["g1"]
	if g.MembersFiltered {
		t.Fatal("#6520(b) RED (producer side): an unnarrowed group must not be marked MembersFiltered — marking it would strip the #1778 per-subnet selector from every authored singleton group")
	}
}

func contains6520(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
