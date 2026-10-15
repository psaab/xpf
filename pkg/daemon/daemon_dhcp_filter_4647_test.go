package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dhcpClusterTestConfig builds a minimal HA config with a single reth in RG1
// whose member is ge-0/0/1 (→ Linux ge-0-0-1), plus a dhcp-local-server group
// binding to the given interface reference (e.g. "reth1.0" untagged or
// "reth1.100" tagged). vlanID sets the reth unit's 802.1Q tag (0 = untagged).
func dhcpClusterTestConfig(groupIface string, vlanID int) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 1,
					Units:           map[int]*config.InterfaceUnit{0: {VlanID: vlanID}},
				},
				"ge-0/0/1": {
					Name:            "ge-0/0/1",
					RedundantParent: "reth1",
				},
			},
		},
		System: config.SystemConfig{
			DHCPServer: config.DHCPServerConfig{
				DHCPLocalServer: &config.DHCPLocalServerConfig{
					Groups: map[string]*config.DHCPServerGroup{
						"g1": {Interfaces: []string{groupIface}},
					},
				},
			},
		},
	}
}

// TestFilterDHCPConfigForMasterRGs_UntaggedRethUnitMatches is the #4647 BUG-A
// regression: a `dhcp-local-server ... interface reth1.0` group must SURVIVE the
// master-RG filter when reth1's member is MASTER, and the kept interface must be
// the bare Linux member "ge-0-0-1" (the real device Kea binds to). Before the
// fix, resolveDHCPRethInterfaces produced "ge-0-0-1.0" but rethInterfacesForRG
// emitted the bare "ge-0-0-1", the exact string compare failed, the group was
// dropped, and Kea's config was wiped even though the RG was MASTER — so DHCP
// server in a cluster never started with the canonical config.
func TestFilterDHCPConfigForMasterRGs_UntaggedRethUnitMatches(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterTestConfig("reth1.0", 0)
	d.getOrCreateRGState(1).SetVRRP("reth1", true)

	got := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())
	if got == nil || got.DHCPLocalServer == nil {
		t.Fatal("reth1.0 group on a MASTER RG must survive the filter (Kea config generated); got nil (BUG-A RED)")
	}
	g, ok := got.DHCPLocalServer.Groups["g1"]
	if !ok {
		t.Fatal("group g1 dropped by the master-RG filter (BUG-A RED)")
	}
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0-0-1" {
		t.Fatalf("expected kept interface [ge-0-0-1] (bare member Kea binds to), got %v", g.Interfaces)
	}
}

// TestFilterDHCPConfigForMasterRGs_TaggedRethUnitMatches verifies the fix does
// not break a TAGGED unit: `interface reth1.100` must match only the tagged
// member "ge-0-0-1.100" (the ".100" is preserved, not normalized away).
func TestFilterDHCPConfigForMasterRGs_TaggedRethUnitMatches(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterTestConfig("reth1.100", 100)
	d.getOrCreateRGState(1).SetVRRP("reth1.100", true)

	got := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())
	if got == nil || got.DHCPLocalServer == nil {
		t.Fatal("reth1.100 group on a MASTER RG must survive the filter; got nil")
	}
	g, ok := got.DHCPLocalServer.Groups["g1"]
	if !ok {
		t.Fatal("tagged group g1 dropped by the master-RG filter")
	}
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0-0-1.100" {
		t.Fatalf("expected kept interface [ge-0-0-1.100] (tagged member), got %v", g.Interfaces)
	}
}

// TestFilterDHCPConfigForMasterRGs_NonMasterRGFiltered verifies a group whose
// RG is NOT master is still filtered to nil (the normalize must not
// accidentally match a non-master RG's interface).
func TestFilterDHCPConfigForMasterRGs_NonMasterRGFiltered(t *testing.T) {
	d := newTestDaemon()
	cfg := dhcpClusterTestConfig("reth1.0", 0)
	// RG1 is BACKUP (not master): no VRRP instance marked master.
	d.getOrCreateRGState(1).SetVRRP("reth1", false)

	if got := d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState()); got != nil {
		t.Fatalf("reth1.0 group on a BACKUP RG must be filtered to nil (Kea cleared), got %+v", got)
	}
}
