package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14331: an untagged unit .0 collapses onto its base netdev (same linux
// name, same ifindex, same live kernel addresses). The base row was built
// from the bare interface key, which is absent from ifaceRoutingInstance
// when the VRF assignment is per-unit (`routing-instances vrf1 interface
// ge-0/0/1.0`), so the base row carried RoutingDomain 0 while sharing the
// VRF unit's addresses. That leaked every VRF local address into Domain:0
// in buildLocalAddressEntriesWithExclusions and made
// localAddressRoutingDomain see domains {0, VRF} for one ifindex and
// reject the interface (fail-closed delete in syncIngressIfaceMapLocked).
func TestBuildSnapshotUntaggedVRFUnitDoesNotConflictWithBaseRowDomain(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-1" {
			return 42, 1500, "02:00:00:00:00:42", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.31.0.1/24"},
				{Family: "inet6", Address: "2001:db8:31::1/64"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.31.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:31::1/64",
		"set routing-instances vrf1 instance-type virtual-router",
		"set routing-instances vrf1 interface ge-0/0/1.0",
	)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	wantDomain := uint32(config.StableRoutingInstanceTableID("vrf1"))
	if wantDomain == 0 {
		t.Fatalf("fixture: vrf1 domain hashed to 0, cannot distinguish from default")
	}

	// Both rows sharing ifindex 42 must agree on the VRF domain.
	base := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1")
	unit := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1.0")
	if base.Ifindex != 42 || unit.Ifindex != 42 {
		t.Fatalf("fixture: base ifindex=%d unit ifindex=%d, want both 42 (untagged collapse)", base.Ifindex, unit.Ifindex)
	}
	if unit.RoutingDomain != wantDomain {
		t.Fatalf("unit RoutingDomain = %d, want %d (vrf1)", unit.RoutingDomain, wantDomain)
	}
	if base.RoutingDomain != wantDomain {
		t.Fatalf("base RoutingDomain = %d, want %d (vrf1): base row collapses onto the untagged .0 unit and must inherit its domain", base.RoutingDomain, wantDomain)
	}

	domain, ok := localAddressRoutingDomain(snap, 42)
	if !ok || domain != wantDomain {
		t.Fatalf("localAddressRoutingDomain(snap, 42) = (%d, %v), want (%d, true)", domain, ok, wantDomain)
	}

	entries := buildLocalAddressEntriesWithExclusions(snap, nil, nil)
	if len(entries) == 0 {
		t.Fatalf("fixture: no local address entries produced")
	}
	for _, e := range entries {
		if e.domain == 0 {
			t.Fatalf("local address entry leaked into Domain:0: %+v (all entries: %+v)", e, entries)
		}
		if e.domain != wantDomain {
			t.Fatalf("local address entry domain = %d, want %d (vrf1): %+v", e.domain, wantDomain, e)
		}
	}
}
