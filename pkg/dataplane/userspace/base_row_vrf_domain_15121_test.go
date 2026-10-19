package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15121 (A86-03, #14331 residual): a RETH member's base row shares the
// ifindex and addresses of an untagged rethN.0 placed in a VRF, but the
// #14331 fix only consulted the member interface's OWN unit 0. The member
// ge-0/0/1 has no units, so its base row kept RoutingDomain 0 while
// snapshotLinuxName maps both reth0 (base/unit path via ResolveReth) and
// reth0.0 onto ge-0-0-1. That republishes the VRF addresses as Domain 0
// locals and makes localAddressRoutingDomain see {0, VRF} for one ifindex,
// so the ingress-domain entry is deleted.
func TestBuildSnapshotRethMemberBaseRowInheritsRethUnitDomain15121(t *testing.T) {
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
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.31.0.1/24",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8:31::1/64",
		"set routing-instances vrf1 instance-type virtual-router",
		"set routing-instances vrf1 interface reth0.0",
		"set security zones security-zone trust interfaces reth0.0",
	)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	wantDomain := uint32(config.StableRoutingInstanceTableID("vrf1"))
	if wantDomain == 0 {
		t.Fatalf("fixture: vrf1 domain hashed to 0, cannot distinguish from default")
	}

	// Fixture sanity: the RETH unit, the RETH base, and the member base all
	// collapse onto the same netdev/ifindex.
	for _, name := range []string{"reth0", "reth0.0", "ge-0/0/1"} {
		row := snapshotByName9132(t, snap.Interfaces, name)
		if row.Ifindex != 42 {
			t.Fatalf("fixture: %s ifindex=%d, want 42 (RETH collapse onto ge-0-0-1)", name, row.Ifindex)
		}
		if row.LinuxName != "ge-0-0-1" {
			t.Fatalf("fixture: %s LinuxName=%q, want ge-0-0-1", name, row.LinuxName)
		}
	}
	if got := snapshotByName9132(t, snap.Interfaces, "reth0.0").RoutingDomain; got != wantDomain {
		t.Fatalf("reth0.0 RoutingDomain = %d, want %d (vrf1)", got, wantDomain)
	}

	// The member base row must not republish the shared netdev in domain 0.
	member := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1")
	if member.RoutingDomain != wantDomain {
		t.Fatalf("member base RoutingDomain = %d, want %d (vrf1): member base row collapses onto reth0.0's netdev and must inherit its domain", member.RoutingDomain, wantDomain)
	}
	if member.RoutingInstance != "vrf1" {
		t.Fatalf("member base RoutingInstance = %q, want vrf1", member.RoutingInstance)
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
		if e.domain != wantDomain {
			t.Fatalf("local address entry domain = %d, want %d (vrf1): %+v (all: %+v)", e.domain, wantDomain, e, entries)
		}
	}

	// The ingress-domain map must keep a single VRF entry for the shared
	// ifindex, not poison/delete it as ambiguous.
	ingress := buildUserspaceIngressDomainEntries(snap)
	key := userspaceIngressDomainKey{Ifindex: 42, VLANID: userspaceIngressDomainUntaggedVLANID}
	if got, present := ingress[key]; !present || got != wantDomain {
		t.Fatalf("ingress domain entry %v = (%d, %v), want (%d, true) (all: %v)", key, got, present, wantDomain, ingress)
	}
}

// Control: a RETH member whose RETH unit is in the default instance keeps
// domain 0 — the cross-interface inheritance must not invent a VRF claim.
func TestBuildSnapshotRethMemberBaseRowDefaultDomainControl15121(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-1" {
			return 42, 1500, "02:00:00:00:00:42", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.31.0.1/24"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.31.0.1/24",
	)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	member := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1")
	if member.RoutingDomain != 0 || member.RoutingInstance != "" {
		t.Fatalf("member base = (domain %d, instance %q), want (0, \"\") for default-instance RETH", member.RoutingDomain, member.RoutingInstance)
	}
	if domain, ok := localAddressRoutingDomain(snap, 42); !ok || domain != 0 {
		t.Fatalf("localAddressRoutingDomain(snap, 42) = (%d, %v), want (0, true)", domain, ok)
	}
}
