package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vipstamp"
	"github.com/vishvananda/netlink"
)

// #18212: AF_XDP is attached to a fabric's physical parent, not its fab*
// overlay. This exercises the real snapshot-to-domain builder with every
// kernel/sysfs observation on the build path fixture-controlled (link,
// address, XFRM, link-state, neighbour, route-rule, and queue-count inputs),
// so the result cannot depend on host state.
func TestFabricParentGetsOverlayIngressDomain18212(t *testing.T) {
	prevBuild, prevXfrm := buildLinkSnapshot, liveXfrmNetdevs
	prevLookup, prevNeighbours := linkByNameFn, fabricNeighListFn
	prevRules, prevDSCPSelectors := ruleListFn, ruleDSCPSelectorsFn
	prevNeighLink, prevNeighList := neighborLinkByNameFn, neighborListFn
	prevRXQueues := userspaceRXQueueCountFn
	prevVIPDump := directVIPStampDumpFn
	t.Cleanup(func() {
		buildLinkSnapshot, liveXfrmNetdevs = prevBuild, prevXfrm
		linkByNameFn, fabricNeighListFn = prevLookup, prevNeighbours
		ruleListFn, ruleDSCPSelectorsFn = prevRules, prevDSCPSelectors
		neighborLinkByNameFn, neighborListFn = prevNeighLink, prevNeighList
		userspaceRXQueueCountFn = prevRXQueues
		directVIPStampDumpFn = prevVIPDump
	})
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "fab0":
			return 31, 9000, "02:00:00:00:00:31", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.99.1.1/30"},
			}
		case "ge-0-0-0":
			return 40, 9000, "02:00:00:00:00:40", nil
		case "ge-0-0-1":
			return 42, 1500, "02:00:00:00:00:42", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.60.2/24"},
			}
		}
		return 0, 0, "", nil
	}
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }
	linkByNameFn = func(string) (netlink.Link, error) { return nil, nil }
	fabricNeighListFn = func(int, int) ([]netlink.Neigh, error) { return nil, nil }
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	ruleDSCPSelectorsFn = func(int) ([]routing.RuleDSCPSelector, error) { return nil, nil }
	neighborLinkByNameFn = func(string) (netlink.Link, error) { return nil, nil }
	neighborListFn = func(int, int) ([]netlink.Neigh, error) { return nil, nil }
	userspaceRXQueueCountFn = func(string) int { return 0 }
	directVIPStampDumpFn = func() ([]vipstamp.Row, error) { return nil, nil }

	cfg := routingDomainCfg7160(t,
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"set chassis cluster node 0",
		"set chassis cluster fabric-interface fab0",
		"set chassis cluster fabric-peer-address 10.99.1.2",
		"set interfaces fab0 unit 0 family inet address 10.99.1.1/30",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.60.2/24",
		"set security zones security-zone control interfaces fab0",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
	)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Fabrics) != 1 || snap.Fabrics[0].ParentIfindex != 40 {
		t.Fatalf("fabric snapshot = %+v, want one fabric on parent ifindex 40", snap.Fabrics)
	}
	fab := snapshotByName9132(t, snap.Interfaces, "fab0.0")
	localEntries := buildLocalAddressEntriesWithExclusions(snap, nil, nil)
	var localDomain uint32
	foundLocal := false
	for _, entry := range localEntries {
		if entry.v4 && entry.v4Key == 0x0A630101 { // 10.99.1.1
			localDomain = entry.domain
			foundLocal = true
			break
		}
	}
	if !foundLocal {
		t.Fatalf("fixture: fabric local address 10.99.1.1 absent from local entries: %+v", localEntries)
	}
	if localDomain != fab.RoutingDomain {
		t.Fatalf("fixture: local address domain %d disagrees with fab row domain %d", localDomain, fab.RoutingDomain)
	}

	domains := buildUserspaceIngressDomainEntries(snap)
	fabricKey := userspaceIngressDomainKey{
		Ifindex: uint32(snap.Fabrics[0].ParentIfindex),
		VLANID:  userspaceIngressDomainUntaggedVLANID,
	}
	got, ok := domains[fabricKey]
	if !ok {
		t.Fatalf("fabric parent ifindex %d has no untagged ingress domain: XDP reads unresolved-domain for local peer ICMP and cannot match address 10.99.1.1; domain rows=%v", fabricKey.Ifindex, domains)
	}
	if got != localDomain {
		t.Errorf("fabric parent ingress domain = %d, want overlay/local-address domain %d", got, localDomain)
	}

	// Control: ordinary data-interface ingress remains mapped from its own row.
	lan := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1.0")
	lanKey := userspaceIngressDomainKey{Ifindex: uint32(lan.Ifindex), VLANID: userspaceIngressDomainUntaggedVLANID}
	if got, ok := domains[lanKey]; !ok || got != lan.RoutingDomain {
		t.Errorf("LAN ingress domain = (%d, %v), want %d from its own interface row", got, ok, lan.RoutingDomain)
	}
}
