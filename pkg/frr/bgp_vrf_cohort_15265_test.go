package frr

import (
	"context"
	"strings"
	"testing"
)

// #15265 B08-03: HA readiness passed the bare routing-instance name
// ("tenant") to the VRF status queries, so FRR was asked for
// `show bgp vrf tenant summary json` — a VRF that does not exist (the
// real one is "vrf-tenant"). FRR answers `{}` and parseBGPSummaryJSON
// returned (nil, nil), so the adjacency arm could never satisfy an
// instance requirement. The VRF argument must be normalized through
// the shared helper to the FRR VRF name, and `{}` for a configured
// (non-empty) VRF must be a status error, not silent zero peers.
func TestGetBGPSummaryVRFUsesFRRVRFName15265(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp vrf vrf-tenant summary json": bgpSummaryJSONFixture,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummaryVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetBGPSummaryVRF(tenant): %v", err)
	}
	if len(peers) != 2 || peers[0].State != "Established" {
		t.Fatalf("VRF peers = %+v, want established peers from vrf-tenant", peers)
	}
	if fake.lastVtyshCmd != "show bgp vrf vrf-tenant summary json" {
		t.Fatalf("vtysh command = %q, want %q", fake.lastVtyshCmd, "show bgp vrf vrf-tenant summary json")
	}
	for _, p := range peers {
		if p.Instance != "tenant" {
			t.Fatalf("peer %+v Instance = %q, want %q (bare routing-instance name)", p, p.Instance, "tenant")
		}
	}
}

func TestGetOSPFNeighborsVRFUsesFRRVRFName15265(t *testing.T) {
	const output = "Neighbor ID     Pri State           Address         Interface\n" +
		"1.1.1.1         1   Full/DR         192.0.2.2       reth0\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show ip ospf vrf vrf-tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetOSPFNeighborsVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetOSPFNeighborsVRF: %v", err)
	}
	if len(neighbors) != 1 || neighbors[0].State != "Full/DR" {
		t.Fatalf("VRF OSPF neighbors = %+v", neighbors)
	}
	if fake.lastVtyshCmd != "show ip ospf vrf vrf-tenant neighbor" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

func TestGetOSPFv3NeighborsVRFUsesFRRVRFName15265(t *testing.T) {
	const output = "Neighbor ID Pri DeadTime State/IfState Duration I/F[State] IfName\n" +
		"1.1.1.1 1 00:00:30 Full/DR 00:00:10 reth0[DR] reth0\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show ipv6 ospf6 vrf vrf-tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetOSPFv3NeighborsVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetOSPFv3NeighborsVRF: %v", err)
	}
	if len(neighbors) != 1 {
		t.Fatalf("VRF OSPFv3 neighbors = %+v", neighbors)
	}
	if fake.lastVtyshCmd != "show ipv6 ospf6 vrf vrf-tenant neighbor" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

func TestGetISISAdjacencyVRFUsesFRRVRFName15265(t *testing.T) {
	const output = "System Id Interface L State Holdtime SNPA\n" +
		"0000.0000.0001 reth0 L1 Up 25 00:00:00:00:00:01\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show isis vrf vrf-tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetISISAdjacencyVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetISISAdjacencyVRF: %v", err)
	}
	if len(neighbors) != 1 || neighbors[0].State != "Up" {
		t.Fatalf("VRF IS-IS neighbors = %+v", neighbors)
	}
	if fake.lastVtyshCmd != "show isis vrf vrf-tenant neighbor" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

// Already-prefixed input must not be doubled (vrf-vrf-tenant).
func TestGetBGPSummaryVRFPrefixedNameNotDoubled15265(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp vrf vrf-tenant summary json": bgpSummaryJSONFixture,
	}}
	manager := &Manager{exec: fake}
	if _, err := manager.GetBGPSummaryVRF(context.Background(), "vrf-tenant"); err != nil {
		t.Fatalf("GetBGPSummaryVRF(vrf-tenant): %v", err)
	}
	if fake.lastVtyshCmd != "show bgp vrf vrf-tenant summary json" {
		t.Fatalf("vtysh command = %q, want single prefix", fake.lastVtyshCmd)
	}
}

// `{}` for a configured VRF instance is a status error (fail closed),
// not zero peers with no error.
func TestGetBGPSummaryVRFEmptyObjectIsError15265(t *testing.T) {
	for _, out := range []string{`{}`, ``, "  \n", `% BGP instance not found`} {
		fake := &fakeExecutor{vtyshResp: map[string]string{
			"show bgp vrf vrf-tenant summary json": out,
		}}
		manager := &Manager{exec: fake}
		peers, err := manager.GetBGPSummaryVRF(context.Background(), "tenant")
		if err == nil {
			t.Fatalf("output %q: err = nil, peers = %+v, want status error for configured VRF", out, peers)
		}
	}
	// Control: global (empty VRF) `{}` stays no-peers/no-error.
	fake := &fakeExecutor{vtyshResp: map[string]string{"show bgp summary json": `{}`}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummary(context.Background())
	if err != nil || len(peers) != 0 {
		t.Fatalf("global {}: peers=%+v err=%v, want 0/nil", peers, err)
	}
	if fake.lastVtyshCmd != "show bgp vrf all summary json" {
		// Global summary now goes through vrf-all; see B08-04 test below.
		// Accept either only if the all-VRF path is not in use — fail here
		// so the command spelling is pinned.
		t.Fatalf("global vtysh command = %q", fake.lastVtyshCmd)
	}
}

// #15265 B08-04: the unscoped summary must query all VRFs and tag each
// peer with its routing instance, so a VRF-only box lists tenant peers.
const bgpSummaryVRFAllFixture15265 = `{
  "ipv4Unicast": {
    "routerId": "10.0.0.1",
    "as": 65001,
    "vrfId": 0,
    "vrfName": "default",
    "peers": {
      "192.0.2.2": {"remoteAs": 65002, "msgRcvd": 10, "msgSent": 11, "peerUptime": "01:02:03", "state": "Established", "pfxRcd": 3}
    }
  }
}`

// FRR `show bgp vrf all summary json` nests per-VRF summaries; the
// parser must also handle that shape. Keyed by VRF name.
const bgpSummaryVRFAllNestedFixture15265 = `{
  "vrf-tenant": {
    "ipv4Unicast": {
      "routerId": "10.1.0.1",
      "as": 65011,
      "vrfId": 2,
      "vrfName": "vrf-tenant",
      "peers": {
        "203.0.113.2": {"remoteAs": 65012, "msgRcvd": 5, "msgSent": 6, "peerUptime": "00:10:00", "state": "Established", "pfxRcd": 7},
        "203.0.113.3": {"remoteAs": 65012, "msgRcvd": 0, "msgSent": 0, "peerUptime": "never", "state": "Active", "pfxRcd": 0}
      }
    }
  }
}`

func TestGetBGPSummaryListsVRFOnlyPeers15265(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp vrf all summary json": bgpSummaryVRFAllNestedFixture15265,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummary(context.Background())
	if err != nil {
		t.Fatalf("GetBGPSummary: %v", err)
	}
	if fake.lastVtyshCmd != "show bgp vrf all summary json" {
		t.Fatalf("vtysh command = %q, want %q", fake.lastVtyshCmd, "show bgp vrf all summary json")
	}
	if len(peers) != 2 {
		t.Fatalf("VRF-only peers = %+v, want 2 tenant peers (incl. down Active peer)", peers)
	}
	byAddr := map[string]BGPPeerSummary{}
	for _, p := range peers {
		byAddr[p.Neighbor] = p
		if p.Instance != "tenant" {
			t.Fatalf("peer %+v Instance = %q, want tenant", p, p.Instance)
		}
	}
	if byAddr["203.0.113.2"].State != "Established" || byAddr["203.0.113.2"].PfxRcd != "7" {
		t.Fatalf("established tenant peer = %+v", byAddr["203.0.113.2"])
	}
	if byAddr["203.0.113.3"].State != "Active" {
		t.Fatalf("down tenant peer must be listed: %+v", byAddr["203.0.113.3"])
	}
}

func TestParseBGPSummaryJSONStampsInstanceFromVRFName15265(t *testing.T) {
	// Flat shape with vrfName carrying the FRR VRF name.
	const flat = `{"ipv4Unicast":{"routerId":"10.1.0.1","as":65011,"vrfName":"vrf-tenant","peers":{"203.0.113.2":{"remoteAs":65012,"msgRcvd":5,"msgSent":6,"peerUptime":"00:10:00","state":"Established","pfxRcd":7}}}}`
	peers, err := parseBGPSummaryJSON(flat)
	if err != nil || len(peers) != 1 {
		t.Fatalf("flat: peers=%+v err=%v", peers, err)
	}
	if peers[0].Instance != "tenant" {
		t.Fatalf("flat Instance = %q, want tenant", peers[0].Instance)
	}
	// Default VRF maps to empty instance.
	peers, err = parseBGPSummaryJSON(bgpSummaryVRFAllFixture15265)
	if err != nil || len(peers) != 1 || peers[0].Instance != "" {
		t.Fatalf("default: peers=%+v err=%v, want 1 peer with empty Instance", peers, err)
	}
	if !strings.Contains(bgpSummaryJSONFixture, `"vrfName": "default"`) {
		t.Fatal("fixture sanity")
	}
}
