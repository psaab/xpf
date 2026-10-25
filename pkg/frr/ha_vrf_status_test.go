package frr

import (
	"context"
	"strings"
	"testing"
)

func TestGetBGPSummaryVRFUsesRoutingInstance(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp vrf vrf-tenant summary json": bgpSummaryJSONFixture,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummaryVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetBGPSummaryVRF: %v", err)
	}
	if len(peers) != 2 || peers[0].State != "Established" {
		t.Fatalf("VRF peers = %+v, want established peers from tenant", peers)
	}
	if fake.lastVtyshCmd != "show bgp vrf vrf-tenant summary json" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

func TestGetOSPFNeighborsVRFUsesRoutingInstance(t *testing.T) {
	const output = "Neighbor ID     Pri State           Address         Interface\n" +
		"1.1.1.1         1   Full/DR         192.0.2.2       reth0\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show ip ospf vrf vrf-tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetOSPFNeighborsVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetOSPFNeighborsVRF: %v", err)
	}
	if len(neighbors) != 1 || neighbors[0].State != "Full/DR" || neighbors[0].Interface != "reth0" {
		t.Fatalf("VRF OSPF neighbors = %+v, want Full adjacency on reth0", neighbors)
	}
	if fake.lastVtyshCmd != "show ip ospf vrf vrf-tenant neighbor" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

func TestGetOSPFv3NeighborsVRFUsesRoutingInstance(t *testing.T) {
	const output = "Neighbor ID Pri DeadTime State/IfState Duration I/F[State] IfName\n" +
		"1.1.1.1 1 00:00:30 Full/DR 00:00:10 reth0[DR] reth0\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show ipv6 ospf6 vrf vrf-tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetOSPFv3NeighborsVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetOSPFv3NeighborsVRF: %v", err)
	}
	if len(neighbors) != 1 || neighbors[0].State != "Full/DR" || neighbors[0].Interface != "reth0" {
		t.Fatalf("VRF OSPFv3 neighbors = %+v, want Full adjacency on reth0", neighbors)
	}
}

func TestGetISISAdjacencyVRFUsesRoutingInstance(t *testing.T) {
	const output = "System Id Interface L State Holdtime SNPA\n" +
		"0000.0000.0001 reth0 L1 Up 25 00:00:00:00:00:01\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show isis vrf vrf-tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetISISAdjacencyVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetISISAdjacencyVRF: %v", err)
	}
	if len(neighbors) != 1 || neighbors[0].State != "Up" || neighbors[0].Interface != "reth0" {
		t.Fatalf("VRF IS-IS neighbors = %+v, want Up adjacency on reth0", neighbors)
	}
}

func TestGetBGPSummaryVRFRejectsCommandInjection(t *testing.T) {
	fake := &fakeExecutor{}
	manager := &Manager{exec: fake}
	if _, err := manager.GetBGPSummaryVRF(context.Background(), "tenant\nconfigure terminal"); err == nil || !strings.Contains(err.Error(), "routing instance") {
		t.Fatalf("invalid VRF name error = %v, want rejection", err)
	}
	if fake.vtyshCalls != 0 {
		t.Fatalf("invalid VRF name reached vtysh %d times", fake.vtyshCalls)
	}
}

// #16829: GetBGPSummaryVRF("") must query only the default instance
// ("show bgp summary json"), not GetBGPSummary's "vrf all", and must
// not return peers stamped with another instance.
const bgpSummaryMixedInstances16829 = `{
  "default": {
    "ipv4Unicast": {
      "vrfName": "default",
      "peers": {
        "10.0.0.1": {"remoteAs": 65002, "msgRcvd": 0, "msgSent": 0, "peerUptime": "never", "state": "Active", "pfxRcd": 0}
      }
    }
  },
  "vrf-tenant": {
    "ipv4Unicast": {
      "vrfName": "vrf-tenant",
      "peers": {
        "10.0.0.1": {"remoteAs": 65002, "msgRcvd": 10, "msgSent": 11, "peerUptime": "01:02:03", "state": "Established", "pfxRcd": 3}
      }
    }
  }
}`

const bgpSummaryDefaultOnly16829 = `{
  "ipv4Unicast": {
    "vrfName": "default",
    "peers": {
      "10.0.0.1": {"remoteAs": 65002, "msgRcvd": 10, "msgSent": 11, "peerUptime": "01:02:03", "state": "Established", "pfxRcd": 3}
    }
  }
}`

func TestGetBGPSummaryVRFDefaultQueriesDefaultOnly16829(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp summary json": bgpSummaryDefaultOnly16829,
		// If the code regresses to "vrf all", the fake returns the mixed
		// fixture and the instance/command assertions below go RED.
		"show bgp vrf all summary json": bgpSummaryMixedInstances16829,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummaryVRF(context.Background(), "")
	if err != nil {
		t.Fatalf("GetBGPSummaryVRF(\"\"): %v", err)
	}
	if fake.lastVtyshCmd != "show bgp summary json" {
		t.Fatalf("vtysh command = %q, want %q (default only, not vrf all)", fake.lastVtyshCmd, "show bgp summary json")
	}
	if len(peers) != 1 || peers[0].Neighbor != "10.0.0.1" || peers[0].Instance != "" || peers[0].State != "Established" {
		t.Fatalf("default peers = %+v, want single Established default-instance 10.0.0.1", peers)
	}
}

func TestGetBGPSummaryVRFDefaultFiltersOtherInstances16829(t *testing.T) {
	// Defence in depth: even if FRR (or a future caller change) returns
	// a "vrf all"-shaped payload for the default query, tenant peers
	// must be filtered out.
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp summary json": bgpSummaryMixedInstances16829,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummaryVRF(context.Background(), "")
	if err != nil {
		t.Fatalf("GetBGPSummaryVRF(\"\"): %v", err)
	}
	if len(peers) != 1 || peers[0].Instance != "" || peers[0].State != "Active" {
		t.Fatalf("default peers = %+v, want only the default Active 10.0.0.1 (tenant Established filtered)", peers)
	}
}

func TestGetBGPSummaryVRFTenantFiltersDefaultInstance16829(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp vrf vrf-tenant summary json": bgpSummaryMixedInstances16829,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummaryVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetBGPSummaryVRF(tenant): %v", err)
	}
	if len(peers) != 1 || peers[0].Instance != "tenant" || peers[0].State != "Established" {
		t.Fatalf("tenant peers = %+v, want only the tenant Established 10.0.0.1", peers)
	}
}
