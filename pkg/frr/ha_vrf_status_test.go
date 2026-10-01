package frr

import (
	"context"
	"strings"
	"testing"
)

func TestGetBGPSummaryVRFUsesRoutingInstance(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show bgp vrf tenant summary json": bgpSummaryJSONFixture,
	}}
	manager := &Manager{exec: fake}
	peers, err := manager.GetBGPSummaryVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetBGPSummaryVRF: %v", err)
	}
	if len(peers) != 2 || peers[0].State != "Established" {
		t.Fatalf("VRF peers = %+v, want established peers from tenant", peers)
	}
	if fake.lastVtyshCmd != "show bgp vrf tenant summary json" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

func TestGetOSPFNeighborsVRFUsesRoutingInstance(t *testing.T) {
	const output = "Neighbor ID     Pri State           Address         Interface\n" +
		"1.1.1.1         1   Full/DR         192.0.2.2       reth0\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show ip ospf vrf tenant neighbor": output}}
	manager := &Manager{exec: fake}
	neighbors, err := manager.GetOSPFNeighborsVRF(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("GetOSPFNeighborsVRF: %v", err)
	}
	if len(neighbors) != 1 || neighbors[0].State != "Full/DR" || neighbors[0].Interface != "reth0" {
		t.Fatalf("VRF OSPF neighbors = %+v, want Full adjacency on reth0", neighbors)
	}
	if fake.lastVtyshCmd != "show ip ospf vrf tenant neighbor" {
		t.Fatalf("vtysh command = %q", fake.lastVtyshCmd)
	}
}

func TestGetOSPFv3NeighborsVRFUsesRoutingInstance(t *testing.T) {
	const output = "Neighbor ID Pri DeadTime State/IfState Duration I/F[State] IfName\n" +
		"1.1.1.1 1 00:00:30 Full/DR 00:00:10 reth0[DR] reth0\n"
	fake := &fakeExecutor{vtyshResp: map[string]string{"show ipv6 ospf6 vrf tenant neighbor": output}}
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
	fake := &fakeExecutor{vtyshResp: map[string]string{"show isis vrf tenant neighbor": output}}
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
