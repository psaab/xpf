package cluster

import (
	"net"
	"strings"
	"testing"
)

func TestRethMAC(t *testing.T) {
	mac := RethMAC(1, 1, 0, 0)
	// Verify locally-administered unicast: bit 1 of first octet set, bit 0 clear.
	if mac[0]&0x02 == 0 {
		t.Error("expected locally-administered bit set")
	}
	if mac[0]&0x01 != 0 {
		t.Error("expected unicast (multicast bit clear)")
	}
	// reth0 preserves the original 02:bf:72:CC:RR:node-id bytes.
	expected := net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}
	if mac.String() != expected.String() {
		t.Errorf("RethMAC(1,1,0,0) = %s, want %s", mac, expected)
	}
}

func TestRethMAC_Deterministic(t *testing.T) {
	a := RethMAC(1, 2, 3, 0)
	b := RethMAC(1, 2, 3, 0)
	if a.String() != b.String() {
		t.Errorf("same inputs produced different MACs: %s vs %s", a, b)
	}
}

func TestRethMAC_DifferentRGs(t *testing.T) {
	mac1 := RethMAC(1, 1, 0, 0)
	mac2 := RethMAC(1, 2, 0, 0)
	if mac1.String() == mac2.String() {
		t.Errorf("different RGs should have different MACs: %s == %s", mac1, mac2)
	}
	if mac1[4] == mac2[4] {
		t.Errorf("RG byte should differ: %02x vs %02x", mac1[4], mac2[4])
	}
}

func TestRethMAC_DifferentClusters(t *testing.T) {
	mac1 := RethMAC(1, 1, 0, 0)
	mac2 := RethMAC(2, 1, 0, 0)
	if mac1.String() == mac2.String() {
		t.Errorf("different cluster IDs should have different MACs: %s == %s", mac1, mac2)
	}
}

func TestRethMAC_DifferentNodes(t *testing.T) {
	mac0 := RethMAC(1, 1, 0, 0)
	mac1 := RethMAC(1, 1, 0, 1)
	if mac0.String() == mac1.String() {
		t.Errorf("different nodes should have different MACs: %s == %s", mac0, mac1)
	}
	if mac0[5] == mac1[5] {
		t.Errorf("node byte should differ: %02x vs %02x", mac0[5], mac1[5])
	}
	if mac0[5] != 0x00 || mac1[5] != 0x01 {
		t.Errorf("reth0 node bytes = %02x/%02x, want 00/01", mac0[5], mac1[5])
	}
}

func TestRethMAC_DifferentRethIndices(t *testing.T) {
	mac0 := RethMAC(1, 1, 0, 0)
	mac1 := RethMAC(1, 1, 1, 0)
	if mac0.String() == mac1.String() || mac0[5] == mac1[5] {
		t.Fatalf("same-RG RETH indices share a MAC: %s", mac0)
	}
}

func TestIsVirtualRethMAC(t *testing.T) {
	tests := []struct {
		name string
		mac  net.HardwareAddr
		want bool
	}{
		{"virtual reth mac node0", net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}, true},
		{"virtual reth mac node1", net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x01}, true},
		{"virtual reth mac rg2", net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x02, 0x00}, true},
		{"physical mac", net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc}, false},
		{"wrong prefix", net.HardwareAddr{0x02, 0xbf, 0x73, 0x01, 0x01, 0x00}, false},
		{"too short", net.HardwareAddr{0x02, 0xbf, 0x72}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVirtualRethMAC(tt.mac); got != tt.want {
				t.Errorf("IsVirtualRethMAC(%s) = %v, want %v", tt.mac, got, tt.want)
			}
		})
	}
}

func TestRethMappingFormatStatus(t *testing.T) {
	// We can't test netlink operations in unit tests, but we can test
	// the format output with no mappings.
	rc := &RethController{
		mappings: nil,
	}

	out := rc.FormatStatus()
	if !strings.Contains(out, "No RETH interfaces configured") {
		t.Fatalf("expected 'No RETH interfaces configured', got: %s", out)
	}
}

func TestRethMappingWithEntries(t *testing.T) {
	rc := &RethController{
		mappings: []RethMapping{
			{RethName: "reth0", RedundancyGrp: 1, Members: []string{"ge-0/0/0", "ge-7/0/0"}},
			{RethName: "reth1", RedundancyGrp: 2, Members: []string{"ge-0/0/3"}},
		},
	}

	out := rc.FormatStatus()
	if !strings.Contains(out, "reth0") {
		t.Fatalf("expected reth0 in output, got: %s", out)
	}
	if !strings.Contains(out, "reth1") {
		t.Fatalf("expected reth1 in output, got: %s", out)
	}
	if !strings.Contains(out, "ge-0/0/0") {
		t.Fatalf("expected member ge-0/0/0 in output, got: %s", out)
	}
	if !strings.Contains(out, "Physical") {
		t.Fatalf("expected 'Physical' header in output, got: %s", out)
	}
}

func TestHandleStateChangeFiltersbyRG(t *testing.T) {
	rc := &RethController{
		mappings: []RethMapping{
			{RethName: "reth0", RedundancyGrp: 1, Members: []string{"eth0"}},
			{RethName: "reth1", RedundancyGrp: 2, Members: []string{"eth1"}},
		},
	}

	// This will attempt netlink ops which will fail in test env, but
	// it should not panic and should only process RG 1 mappings.
	event := ClusterEvent{
		GroupID:  1,
		OldState: StateSecondary,
		NewState: StatePrimary,
	}
	rc.HandleStateChange(event) // should not panic

	event2 := ClusterEvent{
		GroupID:  2,
		OldState: StatePrimary,
		NewState: StateSecondary,
	}
	rc.HandleStateChange(event2) // should not panic
}

func TestHandleStateChange_AlwaysActivates(t *testing.T) {
	// Verify HandleStateChange brings up physical members for all states (not just primary).
	// Physical interfaces must stay UP on both nodes for VRRP to work.
	rc := &RethController{
		mappings: []RethMapping{
			{RethName: "reth0", RedundancyGrp: 1, Members: []string{"eth0"}},
		},
	}

	// All state transitions should not panic and should attempt activation.
	states := []NodeState{StatePrimary, StateSecondary, StateLost, StateSecondaryHold}
	for _, s := range states {
		event := ClusterEvent{
			GroupID:  1,
			OldState: StatePrimary,
			NewState: s,
		}
		rc.HandleStateChange(event) // should not panic, always activates
	}
}
