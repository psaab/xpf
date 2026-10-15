package cluster

import (
	"net"
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
