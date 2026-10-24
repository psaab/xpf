package grpcapi

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16110 gRPC: origin from stored flag; address-only NAT preserves port
// so the peer view the CLI joins against never carries a synthesized 0.
func TestSessionProvenance16110(t *testing.T) {
	if got := sessionOriginLabel(dataplane.SessFlagClusterSynced); got != "cluster-synced" {
		t.Fatalf("synced: %q", got)
	}
	if got := sessionOriginLabel(0); got != "local" {
		t.Fatalf("local: %q", got)
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(57566),
		DstPort:  hostToNetwork16(5211),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagClusterSynced,
		NATSrcIP:   binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}),
		NATSrcPort: 0,
	}
	se := sessionEntryV4(key, val, 0, map[uint16]string{}, map[uint32]string{}, map[uint16][]string{}, map[sessionEgressKey]string{}, false)
	if se.Origin != "cluster-synced" {
		t.Fatalf("v4 origin: %q", se.Origin)
	}
	if se.NatSrcPort != 57566 || se.Nat != "SNAT 172.16.80.8:57566" {
		t.Fatalf("v4 NAT: port=%d nat=%q", se.NatSrcPort, se.Nat)
	}
}
