package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16110 REST: origin from stored flag; address-only NAT preserves port
// (never /0); peer origin carried through sessionEntryFromPB.
func TestSessionProvenance16110(t *testing.T) {
	if got := sessionOriginLabel(0); got != "local" {
		t.Fatalf("local: %q", got)
	}
	if got := sessionOriginLabel(dataplane.SessFlagClusterSynced); got != "cluster-synced" {
		t.Fatalf("synced: %q", got)
	}
	if got := effectiveNATSrcPort(dataplane.SessFlagSNAT, 0, 57566); got != 57566 {
		t.Fatalf("address-only SNAT port: %d", got)
	}
	if got := effectiveNATSrcPort(dataplane.SessFlagSNAT, 40000, 57566); got != 40000 {
		t.Fatalf("PAT port: %d", got)
	}
	if got := effectiveNATDstPort(dataplane.SessFlagDNAT, 0, 5211); got != 5211 {
		t.Fatalf("address-only DNAT port: %d", got)
	}

	key := dataplane.SessionKey{Protocol: 6, SrcPort: ntohs(57566), DstPort: ntohs(5211)}
	copy(key.SrcIP[:], []byte{10, 0, 61, 102})
	copy(key.DstIP[:], []byte{172, 16, 80, 200})
	val := dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagClusterSynced,
		NATSrcIP:   natIPv4(172, 16, 80, 8),
		NATSrcPort: 0, // address-only: stored 0 must render preserved 57566
	}
	se := sessionEntryV4(key, val, 0, sessionView{})
	if se.Origin != "cluster-synced" {
		t.Fatalf("v4 origin: %q", se.Origin)
	}
	if se.NATSrcPort != 57566 || se.NAT != "SNAT 172.16.80.8:57566" {
		t.Fatalf("v4 NAT: port=%d nat=%q", se.NATSrcPort, se.NAT)
	}

	var key6 dataplane.SessionKeyV6
	key6.Protocol = 6
	key6.SrcPort = ntohs(57566)
	key6.DstPort = ntohs(5211)
	var nat6 [16]byte
	copy(nat6[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8})
	val6 := dataplane.SessionValueV6{Flags: dataplane.SessFlagSNAT, NATSrcIP: nat6, NATSrcPort: 0}
	se6 := sessionEntryV6(key6, val6, 0, sessionView{})
	if se6.Origin != "local" || se6.NATSrcPort != 57566 {
		t.Fatalf("v6: origin=%q port=%d nat=%q", se6.Origin, se6.NATSrcPort, se6.NAT)
	}

	peer := sessionEntryFromPB(&pb.SessionEntry{Origin: "cluster-synced"})
	if peer.Origin != "cluster-synced" {
		t.Fatalf("peer origin: %q", peer.Origin)
	}
}
