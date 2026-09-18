package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

func TestDHCPLeaseSnapshotMetadataRoundTrip10170(t *testing.T) {
	base := encodeDHCPLeasePayload(nil)
	want := dhcpserver.LeaseSyncSnapshot{
		Generation: 9,
		Scopes:     []dhcpserver.LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 9, Served: true, Applied: true}},
		Received:   true,
	}
	stamped := appendFullSetSeq(appendDHCPLeaseSnapshotMeta(base, want), 4, 1)
	withoutSeq, _, _ := stripFullSetSeq(stamped)
	gotBase, got, present, valid := stripDHCPLeaseSnapshotMeta(withoutSeq)
	if !present || !valid || string(gotBase) != string(base) || got.Generation != want.Generation || len(got.Scopes) != 1 || !got.Scopes[0].Applied {
		t.Fatalf("snapshot metadata round-trip mismatch: base=%v snapshot=%+v present=%v valid=%v", gotBase, got, present, valid)
	}
}

func TestDHCPLeaseSnapshotReceivedEmptyIsDistinct10170(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	payload := appendDHCPLeaseSnapshotMeta(encodeDHCPLeasePayload(nil), dhcpserver.LeaseSyncSnapshot{Generation: 3, Received: true})
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(payload, 2, 1))
	got := ss.PeerDHCPLeaseSnapshot4()
	if !got.Received || len(got.Leases) != 0 || got.Generation != 3 {
		t.Fatalf("received-empty snapshot lost receipt marker: %+v", got)
	}
	fresh := NewSessionSync(":0", "10.0.0.2:4785", nil).PeerDHCPLeaseSnapshot4()
	if fresh.Received {
		t.Fatal("fresh session must not claim an unreceived empty snapshot")
	}
}

func TestDHCPLeaseSnapshotMalformedMetadataDoesNotAdvanceSequence10170(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	good := dhcpserver.LeaseSyncSnapshot{
		Generation: 10,
		Scopes:     []dhcpserver.LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 10, Served: true, Applied: true}},
		Received:   true,
	}
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(appendDHCPLeaseSnapshotMeta(encodeDHCPLeasePayload(nil), good), 7, 1))

	bad := append([]byte(nil), appendDHCPLeaseSnapshotMeta(encodeDHCPLeasePayload(nil), good)...)
	metaLen := int(binary.LittleEndian.Uint32(bad[len(bad)-12 : len(bad)-8]))
	metaStart := len(bad) - 12 - metaLen
	bad[metaStart+8+8+4+1] |= 0x80 // reserved authority flag
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(bad, 7, 2))
	held := ss.PeerDHCPLeaseSnapshot4()
	if held.Generation != 10 || !held.Received {
		t.Fatalf("malformed metadata replaced the held snapshot: %+v", held)
	}
	if dropped := ss.stats.MalformedRecordsDropped.Load(); dropped == 0 {
		t.Fatal("malformed metadata was not counted")
	}

	replacement := dhcpserver.LeaseSyncSnapshot{Generation: 11, Received: true}
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(appendDHCPLeaseSnapshotMeta(encodeDHCPLeasePayload(nil), replacement), 7, 2))
	held = ss.PeerDHCPLeaseSnapshot4()
	if held.Generation != 11 || !held.Received {
		t.Fatalf("valid frame reusing malformed sequence was rejected: %+v", held)
	}
}
