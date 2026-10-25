package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16856: declined rows carry no client identity; the receiver identity
// filter must keep them, while state=2 and identity-less active rows drop.

func TestDeclined16856_IdentityCarveOut(t *testing.T) {
	declined := dhcpserver.SyncLease{Family: 4, Address: "10.0.61.66", SubnetID: 1, Remaining: 1800, ValidLife: 3600, State: 1}
	if !validLeaseIdentityForFamily(4, declined) {
		t.Fatal("declined v4 without HW/ClientID must pass identity filter")
	}
	declined6 := dhcpserver.SyncLease{Family: 6, Address: "2001:db8::66", SubnetID: 1, Remaining: 1800, State: 1}
	if !validLeaseIdentityForFamily(6, declined6) {
		t.Fatal("declined v6 without DUID must pass identity filter")
	}
	activeNoID := dhcpserver.SyncLease{Family: 4, Address: "10.0.61.10", Remaining: 1800, State: 0}
	if validLeaseIdentityForFamily(4, activeNoID) {
		t.Fatal("active without identity must still drop")
	}
	// Wire round-trip preserves State=1 for identity-less declined.
	payload := encodeDHCPLeasePayload([]dhcpserver.SyncLease{declined})
	out, ok := decodeDHCPLeasePayload(payload)
	if !ok || len(out) != 1 || out[0].State != 1 {
		t.Fatalf("wire declined round-trip: ok=%v out=%+v", ok, out)
	}
	// Receiver path: semantic + identity filters keep declined, drop state=2.
	leases := []dhcpserver.SyncLease{
		declined,
		{Family: 4, Address: "10.0.61.67", HWAddress: "aa:bb:cc:dd:ee:67", Remaining: 1800, State: 2},
		activeNoID,
		{Family: 4, Address: "10.0.61.10", HWAddress: "aa:bb:cc:dd:ee:10", Remaining: 1800, State: 0},
	}
	kept, droppedSem := filterDHCPLeasesBySemantics(4, leases)
	kept, droppedID := filterDHCPLeasesByIdentity(4, kept)
	if droppedSem != 1 {
		t.Fatalf("semantic dropped=%d want 1 (state=2)", droppedSem)
	}
	if droppedID != 1 {
		t.Fatalf("identity dropped=%d want 1 (active no-id)", droppedID)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%+v want declined+active", kept)
	}
	foundDeclined := false
	for _, l := range kept {
		if l.Address == "10.0.61.66" && l.IsDeclined() {
			foundDeclined = true
		}
	}
	if !foundDeclined {
		t.Fatalf("declined lost in filters: %+v", kept)
	}
	// Full handleMessage path keeps declined in held set.
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, encodeDHCPLeasePayload([]dhcpserver.SyncLease{declined}))
	held := ss.PeerDHCPLeases4()
	if len(held) != 1 || !held[0].IsDeclined() {
		t.Fatalf("held declined: %+v", held)
	}
}
