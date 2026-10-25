package daemon

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func delta6666(rtFlowID uint64, v6 bool) dpuserspace.SessionDeltaInfo {
	d := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 2, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 12345, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		RTFlowSessionID: rtFlowID,
	}
	if v6 {
		d.AddrFamily = 10
		d.SrcIP, d.DstIP = "2001:db8::1", "2001:db8::2"
	}
	return d
}

// TestMirrorAdoptsCrossNodeSessionID_6666 is the fail-on-revert gate for the
// decision recorded on #6666.
//
// The BPF conntrack mirror has TWO writers of one field. The control plane
// stamped a node-local id on every conversion; the helper stamps the entry's own
// stable id whenever a frame drives a local publish for the same key. The
// displayed id therefore flipped depending on which wrote last — at promotion,
// and at every bulk resync, since the control-plane id was distinct per
// CONVERSION rather than per session.
//
// It also made #5213's stated invariant false: cli_show_flow.go promises the
// displayed id is identical to the id RT_FLOW emits for the same session, and
// for a peer-synced session it was not.
func TestMirrorAdoptsCrossNodeSessionID_6666(t *testing.T) {
	zoneIDs := map[string]uint32{"lan": 1, "wan": 2}
	const peerID = uint64(7)<<48 | 0x1234_5678

	t.Run("v4 adopts", func(t *testing.T) {
		_, val, ok := userspaceSessionFromDeltaV4(delta6666(peerID, false), zoneIDs)
		if !ok {
			t.Fatal("expected the delta to convert")
		}
		if val.SessionID != peerID {
			t.Fatalf("SessionID = %#x, want the adopted %#x", val.SessionID, peerID)
		}
		if val.RTFlowSessionID != peerID {
			t.Fatalf("RTFlowSessionID = %#x, want %#x — adoption must not disturb the wire field",
				val.RTFlowSessionID, peerID)
		}
	})

	t.Run("v6 adopts", func(t *testing.T) {
		_, val, ok := userspaceSessionFromDeltaV6(delta6666(peerID, true), zoneIDs)
		if !ok {
			t.Fatal("expected the delta to convert")
		}
		if val.SessionID != peerID {
			t.Fatalf("v6 SessionID = %#x, want the adopted %#x — the v6 converter is a separate "+
				"site and a fix applied to only one of the two is the symmetric-surface failure",
				val.SessionID, peerID)
		}
	})
}

// TestLegacyPeerStillMintsALocalID_6666 is the rolling-upgrade guard.
//
// A mixed-base peer sends RTFlowSessionID == 0. That path must stay
// byte-identical to pre-#6666 — a fresh node-local id — or a cluster mid-upgrade
// stamps every synced session with 0, collapsing every row onto one id.
func TestLegacyPeerStillMintsALocalID_6666(t *testing.T) {
	zoneIDs := map[string]uint32{"lan": 1, "wan": 2}

	_, a, ok := userspaceSessionFromDeltaV4(delta6666(0, false), zoneIDs)
	if !ok {
		t.Fatal("expected the delta to convert")
	}
	_, b, ok := userspaceSessionFromDeltaV4(delta6666(0, false), zoneIDs)
	if !ok {
		t.Fatal("expected the delta to convert")
	}
	if a.SessionID == 0 || b.SessionID == 0 {
		t.Fatal("a legacy peer's session was stamped with id 0 — every synced row would " +
			"collapse onto one id and the display would name none of them")
	}
	if a.SessionID == b.SessionID {
		t.Fatalf("two conversions minted the same node-local id %#x; #6198 requires one per "+
			"converted session", a.SessionID)
	}
}

// TestAdoptedIDIsNotInTheControlPlaneNamespace_6666 pins that adoption really
// carries the ORIGINATING node's namespace rather than being re-minted.
//
// Without it, an implementation that minted a fresh id and happened to return it
// would satisfy the adoption test only by coincidence of the fixture; this
// asserts the value is NOT from the control plane's reserved 0xFFFF space, which
// is the property that makes the two writers agree.
func TestAdoptedIDIsNotInTheControlPlaneNamespace_6666(t *testing.T) {
	const peerID = uint64(7)<<48 | 0x1234_5678
	got := adoptedOrLocalSyncedSessionID(peerID)
	if got != peerID {
		t.Fatalf("adoptedOrLocalSyncedSessionID(%#x) = %#x", peerID, got)
	}
	if got>>48 == 0xFFFF {
		t.Fatalf("the adopted id %#x sits in the control plane's reserved 0xFFFF namespace; it "+
			"must carry the originating node's namespace", got)
	}
	// And the fallback DOES use that namespace, which is what keeps the two
	// mint spaces disjoint for a legacy peer.
	if minted := adoptedOrLocalSyncedSessionID(0); minted>>48 != 0xFFFF {
		t.Fatalf("the legacy fallback minted %#x outside the control-plane namespace", minted)
	}
}
