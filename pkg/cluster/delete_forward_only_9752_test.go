package cluster

// #9752: forward-only deletes. A purge-retirement close retires exactly its
// key; the marker travels the cluster delete wire as a trailing byte, and the
// receiver skips companion deletes for flagged keys. A peer that never
// advertised the capability gets flagged deletes WITHHELD (same
// drop-not-journal shape as #9714 F5), since it would derive companions for
// every delete and destroy sessions the purge preserved.

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func forwardOnlyPair9752() (dataplane.SessionKey, dataplane.SessionKey, dataplane.SessionValue) {
	fwd := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	rev := dataplane.SessionKey{SrcIP: [4]byte{172, 16, 80, 200}, DstIP: [4]byte{10, 0, 61, 102},
		Protocol: 6, SrcPort: 5203, DstPort: 47912}
	val := dataplane.SessionValue{ReverseKey: rev}
	return fwd, rev, val
}

func forwardOnlySync9752(t *testing.T) (*SessionSync, *mockSweepDP, dataplane.SessionKey, dataplane.SessionKey) {
	t.Helper()
	fwd, rev, val := forwardOnlyPair9752()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwd: val,
			rev: {IsReverse: 1},
		},
		sessionCounter: 2,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	return ss, dp, fwd, rev
}

func TestForwardOnlyDeleteSkipsCompanions9752(t *testing.T) {
	ss, dp, fwd, rev := forwardOnlySync9752(t)
	ss.deleteClusterSyncedV4(fwd, 15, true)
	if _, ok := dp.v4sessions[fwd]; ok {
		t.Fatal("forward-only delete left the named key behind")
	}
	if _, ok := dp.v4sessions[rev]; !ok {
		t.Fatal("#9752: a forward-only delete removed the companion; the purge " +
			"preserved it deliberately and the marker must protect it")
	}
}

func TestOrdinaryDeleteStillTakesCompanions9752(t *testing.T) {
	ss, dp, fwd, rev := forwardOnlySync9752(t)
	ss.deleteClusterSyncedV4(fwd, 15, false)
	if _, ok := dp.v4sessions[fwd]; ok {
		t.Fatal("ordinary delete left the named key behind")
	}
	if _, ok := dp.v4sessions[rev]; ok {
		t.Fatal("ordinary delete must still retract the stored companion")
	}
}

func TestForwardOnlyDeleteWireRoundTrip9752(t *testing.T) {
	fwd, _, _ := forwardOnlyPair9752()
	msg := encodeDeleteV4(fwd, 15, true)
	if len(msg) != syncHeaderSize+25 {
		t.Fatalf("flagged delete len = %d, want %d", len(msg), syncHeaderSize+25)
	}
	payload := msg[syncHeaderSize:]
	if len(payload) < 25 || payload[24] == 0 {
		t.Fatal("flagged delete must end with a nonzero marker byte")
	}
	plain := encodeDeleteV4(fwd, 15, false)
	if len(plain) != syncHeaderSize+25 {
		t.Fatalf("plain delete len = %d, want %d", len(plain), syncHeaderSize+25)
	}
	if plain[syncHeaderSize+24] != 0 {
		t.Fatal("plain delete must end with a zero marker byte")
	}
}

func TestForwardOnlyDeleteWithheldFromAnIncapablePeer9752(t *testing.T) {
	s := &SessionSync{}
	// A v16/v17-era peer: peer-delete ownership WITHOUT the forward-only
	// bit, so the #9714 gate passes and only this gate can fire.
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if !s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: the capability frame did not land")
	}
	if s.PurgeRetirementForwardOnlyCapable() {
		t.Fatal("FIXTURE: a frame without the bit must not read as forward-only capable")
	}
	fwd, _, _ := forwardOnlyPair9752()
	s.QueueDeleteV4(fwd, true)
	if got := journalLen9714(s); got != 0 {
		t.Errorf("%d forward-only deletes reached an incapable peer; it would derive "+
			"companions for every delete and destroy sessions the purge preserved", got)
	}
	if got := s.stats.DeletesSuppressedPurgeRetirement.Load(); got != 1 {
		t.Errorf("DeletesSuppressedPurgeRetirement = %d, want 1", got)
	}
}

func TestForwardOnlyDeleteReachesACapablePeer9752(t *testing.T) {
	s := &SessionSync{}
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	if !s.PurgeRetirementForwardOnlyCapable() {
		t.Fatal("FIXTURE: the advertised bit did not decode")
	}
	fwd, _, _ := forwardOnlyPair9752()
	s.QueueDeleteV4(fwd, true)
	if got := journalLen9714(s); got != 1 {
		t.Fatalf("a capable peer must receive the delete (journal holds %d, want 1)", got)
	}
}

func TestQueuedDeleteCarriesTheMarkerByte9752(t *testing.T) {
	s := &SessionSync{}
	// Learned + capable, so nothing is suppressed.
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	fwd, _, _ := forwardOnlyPair9752()
	s.QueueDeleteV4(fwd, true)
	if got := journalLen9714(s); got != 1 {
		t.Fatalf("unconnected queue must journal the delete, journal holds %d", got)
	}
	s.deleteJournalMu.Lock()
	msg := s.deleteJournal[0]
	s.deleteJournalMu.Unlock()
	payload := msg[syncHeaderSize:]
	if len(payload) != 25 || payload[24] == 0 {
		t.Fatal("#9752: the queued delete must end with a set marker byte")
	}
}

func forwardOnlyKeyV610068() dataplane.SessionKeyV6 {
	key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 54321, DstPort: 443}
	key.SrcIP = [16]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xbf, 0x01, 0, 0, 0, 0, 0, 0, 0, 1}
	key.DstIP = [16]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xbf, 0x02, 0, 0, 0, 0, 0, 0, 0, 2}
	return key
}

// TestForwardOnlyDeleteWireRoundTripV610068 mirrors
// TestForwardOnlyDeleteWireRoundTrip9752 for the v6 delete codec.
func TestForwardOnlyDeleteWireRoundTripV610068(t *testing.T) {
	key := forwardOnlyKeyV610068()
	msg := encodeDeleteV6(key, 15, true)
	if len(msg) != syncHeaderSize+49 {
		t.Fatalf("flagged v6 delete len = %d, want %d", len(msg), syncHeaderSize+49)
	}
	payload := msg[syncHeaderSize:]
	if payload[0] != 0x20 || payload[15] != 1 || payload[16] != 0x20 || payload[31] != 2 {
		t.Fatalf("flagged v6 delete lost its 128-bit key: src=%x dst=%x", payload[:16], payload[16:32])
	}
	if payload[48] == 0 {
		t.Fatal("flagged v6 delete must end with a nonzero marker byte")
	}
	plain := encodeDeleteV6(key, 15, false)
	if len(plain) != syncHeaderSize+49 {
		t.Fatalf("plain v6 delete len = %d, want %d", len(plain), syncHeaderSize+49)
	}
	if plain[syncHeaderSize+48] != 0 {
		t.Fatal("plain v6 delete must end with a zero marker byte")
	}
}

// TestForwardOnlyDeleteWithheldFromAnIncapablePeerV610068 mirrors
// TestForwardOnlyDeleteWithheldFromAnIncapablePeer9752 for v6 deletes.
func TestForwardOnlyDeleteWithheldFromAnIncapablePeerV610068(t *testing.T) {
	s := &SessionSync{}
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if !s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: the capability frame did not land")
	}
	if s.PurgeRetirementForwardOnlyCapable() {
		t.Fatal("FIXTURE: a frame without the bit must not read as forward-only capable")
	}
	s.QueueDeleteV6(forwardOnlyKeyV610068(), true)
	if got := journalLen9714(s); got != 0 {
		t.Fatalf("%d v6 forward-only deletes reached an incapable peer", got)
	}
	if got := s.stats.DeletesSuppressedPurgeRetirement.Load(); got != 1 {
		t.Errorf("DeletesSuppressedPurgeRetirement = %d, want 1", got)
	}
}

// TestQueuedDeleteCarriesTheMarkerByteV610068 mirrors
// TestQueuedDeleteCarriesTheMarkerByte9752 for v6 deletes.
func TestQueuedDeleteCarriesTheMarkerByteV610068(t *testing.T) {
	s := &SessionSync{}
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	s.QueueDeleteV6(forwardOnlyKeyV610068(), true)
	if got := journalLen9714(s); got != 1 {
		t.Fatalf("unconnected v6 queue must journal one delete, got %d", got)
	}
	s.deleteJournalMu.Lock()
	msg := s.deleteJournal[0]
	s.deleteJournalMu.Unlock()
	payload := msg[syncHeaderSize:]
	if len(payload) != 49 || payload[48] == 0 {
		t.Fatal("#10068: queued v6 delete must end with a set marker byte")
	}
}

// TestPurgeRetirementOnlyPredicate10068 pins the sink-to-cluster seam used by
// both family-specific queue sinks. The marker is one bit of LogFlags: all
// other bits must be ignored, and a clear marker must remain ordinary.
func TestPurgeRetirementOnlyPredicate10068(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint8
		want  bool
	}{
		{name: "clear", flags: 0, want: false},
		{name: "marker", flags: dataplane.LogFlagPurgeRetirementOnly, want: true},
		{name: "marker plus other bits", flags: dataplane.LogFlagPurgeRetirementOnly | 1<<7, want: true},
		{name: "other bits", flags: 1 << 7, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PurgeRetirementOnly(tc.flags); got != tc.want {
				t.Fatalf("PurgeRetirementOnly(%#x) = %t, want %t", tc.flags, got, tc.want)
			}
		})
	}
}
