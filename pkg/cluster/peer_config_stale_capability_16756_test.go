package cluster

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// #16756: the #9569 gate required a type-40 config-apply ACK from every
// peer. A peer predating the ACK (28556c2b19) can never send one, so the
// bare ISSU verb and untargeted/batch failover refused forever against a
// connected legacy peer, blaming a config-apply failure that never
// happened. The peer now advertises ACK support as
// capFlag2ConfigApplyAck in a second capability byte; a peer that does
// not advertise it falls back to pre-ACK semantics (stale iff the newest
// sent generation was NACKed).
//
// FAIL-ON-REVERT: revert PeerConfigStale to the ACK-only form and the
// legacy cells red; drop capFlag2ConfigApplyAck from
// localCapabilityFlags2 and TestLocalAdvertisesConfigApplyAck16756 reds;
// drop the send-time recording in recordLastSentConfigGen and the
// downgrade cells red.

func legacyPeerSync16756(t *testing.T) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	// A pre-ACK peer: a #6650/#7147-era capabilities frame with no
	// second byte. Learned, but not ACK-capable.
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if !s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: legacy capability frame did not land")
	}
	if s.ConfigApplyAckCapable() {
		t.Fatal("FIXTURE: a frame without the second byte read as ACK-capable")
	}
	return s
}

func ackCapablePeerSync16756(t *testing.T) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	// A current peer: full identity tail plus the second byte carrying
	// capFlag2ConfigApplyAck, exactly as sendCapabilities emits it.
	p := capabilityFrame14161(t, 8, localCapabilityFlags, SessionSyncWireVersion)
	p = append(p, make([]byte, bootIncarnationLen+8+8)...)
	p = append(p, localCapabilityFlags2)
	s.handleMessage(nil, syncMsgPeerCapabilities, p)
	if !s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: capable capability frame did not land")
	}
	if !s.ConfigApplyAckCapable() {
		t.Fatal("FIXTURE: the advertised ACK bit did not decode")
	}
	return s
}

func nackGen16756(s *SessionSync, typ uint8, gen uint64) {
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], gen)
	s.handleMessage(nil, typ, p[:])
}

// Acceptance: a legacy peer with no NACK passes the gate — this is the
// probe from the issue, at the SessionSync level.
func TestLegacyPeerWithoutNackPassesConfigStale16756(t *testing.T) {
	s := legacyPeerSync16756(t)
	s.recordLastSentConfigGen(819321886428623)

	if stale, reason := s.PeerConfigStale(); stale {
		t.Fatalf("a legacy peer that never NACKed is stale: %q — it predates "+
			"the ACK and can never send one, so this refusal is permanent (#16756)", reason)
	}
}

// A legacy peer that DID nack the newest send is stale, and the reason
// names the real cause (pre-ACK peer + its own NACK), not a missing ACK.
func TestLegacyPeerWithNackIsStale16756(t *testing.T) {
	s := legacyPeerSync16756(t)
	s.recordLastSentConfigGen(42)

	nackGen16756(s, syncMsgConfigApplyNack, 42)
	stale, reason := s.PeerConfigStale()
	if !stale {
		t.Fatal("a legacy peer that NACKed the newest generation must be stale")
	}
	if !strings.Contains(reason, "predates config-apply ACK") {
		t.Fatalf("reason %q does not name the pre-ACK cause", reason)
	}

	// A newer send supersedes the NACK: pre-ACK semantics clear.
	s.recordLastSentConfigGen(43)
	if stale, _ := s.PeerConfigStale(); stale {
		t.Fatal("a newer send to a legacy peer must clear the NACK staleness")
	}
}

// A straggler NACK for an older generation does not stale a legacy peer.
func TestLegacyPeerStragglerNackIgnored16756(t *testing.T) {
	s := legacyPeerSync16756(t)
	s.recordLastSentConfigGen(10)
	nackGen16756(s, syncMsgConfigApplyNack, 9) // straggler: not the newest send
	if stale, _ := s.PeerConfigStale(); stale {
		t.Fatal("a straggler NACK for a superseded generation staled a legacy peer")
	}
}

// Acceptance, other half: an ACK-capable peer that stays silent is
// still refused, exactly as #9569 requires.
func TestAckCapablePeerSilentIsStale16756(t *testing.T) {
	s := ackCapablePeerSync16756(t)
	s.recordLastSentConfigGen(7)

	stale, reason := s.PeerConfigStale()
	if !stale {
		t.Fatal("an ACK-capable peer that never ACKed the newest generation must be stale")
	}
	if !strings.Contains(reason, "has not acknowledged applying") {
		t.Fatalf("reason %q does not name the missing ACK", reason)
	}

	// Its NACK is also stale (diagnostic under the strict gate).
	s2 := ackCapablePeerSync16756(t)
	s2.recordLastSentConfigGen(7)
	nackGen16756(s2, syncMsgConfigApplyNack, 7)
	if stale, _ := s2.PeerConfigStale(); !stale {
		t.Fatal("an ACK-capable peer that NACKed must be stale")
	}

	// Only the matching ACK clears it.
	nackGen16756(s, syncMsgConfigApplyAck, 7)
	if stale, _ := s.PeerConfigStale(); stale {
		t.Fatal("the matching ACK did not clear an ACK-capable peer")
	}
}

// Manager level: the verbs the issue names (untargeted, batch,
// ForceSecondary) proceed against a legacy peer with no NACK. Wire the
// real SessionSync predicate through, as the daemon does.
func managerWithSync16756(t *testing.T, s *SessionSync) *Manager {
	t.Helper()
	m := twoRGManager9569(t)
	m.SetPeerConfigStaleFunc(s.PeerConfigStale)
	return m
}

func TestLegacyPeerPassesFailoverVerbs16756(t *testing.T) {
	s := legacyPeerSync16756(t)
	s.recordLastSentConfigGen(99)
	m := managerWithSync16756(t, s)

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("untargeted failover against a legacy peer with no NACK: %v", err)
	}
	drainEvents(m, 1)
	if m.IsLocalPrimary(0) {
		t.Fatal("control: the failover did not demote RG0")
	}

	s2 := legacyPeerSync16756(t)
	s2.recordLastSentConfigGen(99)
	m2 := managerWithSync16756(t, s2)
	if err := m2.ForceSecondary(); err != nil {
		t.Fatalf("ForceSecondary against a legacy peer with no NACK: %v", err)
	}
	drainEvents(m2, 2)
}

func TestLegacyPeerNackRefusesFailoverVerbs16756(t *testing.T) {
	s := legacyPeerSync16756(t)
	s.recordLastSentConfigGen(99)
	nackGen16756(s, syncMsgConfigApplyNack, 99)
	m := managerWithSync16756(t, s)

	if _, err := m.ManualFailoverBatch([]int{0, 1}); !errors.Is(err, ErrPeerConfigStale) {
		t.Fatalf("batch failover against a NACKing legacy peer: %v, want ErrPeerConfigStale", err)
	}
	assertStillPrimary9569(t, m, "a refused batch failover", 0, 1)
}

// Downgrade-on-reconnect: the newest send went to an ACK-capable
// incarnation, but the current incarnation is a legacy peer. The
// promised ACK can never arrive from it; the gate must not refuse
// forever. Modelled as the advance does: flags cleared, then the
// legacy advertisement lands.
func TestDowngradeOnReconnectUnblocksGate16756(t *testing.T) {
	s := ackCapablePeerSync16756(t)
	s.recordLastSentConfigGen(55)
	if stale, _ := s.PeerConfigStale(); !stale {
		t.Fatal("FIXTURE: silent ACK-capable peer must be stale before the downgrade")
	}

	// Incarnation advance clears the capability, then the downgraded
	// peer advertises its (ACK-less) set.
	s.peerCapabilityFlags2.Store(0)
	s.peerCapabilityFlags.Store(0)
	s.peerSnaps.peerSnapshotProtocol.Store(0)
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if s.ConfigApplyAckCapable() {
		t.Fatal("FIXTURE: downgraded peer read as ACK-capable")
	}
	if stale, reason := s.PeerConfigStale(); stale {
		t.Fatalf("downgrade-on-reconnect still refuses: %q — the current peer "+
			"can never send the ACK the previous incarnation promised (#16756)", reason)
	}

	// And its own NACK of the newest send still refuses.
	nackGen16756(s, syncMsgConfigApplyNack, 55)
	if stale, _ := s.PeerConfigStale(); !stale {
		t.Fatal("a downgraded peer that NACKed the newest send must be stale")
	}
}

// The advertisement itself: this build must set the bit, in its own
// byte, distinct from every first-byte bit.
func TestLocalAdvertisesConfigApplyAck16756(t *testing.T) {
	t.Parallel()
	if localCapabilityFlags2&capFlag2ConfigApplyAck == 0 {
		t.Fatal("localCapabilityFlags2 does not set capFlag2ConfigApplyAck, so this " +
			"node tells its peer it cannot ACK config applies and every matched-pair " +
			"handover takes the legacy fallback")
	}
	if capFlag2ConfigApplyAck == 0 {
		t.Fatal("capFlag2ConfigApplyAck is 0: an unset second byte would read as capable")
	}
}

// The wire round-trip: sendCapabilities' emitted frame must decode as
// ACK-capable on the receiving side, and a pre-#16756 frame (identity
// tail, no trailing byte) must not.
func TestConfigApplyAckCapabilityWireRoundTrip16756(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})

	// Pre-#16756 layout: header + identity, no trailing byte. The last
	// identity byte is set nonzero to prove it is not misread as flags2.
	old := capabilityFrame14161(t, 8, localCapabilityFlags, SessionSyncWireVersion)
	old = append(old, make([]byte, bootIncarnationLen+8+8)...)
	old[len(old)-1] = 0xFF
	recv.handleMessage(nil, syncMsgPeerCapabilities, old)
	if recv.ConfigApplyAckCapable() {
		t.Fatal("a pre-#16756 frame read as ACK-capable: its last identity byte " +
			"was misread as the second capability byte")
	}

	// Current layout: same frame plus the trailing second byte.
	cur := append(old, localCapabilityFlags2)
	recv.handleMessage(nil, syncMsgPeerCapabilities, cur)
	if !recv.ConfigApplyAckCapable() {
		t.Fatal("the current frame's ACK bit did not decode on the receiving side")
	}

	// A downgrade re-advertisement without the byte revokes it.
	recv.handleMessage(nil, syncMsgPeerCapabilities, old)
	if recv.ConfigApplyAckCapable() {
		t.Fatal("ACK capability survived a peer re-advertising without the byte")
	}
}
