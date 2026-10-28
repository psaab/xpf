package cluster

import "testing"

// #17816: the send generation and the ACK capability promised by that send
// are one debt state. Publishing them as separate atomics lets PeerConfigStale
// observe the new generation with the previous (legacy) capability and pass
// fail-open. Keeping the pair separate from peer-incarnation fields also
// preserves an ACK-capable peer's outstanding debt across a disconnect, while
// an explicitly learned downgrade still uses the legacy NACK-only semantics.
//
// FAIL-ON-REVERT: split the debt publication or clear either side on
// retirePeerIncarnationLocked. TestConfigStaleDebtSnapshot17816 then observes
// the generation/capability tear and/or passes an ACK-capable peer's
// unacknowledged debt after disconnect/reconnect. The legacy control must
// continue to pass without requiring an ACK.
func TestConfigStaleDebtSnapshot17816(t *testing.T) {
	t.Run("generation_and_capability_publish_together", func(t *testing.T) {
		s := ackCapablePeerSync16756(t)
		reached := make(chan struct{})
		release := make(chan struct{})
		done := make(chan struct{})
		released := false
		defer func() {
			if !released {
				close(release)
			}
		}()
		s.testAfterLastSentConfigGenPublish = func() {
			s.testAfterLastSentConfigGenPublish = nil
			close(reached)
			<-release
		}
		go func() {
			s.recordLastSentConfigGen(7)
			close(done)
		}()
		<-reached
		stale, reason := s.PeerConfigStale()
		close(release)
		released = true
		<-done
		if !stale {
			t.Fatalf("the new generation was observed without its ACK-capable send state: stale=%v reason=%q", stale, reason)
		}
	})

	t.Run("unacknowledged_debt_survives_disconnect_and_reconnect", func(t *testing.T) {
		s := ackCapablePeerSync16756(t)
		s.recordLastSentConfigGen(7)
		if stale, _ := s.PeerConfigStale(); !stale {
			t.Fatal("FIXTURE: silent ACK-capable peer must be stale before disconnect")
		}

		// Model full disconnect: the peer-incarnation capability state is
		// retired, but the sent config debt remains owed by its successor.
		s.mu.Lock()
		s.peerSnaps.peerSnapshotProtocolWriteMu.Lock()
		s.retirePeerIncarnationLocked(nil)
		s.peerSnaps.peerSnapshotProtocolWriteMu.Unlock()
		s.mu.Unlock()
		if stale, reason := s.PeerConfigStale(); !stale {
			t.Fatalf("disconnect made an ACK-capable outstanding debt pass the gate: %q", reason)
		}

		// The successor advertises ACK capability; until it ACKs the debt,
		// handover remains blocked even though no new config send intervened.
		p := capabilityFrame14161(t, 8, localCapabilityFlags, SessionSyncWireVersion)
		p = append(p, make([]byte, bootIncarnationLen+8+8)...)
		p = append(p, localCapabilityFlags2)
		s.handleMessage(nil, syncMsgPeerCapabilities, p)
		if !s.ConfigApplyAckCapable() {
			t.Fatal("FIXTURE: successor incarnation did not re-learn ACK capability")
		}
		if stale, reason := s.PeerConfigStale(); !stale {
			t.Fatalf("modern reconnect passed an unacknowledged generation 7 debt: %q", reason)
		}
		nackGen16756(s, syncMsgConfigApplyAck, 7)
		if stale, reason := s.PeerConfigStale(); stale {
			t.Fatalf("matching ACK did not clear generation 7 debt: %q", reason)
		}
	})

	t.Run("unknown_capability_is_not_legacy", func(t *testing.T) {
		s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
		s.recordLastSentConfigGen(10)
		if stale, reason := s.PeerConfigStale(); !stale {
			t.Fatalf("unknown capability was treated as proof of a legacy peer: %q", reason)
		}

		// An explicit pre-ACK advertisement, unlike no advertisement,
		// permits the legacy NACK-only fallback.
		s.handleMessage(nil, syncMsgPeerCapabilities,
			capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
		if stale, reason := s.PeerConfigStale(); stale {
			t.Fatalf("explicit legacy peer was not allowed through the NACK-only fallback: %q", reason)
		}
	})

	t.Run("legacy_peer_control", func(t *testing.T) {
		s := legacyPeerSync16756(t)
		s.recordLastSentConfigGen(9)
		if stale, reason := s.PeerConfigStale(); stale {
			t.Fatalf("CONTROL: a genuinely pre-ACK peer with no NACK must not be stale: %q", reason)
		}
	})
}
