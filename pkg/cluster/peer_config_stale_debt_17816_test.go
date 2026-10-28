package cluster

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// #17816: the send generation and the ACK capability promised by that send
// are one debt state. Publishing them as separate atomics lets PeerConfigStale
// observe the new generation with the previous (legacy) capability and pass
// fail-open. Keeping the pair separate from peer-incarnation fields also
// preserves an ACK-capable peer's outstanding debt across a disconnect, while
// an explicitly learned downgrade still uses the legacy NACK-only semantics.
//
// FAIL-ON-REVERT: split debt publication, release the publication lock early,
// or clear either debt on retirement. The reader arm attempts PeerConfigStale
// while the writer holds that lock and must wait for the coherent snapshot;
// because the snapshot is one struct assignment, this does not model a
// partially-written in-memory struct. Other arms pin reconnect persistence,
// the legacy control, and capability-change serialization across an ungated
// socket write.
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
		s.testBeforeLastSentConfigDebtUnlock = func() {
			close(reached)
			<-release
		}
		go func() {
			s.recordLastSentConfigGen(7)
			close(done)
		}()
		<-reached
		type staleResult struct {
			stale  bool
			reason string
		}
		readerStarted := make(chan struct{})
		readerDone := make(chan staleResult, 1)
		go func() {
			close(readerStarted)
			stale, reason := s.PeerConfigStale()
			readerDone <- staleResult{stale: stale, reason: reason}
		}()
		<-readerStarted
		select {
		case got := <-readerDone:
			t.Fatalf("PeerConfigStale returned while the debt publication lock was held: stale=%v reason=%q", got.stale, got.reason)
		case <-time.After(50 * time.Millisecond):
		}
		close(release)
		released = true
		<-done
		got := <-readerDone
		if !got.stale {
			t.Fatalf("the new generation was observed without its ACK-capable send state: stale=%v reason=%q", got.stale, got.reason)
		}
	})
	t.Run("capability_change_cannot_split_ungated_send", func(t *testing.T) {
		s := legacyPeerSync16756(t)
		senderConn, peerConn := net.Pipe()
		defer senderConn.Close()
		defer peerConn.Close()

		reached := make(chan struct{})
		release := make(chan struct{})
		released := false
		defer func() {
			if !released {
				close(release)
			}
		}()
		s.testBeforeLastSentConfigDebtUnlock = func() {
			close(reached)
			<-release
		}
		sendDone := make(chan bool, 1)
		go func() {
			sendDone <- s.queueConfigOnConn(senderConn, "generation 9 config", nil, 9, nil)
		}()
		<-reached

		frame := capabilityFrame14161(t, 8, localCapabilityFlags, SessionSyncWireVersion)
		frame = append(frame, make([]byte, bootIncarnationLen+8+8)...)
		frame = append(frame, localCapabilityFlags2)
		capabilityStarted := make(chan struct{})
		capabilityDone := make(chan struct{})
		go func() {
			close(capabilityStarted)
			s.handleMessage(nil, syncMsgPeerCapabilities, frame)
			close(capabilityDone)
		}()
		<-capabilityStarted
		deadline := time.Now().Add(time.Second)
		for {
			select {
			case <-capabilityDone:
				t.Fatal("modern capability update completed between debt publication and socket write")
			default:
			}
			if !s.mu.TryLock() {
				break // capability handler holds mu while waiting for the send mutex
			}
			s.mu.Unlock()
			if time.Now().After(deadline) {
				t.Fatal("modern capability handler did not reach the send-mutex barrier")
			}
			runtime.Gosched()
		}

		if err := peerConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set peer read deadline: %v", err)
		}
		close(release)
		released = true
		msgType, payload, _ := readOneFrame(t, peerConn)
		if msgType != syncMsgConfig {
			t.Fatalf("config send type = %d, want %d", msgType, syncMsgConfig)
		}
		if _, gen := decodeConfigPayload(payload); gen != 9 {
			t.Fatalf("sent generation = %d, want 9", gen)
		}
		select {
		case ok := <-sendDone:
			if !ok {
				t.Fatal("config send failed")
			}
		case <-time.After(time.Second):
			t.Fatal("config send did not finish after the peer read the frame")
		}
		select {
		case <-capabilityDone:
		case <-time.After(time.Second):
			t.Fatal("capability update did not finish after the config write")
		}
		if !s.ConfigApplyAckCapable() {
			t.Fatal("FIXTURE: successor did not install ACK capability after the send")
		}
		if stale, reason := s.PeerConfigStale(); !stale {
			t.Fatalf("generation delivered before the modern advertisement passed the gate as legacy debt: %q", reason)
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
