package cluster

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// RED-on-revert: without the post-apply ACK the sender cannot distinguish an
// accepted socket write from an applied standby configuration.
func TestConfigApplyLoopSendsAckOnlyAfterSuccessfulApply11070(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	applied := make(chan struct{}, 1)
	s.OnConfigReceived = func(string) error {
		applied <- struct{}{}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.configApplyLoop(ctx)
	}()
	const gen = uint64(83)
	s.configApplyCh <- configApplyItem{gen: gen, text: "set system host-name standby", conn: conn}
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("config apply callback did not run")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, frame := range conn.frames() {
			if frame.msgType != syncMsgConfigApplyAck {
				continue
			}
			if len(frame.payload) < 8 || binary.LittleEndian.Uint64(frame.payload[:8]) != gen {
				t.Fatalf("apply ACK payload = %v, want generation %d", frame.payload, gen)
			}
			if s.lastAppliedConfigGen.Load() != gen {
				t.Fatalf("ACK preceded applied high-water: got %d, want %d", s.lastAppliedConfigGen.Load(), gen)
			}
			cancel()
			<-done
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("successful apply emitted no positive config-apply ACK")
}

func TestPeerAppliedGenerationResetsOnlyOnKnownReboot11070(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	s.peerAppliedConfigGen.Store(12)
	if !s.notePeerBootIncarnation(incarnation6910(0xA1)) {
		t.Fatal("first known peer incarnation was not recorded")
	}
	if got := s.peerAppliedConfigGen.Load(); got != 12 {
		t.Fatalf("first known incarnation reset applied mark to %d; want 12", got)
	}
	s.peerAppliedConfigGen.Store(18)
	if !s.notePeerBootIncarnation(incarnation6910(0xB2)) {
		t.Fatal("different known peer incarnation was not recognized as reboot")
	}
	if got := s.peerAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("peer reboot retained prior boot ACK %d", got)
	}
}
