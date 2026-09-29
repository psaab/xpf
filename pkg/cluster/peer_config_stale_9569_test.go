package cluster

import (
	"encoding/binary"
	"errors"
	"testing"
)

// #9569: the untargeted RG failover, the batch form and ForceSecondary demote
// THIS node and used to promote a config-stale standby. They now refuse when
// the peer nacked the newest config generation this node sent.

// twoRGManager9569 is node 0, primary for RG0 and RG1, with a live peer.
func twoRGManager9569(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	))
	drainEvents(m, 2)
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	})
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("setup: node 0 must be primary for RG0 and RG1")
	}
	return m
}

func staleFn9569(stale *bool) func() (bool, string) {
	return func() (bool, string) {
		if *stale {
			return true, "the standby did not apply config generation 7"
		}
		return false, ""
	}
}

func assertStillPrimary9569(t *testing.T, m *Manager, what string, rgs ...int) {
	t.Helper()
	for _, rg := range rgs {
		if !m.IsLocalPrimary(rg) {
			t.Errorf("%s demoted redundancy group %d onto a config-stale peer", what, rg)
		}
	}
}

func TestUntargetedFailoverRefusesAConfigStalePeer_9569(t *testing.T) {
	m := twoRGManager9569(t)
	stale := true
	m.SetPeerConfigStaleFunc(staleFn9569(&stale))

	_, err := m.ManualFailover(0)
	if !errors.Is(err, ErrPeerConfigStale) {
		t.Fatalf("#9569: the untargeted RG0 failover onto a standby that nacked the newest config returned %v, "+
			"want ErrPeerConfigStale. The stale standby is promoted and pushes its older config over the committed one", err)
	}
	assertStillPrimary9569(t, m, "a refused manual failover", 0)

	// The refusal must not leave the failover marked in progress.
	stale = false
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("once the peer is current, the failover must proceed; got %v", err)
	}
	drainEvents(m, 1)
	if m.IsLocalPrimary(0) {
		t.Errorf("control: a failover onto a current peer did not demote redundancy group 0")
	}
}

func TestManualFailoverBatchRefusesAConfigStalePeer_9569(t *testing.T) {
	m := twoRGManager9569(t)
	stale := true
	m.SetPeerConfigStaleFunc(staleFn9569(&stale))

	if _, err := m.ManualFailoverBatch([]int{0, 1}); !errors.Is(err, ErrPeerConfigStale) {
		t.Fatalf("#9569: the batch failover onto a config-stale peer returned %v, want ErrPeerConfigStale", err)
	}
	assertStillPrimary9569(t, m, "a refused batch failover", 0, 1)

	stale = false
	if _, err := m.ManualFailoverBatch([]int{0, 1}); err != nil {
		t.Fatalf("once the peer is current, the batch must proceed (the refusal left it in progress?): %v", err)
	}
}

func TestForceSecondaryRefusesAConfigStalePeer_9569(t *testing.T) {
	m := twoRGManager9569(t)
	stale := true
	m.SetPeerConfigStaleFunc(staleFn9569(&stale))

	if err := m.ForceSecondary(); !errors.Is(err, ErrPeerConfigStale) {
		t.Fatalf("#9569: ForceSecondary (the ISSU drain) onto a config-stale peer returned %v, want ErrPeerConfigStale", err)
	}
	assertStillPrimary9569(t, m, "a refused ForceSecondary", 0, 1)

	stale = false
	if err := m.ForceSecondary(); err != nil {
		t.Fatalf("control: ForceSecondary onto a current peer failed: %v", err)
	}
	drainEvents(m, 2)
}

// A NACK is diagnostic, not proof of peer state. New sends remain stale until
// the peer positively acknowledges successful apply of the newest generation.
func TestPeerConfigStaleRequiresPositiveApplyAck11070(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	nack := func(typ uint8, gen uint64) {
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], gen)
		s.handleMessage(nil, typ, p[:])
	}

	if stale, _ := s.PeerConfigStale(); stale {
		t.Fatal("a SessionSync that sent nothing reports a stale peer")
	}
	s.lastSentConfigGen.Store(7)
	nack(syncMsgConfigApplyNack, 7)
	if stale, reason := s.PeerConfigStale(); !stale || reason == "" {
		t.Fatalf("the newest sent generation without an apply ACK must be stale: stale=%v reason=%q", stale, reason)
	}

	s.lastSentConfigGen.Store(8)
	if stale, _ := s.PeerConfigStale(); !stale {
		t.Fatal("a newer send cleared stale state before the standby applied it")
	}
	nack(syncMsgConfigApplyAck, 7)
	if stale, _ := s.PeerConfigStale(); !stale {
		t.Fatal("ACK of generation 7 incorrectly cleared the outstanding generation 8")
	}
	nack(syncMsgConfigApplyAck, 9)
	if got := s.peerAppliedConfigGen.Load(); got != 7 {
		t.Fatalf("ACK for an unsent generation advanced peer-applied mark to %d", got)
	}
	nack(syncMsgConfigApplyAck, 8)
	if stale, _ := s.PeerConfigStale(); stale {
		t.Fatal("the matching positive apply ACK did not clear stale state")
	}
	nack(syncMsgConfigApplyAck, 7)
	if got := s.peerAppliedConfigGen.Load(); got != 8 {
		t.Fatalf("out-of-order ACK regressed peer-applied mark to %d", got)
	}
}
