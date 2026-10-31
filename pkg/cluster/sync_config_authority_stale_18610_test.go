package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// #18610: an RG0 primary that refuses a peer's config push (the peer briefly
// believed itself primary) must not read "standby config stale" or raise CF for
// that refusal while it stays the authority. Before the fix the received mark
// stayed above the applied mark for as long as the node stayed primary, the
// local RGs read Transfer ready: no, and a rolling upgrade started on the
// primary aborted with "peer is NOT takeover-ready".

const (
	authorityAppliedGen18610 = uint64(5358110549851)
	peerPushedGen18610       = uint64(5358110549853)
)

// runOneConfigItem18610 drives the real configApplyLoop for one item and
// waits until it has been fully processed: the ack (success) or nack
// (failure) frame is on the wire.
func runOneConfigItem18610(t *testing.T, s *SessionSync, conn *captureConn, gen uint64, want byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.configApplyLoop(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	s.configApplyCh <- configApplyItem{gen: gen, text: "set system host-name peer", conn: conn}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, frame := range conn.frames() {
			if frame.msgType == want {
				// The frame is written before endConfigApply; give the loop
				// a moment to finish the iteration.
				time.Sleep(20 * time.Millisecond)
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("config apply loop did not emit message type %d for gen %d", want, gen)
}

func newAuthoritySync18610(t *testing.T, primary *atomic.Bool, applyErr error) (*SessionSync, *captureConn, *atomic.Int32) {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	s.IsPrimaryFn = primary.Load
	s.OnConfigReceived = func(string) error { return applyErr }
	raised := &atomic.Int32{}
	s.OnConfigApplyHealth = func(failing bool, _ string) {
		if failing {
			raised.Add(1)
		}
	}
	// This node applied ...851 while it was secondary, then became primary.
	s.recordAppliedConfigGen(authorityAppliedGen18610)
	// The receive edge raises the received mark before apply (#5563).
	s.recordRecvConfigGen(peerPushedGen18610)
	return s, conn, raised
}

// The defect cell. RED on revert: ConfigStale stays true on the primary and
// the CF streak is armed.
func TestAuthorityRejectionDoesNotLeaveThePrimaryConfigStale18610(t *testing.T) {
	primary := &atomic.Bool{}
	primary.Store(true)
	// Wrapped, as a caller may: the loop must match the sentinel with errors.Is.
	rejected := fmt.Errorf("handleConfigSync: %w", ErrConfigSyncRejectedAuthority)
	s, conn, raised := newAuthoritySync18610(t, primary, rejected)

	runOneConfigItem18610(t, s, conn, peerPushedGen18610, syncMsgConfigApplyNack)

	snap := s.TransferReadiness()
	if snap.ConfigStale() || strings.Contains(snap.Reason(), "standby config stale") {
		t.Fatalf("the RG0 authority reads config-stale after refusing a peer push as primary: %+v (%s)", snap, snap.Reason())
	}
	s.configApplyMu.Lock()
	streak := s.firstUnappliedFailNano
	s.configApplyMu.Unlock()
	if streak != 0 || raised.Load() != 0 {
		t.Fatalf("the authority's own refusal armed the CF health streak (streak=%d raised=%d)", streak, raised.Load())
	}
	// #4151 is kept: the high-water stays pinned and the generation stays
	// eligible should this node demote; #7328's nack was sent (we waited on it).
	if got := s.lastAppliedConfigGen.Load(); got != authorityAppliedGen18610 {
		t.Fatalf("applied high-water moved to %d on a refusal; want it pinned at %d", got, authorityAppliedGen18610)
	}
	if !s.shouldApplyConfigGen(peerPushedGen18610) {
		t.Fatal("the refused generation must stay admissible for a re-push after demotion (#4151)")
	}

	// Once this node is no longer the authority the refused generation counts
	// again: it must not be promoted back before the new primary's push applies.
	primary.Store(false)
	if snap := s.TransferReadiness(); !snap.ConfigStale() {
		t.Fatalf("after demotion the refused generation must make this node config-stale again: %+v", snap)
	}
}

// Twin: an ordinary apply failure, on a primary or not, still arms CF and still
// reads stale. RED if the exemption is keyed on IsPrimaryFn instead of on the
// authority-refusal error.
func TestOrdinaryApplyFailureStillArmsCFAndStaleness18610(t *testing.T) {
	for _, isPrimary := range []bool{false, true} {
		primary := &atomic.Bool{}
		primary.Store(isPrimary)
		s, conn, _ := newAuthoritySync18610(t, primary, errors.New("compile failed"))
		runOneConfigItem18610(t, s, conn, peerPushedGen18610, syncMsgConfigApplyNack)
		if snap := s.TransferReadiness(); !snap.ConfigStale() {
			t.Fatalf("primary=%v: a failed apply must leave the node config-stale: %+v", isPrimary, snap)
		}
		s.configApplyMu.Lock()
		streak := s.firstUnappliedFailNano
		s.configApplyMu.Unlock()
		if streak == 0 {
			t.Fatalf("primary=%v: a failed apply must arm the #6387 CF streak", isPrimary)
		}
	}
}

// Restart cell (coordinator, #18610): a node that restarted with a config
// identical to the peer's takes the daemon's "already matches active and is
// applied" fast path, which returns nil. The loop must still record the
// generation as applied, so readiness is true afterwards.
func TestRestartWithIdenticalConfigIsTransferReady18610(t *testing.T) {
	primary := &atomic.Bool{}
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	s.IsPrimaryFn = primary.Load
	s.OnConfigReceived = func(string) error { return nil } // the skip path
	// Fresh process: both marks 0, then the reconnect re-push arrives.
	s.recordRecvConfigGen(peerPushedGen18610)
	if snap := s.TransferReadiness(); !snap.ConfigStale() {
		t.Fatalf("premise: before the re-push applies the restarted standby is config-stale: %+v", snap)
	}
	runOneConfigItem18610(t, s, conn, peerPushedGen18610, syncMsgConfigApplyAck)
	if snap := s.TransferReadiness(); snap.ConfigStale() || !snap.ReadyForManualFailover() {
		t.Fatalf("a restarted standby whose config already matches must be transfer-ready: %+v (%s)", snap, snap.Reason())
	}
}

// The rejected-as-authority mark is part of the receiver's generation
// namespace and is cleared with it. RED if resetRecvGen leaves it standing.
func TestResetRecvGenClearsRejectedAsAuthority18610(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	s.recordConfigRejectedAsAuthority(peerPushedGen18610)
	s.resetRecvGen()
	if got := s.rejectedAsAuthorityConfigGen.Load(); got != 0 {
		t.Fatalf("resetRecvGen left rejectedAsAuthorityConfigGen=%d", got)
	}
}
