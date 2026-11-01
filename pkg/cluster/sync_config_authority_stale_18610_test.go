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
	// As the receive edge does: the role is sampled at enqueue.
	runConfigItem18610(t, s, conn, configApplyItem{gen: gen, text: "set system host-name peer", conn: conn,
		authorityAtReceive: s.localConfigAuthority()}, want)
}

func runConfigItem18610(t *testing.T, s *SessionSync, conn *captureConn, item configApplyItem, want byte) {
	t.Helper()
	gen := item.gen
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
	s.configApplyCh <- item
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
	// Seat U: the refusal has its own counter and last-generation row, and
	// is not counted as an apply failure. Read through Stats() so the
	// descriptor wiring is covered too.
	st := s.Stats()
	if st.ConfigsRejectedAsAuthority != 1 || st.ConfigRejectedAsAuthorityLastGen != peerPushedGen18610 {
		t.Fatalf("authority refusal counters: rejected=%d last_gen=%d, want 1 and %d",
			st.ConfigsRejectedAsAuthority, st.ConfigRejectedAsAuthorityLastGen, peerPushedGen18610)
	}
	if st.ConfigsApplyFailed != 0 {
		t.Fatalf("an authority refusal was counted as an apply failure (ConfigsApplyFailed=%d)", st.ConfigsApplyFailed)
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
		if st := s.Stats(); st.ConfigsApplyFailed != 1 || st.ConfigsRejectedAsAuthority != 0 || st.ConfigRejectedAsAuthorityLastGen != 0 {
			t.Fatalf("primary=%v: a failed apply must count ConfigsApplyFailed only: failed=%d rejected=%d last_gen=%d",
				isPrimary, st.ConfigsApplyFailed, st.ConfigsRejectedAsAuthority, st.ConfigRejectedAsAuthorityLastGen)
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

// The config-received callback can name the generation it was handed: the
// daemon's refusal Warn reads it through ApplyingConfigGen. RED if the
// accessor reads anything but the in-flight apply fence.
func TestApplyingConfigGenNamesTheGenerationInsideTheCallback18610(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	var seen atomic.Uint64
	s.OnConfigReceived = func(string) error {
		seen.Store(s.ApplyingConfigGen())
		return nil
	}
	s.recordRecvConfigGen(peerPushedGen18610)
	runOneConfigItem18610(t, s, conn, peerPushedGen18610, syncMsgConfigApplyAck)
	if got := seen.Load(); got != peerPushedGen18610 {
		t.Fatalf("ApplyingConfigGen inside the callback = %d, want %d", got, peerPushedGen18610)
	}
	if got := s.ApplyingConfigGen(); got != 0 {
		t.Fatalf("ApplyingConfigGen after the apply = %d, want 0", got)
	}
}

// Review T1: a generation received while this node was SECONDARY and refused
// because a promotion landed before the apply loop reached it is the previous
// primary's last config, lost. It must keep the staleness and the CF streak,
// exactly like the same generation failing for another reason. RED if the
// authority classification is made from the role at apply time.
func TestReceivedAsStandbyRefusedAfterPromotionStaysStale18610(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"refused-after-promotion", ErrConfigSyncRejectedAuthority},
		{"failed-then-promoted", errors.New("compile failed")},
	} {
		primary := &atomic.Bool{} // secondary at receive
		s, conn, _ := newAuthoritySync18610(t, primary, tc.err)
		item := configApplyItem{gen: peerPushedGen18610, text: "set system host-name peer", conn: conn,
			authorityAtReceive: s.localConfigAuthority()}
		primary.Store(true) // promoted before the queued item is applied
		runConfigItem18610(t, s, conn, item, syncMsgConfigApplyNack)
		if snap := s.TransferReadiness(); !snap.ConfigStale() {
			t.Fatalf("%s: the previous primary's lost config must leave this node config-stale: %+v", tc.name, snap)
		}
		s.configApplyMu.Lock()
		streak := s.firstUnappliedFailNano
		s.configApplyMu.Unlock()
		if streak == 0 {
			t.Fatalf("%s: the previous primary's lost config must arm the #6387 CF streak", tc.name)
		}
		if st := s.Stats(); st.ConfigsRejectedAsAuthority != 0 || st.ConfigsApplyFailed != 1 {
			t.Fatalf("%s: counted rejected=%d failed=%d, want 0 and 1", tc.name, st.ConfigsRejectedAsAuthority, st.ConfigsApplyFailed)
		}
	}
}

// Review T1: the role is sampled by the RECEIVE edge onto the item. RED if
// handleConfigPayload stops recording it (every refusal would then read as
// received-as-standby) or records something other than the live role.
func TestReceiveEdgeRecordsAuthorityOnTheItem18610(t *testing.T) {
	for _, isPrimary := range []bool{true, false} {
		primary := &atomic.Bool{}
		primary.Store(isPrimary)
		s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
		s.IsPrimaryFn = primary.Load
		if !s.handleMessage(nil, syncMsgConfig, encodeConfigPayload("set system host-name peer", peerPushedGen18610)) {
			t.Fatalf("primary=%v: config frame refused at the receive edge", isPrimary)
		}
		select {
		case item := <-s.configApplyCh:
			if item.authorityAtReceive != isPrimary {
				t.Fatalf("primary=%v: item.authorityAtReceive=%v", isPrimary, item.authorityAtReceive)
			}
		default:
			t.Fatalf("primary=%v: the config frame was not queued for apply", isPrimary)
		}
	}
}

// Review T2, the losing node's half. The loser applied the authority's push
// (G1) before the split, then pushed its own config (debt X) while it believed
// itself primary; the authority refused and nacked it, so the loser's #9569
// gate refuses the handovers it starts. The authority's re-push after the
// refusal goes through the ordinary reconcile, under a NEW wire generation G2:
// the loser applies it, ACKs, and the debt is superseded. The twin is the
// same-generation resend the #18521 overdue path would send: a duplicate of G1
// runs no handler and leaves the debt standing, which is why the re-push must
// not reuse it. RED if applying the authority's new generation stops retiring
// the loser's debt.
func TestLoserAppliesTheAuthorityRepushAndRetiresItsDebt18610(t *testing.T) {
	const preSplitGen = uint64(5358110549851) // the authority's push, applied
	const repushGen = uint64(5358110549860)   // the re-push, a new generation
	const loserDebtGen = uint64(7716000000123)
	for _, tc := range []struct {
		name      string
		gen       uint64
		wantStale bool
	}{
		{"re-push under a new generation retires the debt", repushGen, false},
		{"a same-generation resend leaves the debt standing", preSplitGen, true},
	} {
		s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
		conn := &captureConn{}
		s.mu.Lock()
		s.conn0 = conn
		s.mu.Unlock()
		s.IsPrimaryFn = func() bool { return false } // the loser, secondary again
		s.OnConfigReceived = func(string) error { return nil }
		s.recordRecvConfigGen(preSplitGen)
		s.recordAppliedConfigGen(preSplitGen)
		s.SetOverdueConfigApplyDebtForTesting(loserDebtGen, 2*time.Minute)
		if stale, _ := s.PeerConfigStale(); !stale {
			t.Fatalf("%s: fixture: the loser's refused push must leave its #9569 gate stale", tc.name)
		}
		s.recordRecvConfigGen(tc.gen)
		runOneConfigItem18610(t, s, conn, tc.gen, syncMsgConfigApplyAck)
		if stale, reason := s.PeerConfigStale(); stale != tc.wantStale {
			t.Fatalf("%s: PeerConfigStale=%v (%s), want %v", tc.name, stale, reason, tc.wantStale)
		}
	}
}
