package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9716: the #9174 V013 incarnation check refuses a BulkEnd only when BOTH sides carry a boot
// incarnation and the two differ. When either is missing, the end marker was matched on the epoch
// alone, and every peer process restarts its epoch at 1. So a BulkEnd buffered on a dead peer
// process's still-established socket completed the live bulk. The receiver then:
//   - reconciled against a partly received table;
//   - latched bulkEverCompleted;
//   - released the VRRP sync hold.
//
// BulkSync pins one connection for a whole bulk, so the fence is the connection that carried the
// accepted BulkStart.

// THE DEFECT, as the issue's acceptance states it.
func TestLegacyBulkEndOnTheDeadConnectionDoesNotCompleteTheLiveBulk_9716(t *testing.T) {
	e, released := newBulkEnv(t)

	// A peer process on an older build primes a legacy bulk (no incarnation) on fabric 0.
	e.prime(0, 7, nil)
	// It dies. Its replacement primes on fabric 1 WITH an incarnation, at the same epoch. That is
	// accepted, because zero -> incB is a switch.
	e.prime(1, 7, &incB)
	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 7 {
		t.Fatalf("CONTROL FAILED: the replacement's BulkStart on fabric 1 was not accepted "+
			"(inProgress=%v epoch=%d). Nothing below can tell a fenced BulkEnd from a bulk that never "+
			"started", e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}

	// The dead process's legacy BulkEnd, buffered on its still-established socket, lands on fabric 0.
	e.bulkEnd(0, 7, nil)

	got := e.observeBulk(released)
	if got.everCompleted || got.endTime != 0 || got.holdReleased {
		t.Fatalf("#9716: a legacy BulkEnd on the DEAD process's connection completed the replacement's "+
			"live bulk (everCompleted=%v endTime=%d holdReleased=%v). The incarnation check fails open for "+
			"an un-incarnated marker, so it was matched on the epoch alone, and every peer process restarts "+
			"its epoch at 1", got.everCompleted, got.endTime, got.holdReleased)
	}
	if !e.s.bulkInProgress {
		t.Fatal("#9716: refusing the dead connection's BulkEnd tore down the live bulk; the replacement's " +
			"own BulkEnd must still be able to complete it")
	}
	if n := e.s.stats.BulkEndsForeignConnDropped.Load(); n != 1 {
		t.Errorf("BulkEndsForeignConnDropped = %d, want 1: the refusal must be countable", n)
	}

	// The replacement's install on fabric 1 lands, and its own BulkEnd on fabric 1 completes the bulk.
	key := keyFor9174()
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	e.s.handleMessage(e.conns[1], syncMsgSessionV4, encodeSessionV4Payload(key, val))
	if _, err := e.s.sessions.GetV4(key); err != nil {
		t.Fatalf("FIXTURE: the replacement's install on fabric 1 did not land: %v", err)
	}
	e.bulkEnd(1, 7, &incB)
	got = e.observeBulk(released)
	if !got.everCompleted || got.endTime == 0 || !got.holdReleased {
		t.Fatalf("the replacement's own BulkEnd on fabric 1 must complete the bulk "+
			"(everCompleted=%v endTime=%d holdReleased=%v)", got.everCompleted, got.endTime, got.holdReleased)
	}
	if _, err := e.s.sessions.GetV4(key); err != nil {
		t.Errorf("the session the live bulk carried was reconciled away at its own BulkEnd: %v", err)
	}
}

// A legacy bulk started and ended on ONE connection still completes, and the completion is counted,
// because the incarnation check could not judge it.
func TestEpochOnlyCompletionStillCompletesAndIsCounted_9716(t *testing.T) {
	e, released := newBulkEnv(t)
	e.prime(0, 7, nil)
	e.bulkEnd(0, 7, nil)

	got := e.observeBulk(released)
	if !got.everCompleted || !got.holdReleased {
		t.Fatalf("a legacy bulk started and ended on one connection must still complete "+
			"(everCompleted=%v holdReleased=%v); failing closed would strand the standby for the whole "+
			"rolling-upgrade window", got.everCompleted, got.holdReleased)
	}
	if n := e.s.stats.BulkEndsEpochOnlyMatched.Load(); n != 1 {
		t.Errorf("BulkEndsEpochOnlyMatched = %d, want 1: a completion matched on epoch alone must be "+
			"countable (#9716)", n)
	}
	if n := e.s.stats.BulkEndsForeignConnDropped.Load(); n != 0 {
		t.Errorf("BulkEndsForeignConnDropped = %d, want 0 for a single-connection bulk", n)
	}
}

// The counter's other side: a bulk whose start and end both carry the same incarnation was judged
// by the incarnation check, so it is not an epoch-only match.
func TestIncarnatedCompletionIsNotCountedAsEpochOnly_9716(t *testing.T) {
	e, released := newBulkEnv(t)
	e.prime(0, 7, &incA)
	e.bulkEnd(0, 7, &incA)

	if got := e.observeBulk(released); !got.everCompleted {
		t.Fatal("FIXTURE: an incarnated single-connection bulk must complete")
	}
	if n := e.s.stats.BulkEndsEpochOnlyMatched.Load(); n != 0 {
		t.Errorf("BulkEndsEpochOnlyMatched = %d, want 0: the incarnation check judged this completion", n)
	}
}
