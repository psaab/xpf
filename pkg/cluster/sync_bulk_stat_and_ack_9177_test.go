package cluster

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// #9177 — two small, INDEPENDENT defects in the same bulk-sync reader. They are
// unrelated edits and are kept in separate cells deliberately.
//
//	V052  the three `s.stats.BulkSync*` stores run ABOVE the #8966 accept
//	      decision, so a REFUSED BulkStart still zeroes the bulk telemetry.
//	V053  `BulkAck` accepts a FUTURE epoch (`epoch < pending` rather than
//	      `epoch != pending`), releasing the #3912 failover gate on a bulk
//	      that never completed.
//
// Both are recorded at the severity that survived their own re-derivation, not
// the one they were filed at. V052's filed headline — that the `len(payload) >=
// 8` read admits a malformed short frame — is REFUTED and is not tested here: a
// short frame is read as epoch 0 and is only accepted when no bulk is in
// progress, a state in which any epoch is accepted, so it grants nothing a
// well-formed frame does not. V053 needs a non-conforming or compromised peer
// past the #5303 pre-auth admission, which is why it is Low; it is fixed because
// the comparator has no reason to be loose and the fix is one operator.

// ── V052: the stat reset must run BELOW the accept ────────────────────────

// statusFor9177 renders the operator-facing `show chassis cluster information`
// text from a Manager wired to this SessionSync — `Manager.FormatInformation`,
// which is what `pkg/cli`'s showChassisClusterInformation prints and where the
// "Cold synchronization" block lives. (`FormatStatus`, the shorter render, does
// not carry it; the fixture guard below is what caught that, and it is kept so a
// future reader cannot mistake an absent section for a passing assertion.)
//
// THE OBSERVABLE IS THE STATUS, NOT THE ACCEPT DECISION. An assertion on the
// accept path cannot see this defect at all: the accept is CORRECT — #8966 made
// it so — and what is wrong is that three statements ran before it. So the cell
// has to read what the operator reads.
func statusFor9177(t *testing.T, s *SessionSync) string {
	t.Helper()
	m := NewManager(0, 1)
	// The render carries the cold-sync block only for a CONFIGURED manager, so
	// the fixture gives it a redundancy group the way the production wiring
	// does. Without this the section is absent and every "the line is not
	// there" assertion below would pass vacuously.
	m.UpdateConfig(makeConfig(makeRG(0, true, map[int]int{0: 100})))
	recvEvent19161(t, m.Events(), "the next event")
	m.SetSyncStats(s)
	out := m.FormatInformation()
	if !strings.Contains(out, "Cold synchronization:") {
		t.Fatalf("FIXTURE FAILED: the render carries no Cold synchronization "+
			"section, so no cell in this file can observe the bulk telemetry:\n%s", out)
	}
	return out
}

func bulkAckPayload9177(epoch uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, epoch)
	return b
}

const (
	inProgressLine9177 = "Bulk sync in progress since"
	lastBulkLine9177   = "Last bulk sync:"
)

// THE DEFECT. A completed bulk leaves `show chassis cluster` reporting
// `Last bulk sync: <when>`. A REFUSED BulkStart — the reordered one #8966's own
// text calls "the ordinary case" with two fabric streams — then re-stamps
// BulkSyncStartTime and zeroes BulkSyncEndTime on its way to being rejected, and
// the status flips to `Bulk sync in progress since …` and stays there
// indefinitely, because the frame that would have set an end time was never
// accepted.
//
// This is a statement-ORDERING defect, not an epoch-validation one. No
// incarnation rule fixes it: the accept already refuses the frame correctly.
func TestRefusedBulkStartDoesNotReopenTheStatus9177(t *testing.T) {
	e := newIncEnv(t, 2)

	// A real bulk completes: BulkStart -> BulkEnd.
	e.prime(0, 7, &incA)
	e.s.handleMessage(e.conns[0], syncMsgBulkEnd,
		append(bulkAckPayload9177(7), incA[:]...))
	if e.s.stats.BulkSyncEndTime.Load() == 0 {
		t.Fatalf("CONTROL FAILED: the bulk did not complete, so there is no " +
			"`Last bulk sync` state for a refused start to destroy")
	}
	before := statusFor9177(t, e.s)
	if !strings.Contains(before, lastBulkLine9177) {
		t.Fatalf("CONTROL FAILED: status does not report a completed bulk:\n%s", before)
	}
	startedAt := e.s.stats.BulkSyncStartTime.Load()

	// A STALE BulkStart on the other fabric. It is refused — that part is
	// correct and is #8966's/#9174's job — but the three stat stores have
	// already run.
	e.prime(1, 5, &incA)
	if e.s.bulkInProgress {
		t.Fatalf("CONTROL FAILED: the stale BulkStart was ACCEPTED, so this cell " +
			"is measuring the accept path rather than the statement ordering")
	}

	after := statusFor9177(t, e.s)
	if strings.Contains(after, inProgressLine9177) {
		t.Errorf("#9177 V052: a REFUSED BulkStart flipped `show chassis cluster` to "+
			"%q, and nothing will ever clear it — the BulkEnd that would set an end "+
			"time belongs to a bulk that was never accepted.\n"+
			"  The three s.stats.BulkSync* stores run ABOVE the bulkMu accept "+
			"decision. The #8966 author moved resetRecvGen below that accept for "+
			"exactly this reason and left the stat stores where they were.\n"+
			"  status after the refusal:\n%s", inProgressLine9177, after)
	}
	if !strings.Contains(after, lastBulkLine9177) {
		t.Errorf("#9177 V052: the completed bulk's `%s` line disappeared from the "+
			"status after a REFUSED BulkStart:\n%s", lastBulkLine9177, after)
	}
	if got := e.s.stats.BulkSyncStartTime.Load(); got != startedAt {
		t.Errorf("#9177 V052: a refused BulkStart re-stamped BulkSyncStartTime "+
			"(%d -> %d)", startedAt, got)
	}
	if e.s.stats.BulkSyncEndTime.Load() == 0 {
		t.Errorf("#9177 V052: a refused BulkStart zeroed BulkSyncEndTime")
	}
}

// The second consequence, and it is not implied by the status text: with
// BulkSyncStartTime re-stamped and BulkSyncEndTime zeroed, the session handlers'
// `StartTime > 0 && EndTime == 0` test reads TRUE, so every subsequent
// INCREMENTAL session install is counted into BulkSyncSessions and reported as
// part of a bulk that is not running.
func TestRefusedBulkStartDoesNotMiscountIncrementalInstalls9177(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)
	e.s.handleMessage(e.conns[0], syncMsgBulkEnd,
		append(bulkAckPayload9177(7), incA[:]...))
	sessionsAtComplete := e.s.stats.BulkSyncSessions.Load()

	e.prime(1, 5, &incA) // refused

	// An ordinary incremental session arrives afterwards. The payload is
	// deliberately malformed for the INSTALL path — that arm counts the record
	// as malformed and installs nothing — but the bulk accounting above it runs
	// first and unconditionally, which is the code under test here.
	e.s.handleMessage(e.conns[0], syncMsgSessionV4, make([]byte, 4))

	if got := e.s.stats.BulkSyncSessions.Load(); got != sessionsAtComplete {
		t.Errorf("#9177 V052: an INCREMENTAL session install after a refused "+
			"BulkStart was counted as bulk traffic (%d -> %d). The refused frame "+
			"left BulkSyncStartTime set and BulkSyncEndTime zero, which is exactly "+
			"the `bulk in progress` test the session handlers apply",
			sessionsAtComplete, got)
	}
}

// LOAD-BEARING CONTROL. An ACCEPTED BulkStart must still stamp all three stats.
// Moving the stores below the accept is satisfiable by deleting them, and that
// would leave `show chassis cluster` unable to report a bulk at all — a worse
// outcome than the defect, and invisible to every cell above.
func TestAcceptedBulkStartStillStampsTheStats9177(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)
	e.s.handleMessage(e.conns[0], syncMsgBulkEnd,
		append(bulkAckPayload9177(7), incA[:]...))
	endAfterFirst := e.s.stats.BulkSyncEndTime.Load()
	if endAfterFirst == 0 {
		t.Fatal("CONTROL FAILED: the first bulk did not complete")
	}

	// A genuinely NEWER bulk: accepted.
	time.Sleep(2 * time.Millisecond) // so a re-stamped start time is distinguishable
	e.prime(1, 9, &incA)
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: the newer BulkStart was refused")
	}

	if e.s.stats.BulkSyncEndTime.Load() != 0 {
		t.Error("an ACCEPTED BulkStart must zero BulkSyncEndTime — otherwise the " +
			"status keeps reporting the PREVIOUS bulk's completion while a new one " +
			"is running")
	}
	if e.s.stats.BulkSyncStartTime.Load() == 0 {
		t.Error("an ACCEPTED BulkStart must stamp BulkSyncStartTime")
	}
	if e.s.stats.BulkSyncSessions.Load() != 0 {
		t.Error("an ACCEPTED BulkStart must zero BulkSyncSessions, or the new " +
			"bulk's count carries the previous bulk's total")
	}

	out := statusFor9177(t, e.s)
	if !strings.Contains(out, inProgressLine9177) {
		t.Errorf("with a bulk genuinely in progress the status must say %q:\n%s",
			inProgressLine9177, out)
	}
}

// The first bulk a receiver ever sees must stamp too — the stores must not end
// up behind a condition that only a SUBSEQUENT bulk satisfies.
func TestFirstEverBulkStartStampsTheStats9177(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 1, &incA)
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: the first BulkStart was refused")
	}
	if e.s.stats.BulkSyncStartTime.Load() == 0 {
		t.Error("#9177 V052: the FIRST bulk never stamped BulkSyncStartTime, so " +
			"`show chassis cluster` reports nothing for it")
	}
	if !strings.Contains(statusFor9177(t, e.s), inProgressLine9177) {
		t.Error("the first bulk must render as in progress")
	}
}

// ── V053: BulkAck must not accept a FUTURE epoch ──────────────────────────

// ackEnv9177 wires a SessionSync with an observable ack callback.
func ackEnv9177(t *testing.T) (*SessionSync, chan struct{}) {
	t.Helper()
	ss := newAckTestSync(t)
	fired := make(chan struct{}, 4)
	ss.OnBulkSyncAckReceived = func() { fired <- struct{}{} }
	return ss, fired
}

func ackFired9177(fired chan struct{}) bool {
	select {
	case <-fired:
		return true
	case <-time.After(250 * time.Millisecond):
		return false
	}
}

// THE DEFECT. `pendingBulkAckEpoch` is LOCAL authority: our own send path sets
// it under `bulkSendMu` BEFORE writing the BulkEnd, so it is by construction the
// largest epoch we have ever put on the wire. A correct peer cannot echo a
// larger one — so an ack for a FUTURE epoch is not an ack for anything, and
// accepting it clears `pending`, latches `bulkEverCompleted` /
// `outboundBulkAcked` and fires `OnBulkSyncAckReceived`, releasing the #3912
// failover gate on a bulk that never completed.
func TestFutureEpochBulkAckIsRefused9177(t *testing.T) {
	ss, fired := ackEnv9177(t)
	ss.pendingBulkAckEpoch.Store(5)
	ss.pendingBulkAckSince.Store(MonotonicNanos())

	ss.handleMessage(pipeConn(t), syncMsgBulkAck, bulkAckPayload9177(9))

	if got := ss.pendingBulkAckEpoch.Load(); got != 5 {
		t.Errorf("#9177 V053: a BulkAck for epoch 9 cleared a pending epoch of 5 "+
			"(now %d). pendingBulkAckEpoch is set by our OWN send path before the "+
			"BulkEnd write, so it is the largest epoch we ever emitted and a "+
			"conforming peer cannot ack past it. `epoch < pending` admits it; "+
			"`epoch != pending` is strictly tighter, costs one operator and needs "+
			"no new input", got)
	}
	if ss.outboundBulkAcked.Load() {
		t.Error("#9177 V053: a future-epoch ack latched outboundBulkAcked, which " +
			"suppresses the #4090/#4360 stranded-bulk re-drive for a bulk that was " +
			"never acknowledged")
	}
	if ss.bulkEverCompleted.Load() {
		t.Error("#9177 V053: a future-epoch ack latched bulkEverCompleted")
	}
	if ackFired9177(fired) {
		t.Error("#9177 V053: a future-epoch ack fired OnBulkSyncAckReceived, " +
			"releasing the #3912 failover gate on a bulk that never completed")
	}
}

// LOAD-BEARING CONTROL. The EXACT epoch must still be accepted. Tightening `<`
// to `!=` is satisfiable by refusing everything, and refusing the real ack
// latches a phantom pending epoch that nothing ever clears — permanently
// blocking manual failover, which is the #3912 defect this comparator sits in
// the middle of.
func TestMatchingEpochBulkAckStillReleasesTheGate9177(t *testing.T) {
	ss, fired := ackEnv9177(t)
	ss.pendingBulkAckEpoch.Store(5)
	ss.pendingBulkAckSince.Store(MonotonicNanos())

	ss.handleMessage(pipeConn(t), syncMsgBulkAck, bulkAckPayload9177(5))

	if got := ss.pendingBulkAckEpoch.Load(); got != 0 {
		t.Fatalf("the peer's ack for the epoch we are actually waiting on must "+
			"clear the pending state, got %d. Leaving it set latches a phantom "+
			"pending epoch that no future ack clears (#3912)", got)
	}
	if !ss.outboundBulkAcked.Load() {
		t.Error("a matching ack must latch outboundBulkAcked")
	}
	if !ss.bulkEverCompleted.Load() {
		t.Error("a matching ack must latch bulkEverCompleted")
	}
	if !ackFired9177(fired) {
		t.Error("a matching ack must fire OnBulkSyncAckReceived and release the " +
			"failover gate")
	}
}

// The #5272 arm must survive the tightening: an OLDER epoch is still refused.
func TestStaleEpochBulkAckStillRefused9177(t *testing.T) {
	ss, fired := ackEnv9177(t)
	ss.pendingBulkAckEpoch.Store(5)

	ss.handleMessage(pipeConn(t), syncMsgBulkAck, bulkAckPayload9177(3))

	if got := ss.pendingBulkAckEpoch.Load(); got != 5 {
		t.Errorf("#5272: an ack for a STALE epoch must not clear the pending "+
			"epoch, got %d", got)
	}
	if ss.outboundBulkAcked.Load() || ackFired9177(fired) {
		t.Error("#5272: a stale ack released the outbound-bulk gate")
	}
}

// The other #5272 arm: no pending outbound bulk at all.
func TestBulkAckWithNoPendingOutboundBulkIsRefused9177(t *testing.T) {
	ss, fired := ackEnv9177(t)
	if ss.pendingBulkAckEpoch.Load() != 0 {
		t.Fatal("fixture must start with no pending outbound bulk")
	}

	ss.handleMessage(pipeConn(t), syncMsgBulkAck, bulkAckPayload9177(9))

	if ss.outboundBulkAcked.Load() || ss.bulkEverCompleted.Load() || ackFired9177(fired) {
		t.Error("#5272: a BulkAck with NO pending outbound bulk released the gate")
	}
}

// A short ack frame is ignored rather than read as epoch 0 — pre-existing
// behaviour, asserted because the comparator change sits directly under it and a
// future edit that folds the length gate into the epoch test would be invisible
// otherwise.
func TestShortBulkAckIsIgnored9177(t *testing.T) {
	ss, fired := ackEnv9177(t)
	ss.pendingBulkAckEpoch.Store(5)

	ss.handleMessage(pipeConn(t), syncMsgBulkAck, []byte{1, 2, 3})

	if got := ss.pendingBulkAckEpoch.Load(); got != 5 {
		t.Errorf("a short BulkAck must be ignored, not parsed; pending became %d", got)
	}
	if ackFired9177(fired) {
		t.Error("a short BulkAck fired the ack callback")
	}
}
