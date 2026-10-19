package cluster

import (
	"strings"
	"testing"
	"time"
)

// #15254 (A82-03) — the abandoned-accept shape, the twin #9177 V052 did not
// cover.
//
// #9177 fixed the REFUSED-start shape: the three BulkSync* telemetry stores
// ran above the #8966 accept decision, so a refused BulkStart re-stamped
// BulkSyncStartTime and zeroed BulkSyncEndTime, flipping the status to
// "Bulk sync in progress since …" indefinitely.
//
// This is the ACCEPTED-start shape with the same symptom through a different
// statement gap. An accepted BulkStart stamps BulkSyncStartTime and zeroes
// BulkSyncEndTime (correctly — a bulk IS running). If every fabric then drops
// before the BulkEnd, handleDisconnect's full-disconnect block clears
// bulkInProgress but NOT the telemetry pair. Status therefore reports an
// in-progress bulk for the whole peer outage, and on reconnect every early
// incremental session record satisfies the session handlers'
// `StartTime > 0 && EndTime == 0` telemetry test and is counted (and, on the
// 1st/64th, Info-logged) as bulk traffic until the next accepted BulkStart
// re-stamps the pair or a BulkEnd sets an end — neither of which the abandoned
// bulk will ever do.
//
// Fix direction (issue): on full disconnect with hadBulkInProgress, stamp an
// abandoned end, and key the counter/log on bulkInProgress.
//
// The abandoned end must NOT count as a completed bulk: BulkSyncs /
// bulkEverCompleted / OnBulkSyncReceived belong to BulkEnd only (#5272). The
// stamp only closes the telemetry window the accepted start opened.

// TestAbandonedBulkDisconnectStampsEnd15254 is the defect cell: an accepted
// bulk, then a FULL disconnect, must close the status window.
func TestAbandonedBulkDisconnectStampsEnd15254(t *testing.T) {
	e := newIncEnv(t, 2)

	// An ACCEPTED BulkStart: telemetry opens (Start set, End zero).
	e.prime(0, 7, &incA)
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: the BulkStart was refused, so this cell is not measuring the accepted/abandoned shape")
	}
	if e.s.stats.BulkSyncStartTime.Load() == 0 || e.s.stats.BulkSyncEndTime.Load() != 0 {
		t.Fatalf("CONTROL FAILED: accepted BulkStart did not open the telemetry window (start=%d end=%d)",
			e.s.stats.BulkSyncStartTime.Load(), e.s.stats.BulkSyncEndTime.Load())
	}
	if out := statusFor9177(t, e.s); !strings.Contains(out, inProgressLine9177) {
		t.Fatalf("CONTROL FAILED: status does not report the running bulk:\n%s", out)
	}

	// Every fabric drops mid-bulk. handleDisconnect on the last fabric takes
	// the full-disconnect block and clears bulkInProgress.
	e.s.handleDisconnect(e.conns[0])
	e.s.handleDisconnect(e.conns[1])
	if e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: full disconnect did not clear bulkInProgress; the fixture is not on the abandoned path")
	}

	if e.s.stats.BulkSyncEndTime.Load() == 0 {
		t.Errorf("#15254: a full disconnect abandoned an in-progress bulk but left BulkSyncEndTime zero, so status reports an in-progress bulk for the whole peer outage")
	}
	out := statusFor9177(t, e.s)
	if strings.Contains(out, inProgressLine9177) {
		t.Errorf("#15254: status still reports %q after the peer fully disconnected mid-bulk:\n%s", inProgressLine9177, out)
	}
	if !strings.Contains(out, lastBulkLine9177) {
		t.Errorf("#15254: the abandoned bulk should render as %q (last, ended), not in-progress:\n%s", lastBulkLine9177, out)
	}
	// The abandoned stamp must not impersonate a completion.
	if e.s.bulkEverCompleted.Load() {
		t.Error("#15254: an abandoned bulk must not latch bulkEverCompleted — no BulkEnd arrived (#5272)")
	}
}

// The second consequence, mirroring the #9177 miscount cell: sessions that
// arrive while no bulk is running must not be counted as bulk traffic. After
// the fix the session handlers key on bulkInProgress, so neither the outage
// window nor an early post-reconnect incremental can be miscounted. On
// unfixed code the handlers key on the telemetry pair, which the abandoned
// bulk left open, so the first incremental after the disconnect is counted.
func TestAbandonedBulkDoesNotMiscountIncrementalInstalls15254(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)

	e.s.handleDisconnect(e.conns[0])
	e.s.handleDisconnect(e.conns[1])

	sessionsAtAbandon := e.s.stats.BulkSyncSessions.Load()

	// An ordinary incremental (malformed for the install path, like the 9177
	// cell — the bulk accounting above the install runs first). It arrives
	// when bulkInProgress is false: it is NOT bulk traffic.
	e.s.handleMessage(e.conns[0], syncMsgSessionV4, make([]byte, 4))
	e.s.handleMessage(e.conns[0], syncMsgSessionV6, make([]byte, 4))

	if got := e.s.stats.BulkSyncSessions.Load(); got != sessionsAtAbandon {
		t.Errorf("#15254: incremental session records with no bulk in progress were counted as bulk traffic (%d -> %d); the counter/log must key on bulkInProgress, not the telemetry pair the abandoned bulk left open",
			sessionsAtAbandon, got)
	}
}

// LOAD-BEARING CONTROL (the v29 twin stays green): session records DURING a
// genuinely running bulk must still be counted. Keying the counter on
// bulkInProgress is satisfiable by never counting, which would hide real
// bulk progress from the operator.
func TestRunningBulkStillCountsSessions15254(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: the BulkStart was refused")
	}
	before := e.s.stats.BulkSyncSessions.Load()
	e.s.handleMessage(e.conns[0], syncMsgSessionV4, make([]byte, 4))
	e.s.handleMessage(e.conns[0], syncMsgSessionV6, make([]byte, 4))
	if got := e.s.stats.BulkSyncSessions.Load(); got != before+2 {
		t.Errorf("sessions received during a running bulk must be counted as bulk traffic (%d -> %d, want %d)", before, got, before+2)
	}
}

// LOAD-BEARING CONTROL: a disconnect with NO bulk in progress must not stamp
// an end over a previously completed bulk's record. The abandoned stamp is
// gated on hadBulkInProgress; an ungated stamp would rewrite the last
// completed bulk's end (and duration) on every later outage.
func TestDisconnectWithoutBulkLeavesCompletedStats15254(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)
	e.s.handleMessage(e.conns[0], syncMsgBulkEnd, bulkEndPayload(7, &incA))
	endAfterComplete := e.s.stats.BulkSyncEndTime.Load()
	if endAfterComplete == 0 {
		t.Fatal("CONTROL FAILED: the bulk did not complete")
	}
	if e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: bulk still in progress after BulkEnd")
	}

	// Let the clock move so an ungated re-stamp is distinguishable.
	time.Sleep(2 * time.Millisecond)
	e.s.handleDisconnect(e.conns[0])
	e.s.handleDisconnect(e.conns[1])

	if got := e.s.stats.BulkSyncEndTime.Load(); got != endAfterComplete {
		t.Errorf("a full disconnect with no bulk in progress re-stamped BulkSyncEndTime (%d -> %d); the abandoned stamp must be gated on hadBulkInProgress", endAfterComplete, got)
	}
}

// LOAD-BEARING CONTROL: a PARTIAL disconnect (one fabric survives) must not
// abandon the bulk — the same peer process is still streaming on the survivor
// and its BulkEnd remains acceptable (#9716 pins the end to the starting
// connection; the receive window itself survives while the peer lives).
func TestPartialDisconnectKeepsBulkWindow15254(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: the BulkStart was refused")
	}

	e.s.handleDisconnect(e.conns[1]) // fabric 1 drops; fabric 0 survives

	if !e.s.bulkInProgress {
		t.Error("a partial disconnect tore down the in-progress bulk; only a FULL disconnect abandons it")
	}
	if e.s.stats.BulkSyncEndTime.Load() != 0 {
		t.Error("a partial disconnect stamped BulkSyncEndTime; the running bulk's telemetry window must stay open")
	}
	if out := statusFor9177(t, e.s); !strings.Contains(out, inProgressLine9177) {
		t.Errorf("with a bulk running on the surviving fabric the status must say %q:\n%s", inProgressLine9177, out)
	}
}

// A completed-then-abandoned sequence: the NEXT accepted BulkStart after an
// abandonment must re-open the window cleanly (accepted-start control, the
// #9177 cell's shape carried across the new stamp).
func TestBulkAfterAbandonmentReopensWindow15254(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 7, &incA)
	e.s.handleDisconnect(e.conns[0])
	e.s.handleDisconnect(e.conns[1])
	if e.s.stats.BulkSyncEndTime.Load() == 0 {
		t.Fatalf("#15254: abandonment left no end stamp; the reconnect cell cannot distinguish a re-open from a never-closed window")
	}

	e.prime(0, 9, &incA)
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: the post-reconnect BulkStart was refused")
	}
	if e.s.stats.BulkSyncEndTime.Load() != 0 {
		t.Error("an ACCEPTED BulkStart after an abandonment must zero BulkSyncEndTime — otherwise the status keeps reporting the abandoned bulk while a new one runs")
	}
	if e.s.stats.BulkSyncSessions.Load() != 0 {
		t.Error("an ACCEPTED BulkStart after an abandonment must zero BulkSyncSessions")
	}
	if out := statusFor9177(t, e.s); !strings.Contains(out, inProgressLine9177) {
		t.Errorf("with the reconnect bulk running the status must say %q:\n%s", inProgressLine9177, out)
	}
}
