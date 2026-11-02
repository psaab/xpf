package userspace

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTracker18685 is a fresh generation-1 tracker started at t0.
func newTracker18685(t0 time.Time) *helperLivenessTracker {
	tr := &helperLivenessTracker{}
	tr.reset(1, t0, false)
	return tr
}

// TestKillOnTimeAtTheWedgedCadence18685 is the #18685 confirming cell. While a
// helper is wedged, every queued control caller burns its 3 s deadline, so the
// status poll itself only gets a turn about every 90 s. The kill must still
// come about helperWedgeMinSpan after the helper went silent, not after 30
// polls (~45 minutes at that cadence, which is what #9651 did on loss).
func TestKillOnTimeAtTheWedgedCadence18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	tr.noteAnswered(1, t0)
	silence := t0.Add(time.Second) // the first unanswered round trip starts here
	var killedAt time.Duration
	// Other verbs time out back to back (3 s each); a status poll lands at
	// +90 s, +180 s, ... The watchdog evaluates once a second.
	next := silence
	for sec := 1; sec <= 200 && killedAt == 0; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		for !next.Add(3 * time.Second).After(now) {
			tr.noteSilent(1, next, next.Add(3*time.Second))
			next = next.Add(3 * time.Second)
		}
		if due, _ := tr.killDue(now); due {
			killedAt = now.Sub(silence)
		}
	}
	if killedAt < helperWedgeMinSpan || killedAt > helperWedgeMinSpan+3*time.Second {
		t.Fatalf("kill came %s after the helper went silent, want within [%s, %s]", killedAt, helperWedgeMinSpan, helperWedgeMinSpan+3*time.Second)
	}
}

// TestSparseSilenceKillsAtTheSecondRoundTrip18685: with ONLY status polls, one
// per 90 s, the kill comes at the second unanswered one (silence 90 s), not
// after 30 of them.
func TestSparseSilenceKillsAtTheSecondRoundTrip18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	first := t0.Add(90 * time.Second)
	tr.noteSilent(1, first, first.Add(3*time.Second))
	if due, _ := tr.killDue(first.Add(80 * time.Second)); due {
		t.Fatal("one unanswered round trip killed the helper")
	}
	second := first.Add(90 * time.Second)
	tr.noteSilent(1, second, second.Add(3*time.Second))
	if due, span := tr.killDue(second.Add(3 * time.Second)); !due {
		t.Fatalf("two unanswered round trips %s apart did not kill (span %s)", 90*time.Second, span)
	}
}

// TestDemoteBeforeKill18685: two silent round trips spanning the demote span
// raise the suspected verdict (reversible) long before a kill is due, and one
// silent round trip alone does not.
func TestDemoteBeforeKill18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	tr.noteSilent(1, t0, t0.Add(3*time.Second))
	if tr.wedgeSuspected(t0.Add(20 * time.Second)) {
		t.Fatal("one silent round trip raised the wedge verdict")
	}
	tr.noteSilent(1, t0.Add(3*time.Second), t0.Add(6*time.Second))
	if !tr.wedgeSuspected(t0.Add(6 * time.Second)) {
		t.Fatalf("two silent round trips spanning %s did not raise the verdict", 6*time.Second)
	}
	if due, _ := tr.killDue(t0.Add(6 * time.Second)); due {
		t.Fatal("kill due at the demote bound; the kill must wait for helperWedgeMinSpan")
	}
}

// TestSlowButAnsweringNeverDemotes18685: answers that each take up to just
// under the deadline, and a lone timeout followed by an answer, never raise
// the verdict.
func TestSlowButAnsweringNeverDemotes18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	at := t0
	for i := 0; i < 100; i++ {
		at = at.Add(2900 * time.Millisecond)
		tr.noteAnswered(1, at)
		if i%10 == 0 {
			tr.noteSilent(1, at, at.Add(3*time.Second))
			at = at.Add(3 * time.Second)
			tr.noteAnswered(1, at.Add(100*time.Millisecond))
		}
		if tr.wedgeSuspected(at) {
			t.Fatalf("slow-but-answering helper raised the verdict at round %d", i)
		}
	}
}

// heartbeats18685 builds n worker heartbeats all at hb.
func heartbeats18685(n int, hb time.Time) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = hb
	}
	return out
}

// TestFrozenWorkerDemotesThenClears18685: the primary wedge input. One worker
// whose heartbeat stops moving while the control thread keeps answering (the
// #18655 busy convoy measured 16-22 s on tcp) raises the verdict after
// helperWorkerFrozenAfter; it clears only after the worker moves again and the
// helper has looked healthy for the hysteresis window.
func TestFrozenWorkerDemotesThenClears18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	frozenHB := t0
	var raisedAt time.Duration
	for sec := 1; sec <= 30; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		hbs := heartbeats18685(6, now)
		hbs[2] = frozenHB // worker 2 stopped
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, hbs, true)
		if raisedAt == 0 && tr.wedgeSuspected(now) {
			raisedAt = now.Sub(t0)
		}
	}
	if raisedAt < helperWorkerFrozenAfter || raisedAt > helperWorkerFrozenAfter+2*time.Second {
		t.Fatalf("frozen worker raised the verdict after %s, want about %s", raisedAt, helperWorkerFrozenAfter)
	}
	if due, _ := tr.killDue(t0.Add(30 * time.Second)); due {
		t.Fatal("a frozen worker with an answering control thread was killed inside helperWorkerFrozenKillAfter; it must only demote")
	}
	// The worker moves again: still raised inside the hysteresis window...
	resume := t0.Add(31 * time.Second)
	tr.noteAnswered(1, resume)
	tr.noteStatus(1, resume, heartbeats18685(6, resume), true)
	if !tr.wedgeSuspected(resume) {
		t.Fatal("verdict cleared on the first healthy status; it must wait out the hysteresis")
	}
	// ...and clears once healthy for the window with enough answers.
	for sec := 32; sec <= 40; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, heartbeats18685(6, now), true)
	}
	if tr.wedgeSuspected(t0.Add(40 * time.Second)) {
		t.Fatal("verdict did not clear after the worker resumed and the helper looked healthy")
	}
}

// TestFrozenWorkerKillsAfterTheLongBound18685: a worker still frozen after
// helperWorkerFrozenKillAfter is not coming back, so the helper is killed even
// though the control thread answers.
func TestFrozenWorkerKillsAfterTheLongBound18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	for sec := 1; sec <= int((helperWorkerFrozenKillAfter+2*time.Second)/time.Second); sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		hbs := heartbeats18685(4, now)
		hbs[0] = t0
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, hbs, true)
	}
	if due, _ := tr.killDue(t0.Add(helperWorkerFrozenKillAfter + 2*time.Second)); !due {
		t.Fatalf("a worker frozen for %s did not kill the helper", helperWorkerFrozenKillAfter)
	}
}

// TestNoStatusNoFreeze18685: freeze is judged against the latest answered
// status, not the wall clock, so a stretch with no polls at all (a RETH MAC
// link cycle skips the status loop and parks the workers) never ages a worker
// into "frozen".
func TestNoStatusNoFreeze18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	tr.noteAnswered(1, t0)
	tr.noteStatus(1, t0, heartbeats18685(6, t0), true)
	if tr.wedgeSuspected(t0.Add(5 * time.Minute)) {
		t.Fatal("five minutes without a status poll aged the workers into frozen")
	}
}

// TestUnexpectedExitInheritsNotReadyUntilArmed18685 (#18697): the generation
// started after an unexpected exit starts not-ready and stays so until it
// reports ForwardingArmed AND then looks healthy for the hysteresis window.
func TestUnexpectedExitInheritsNotReadyUntilArmed18685(t *testing.T) {
	t0 := time.Now()
	tr := &helperLivenessTracker{}
	tr.reset(2, t0, true)
	if !tr.wedgeSuspected(t0) {
		t.Fatal("a generation after an unexpected exit started ready")
	}
	for sec := 1; sec <= 20; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		tr.noteAnswered(2, now)
		tr.noteStatus(2, now, heartbeats18685(6, now), false)
	}
	if !tr.wedgeSuspected(t0.Add(20 * time.Second)) {
		t.Fatal("cleared while the new helper had never reported ForwardingArmed")
	}
	for sec := 21; sec <= 30; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		tr.noteAnswered(2, now)
		tr.noteStatus(2, now, heartbeats18685(6, now), true)
	}
	if tr.wedgeSuspected(t0.Add(30 * time.Second)) {
		t.Fatal("still not ready after the new helper armed and looked healthy")
	}
	// An intentional respawn does not inherit.
	tr.reset(3, t0.Add(31*time.Second), false)
	if tr.wedgeSuspected(t0.Add(31 * time.Second)) {
		t.Fatal("an intentional respawn started not-ready")
	}
}

// TestStaleGenerationEvidenceIsIgnored18685: a round trip begun against the old
// helper and finished after a respawn says nothing about the new one.
func TestStaleGenerationEvidenceIsIgnored18685(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	tr.reset(2, t0, false)
	tr.noteSilent(1, t0, t0.Add(3*time.Second))
	tr.noteSilent(1, t0.Add(3*time.Second), t0.Add(40*time.Second))
	if due, _ := tr.killDue(t0.Add(40 * time.Second)); due {
		t.Fatal("silence recorded against the previous generation killed the new one")
	}
}

// TestWatchdogKillsWithoutManagerMutex18685: the per-generation watchdog kills
// the generation's own process while another goroutine holds m.mu, which is
// what a caller blocked in a control round trip does. If the kill needed m.mu
// it would wait as long as the round trips do.
func TestWatchdogKillsWithoutManagerMutex18685(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)
	now := time.Now()
	gen := m.liveTrack.generation()
	start := now.Add(-helperWedgeMinSpan - 5*time.Second)
	m.liveTrack.noteSilent(gen, start, start.Add(3*time.Second))
	m.liveTrack.noteSilent(gen, now.Add(-3*time.Second), now)
	m.mu.Lock()
	exited := m.procSup.exited
	waited := make(chan error, 1)
	go func() {
		// cmd.Wait belongs to the supervisor; observe the exit via the
		// generation's channel instead.
		select {
		case <-exited:
			waited <- nil
		case <-time.After(5 * time.Second):
			waited <- os.ErrDeadlineExceeded
		}
	}()
	err := <-waited
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("the watchdog did not kill pid %d within 5 s while m.mu was held", cmd.Process.Pid)
	}
	if got := m.liveTrack.kills.Load(); got != 1 {
		t.Fatalf("kills = %d, want 1", got)
	}
}

// TestRoundTripSiteRecordsLiveness18685 binds the wiring: requestDetailedAtSocket
// records an answer for a reply and silence for an EOF with no bytes, for a
// verb other than status.
func TestRoundTripSiteRecordsLiveness18685(t *testing.T) {
	dir, err := os.MkdirTemp("", "x18685rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	answer := make(chan bool, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			_ = json.NewDecoder(conn).Decode(&req)
			if <-answer {
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}
			_ = conn.Close()
		}
	}()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.liveTrack.reset(1, time.Now(), false)

	answer <- false
	if _, err := m.requestDetailedAtSocket(ControlRequest{Type: "update_neighbors"}, sock); err == nil {
		t.Fatal("a close with no reply returned nil")
	}
	m.liveTrack.mu.Lock()
	silent := m.liveTrack.silentTrips
	m.liveTrack.mu.Unlock()
	if silent != 1 {
		t.Fatalf("silentTrips = %d after an EOF with no bytes, want 1", silent)
	}
	answer <- true
	if _, err := m.requestDetailedAtSocket(ControlRequest{Type: "update_neighbors"}, sock); err != nil {
		t.Fatalf("answered round trip: %v", err)
	}
	m.liveTrack.mu.Lock()
	silent, since := m.liveTrack.silentTrips, m.liveTrack.silentSince
	m.liveTrack.mu.Unlock()
	if silent != 0 || !since.IsZero() {
		t.Fatalf("an answer did not clear the silence: silentTrips=%d silentSince=%v", silent, since)
	}
}

// --- #18704 review fold: judge a frozen worker by heartbeat AGE ---

// TestJitteredFrozenHeartbeatStillDemotes18704 is the review's blocking case.
// The helper re-derives every heartbeat on every status call from two fresh
// clock reads, so a frozen worker's heartbeat wobbles by microseconds from poll
// to poll. Change detection never saw a freeze; age must.
func TestJitteredFrozenHeartbeatStillDemotes18704(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	var raisedAt time.Duration
	for sec := 1; sec <= 30 && raisedAt == 0; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		hbs := heartbeats18685(6, now.Add(-200*time.Millisecond))
		// Worker 3 stopped at t0; its re-derived heartbeat jitters by up to
		// +/-15 us on every call, as measured on the real helper.
		jitter := time.Duration((sec*7919)%31-15) * time.Microsecond
		hbs[3] = t0.Add(jitter)
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, hbs, true)
		if tr.wedgeSuspected(now) {
			raisedAt = now.Sub(t0)
		}
	}
	if raisedAt < helperWorkerFrozenAfter || raisedAt > helperWorkerFrozenAfter+2*time.Second {
		t.Fatalf("jittered frozen heartbeat raised the verdict after %s, want about %s", raisedAt, helperWorkerFrozenAfter)
	}
}

// TestRealHelperHeartbeatFormatThroughDecode18704 is the contract cell. Status
// JSON in the helper's own heartbeat format (RFC 3339 at nanosecond resolution,
// the shape captured from a live udp helper: "2026-11-01T11:03:26.775281841Z"),
// decoded by the real Go ProcessStatus decode, re-derived with fresh
// nanoseconds every poll for a frozen worker, must reach the frozen verdict.
func TestRealHelperHeartbeatFormatThroughDecode18704(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 11, 3, 26, 775281841, time.UTC)
	tr := newTracker18685(t0)
	raised := false
	for sec := 1; sec <= 15; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		live := now.Add(-150 * time.Millisecond).Format(time.RFC3339Nano)
		frozen := t0.Add(time.Duration(sec*313%997) * time.Nanosecond).Format(time.RFC3339Nano)
		doc := `{"pid":4242,"forwarding_armed":true,"worker_heartbeats":["` + live + `","` + frozen + `","` + live + `"]}`
		var st ProcessStatus
		if err := json.Unmarshal([]byte(doc), &st); err != nil {
			t.Fatalf("decode %s: %v", doc, err)
		}
		if len(st.WorkerHeartbeats) != 3 || st.WorkerHeartbeats[1].IsZero() {
			t.Fatalf("decoded heartbeats %v from %s", st.WorkerHeartbeats, doc)
		}
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, st.WorkerHeartbeats, st.ForwardingArmed)
		raised = raised || tr.wedgeSuspected(now)
	}
	if !raised {
		t.Fatal("a frozen worker in the helper's own heartbeat format never raised the verdict")
	}
}

// TestDisarmedWorkersNeverFreeze18704: heartbeats of a helper that is not
// forwarding-armed are parked workers, not frozen ones.
func TestDisarmedWorkersNeverFreeze18704(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	for sec := 1; sec <= 30; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, heartbeats18685(6, t0), false)
	}
	if tr.wedgeSuspected(t0.Add(30 * time.Second)) {
		t.Fatal("a disarmed helper's parked workers raised the frozen verdict")
	}
}

// TestFirstStatusAfterAGapNeedsConfirmation18704: one status showing an old
// heartbeat (the first poll after a link cycle parked the workers) is not a
// freeze; the next status must agree.
func TestFirstStatusAfterAGapNeedsConfirmation18704(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	gapEnd := t0.Add(30 * time.Second)
	tr.noteAnswered(1, gapEnd)
	tr.noteStatus(1, gapEnd, heartbeats18685(4, t0), true) // parked through the gap
	if tr.wedgeSuspected(gapEnd) {
		t.Fatal("a single status after a polling gap raised the frozen verdict")
	}
	next := gapEnd.Add(time.Second)
	tr.noteAnswered(1, next)
	tr.noteStatus(1, next, heartbeats18685(4, next), true) // workers resumed
	if tr.wedgeSuspected(next) {
		t.Fatal("workers that resumed after the gap were judged frozen")
	}
}

// TestStaleGenerationAnswerDoesNotClearSilence18704 (review LOW b): an answer
// from a round trip begun against the PREVIOUS generation says nothing about
// the current helper and must not clear its silence.
func TestStaleGenerationAnswerDoesNotClearSilence18704(t *testing.T) {
	t0 := time.Now()
	tr := &helperLivenessTracker{}
	tr.reset(2, t0, false)
	tr.noteSilent(2, t0, t0.Add(3*time.Second))
	tr.noteSilent(2, t0.Add(30*time.Second), t0.Add(33*time.Second))
	tr.noteAnswered(1, t0.Add(33*time.Second)) // a late reply to generation 1
	if due, span := tr.killDue(t0.Add(33 * time.Second)); !due {
		t.Fatalf("a stale-generation answer cleared the current generation's silence (span %s)", span)
	}
}

// TestIntentionalStopRetiresTheGeneration18704 (review LOW a): after an
// intentional stop, silence recorded against the stopped helper cannot accrue
// into a verdict however long the stop-to-respawn takes.
func TestIntentionalStopRetiresTheGeneration18704(t *testing.T) {
	t0 := time.Now()
	tr := newTracker18685(t0)
	tr.noteSilent(1, t0, t0.Add(3*time.Second))
	tr.retire()
	tr.noteSilent(1, t0.Add(3*time.Second), t0.Add(60*time.Second))
	if tr.wedgeSuspected(t0.Add(60 * time.Second)) {
		t.Fatal("silence after an intentional stop raised the wedge verdict")
	}
	if due, _ := tr.killDue(t0.Add(60 * time.Second)); due {
		t.Fatal("silence after an intentional stop made a kill due")
	}
}

// TestManagerMutexWaitIsNotHeartbeatAge18704 (review MINOR): the heartbeat-age
// reference is when the status round trip RETURNED. A healthy helper whose
// replies then wait behind a long m.mu holder, on two consecutive polls, must
// not look frozen. Before the fix the reference was taken after re-acquiring
// m.mu, so the wait was added to every worker's age.
func TestManagerMutexWaitIsNotHeartbeatAge18704(t *testing.T) {
	oldInterval, oldFrozen := statusLoopInterval, helperWorkerFrozenAfter
	statusLoopInterval, helperWorkerFrozenAfter = 5*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { statusLoopInterval, helperWorkerFrozenAfter = oldInterval, oldFrozen })

	m, _ := stalePollManager16653(t)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	var polls atomic.Int32
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		st := armedStatus16653()
		if req.Type == "status" {
			// A healthy helper: every worker heartbeat is fresh at the
			// moment the reply is built.
			now := time.Now()
			st.WorkerHeartbeats = []time.Time{now, now, now, now}
			if polls.Add(1) <= 2 {
				// Off-lock, mid round trip: let the test take m.mu so the
				// loop waits for it after this reply returns.
				entered <- struct{}{}
				<-proceed
			}
		}
		if status != nil {
			*status = *st
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.statusLoop(ctx, false) }()
	t.Cleanup(func() { cancel(); <-done })

	// Two consecutive polls each return a healthy reply and then wait 500 ms,
	// more than the shrunken 300 ms freeze bound, for m.mu.
	for range 2 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("the status loop never reached a status round trip")
		}
		m.mu.Lock()
		proceed <- struct{}{}
		time.Sleep(500 * time.Millisecond)
		m.mu.Unlock()
	}
	deadline := time.Now().Add(2 * time.Second)
	for polls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.liveTrack.wedgeSuspected(time.Now()) {
		t.Fatal("waiting on m.mu after a healthy reply made the workers look frozen")
	}
}

// TestAnswerAgeUndefinedWithoutALiveGeneration18704 (review LOW b): the answer
// age is negative (undefined) before any generation and after an intentional
// stop, rather than climbing through a planned stop-to-respawn.
func TestAnswerAgeUndefinedWithoutALiveGeneration18704(t *testing.T) {
	var tr helperLivenessTracker
	if got := tr.answerAge(time.Now()); got >= 0 {
		t.Fatalf("answer age before any generation = %s, want negative", got)
	}
	t0 := time.Now()
	tr.reset(1, t0, false)
	if got := tr.answerAge(t0.Add(time.Second)); got != time.Second {
		t.Fatalf("answer age of a live generation = %s, want 1s", got)
	}
	tr.retire()
	if got := tr.answerAge(t0.Add(time.Minute)); got >= 0 {
		t.Fatalf("answer age after an intentional stop = %s, want negative", got)
	}
}

// lockProbeHandler18704 records, for every log record, whether the tracker
// mutex was free at the moment the record was emitted.
type lockProbeHandler18704 struct {
	tr      *helperLivenessTracker
	mu      sync.Mutex
	records []string
	locked  int
}

func (h *lockProbeHandler18704) Enabled(context.Context, slog.Level) bool { return true }
func (h *lockProbeHandler18704) Handle(_ context.Context, r slog.Record) error {
	free := h.tr.mu.TryLock()
	if free {
		h.tr.mu.Unlock()
	}
	h.mu.Lock()
	h.records = append(h.records, r.Message)
	if !free {
		h.locked++
	}
	h.mu.Unlock()
	return nil
}
func (h *lockProbeHandler18704) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *lockProbeHandler18704) WithGroup(string) slog.Handler      { return h }

// TestTransitionLogsAreEmittedOutsideTheTrackerLock18704 (review nit): the
// raise and clear lines are built under t.mu but written after it is released,
// so a blocked stderr or journald can never stall the lock-free readers (the
// transit tick reads the verdict through HelperElectionNotReady).
func TestTransitionLogsAreEmittedOutsideTheTrackerLock18704(t *testing.T) {
	tr := &helperLivenessTracker{}
	h := &lockProbeHandler18704{tr: tr}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })

	t0 := time.Now()
	tr.reset(1, t0, true) // inherited: logs the #18697 hold
	tr.noteSilent(1, t0, t0.Add(3*time.Second))
	tr.noteSilent(1, t0.Add(3*time.Second), t0.Add(6*time.Second)) // raise
	for sec := 7; sec <= 20; sec++ {
		now := t0.Add(time.Duration(sec) * time.Second)
		tr.noteAnswered(1, now)
		tr.noteStatus(1, now, heartbeats18685(2, now), true) // armed + healthy: clear
	}
	tr.wedgeSuspected(t0.Add(21 * time.Second))
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) < 2 {
		t.Fatalf("expected the hold/raise and the clear lines, got %v", h.records)
	}
	if h.locked != 0 {
		t.Fatalf("%d of %d transition log lines were emitted while the tracker mutex was held: %v", h.locked, len(h.records), h.records)
	}
}
