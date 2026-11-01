package userspace

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"
)

var errTransport9651 = errors.New("dial unix /run/xpf/userspace-dp.sock: connect: resource temporarily unavailable")

// silentTrips9651 records n silent control round trips, each lasting 3 s (the
// base deadline) and starting `gap` apart from start, on the current
// generation's tracker. It returns the end of the last one.
func silentTrips9651(m *Manager, start time.Time, gap time.Duration, n int) time.Time {
	gen := m.liveTrack.generation()
	end := start
	for i := 0; i < n; i++ {
		s := start.Add(time.Duration(i) * gap)
		end = s.Add(3 * time.Second)
		m.liveTrack.noteSilent(gen, s, end)
	}
	return end
}

// TestWedgedHelperIsKilledAndRestarted9651: a helper that answered nothing for
// helperWedgeMinSpan is killed, and the kill goes through the REAL supervisor,
// which records a crash, schedules a restart and stops reporting takeover-ready.
// Since #18685 the evidence is time across round trips, and the kill normally
// comes from the per-generation watchdog; the status-loop path asks the same
// tracker, and the two kill a generation at most once between them.
func TestWedgedHelperIsKilledAndRestarted9651(t *testing.T) {
	m, cmd, rec := spawnSupervisedChild(t)
	now := time.Now()
	silentTrips9651(m, now.Add(-helperWedgeMinSpan-5*time.Second), helperWedgeMinSpan, 2)
	m.mu.Lock()
	exited := m.procSup.exited
	if m.noteStatusPollResultLocked(errTransport9651, now) {
		m.killWedgedHelperLocked(now)
	}
	m.mu.Unlock()
	awaitSupervisor(t, m, exited)
	if got := m.liveTrack.kills.Load(); got != 1 {
		t.Errorf("kills = %d, want exactly 1 (watchdog and status-loop paths must not both kill)", got)
	}
	m.mu.Lock()
	crash := m.helperCrash
	m.mu.Unlock()
	if !crash.LastExitWasCrash || crash.PID != cmd.Process.Pid {
		t.Errorf("the killed helper was not reaped as an unexpected exit: %+v", crash)
	}
	if len(rec.snapshot()) == 0 {
		t.Error("no restart was scheduled for the killed helper; the supervisor must own recovery")
	}
	if ready, _ := m.TakeoverReady(); ready {
		t.Error("TakeoverReady() = true after killing a wedged helper")
	}
}

// TestRecoveringPressureIsNeverKilled9651: any request that gets through clears
// the silence, so a helper that answers even occasionally is never restarted.
func TestRecoveringPressureIsNeverKilled9651(t *testing.T) {
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	start := time.Now()
	for round := 0; round < 5; round++ {
		base := start.Add(time.Duration(round) * 40 * time.Second)
		end := silentTrips9651(m, base, 4*time.Second, 7) // 27 s of silence
		if due, span := m.liveTrack.killDue(end); due {
			t.Fatalf("round %d: kill due after %s of silence with an answer between rounds", round, span)
		}
		m.liveTrack.noteAnswered(1, end.Add(time.Second))
	}
}

// TestInBandRefusalIsAnAnswer9651: a helper that refuses a request answered it.
func TestInBandRefusalIsAnAnswer9651(t *testing.T) {
	if answered, silent := classifyControlRoundTrip(newHelperRejection("status: busy"), true); !answered || silent {
		t.Fatalf("in-band refusal classified answered=%v silent=%v, want an answer", answered, silent)
	}
}

// TestFastFailuresNeedTheMinimumSpan9651: many silent round trips inside the
// span are not enough; the span is.
func TestFastFailuresNeedTheMinimumSpan9651(t *testing.T) {
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	start := time.Now()
	gen := m.liveTrack.generation()
	for i := 0; i < 200; i++ {
		s := start.Add(time.Duration(i) * 100 * time.Millisecond)
		m.liveTrack.noteSilent(gen, s, s.Add(50*time.Millisecond))
	}
	if due, span := m.liveTrack.killDue(start.Add(helperWedgeMinSpan - time.Second)); due {
		t.Fatalf("kill due after %s, inside the %s minimum span", span, helperWedgeMinSpan)
	}
	if due, _ := m.liveTrack.killDue(start.Add(helperWedgeMinSpan)); !due {
		t.Fatal("no kill once the silence spanned the minimum")
	}
}

// TestNoKillInsideTheRGActivationGrace9651: a wedge declared just after an
// update_ha_state waits out the grace.
func TestNoKillInsideTheRGActivationGrace9651(t *testing.T) {
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	start := time.Now()
	end := silentTrips9651(m, start, helperWedgeMinSpan, 2)
	rg := end.Add(-2 * time.Second)
	m.liveTrack.noteRGActivate(rg)
	if due, _ := m.liveTrack.killDue(end); due {
		t.Fatalf("kill due %s after an RG activation", 2*time.Second)
	}
	if due, _ := m.liveTrack.killDue(rg.Add(helperWedgeRGGrace)); !due {
		t.Fatal("still no kill once the RG grace elapsed")
	}
}

// TestStatusLoopWiresTheLivenessCount9651 binds the wiring: a status result
// updates poll health before the stale-sequence publication fence.
func TestStatusLoopWiresTheLivenessCount9651(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "process_status.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var loop *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "statusLoop" {
			loop = fn
		}
	}
	if loop == nil {
		t.Fatal("statusLoop not found")
	}

	var healthStmt, sequenceFence *ast.IfStmt
	ast.Inspect(loop, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if expr, ok := s.Cond.(*ast.BinaryExpr); ok {
			if left, ok := expr.X.(*ast.Ident); ok && left.Name == "pollErr" {
				if expr.Op == token.EQL && lenExprCalls(s.Body, "noteStatusPollResultLocked") != 0 {
					healthStmt = s
				}
			}
			if left, ok := expr.X.(*ast.SelectorExpr); ok &&
				left.Sel.Name == "lastStatusSeq" && expr.Op == token.NEQ {
				if right, ok := expr.Y.(*ast.Ident); ok && right.Name == "pollStatusSeq" {
					sequenceFence = s
				}
			}
		}
		return true
	})
	if healthStmt == nil || sequenceFence == nil {
		t.Fatal("status poll-health branch or stale-sequence fence not found")
	}
	if healthStmt.Pos() >= sequenceFence.Pos() {
		t.Error("status poll-health accounting must run before the #16653 sequence fence")
	}
	if got := lenExprCalls(healthStmt, "noteStatusPollResultLocked"); got != 3 {
		t.Errorf("status poll-health branch has %d note calls, want success, decode-answer, and failure accounting", got)
	}
	if got := lenExprCalls(healthStmt, "killWedgedHelperLocked"); got != 1 {
		t.Errorf("status poll-health branch has %d wedge kills, want 1 on a counted failure", got)
	}
}

func lenExprCalls(n ast.Node, name string) int {
	count := 0
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				count++
			}
		}
		return true
	})
	return count
}

// --- #18293: decode failures are answers, not silence ---

var errDecode18293 = &statusDecodeError{cause: errors.New("json: cannot unmarshal string into Go struct field")}

// TestUndecodableAnswersNeverKill18293 is the confirming cell from #18293: a
// helper that answers every poll with an undecodable status is never declared
// wedged, each poll is counted as a decode error, and no silence starts.
func TestUndecodableAnswersNeverKill18293(t *testing.T) {
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	before := StatusPollDecodeErrors()
	start := time.Now()
	for i := 0; i < 90; i++ {
		if answered, silent := classifyControlRoundTrip(errDecode18293, true); answered || silent {
			t.Fatalf("undecodable reply classified answered=%v silent=%v, want neither", answered, silent)
		}
		if m.noteStatusPollResultLocked(errDecode18293, start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("declared wedged at poll %d on answered-but-undecodable polls (#18293)", i+1)
		}
	}
	if got, want := m.liveness.decodeErrors, uint64(90); got != want {
		t.Fatalf("per-manager decodeErrors = %d, want %d", got, want)
	}
	if got, want := StatusPollDecodeErrors()-before, uint64(90); got != want {
		t.Fatalf("StatusPollDecodeErrors moved by %d, want %d (decode error/metric must surface)", got, want)
	}
	if due, _ := m.liveTrack.killDue(start.Add(90 * time.Second)); due {
		t.Fatal("undecodable answers started a silence")
	}
}

// TestDecodeFailureNeitherAdvancesNorResetsSilence18293: a decode failure in
// the middle of genuine silence leaves the silence untouched, so it still kills
// on the original schedule.
func TestDecodeFailureNeitherAdvancesNorResetsSilence18293(t *testing.T) {
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	start := time.Now()
	silentTrips9651(m, start, 10*time.Second, 2) // silence from start
	// A decode failure: classified as neither, so nothing is recorded.
	if answered, silent := classifyControlRoundTrip(errDecode18293, true); answered || silent {
		t.Fatalf("decode failure classified answered=%v silent=%v", answered, silent)
	}
	if m.noteStatusPollResultLocked(errDecode18293, start.Add(20*time.Second)) {
		t.Fatal("a decode failure asked for a kill")
	}
	silentTrips9651(m, start.Add(25*time.Second), time.Second, 1)
	if due, _ := m.liveTrack.killDue(start.Add(helperWedgeMinSpan)); !due {
		t.Fatal("silence around a decode failure did not kill on the original schedule")
	}
}

// TestSilentHelperStillKilledOnSchedule18293: the other half of the confirming
// cell, genuine silence still kills, and silence never moves the decode counter.
func TestSilentHelperStillKilledOnSchedule18293(t *testing.T) {
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	before := StatusPollDecodeErrors()
	start := time.Now()
	end := silentTrips9651(m, start, helperWedgeMinSpan, 2)
	if !m.noteStatusPollResultLocked(errTransport9651, end) {
		t.Fatal("a silent helper was not declared wedged after the minimum span")
	}
	if got := StatusPollDecodeErrors() - before; got != 0 {
		t.Fatalf("silence moved the decode counter by %d, want 0", got)
	}
}

// TestStatusDecodeClassification18293 pins the error class itself: it matches
// errStatusDecode, preserves the cause verbatim, and does not collide with
// the refusal or silence classes.
func TestStatusDecodeClassification18293(t *testing.T) {
	cause := errors.New("json: cannot unmarshal number into Go value of type string")
	err := error(&statusDecodeError{cause: cause})
	if !errors.Is(err, errStatusDecode) {
		t.Fatal("statusDecodeError does not match errStatusDecode")
	}
	if !errors.Is(err, cause) {
		t.Fatal("statusDecodeError lost its cause")
	}
	if err.Error() != cause.Error() {
		t.Fatalf("message = %q, want verbatim cause %q", err.Error(), cause.Error())
	}
	if errors.Is(err, errHelperRejected) || errors.Is(err, errHelperPostTeardown) {
		t.Fatal("decode failure misclassified as a helper refusal")
	}
	if errors.Is(errTransport9651, errStatusDecode) || errors.Is(newHelperRejection("busy"), errStatusDecode) {
		t.Fatal("silence/refusal misclassified as a decode failure")
	}
}
