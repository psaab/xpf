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

// feed9651 records n failed polls one second apart starting at start, and
// returns the index (1-based) of the first poll that asked for a kill, or 0.
func feed9651(m *Manager, err error, start time.Time, n int) int {
	for i := 0; i < n; i++ {
		if m.noteStatusPollResultLocked(err, start.Add(time.Duration(i)*time.Second)) {
			return i + 1
		}
	}
	return 0
}

// TestWedgedHelperIsKilledAndRestarted9651: 30 unanswered polls over 30s ask
// for a kill, and the kill goes through the REAL supervisor, which records a
// crash, schedules a restart and stops reporting takeover-ready.
func TestWedgedHelperIsKilledAndRestarted9651(t *testing.T) {
	m, cmd, rec := spawnSupervisedChild(t)
	start := time.Now()
	m.mu.Lock()
	at := feed9651(m, errTransport9651, start, helperWedgeFailedPolls+1)
	exited := m.procSup.exited
	if at == 0 {
		m.mu.Unlock()
		t.Fatal("a helper that answered no poll for 30s was never declared wedged")
	}
	m.killWedgedHelperLocked(start.Add(time.Duration(at-1) * time.Second))
	kills := m.liveness.kills
	m.mu.Unlock()
	if at != helperWedgeFailedPolls+1 {
		t.Errorf("declared wedged at poll %d, want %d (count %d AND span %s)", at, helperWedgeFailedPolls+1, helperWedgeFailedPolls, helperWedgeMinSpan)
	}
	if kills != 1 {
		t.Errorf("kills = %d, want 1", kills)
	}
	awaitSupervisor(t, m, exited)
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

// TestRecoveringPressureIsNeverKilled9651: any poll that gets through starts the
// count over, so a helper that answers even occasionally is never restarted.
func TestRecoveringPressureIsNeverKilled9651(t *testing.T) {
	m := &Manager{}
	start := time.Now()
	for round := 0; round < 5; round++ {
		base := start.Add(time.Duration(round*helperWedgeFailedPolls) * time.Second)
		if at := feed9651(m, errTransport9651, base, helperWedgeFailedPolls-1); at != 0 {
			t.Fatalf("round %d: declared wedged at poll %d with an answer between rounds", round, at)
		}
		m.noteStatusPollResultLocked(nil, base.Add(time.Duration(helperWedgeFailedPolls-1)*time.Second))
	}
}

// TestInBandRefusalIsAnAnswer9651: a helper that refuses the status request
// answered it, so refusals never count toward a wedge.
func TestInBandRefusalIsAnAnswer9651(t *testing.T) {
	m := &Manager{}
	if at := feed9651(m, newHelperRejection("status: busy"), time.Now(), 3*helperWedgeFailedPolls); at != 0 {
		t.Fatalf("declared wedged at poll %d on in-band refusals", at)
	}
	if at := feed9651(m, errTransport9651, time.Now(), helperWedgeFailedPolls-1); at != 0 {
		t.Fatalf("refusals leaked into the transport count: wedged at poll %d", at)
	}
}

// TestFastFailuresNeedTheMinimumSpan9651: the count alone is not enough.
func TestFastFailuresNeedTheMinimumSpan9651(t *testing.T) {
	m := &Manager{}
	start := time.Now()
	for i := 0; i < helperWedgeFailedPolls*2; i++ {
		if m.noteStatusPollResultLocked(errTransport9651, start.Add(time.Duration(i)*100*time.Millisecond)) {
			t.Fatalf("declared wedged after %s, inside the %s minimum span", time.Duration(i)*100*time.Millisecond, helperWedgeMinSpan)
		}
	}
	if !m.noteStatusPollResultLocked(errTransport9651, start.Add(helperWedgeMinSpan)) {
		t.Fatal("not declared wedged once both the count and the span were reached")
	}
}

// TestSlowFailuresNeedTheFullCount9651: at the real 1s cadence the span binds
// before the count does, so the count is only observable when polls fail
// slowly. Failures 3s apart (the base control deadline) reach the span at the
// 11th poll but must not be declared wedged until the 30th.
func TestSlowFailuresNeedTheFullCount9651(t *testing.T) {
	m := &Manager{}
	start := time.Now()
	for i := 1; i <= helperWedgeFailedPolls; i++ {
		got := m.noteStatusPollResultLocked(errTransport9651, start.Add(time.Duration(i-1)*3*time.Second))
		if want := i == helperWedgeFailedPolls; got != want {
			t.Fatalf("poll %d (%s in): wedged=%v, want %v", i, time.Duration(i-1)*3*time.Second, got, want)
		}
	}
}

// TestNoKillInsideTheRGActivationGrace9651: a wedge declared just after an
// update_ha_state waits out the grace.
func TestNoKillInsideTheRGActivationGrace9651(t *testing.T) {
	m := &Manager{}
	start := time.Now()
	last := start.Add(time.Duration(helperWedgeFailedPolls) * time.Second)
	m.lastRGActivateTime = last.Add(-2 * time.Second)
	if at := feed9651(m, errTransport9651, start, helperWedgeFailedPolls+1); at != 0 {
		t.Fatalf("declared wedged at poll %d, %s after an RG activation", at, 2*time.Second)
	}
	if !m.noteStatusPollResultLocked(errTransport9651, m.lastRGActivateTime.Add(helperWedgeRGGrace)) {
		t.Fatal("still not declared wedged once the RG grace elapsed")
	}
}

// TestStatusLoopWiresTheLivenessCount9651 binds the wiring: statusLoop's
// answered branch resets the count, and its failed branch feeds it and kills.
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
	var ifStmt *ast.IfStmt
	ast.Inspect(loop, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || s.Init == nil || s.Else == nil {
			return true
		}
		found := false
		ast.Inspect(s.Init, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok && id.Name == "pollErr" {
				found = true
			}
			return true
		})
		if found {
			ifStmt = s
			return false
		}
		return true
	})
	if ifStmt == nil {
		t.Fatal("the status request branch in statusLoop was not found")
	}
	calls := func(n ast.Node, name string) bool {
		hit := false
		ast.Inspect(n, func(x ast.Node) bool {
			if c, ok := x.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
					hit = true
				}
			}
			return true
		})
		return hit
	}
	if !calls(ifStmt.Body, "noteStatusPollResultLocked") {
		t.Error("an answered status poll no longer resets the #9651 wedge count")
	}
	if !calls(ifStmt.Else, "noteStatusPollResultLocked") || !calls(ifStmt.Else, "killWedgedHelperLocked") {
		t.Error("a failed status poll no longer feeds the #9651 wedge count or kills a wedged helper")
	}
}

// --- #18293: decode failures are answers, not silence ---

var errDecode18293 = &statusDecodeError{cause: errors.New("json: cannot unmarshal string into Go struct field")}

// TestUndecodableAnswersNeverKill18293 is the confirming cell from #18293:
// a helper that answers every poll with an undecodable status payload for
// more than helperWedgeFailedPolls polls is never declared wedged, each poll
// is counted as a decode error, and the silence streak never starts.
func TestUndecodableAnswersNeverKill18293(t *testing.T) {
	m := &Manager{}
	before := StatusPollDecodeErrors()
	if at := feed9651(m, errDecode18293, time.Now(), 3*helperWedgeFailedPolls); at != 0 {
		t.Fatalf("declared wedged at poll %d on answered-but-undecodable polls (#18293)", at)
	}
	if m.liveness.failures != 0 || !m.liveness.firstFailure.IsZero() {
		t.Fatalf("decode failures leaked into the wedge count: failures=%d firstFailure=%v", m.liveness.failures, m.liveness.firstFailure)
	}
	if got, want := m.liveness.decodeErrors, uint64(3*helperWedgeFailedPolls); got != want {
		t.Fatalf("per-manager decodeErrors = %d, want %d", got, want)
	}
	if got, want := StatusPollDecodeErrors()-before, uint64(3*helperWedgeFailedPolls); got != want {
		t.Fatalf("StatusPollDecodeErrors moved by %d, want %d (decode error/metric must surface)", got, want)
	}
	if m.liveness.kills != 0 {
		t.Fatalf("kills = %d, want 0", m.liveness.kills)
	}
}

// TestDecodeFailureNeitherAdvancesNorResetsSilence18293: a decode failure
// interleaved in a genuine-silence streak leaves the streak untouched, so
// silence before and after it still kills on the original schedule.
func TestDecodeFailureNeitherAdvancesNorResetsSilence18293(t *testing.T) {
	m := &Manager{}
	start := time.Now()
	// 29 silent polls, one decode failure, then the 30th silent poll.
	if at := feed9651(m, errTransport9651, start, helperWedgeFailedPolls-1); at != 0 {
		t.Fatalf("wedged early at silent poll %d", at)
	}
	if m.noteStatusPollResultLocked(errDecode18293, start.Add(29*time.Second)) {
		t.Fatal("a decode failure asked for a kill")
	}
	if m.liveness.failures != helperWedgeFailedPolls-1 {
		t.Fatalf("decode failure changed the silence streak: failures=%d, want %d", m.liveness.failures, helperWedgeFailedPolls-1)
	}
	if !m.noteStatusPollResultLocked(errTransport9651, start.Add(30*time.Second)) {
		t.Fatal("30th silent poll (span satisfied) did not ask for a kill after an interleaved decode failure")
	}
}

// TestSilentHelperStillKilledOnSchedule18293: the other half of the
// confirming cell — genuine silence still kills. (The full supervisor path
// is already bound by TestWedgedHelperIsKilledAndRestarted9651.)
func TestSilentHelperStillKilledOnSchedule18293(t *testing.T) {
	m := &Manager{}
	before := StatusPollDecodeErrors()
	if at := feed9651(m, errTransport9651, time.Now(), helperWedgeFailedPolls+1); at != helperWedgeFailedPolls+1 {
		t.Fatalf("silent helper declared wedged at poll %d, want %d", at, helperWedgeFailedPolls+1)
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
