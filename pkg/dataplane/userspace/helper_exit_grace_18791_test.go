package userspace

import (
	"testing"
	"time"
)

// #18791: an unexpected helper exit raises election debt only if the
// replacement is not armed within helperExitGrace. A crash loop or an already
// wedged helper gets no grace. The wedge verdict is unchanged.

// exit18791 emulates handleUnexpectedHelperExitLocked's verdict steps: the
// grace decision, then the flag.
func exit18791(m *Manager, now time.Time) {
	m.mu.Lock()
	m.noteUnexpectedExitGraceLocked(now)
	m.helperDownUnexpected.Store(true)
	m.mu.Unlock()
}

// respawn18791 emulates startHelperSupervisorLocked's verdict hand-off.
func respawn18791(m *Manager, gen uint64, now time.Time) {
	m.mu.Lock()
	m.handOffExitVerdictLocked(gen, now)
	m.mu.Unlock()
}

func armed18791(m *Manager, gen uint64, now time.Time) {
	m.liveTrack.noteAnswered(gen, now)
	m.liveTrack.noteStatus(gen, now, heartbeats18685(4, now), true)
}

func newGraceManager18791(t *testing.T) *Manager {
	t.Helper()
	m := &Manager{}
	m.liveTrack.reset(1, time.Now(), false)
	return m
}

// TestIsolatedExitReArmedInsideTheGraceRaisesNoDebt18791: the #18707 shape.
// The helper dies, its replacement arms about 1 s later, and the node never
// reports not-ready, so the RGs never move.
func TestIsolatedExitReArmedInsideTheGraceRaisesNoDebt18791(t *testing.T) {
	m := newGraceManager18791(t)
	now := time.Now()
	exit18791(m, now)
	if m.HelperElectionNotReady() {
		t.Fatal("an isolated exit raised election debt inside the restart grace")
	}
	if !m.HelperExitedUnexpectedly() {
		t.Fatal("no helper is running, but HelperExitedUnexpectedly is false")
	}
	respawn18791(m, 2, now.Add(25*time.Millisecond))
	if m.HelperElectionNotReady() || m.HelperExitedUnexpectedly() {
		t.Fatal("the respawned, not yet armed generation raised debt inside the grace")
	}
	armed18791(m, 2, time.Now())
	if m.HelperElectionNotReady() {
		t.Fatal("an armed replacement still reports not-ready")
	}
	if m.liveTrack.exitEpisodeOpen() {
		t.Fatal("the episode did not end when the replacement armed inside the grace")
	}
	// The deadline passing after the arm changes nothing.
	if m.liveTrack.wedgeSuspected(now.Add(helperExitGrace + time.Second)) {
		t.Fatal("the grace expiry raised debt after the replacement had armed")
	}
}

// TestReplacementNotArmedRaisesDebtAtTheGrace18791: a replacement that has not
// armed by the deadline raises the debt then. From that point the #18697 rule
// applies: it clears only once the replacement is armed and looks healthy.
func TestReplacementNotArmedRaisesDebtAtTheGrace18791(t *testing.T) {
	t0 := time.Now()
	tr := &helperLivenessTracker{}
	tr.resetWithGrace(2, t0, true, t0.Add(helperExitGrace))
	if tr.wedgeSuspected(t0.Add(helperExitGrace - 100*time.Millisecond)) {
		t.Fatal("debt raised before the grace ended")
	}
	if !tr.wedgeSuspected(t0.Add(helperExitGrace)) {
		t.Fatal("the grace ended without an arm and no debt was raised")
	}
	// Arming after the deadline does not clear it at once (#18697 hysteresis).
	late := t0.Add(helperExitGrace + time.Second)
	tr.noteAnswered(2, late)
	tr.noteStatus(2, late, heartbeats18685(4, late), true)
	if !tr.wedgeSuspected(late) {
		t.Fatal("a late arm cleared the post-grace debt without the healthy period")
	}
	for s := 1; s <= 8; s++ {
		now := late.Add(time.Duration(s) * time.Second)
		tr.noteAnswered(2, now)
		tr.noteStatus(2, now, heartbeats18685(4, now), true)
	}
	if tr.wedgeSuspected(late.Add(8 * time.Second)) {
		t.Fatal("the post-grace debt never cleared once the replacement was armed and healthy")
	}
}

// TestNoHelperAtTheGraceRaisesDebt18791: no replacement at all by the deadline
// (a respawn that is slow or blocked) raises the debt from the exit flag.
func TestNoHelperAtTheGraceRaisesDebt18791(t *testing.T) {
	old := helperExitGrace
	helperExitGrace = 50 * time.Millisecond
	t.Cleanup(func() { helperExitGrace = old })
	m := newGraceManager18791(t)
	exit18791(m, time.Now())
	if m.HelperElectionNotReady() {
		t.Fatal("debt raised before the grace ended")
	}
	time.Sleep(80 * time.Millisecond)
	if !m.HelperElectionNotReady() {
		t.Fatal("no helper respawned within the grace, and no debt was raised")
	}
	// A respawn after the deadline inherits a raised verdict.
	respawn18791(m, 2, time.Now())
	if !m.HelperElectionNotReady() {
		t.Fatal("a respawn after the grace started ready")
	}
}

// TestSecondExitInsideTheGraceGetsNoGrace18791: the replacement dies before it
// arms. That is a crash loop, and the debt is raised at once.
func TestSecondExitInsideTheGraceGetsNoGrace18791(t *testing.T) {
	m := newGraceManager18791(t)
	now := time.Now()
	exit18791(m, now)
	respawn18791(m, 2, now.Add(25*time.Millisecond))
	// lastUnexpectedExit is fresh too; isolate the episode rule.
	m.lastUnexpectedExitNs.Store(now.Add(-time.Hour).UnixNano())
	exit18791(m, now.Add(500*time.Millisecond))
	if !m.HelperElectionNotReady() {
		t.Fatal("a second exit before the replacement armed got a grace")
	}
	if r := m.HelperElectionReason(); r == "" {
		t.Fatal("no reason for the waived grace")
	}
}

// TestExitWithinTheCrashLoopWindowGetsNoGrace18791: an exit within 30 s of the
// previous one, even though the previous replacement armed, gets no grace. One
// just outside the window gets the grace (control).
func TestExitWithinTheCrashLoopWindowGetsNoGrace18791(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sincePrev time.Duration
		wantDebt  bool
	}{
		{"within-the-window", 10 * time.Second, true},
		{"outside-the-window", helperExitCrashLoopWindow + time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newGraceManager18791(t)
			now := time.Now()
			m.lastUnexpectedExitNs.Store(now.Add(-tc.sincePrev).UnixNano())
			exit18791(m, now)
			if got := m.HelperElectionNotReady(); got != tc.wantDebt {
				t.Fatalf("exit %s after the previous one: not-ready=%v, want %v", tc.sincePrev, got, tc.wantDebt)
			}
		})
	}
}

// TestWedgedHelperExitGetsNoGrace18791: a helper already judged wedged (the
// wedge kill, or a crash while wedged) was already giving up its RGs. Its exit
// keeps the debt with no grace.
func TestWedgedHelperExitGetsNoGrace18791(t *testing.T) {
	m := newGraceManager18791(t)
	m.liveTrack.mu.Lock()
	m.liveTrack.suspected = true
	m.liveTrack.reason = "test wedge"
	m.liveTrack.mu.Unlock()
	now := time.Now()
	exit18791(m, now)
	if !m.HelperElectionNotReady() {
		t.Fatal("the exit of a wedged helper reads ready")
	}
	// The dying generation's own verdict still shows above. The rule is
	// visible at the replacement: with a grace it would start ready.
	respawn18791(m, 2, now.Add(25*time.Millisecond))
	if !m.HelperElectionNotReady() {
		t.Fatal("the replacement of a wedged helper started ready: its exit got a restart grace")
	}
}

// TestFrozenReplacementIsStillCaughtByTheWedgeVerdict18791: the grace does not
// mask the wedge verdict. A replacement that arms but whose worker is frozen
// ends the exit episode, and the frozen-worker verdict still raises the debt.
func TestFrozenReplacementIsStillCaughtByTheWedgeVerdict18791(t *testing.T) {
	oldF := helperWorkerFrozenAfter
	helperWorkerFrozenAfter = 100 * time.Millisecond
	t.Cleanup(func() { helperWorkerFrozenAfter = oldF })
	t0 := time.Now()
	tr := &helperLivenessTracker{}
	tr.resetWithGrace(2, t0, true, t0.Add(helperExitGrace))
	stale := []time.Time{t0.Add(-time.Second)}
	for i := 1; i <= 3; i++ {
		now := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		tr.noteAnswered(2, now)
		tr.noteStatus(2, now, stale, true)
	}
	if !tr.wedgeSuspected(t0.Add(400 * time.Millisecond)) {
		t.Fatal("a frozen worker inside the restart grace raised no debt")
	}
}

// TestExitFlagHandOffHasNoReadyGap18791 (seat AE on #18717): a reader between
// the flag read and the tracker reset must still see not-ready. The pre-fix
// hand-off cleared the flag first, so that reader saw the flag false and the
// dead generation's healthy verdict. The exit here gets no grace, so the
// verdict must hold at every point.
func TestExitFlagHandOffHasNoReadyGap18791(t *testing.T) {
	m := newGraceManager18791(t)
	now := time.Now()
	m.lastUnexpectedExitNs.Store(now.Add(-time.Second).UnixNano()) // crash loop: no grace
	exit18791(m, now)
	if !m.HelperElectionNotReady() {
		t.Fatal("setup: the waived exit must be not-ready")
	}
	gapSeen := false
	m.testAfterExitFlagRead = func() {
		if !m.HelperElectionNotReady() {
			gapSeen = true
		}
	}
	respawn18791(m, 2, now.Add(25*time.Millisecond))
	if gapSeen {
		t.Fatal("a reader inside the generation hand-off saw ready: the flag was cleared before the tracker inherited the verdict")
	}
	if !m.HelperElectionNotReady() {
		t.Fatal("the new generation did not inherit the not-ready verdict")
	}
}

// TestGraceExpiryWakesTheTransitGate18791: the grace arms a wake at the
// deadline (plus slack), so the debt lands promptly and not at the next 1 s
// transit tick. A waived grace arms none.
func TestGraceExpiryWakesTheTransitGate18791(t *testing.T) {
	m := newGraceManager18791(t)
	woke := 0
	m.helperSupervisorObserver = func() { woke++ }
	var armed []time.Duration
	m.exitGraceAfterFunc = func(d time.Duration, f func()) {
		armed = append(armed, d)
		f()
	}
	exit18791(m, time.Now())
	if len(armed) != 1 || armed[0] != helperExitGrace+helperExitGraceWakeSlack || woke != 1 {
		t.Fatalf("armed=%v woke=%d: want one wake at grace+slack", armed, woke)
	}
	exit18791(m, time.Now()) // within the crash-loop window: no grace, no wake
	if len(armed) != 1 {
		t.Fatalf("a waived grace armed a wake: %v", armed)
	}
}
