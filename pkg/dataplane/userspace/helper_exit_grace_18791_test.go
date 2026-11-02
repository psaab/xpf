package userspace

import (
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// #18791: an unexpected helper exit raises election debt only if the
// replacement becomes forwarding-ready within helperExitGrace. A crash loop
// or an already-wedged helper gets no grace. The wedge verdict is unchanged.

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
	m.noteHelperStatus(gen, now, heartbeats18685(4, now), true)
	m.xskLivenessProven = true
	status := readyHelperStatus()
	status.ForwardingArmed = true
	m.noteHelperForwardingReady(gen, now, status, nil)
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
	if m.HelperElectionNotReady() {
		t.Fatal("the respawned, not yet armed generation raised election debt inside the grace")
	}
	if !m.HelperExitedUnexpectedly() {
		t.Fatal("the spawned, unarmed replacement cleared the VIP-first demotion signal")
	}
	armed18791(m, 2, time.Now())
	if m.HelperElectionNotReady() || m.HelperExitedUnexpectedly() {
		t.Fatal("an armed replacement still reports not-ready or helper-down")
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
	tr.noteAppliedForwardingReady(2, late)
	if !tr.wedgeSuspected(late) {
		t.Fatal("a late arm cleared the post-grace debt without the healthy period")
	}
	for s := 1; s <= 8; s++ {
		now := late.Add(time.Duration(s) * time.Second)
		tr.noteAnswered(2, now)
		tr.noteStatus(2, now, heartbeats18685(4, now), true)
		tr.noteAppliedForwardingReady(2, now)
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
	prev := now.Add(-time.Hour)
	m.lastUnexpectedExit.Store(&prev)
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
			prev := now.Add(-tc.sincePrev)
			m.lastUnexpectedExit.Store(&prev)
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
	prev := now.Add(-time.Second)
	m.lastUnexpectedExit.Store(&prev) // crash loop: no grace
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

// TestLateArmAfterTheGraceRaisesDebtThenClearsByHysteresisFold18794 (F1 fold):
// the grace is a BOUND, not a suggestion. A first ForwardingArmed report after
// the deadline must raise debt (the deadline passed without applied readiness),
// and the debt then clears only via normal forwarding-ready-and-healthy
// hysteresis. It must not erase the episode as if readiness had been in time.
// RED on head: evaluateExitGraceLocked checked raw arm state before the deadline,
// so a late arm cleared `inherited` with no debt at all.
func TestLateArmAfterTheGraceRaisesDebtThenClearsByHysteresisFold18794(t *testing.T) {
	t0 := time.Now()
	tr := &helperLivenessTracker{}
	tr.resetWithGrace(2, t0, true, t0.Add(helperExitGrace))
	// No evaluation at all until after the deadline: the first status the
	// tracker ever sees already reports ForwardingArmed, late.
	late := t0.Add(helperExitGrace + time.Second)
	// noteStatus is the first observation of this generation; no earlier
	// round-trip evaluation has had a chance to raise debt at the deadline.
	tr.noteStatus(2, late, heartbeats18685(4, late), true)
	tr.noteAppliedForwardingReady(2, late)
	if !tr.wedgeSuspected(late) {
		t.Fatal("a first arm observed after the grace deadline erased the episode: no debt was raised")
	}
	// The late arm does not clear at once; the armed-and-healthy hysteresis
	// (helperWedgeClearAfter / helperWedgeClearTrips) governs from here.
	for s := 1; s <= 8; s++ {
		now := late.Add(time.Duration(s) * time.Second)
		tr.noteAnswered(2, now)
		tr.noteStatus(2, now, heartbeats18685(4, now), true)
		tr.noteAppliedForwardingReady(2, now)
	}
	if tr.wedgeSuspected(late.Add(8 * time.Second)) {
		t.Fatal("the post-grace debt never cleared once the replacement was armed and healthy")
	}
}

// TestSpawnedUnarmedReplacementKeepsHelperDownVerdictFold18794 (F2 fold,
// userspace half): before this fix, handOff cleared helperDownUnexpected at
// spawn, so a spawned-but-unarmed replacement lost the daemon's VIP-first
// demotion signal even though election debt remained suppressed inside grace.
// Keep that signal until arm; a responsive control socket stays a separate
// fact. RED on head: the assertion after respawn fails.
func TestSpawnedUnarmedReplacementKeepsHelperDownVerdictFold18794(t *testing.T) {
	m := newGraceManager18791(t)
	now := time.Now()
	exit18791(m, now)
	respawn18791(m, 2, now.Add(25*time.Millisecond))
	if m.HelperElectionNotReady() {
		t.Fatal("the spawned, unarmed generation raised election debt inside the grace")
	}
	if !m.HelperExitedUnexpectedly() {
		t.Fatal("a spawned but unarmed replacement cleared the helper-down verdict: a peer demotion in this window loses the VIP-first path")
	}
	m.noteHelperControlAnswered(2)
	if m.HelperControlUnresponsive() {
		t.Fatal("a spawned replacement that answered control was incorrectly classified silent")
	}
	armed18791(m, 2, time.Now())
	if m.HelperExitedUnexpectedly() {
		t.Fatal("an armed replacement still reports the helper-down verdict")
	}
}

// TestStoppedResponsiveUnarmedReplacementBecomesControlUnavailableFold18794
// ensures retiring an unarmed, control-responsive replacement marks its
// control channel gone without losing the separate unexpected-exit signal.
func TestStoppedResponsiveUnarmedReplacementBecomesControlUnavailableFold18794(t *testing.T) {
	m := newGraceManager18791(t)
	now := time.Now()
	exit18791(m, now)
	respawn18791(m, 2, now.Add(25*time.Millisecond))
	m.procGen = 2
	m.noteHelperControlAnswered(2)
	if m.HelperControlUnresponsive() {
		t.Fatal("a live replacement that answered control was marked unavailable before stop")
	}
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
	if !m.HelperExitedUnexpectedly() {
		t.Fatal("stopping an unarmed replacement erased the unexpected-exit signal")
	}
	if !m.HelperControlUnresponsive() {
		t.Fatal("stopLocked left an answered-but-departed generation marked control-responsive")
	}
}

// TestStopInProgressKeepsAnsweredHelperAvailableUntilExitFold18794 guards
// against publishing a departed control channel before teardown has actually
// stopped the child. The held session lock pins stopLocked in the live-child
// window, where demotion must not treat its control path as fenced.
func TestStopInProgressKeepsAnsweredHelperAvailableUntilExitFold18794(t *testing.T) {
	m, cmd, _ := spawnSupervisedHelper18213(t)
	m.mu.Lock()
	control := &helperControlGeneration{gen: m.procGen}
	control.answered.Store(true)
	m.helperControlGeneration.Store(control)
	m.helperDownUnexpected.Store(true)
	m.mu.Unlock()
	if m.HelperControlUnresponsive() {
		t.Fatal("setup marked a live answered helper control-unresponsive")
	}

	m.sessionMu.Lock()
	stopped := make(chan struct{})
	go func() {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
		close(stopped)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !m.mu.TryLock() {
			break
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			m.sessionMu.Unlock()
			<-stopped
			t.Fatal("stopLocked did not reach the held session lock")
		}
		time.Sleep(time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		m.sessionMu.Unlock()
		<-stopped
		t.Fatalf("child exited before teardown could reach its stop window: %v", err)
	}
	if m.HelperControlUnresponsive() {
		m.sessionMu.Unlock()
		<-stopped
		t.Fatal("stopLocked published control unavailability while the child was still alive")
	}
	m.sessionMu.Unlock()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("stopLocked did not finish after the session lock was released")
	}
	if !m.HelperControlUnresponsive() {
		t.Fatal("stopped unarmed generation still reports responsive control")
	}
}

// TestFailedReplacementStopRetainsDebtFold18794 (F4 fold): a spawned child
// never answers or arms, so the grace raises debt before readiness cleanup
// retires the tracker's inherited state. That cleanup must not erase the
// original exit episode. RED on head: spawn cleared the only exit signal, and
// stopLocked then retires the tracker that had raised debt at the deadline.
func TestFailedReplacementStopRetainsDebtFold18794(t *testing.T) {
	old := helperExitGrace
	helperExitGrace = time.Second
	t.Cleanup(func() { helperExitGrace = old })
	m := newGraceManager18791(t)
	m.disableCtrlMapHook = &fakeCtrlMap{stored: userspaceCtrlValue{Enabled: 1}, haveStored: true}
	now := time.Now()
	exit18791(m, now)
	dir := t.TempDir()
	m.cfg.ControlSocket = filepath.Join(dir, "no-listener.sock")
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start non-serving replacement: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	m.mu.Lock()
	m.proc = cmd
	m.startHelperSupervisorLocked(cmd)
	gen := m.procGen
	m.mu.Unlock()
	// Check immediately: the one-second grace leaves ample subprocess-setup
	// margin without sleeping near the deadline.
	if m.HelperElectionNotReady() {
		t.Fatal("the non-serving replacement raised debt inside the grace")
	}
	time.Sleep(time.Until(m.exitGraceDeadline()) + 25*time.Millisecond)
	if !m.HelperElectionNotReady() {
		t.Fatal("a non-serving replacement did not raise debt at the grace deadline")
	}
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
	if !m.HelperElectionNotReady() {
		t.Fatalf("replacement generation %d was stopped by readiness cleanup and its inherited exit debt vanished", gen)
	}
}

// TestExitGraceDeadlineRetainsMonotonicClockFold18794 (F3 fold): the exit grace
// is elapsed-time bounded. The Manager's stored deadline must retain the Go
// monotonic reading, not just the wall-clock Unix timestamp. RED on head: the
// UnixNano round-trip strips the monotonic component.
func TestExitGraceDeadlineRetainsMonotonicClockFold18794(t *testing.T) {
	m := newGraceManager18791(t)
	now := time.Now()
	exit18791(m, now)
	want := now.Add(helperExitGrace)
	if got := m.exitGraceDeadline(); got != want {
		t.Fatalf("stored grace deadline %v lost the monotonic reading; want original monotonic deadline %v", got, want)
	}
}

// TestExitGraceNeedsAppliedForwardingReadyFold18794 catches the status-vs-
// dataplane readiness gap: an armed helper status is not serving when ctrl
// remains disabled, XSK liveness is unproven, or a live binding is not BPF
// READY. Grace ends only after all forwarding-readiness gates have passed.
func TestExitGraceNeedsAppliedForwardingReadyFold18794(t *testing.T) {
	oldGrace := helperExitGrace
	helperExitGrace = 100 * time.Millisecond
	t.Cleanup(func() { helperExitGrace = oldGrace })

	t.Run("armed but ctrl disabled", func(t *testing.T) {
		m, ctrl := seamedManager(t)
		now := time.Now()
		exit18791(m, now)
		m.mu.Lock()
		m.procGen = 2
		m.xskLivenessFailed = true
		m.mu.Unlock()
		respawn18791(m, 2, time.Now())

		status := readyHelperStatus()
		status.ForwardingArmed = true
		observedAt := time.Now()
		m.noteHelperStatus(2, observedAt, heartbeats18685(1, observedAt), true)
		m.mu.Lock()
		err := m.applyHelperStatusLocked(status)
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("apply armed status with broken XSK: %v", err)
		}
		if !ctrl.haveStored || ctrl.stored.Enabled != 0 {
			t.Fatalf("non-vacuous disabled-gate premise failed: stored=%v ctrl=%+v, want ctrl.Enabled=0",
				ctrl.haveStored, ctrl.stored)
		}
		if m.HelperElectionNotReady() {
			t.Fatal("an armed report with ctrl still disabled raised debt inside the grace")
		}
		time.Sleep(time.Until(m.exitGraceDeadline()) + 10*time.Millisecond)
		if !m.HelperElectionNotReady() {
			t.Fatal("ForwardingArmed with persistently disabled ctrl erased the exit episode; debt did not rise at grace")
		}
		if !m.HelperExitedUnexpectedly() {
			t.Fatal("disabled ctrl cleared the unexpected-exit signal before dataplane forwarding was ready")
		}
	})

	t.Run("armed and fully forwarding-ready", func(t *testing.T) {
		m, ctrl := seamedManager(t)
		now := time.Now()
		exit18791(m, now)
		m.mu.Lock()
		m.procGen = 2
		m.mu.Unlock()
		respawn18791(m, 2, time.Now())

		status := readyHelperStatus()
		status.ForwardingArmed = true
		observedAt := time.Now()
		m.noteHelperStatus(2, observedAt, heartbeats18685(1, observedAt), true)
		if !m.HelperExitedUnexpectedly() {
			t.Fatal("raw ForwardingArmed status cleared the exit signal before ctrl application")
		}
		m.mu.Lock()
		err := m.applyHelperStatusLocked(status)
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("apply ready helper status: %v", err)
		}
		if !ctrl.haveStored || ctrl.stored.Enabled != 1 {
			t.Fatalf("positive control: stored=%v ctrl=%+v, want ctrl.Enabled=1",
				ctrl.haveStored, ctrl.stored)
		}
		if m.HelperExitedUnexpectedly() || m.HelperElectionNotReady() {
			t.Fatal("successfully applied forwarding-ready status did not close the in-grace exit episode")
		}
		time.Sleep(time.Until(m.exitGraceDeadline()) + 10*time.Millisecond)
		if m.HelperElectionNotReady() {
			t.Fatal("grace expiry raised debt after full forwarding readiness was applied")
		}
	})
}

type forwardingReadyBindingsMap18794 struct {
	rows map[uint32]userspaceBindingValue
}

func (f *forwardingReadyBindingsMap18794) Lookup(_, _ interface{}) error {
	return ebpf.ErrKeyNotExist
}

func (f *forwardingReadyBindingsMap18794) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	f.rows[key.(uint32)] = value.(userspaceBindingValue)
	return nil
}

// TestExitGraceRequiresBoundAndProvenXSKFold18794 covers a successful ctrl=1
// write that only starts the liveness probe. A registered+armed but unbound
// binding is not BPF-ready, so it must not close inherited exit grace.
// RED on the pre-fix path: ctrl=1 plus ForwardingArmed ended grace while the
// userspace_bindings READY flag was still clear.
func TestExitGraceRequiresBoundAndProvenXSKFold18794(t *testing.T) {
	oldGrace := helperExitGrace
	helperExitGrace = 100 * time.Millisecond
	t.Cleanup(func() { helperExitGrace = oldGrace })

	m, ctrl := seamedManager(t)
	bindings := &forwardingReadyBindingsMap18794{rows: make(map[uint32]userspaceBindingValue)}
	m.helperStatusBindingsMapHook = bindings
	m.xskLivenessProven = false
	m.neighborsPrewarmed = true

	now := time.Now()
	exit18791(m, now)
	m.mu.Lock()
	m.procGen = 2
	m.mu.Unlock()
	respawn18791(m, 2, time.Now())

	status := readyHelperStatus()
	status.ForwardingArmed = true
	status.Bindings = []BindingStatus{{
		Slot: 0, QueueID: 0, WorkerID: 0,
		Interface: "ge-0-0-1", Ifindex: 7,
		Registered: true, Armed: true, Ready: false, Bound: false,
	}}
	observedAt := time.Now()
	m.noteHelperStatus(2, observedAt, heartbeats18685(1, observedAt), true)
	m.mu.Lock()
	err := m.applyHelperStatusLocked(status)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("apply armed, registered-but-unbound status: %v", err)
	}
	if !ctrl.haveStored || ctrl.stored.Enabled != 1 {
		t.Fatalf("non-vacuous probe premise failed: stored=%v ctrl=%+v, want successful ctrl.Enabled=1",
			ctrl.haveStored, ctrl.stored)
	}
	if m.xskLivenessProven || m.xskProbeStart.IsZero() {
		t.Fatalf("non-vacuous XSK probe premise failed: proven=%v probeStart=%v, want unproven probe running",
			m.xskLivenessProven, m.xskProbeStart)
	}
	index := uint32(status.Bindings[0].Ifindex)*bindingQueuesPerIface + status.Bindings[0].QueueID
	row, ok := bindings.rows[index]
	if !ok || row.Flags != 0 {
		t.Fatalf("registered-but-unbound binding row = %+v present=%v, want BPF READY clear", row, ok)
	}
	if m.HelperElectionNotReady() {
		t.Fatal("registered-but-unbound helper raised election debt before the grace deadline")
	}
	time.Sleep(time.Until(m.exitGraceDeadline()) + 10*time.Millisecond)
	if !m.HelperElectionNotReady() {
		t.Fatal("ctrl=1 only started the XSK probe, but unbound/non-READY status ended grace; RG kept full weight after the deadline")
	}
	if !m.HelperExitedUnexpectedly() {
		t.Fatal("the unbound replacement cleared the helper-down demotion signal")
	}
}

// TestExitGraceRequiresProvenXSKFold18794 makes the complementary proof
// explicit: even a BPF-READY binding and ctrl=1 are only a probe until the
// manager has established XSK liveness.
func TestExitGraceRequiresProvenXSKFold18794(t *testing.T) {
	oldGrace := helperExitGrace
	helperExitGrace = 100 * time.Millisecond
	t.Cleanup(func() { helperExitGrace = oldGrace })

	m, ctrl := seamedManager(t)
	bindings := &forwardingReadyBindingsMap18794{rows: make(map[uint32]userspaceBindingValue)}
	m.helperStatusBindingsMapHook = bindings
	m.xskLivenessProven = false
	m.neighborsPrewarmed = true

	now := time.Now()
	exit18791(m, now)
	m.mu.Lock()
	m.procGen = 2
	m.mu.Unlock()
	respawn18791(m, 2, time.Now())

	status := readyHelperStatus()
	status.ForwardingArmed = true
	status.Bindings[0].RXPackets = 0
	observedAt := time.Now()
	m.noteHelperStatus(2, observedAt, heartbeats18685(1, observedAt), true)
	m.mu.Lock()
	err := m.applyHelperStatusLocked(status)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("apply armed, BPF-ready but XSK-unproven status: %v", err)
	}
	if !ctrl.haveStored || ctrl.stored.Enabled != 1 {
		t.Fatalf("non-vacuous probe premise failed: stored=%v ctrl=%+v, want successful ctrl.Enabled=1",
			ctrl.haveStored, ctrl.stored)
	}
	if m.xskLivenessProven || m.xskProbeStart.IsZero() {
		t.Fatalf("non-vacuous XSK proof premise failed: proven=%v probeStart=%v, want unproven probe running",
			m.xskLivenessProven, m.xskProbeStart)
	}
	index := uint32(status.Bindings[0].Ifindex)*bindingQueuesPerIface + status.Bindings[0].QueueID
	row, ok := bindings.rows[index]
	if !ok || row.Flags != userspaceBindingReady {
		t.Fatalf("bound+ready binding row = %+v present=%v, want BPF READY set during liveness probe", row, ok)
	}
	if m.HelperElectionNotReady() {
		t.Fatal("XSK-unproven helper raised election debt before the grace deadline")
	}
	time.Sleep(time.Until(m.exitGraceDeadline()) + 10*time.Millisecond)
	if !m.HelperElectionNotReady() {
		t.Fatal("BPF READY and ctrl=1 without XSK proof ended grace; RG kept full weight after the deadline")
	}
	if !m.HelperExitedUnexpectedly() {
		t.Fatal("the XSK-unproven replacement cleared the helper-down demotion signal")
	}
}

// TestTransitGateReadsGraceDebtWhileManagerMutexHeldFold18794 reproduces the
// transit-gate call order: HelperSupervisorState first, then
// HelperElectionNotReady. A non-serving spawned helper may hold m.mu through
// its readiness wait, but the gate must still observe the grace deadline in
// time instead of waiting for that 5 s startup timeout.
func TestTransitGateReadsGraceDebtWhileManagerMutexHeldFold18794(t *testing.T) {
	oldGrace := helperExitGrace
	helperExitGrace = 100 * time.Millisecond
	t.Cleanup(func() { helperExitGrace = oldGrace })

	m := newGraceManager18791(t)
	wake := make(chan struct{}, 1)
	m.SetHelperSupervisorObserver(func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	exit18791(m, time.Now())
	dir := t.TempDir()
	m.cfg.ControlSocket = filepath.Join(dir, "no-listener.sock")
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start non-serving replacement: %v", err)
	}
	m.disableCtrlMapHook = &fakeCtrlMap{stored: userspaceCtrlValue{Enabled: 1}, haveStored: true}
	m.mu.Lock()
	m.proc = cmd
	m.startHelperSupervisorLocked(cmd)
	t.Cleanup(func() {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
	})
	published := m.helperSupervisorState.Load()
	if published == nil || published.generation != m.procGen || !published.running {
		m.mu.Unlock()
		t.Fatalf("spawn snapshot = %+v, want generation %d running", published, m.procGen)
	}
	// The grace observer fires while m.mu is still held, matching the startup
	// readiness wait; the following query reproduces the gate's call order.
	select {
	case <-wake:
	case <-time.After(helperExitGrace + helperExitGraceWakeSlack + 100*time.Millisecond):
		m.mu.Unlock()
		t.Fatal("grace deadline did not wake the gate while readiness held m.mu")
	}

	type gateState struct {
		running, looping, notReady bool
	}
	done := make(chan gateState, 1)
	go func() {
		running, looping := m.HelperSupervisorState()
		done <- gateState{running: running, looping: looping, notReady: m.HelperElectionNotReady()}
	}()
	select {
	case state := <-done:
		m.mu.Unlock()
		if !state.running || state.looping {
			t.Fatalf("supervisor state = (running=%v, crashLooping=%v), want (true,false)", state.running, state.looping)
		}
		if !state.notReady {
			t.Fatal("the transit gate did not observe exit debt at the grace deadline while readiness held m.mu")
		}
	case <-time.After(100 * time.Millisecond):
		m.mu.Unlock()
		<-done
		t.Fatal("HelperSupervisorState blocked behind the replacement's readiness-held m.mu past the grace deadline")
	}
}
