package userspace

// Session-socket HA refresh cells (#9629): the watchdog backstop publishes
// update_ha_state lease refreshes via the session socket (outside m.mu) when
// the helper advertises HaSessionRefreshSupported, and stays on the legacy
// main path otherwise.
//
// Map-free fixtures throughout (a nil ha_watchdog map makes
// refreshHAWatchdogOnlyFromMapsLocked a no-op success), matching the #2549
// throttle-test precedent — the one-IPC/full-set/mark-once properties below do
// not depend on map contents. Refresh-before-mark ordering (production maps
// case) is pinned by code position (refresh precedes snapshot in
// UpdateHAWatchdog) plus the multi-RG one-IPC behavior; privileged BPF
// fixtures are out of scope, consistent with existing HA throttle tests.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// fakeProc9629 fakes a live helper process (throttle-test precedent). Cells
// here never tear down, so the test-runner-PID caveat (#9642) does not apply.
func fakeProc9629(t *testing.T) *exec.Cmd {
	t.Helper()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	return &exec.Cmd{Process: proc}
}

// sessionTestManager9629 returns a map-free manager with proc, HA inventory,
// and shim stub wired, ready for watchdog cells. Callers set capability bits
// and hooks. Mirrors TestUpdateHAWatchdogThrottlesIPCButWritesMapEveryTick.
func sessionTestManager9629(t *testing.T, groups map[int]HAGroupStatus) *Manager {
	t.Helper()
	m := New()
	m.proc = fakeProc9629(t)
	m.haWatchdogMapWrite = func(int, uint64) error { return nil }
	m.mu.Lock()
	for id, g := range groups {
		g.RGID = id
		m.haGroups[id] = g
	}
	m.publishHAWatchdogSnapshotLocked()
	m.mu.Unlock()
	return m
}

// haRefreshOracle9629 is a small stateful mirror of Rust's lease-only
// decision table. It deliberately models key-set equality, matching refreshes,
// valid stored-active mismatch renewal, and expired stored-active mismatch
// preservation, so the Go composition cells validate helper behavior rather
// than only capturing a request payload.
type haRefreshOutcome9629 uint8

const (
	haRefreshNeedsLock9629 haRefreshOutcome9629 = iota
	haRefreshServed9629
)

type haRefreshOracle9629 struct {
	now        uint64
	groups     map[int]HAGroupStatus
	leaseUntil map[int]uint64
}

func newHARefreshOracle9629(groups []HAGroupStatus, now uint64) *haRefreshOracle9629 {
	oracle := &haRefreshOracle9629{
		now:        now,
		groups:     make(map[int]HAGroupStatus, len(groups)),
		leaseUntil: make(map[int]uint64, len(groups)),
	}
	for _, group := range groups {
		oracle.groups[group.RGID] = group
		if group.Active {
			oracle.leaseUntil[group.RGID] = now + 2
		}
	}
	return oracle
}

func (o *haRefreshOracle9629) apply(groups []HAGroupStatus) haRefreshOutcome9629 {
	incoming := make(map[int]HAGroupStatus, len(groups))
	for _, group := range groups {
		incoming[group.RGID] = group
	}
	if len(incoming) != len(o.groups) {
		return haRefreshNeedsLock9629
	}
	for rgID := range o.groups {
		if _, ok := incoming[rgID]; !ok {
			return haRefreshNeedsLock9629
		}
	}

	nextGroups := make(map[int]HAGroupStatus, len(o.groups))
	for rgID, group := range o.groups {
		nextGroups[rgID] = group
	}
	nextLeaseUntil := make(map[int]uint64, len(o.leaseUntil))
	for rgID, leaseUntil := range o.leaseUntil {
		nextLeaseUntil[rgID] = leaseUntil
	}
	refreshed := 0
	for rgID, stored := range o.groups {
		next := incoming[rgID]
		if stored.Active == next.Active {
			stored.WatchdogTimestamp = next.WatchdogTimestamp
			if next.Active {
				leaseBase := next.WatchdogTimestamp
				if leaseBase < o.now {
					leaseBase = o.now
				}
				nextLeaseUntil[rgID] = leaseBase + 10
			} else {
				nextLeaseUntil[rgID] = 0
			}
			nextGroups[rgID] = stored
			refreshed++
			continue
		}
		if stored.Active && nextLeaseUntil[rgID] != 0 && o.now <= nextLeaseUntil[rgID] {
			leaseBase := stored.WatchdogTimestamp
			if leaseBase < o.now {
				leaseBase = o.now
			}
			nextLeaseUntil[rgID] = leaseBase + 10
			refreshed++
		}
	}
	if refreshed == 0 {
		return haRefreshNeedsLock9629
	}
	o.groups = nextGroups
	o.leaseUntil = nextLeaseUntil
	return haRefreshServed9629
}

func (o *haRefreshOracle9629) forwardingActive(rgID int) bool {
	stored, ok := o.groups[rgID]
	return ok && stored.Active && o.leaseUntil[rgID] != 0 && o.now <= o.leaseUntil[rgID]
}

func TestHARefreshOracleLeaseBoundaryIsInclusive9629(t *testing.T) {
	oracle := newHARefreshOracle9629(
		[]HAGroupStatus{{RGID: 1, Active: true, WatchdogTimestamp: 1}},
		10,
	)
	oracle.leaseUntil[1] = 10
	if !oracle.forwardingActive(1) {
		t.Fatal("oracle marked lease_until == now inactive; Rust uses now <= until")
	}
	if got := oracle.apply([]HAGroupStatus{{RGID: 1, Active: false}}); got != haRefreshServed9629 {
		t.Fatalf("oracle equality-boundary mismatch outcome = %v, want Served", got)
	}
	if oracle.leaseUntil[1] != 20 {
		t.Fatalf("oracle equality-boundary lease_until = %d, want renewed to 20", oracle.leaseUntil[1])
	}
}

// The session sender never takes m.mu: with m.mu held by the test, a session
// HA round trip against a fake helper still completes. If the sender took
// m.mu (revert), this deadlocks and the 5s bound fails instead of hanging.
func TestRequestHAWatchdogSessionNeverTakesManagerMu9629(t *testing.T) {
	dir := shortSockDir9770(t)
	m := New()
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	sockPath := m.sessionSocketPath()
	fakeSessionSocket9770(t, sockPath, ControlResponse{OK: true}, nil)

	m.mu.Lock()
	defer m.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		done <- m.requestHAWatchdogSessionAtPath([]HAGroupStatus{{RGID: 1, Active: true}}, sockPath)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session HA with m.mu held: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("requestHAWatchdogSession blocked while m.mu was held — the sender takes m.mu")
	}
}

// The complete production entry point must also escape m.mu, not only the
// sender helper. This models a long snapshot/apply holding m.mu while a
// heartbeat arrives; the immutable watchdog snapshot carries the capability
// and inventory into the session request.
func TestUpdateHAWatchdogEntryPointNeverWaitsOnManagerMu9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.mu.Lock()
	defer m.mu.Unlock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true}}
	m.publishHAWatchdogSnapshotLocked()
	got := make(chan ControlRequest, 1)
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		got <- req
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- m.UpdateHAWatchdog(1, 100)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UpdateHAWatchdog with m.mu held: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateHAWatchdog blocked while m.mu was held; entry point still depends on snapshot mutex")
	}
	select {
	case req := <-got:
		if req.Type != "update_ha_state" || req.HAState == nil ||
			len(req.HAState.Groups) != 1 ||
			req.HAState.Groups[0].RGID != 1 ||
			req.HAState.Groups[0].WatchdogTimestamp != 100 {
			t.Fatalf("session hook saw %+v, want one RG1 update_ha_state at timestamp 100", req)
		}
	default:
		t.Fatal("session hook saw no positive update_ha_state witness")
	}
}

// Config applies publish the control-socket path under m.mu while watchdog
// calls send after releasing it. This cell exercises those operations together
// so -race catches any sender that reads m.cfg after the unlock.
func TestUpdateHAWatchdogAndConfigMutationRace9629(t *testing.T) {
	dir := t.TempDir()
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.mu.Lock()
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true}}
	m.publishHAWatchdogSnapshotLocked()
	m.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			m.mu.Lock()
			m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
			m.publishHAWatchdogSnapshotLocked()
			m.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for tick := range 200 {
			_ = m.UpdateHAWatchdog(1, uint64(100+tick))
		}
	}()
	wg.Wait()
}

// A watchdog refresh can pass its first snapshot-generation check and queue on
// sessionMu while the helper is being retired. The final check must discard it
// before it can reach a replacement helper. Holding sessionMu first, then
// advancing the retired generation under m.mu, makes this race deterministic.
func TestHARefreshQueuedOnSessionMuDropsAfterRestart9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true}}
	m.publishHAWatchdogSnapshotLocked()
	oldGen := m.haWatchdogProcessGen.Load()
	m.mu.Unlock()

	m.sessionMu.Lock()
	m.mu.Lock()
	attempted := make(chan struct{})
	m.haWatchdogSessionLockHook = func() { close(attempted) }
	sent := false
	m.sessionRequestHook = func(ControlRequest, *ProcessStatus) error {
		sent = true
		return nil
	}
	type result struct {
		handled bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		handled, err := m.tryUpdateHAWatchdogWhileManagerMuHeld(1, 100)
		done <- result{handled: handled, err: err}
	}()
	<-attempted

	// This mirrors stopLocked's generation retirement while the queued sender
	// is still behind sessionMu: atomic publication precedes the unlock.
	m.procGen = oldGen + 1
	m.haWatchdogProcessGen.Store(m.procGen)
	m.mu.Unlock()
	m.sessionMu.Unlock()

	got := <-done
	if !got.handled || got.err != nil {
		t.Fatalf("queued old-generation refresh returned handled=%v err=%v, want throttle-success no-op",
			got.handled, got.err)
	}
	if sent {
		t.Fatal("queued old-generation refresh reached the session request hook")
	}
}

// A refresh payload can be captured before an ownership transition and then
// queue behind sessionMu. The final fence must reject that stale Active=true
// payload after UpdateRGActive(false) publishes its intent, or Rust would
// match the stored active entry and renew an expired owner.
func TestHARefreshQueuedBeforeDemotionDropsStaleIntent9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: true, WatchdogTimestamp: 1},
	})
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.xskLivenessProven = true
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{
		{RGID: 1, Active: true, WatchdogTimestamp: 1},
	}
	m.publishHAWatchdogSnapshotLocked()
	m.mu.Unlock()

	oracle := newHARefreshOracle9629([]HAGroupStatus{
		{RGID: 1, Active: true, WatchdogTimestamp: 1},
	}, 10)
	oracle.leaseUntil[1] = 9
	queued := make(chan struct{})
	senderRelease := make(chan struct{})
	m.haWatchdogSessionLockHook = func() {
		close(queued)
		<-senderRelease
	}
	sent := false
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = true
			if oracle.apply(req.HAState.Groups) != haRefreshServed9629 {
				return errors.New("HA refresh oracle rejected queued demotion payload")
			}
		}
		return nil
	}
	mainEntered := make(chan struct{})
	mainRelease := make(chan struct{})
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" {
			close(mainEntered)
			<-mainRelease
			*status = *readyHelperStatus()
		}
		return nil
	}

	refreshDone := make(chan error, 1)
	go func() { refreshDone <- m.UpdateHAWatchdog(1, 100) }()
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		close(senderRelease)
		<-refreshDone
		t.Fatal("watchdog refresh never queued before its sessionMu acquisition")
	}

	demoteDone := make(chan error, 1)
	go func() { demoteDone <- m.UpdateRGActive(1, false) }()
	select {
	case <-mainEntered:
	case <-time.After(5 * time.Second):
		close(senderRelease)
		close(mainRelease)
		<-refreshDone
		<-demoteDone
		t.Fatal("authoritative demotion never reached its blocked main request")
	}
	close(senderRelease)

	refreshErr := <-refreshDone
	sentBeforeRelease := sent
	oracleForwardingActive := oracle.forwardingActive(1)
	oracleLeaseUntil := oracle.leaseUntil[1]
	close(mainRelease)
	demoteErr := <-demoteDone
	if refreshErr != nil {
		t.Fatalf("queued pre-demotion refresh: %v", refreshErr)
	}
	if sentBeforeRelease {
		t.Fatal("queued pre-demotion refresh reached the session request hook")
	}
	if oracleForwardingActive || oracleLeaseUntil != 9 {
		t.Fatalf("oracle queued-demotion state = active=%v lease_until=%d, want expired unchanged lease",
			oracleForwardingActive, oracleLeaseUntil)
	}
	if demoteErr != nil {
		t.Fatalf("authoritative demotion: %v", demoteErr)
	}
}

// The final epoch check and the request hook are one sessionMu critical
// section. Park the sender after the check, probe that it owns the real
// production mutex, then start demotion and probe that mutation's lock in the
// same rendezvous style.
func TestHARefreshDemotionWaitsForPostFenceSend9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: true, WatchdogTimestamp: 1},
	})
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.xskLivenessProven = true
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{
		{RGID: 1, Active: true, WatchdogTimestamp: 1},
	}
	m.publishHAWatchdogSnapshotLocked()
	m.mu.Unlock()

	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" {
			*status = *readyHelperStatus()
		}
		return nil
	}
	fencePassed := make(chan struct{})
	fenceRelease := make(chan struct{})
	m.haWatchdogSessionFenceHook = func() {
		close(fencePassed)
		<-fenceRelease
	}
	sessionSent := make(chan struct{})
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			close(sessionSent)
		}
		return nil
	}
	oldIntent := m.haWatchdogIntentGen.Load()
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- m.UpdateHAWatchdog(1, 100) }()
	select {
	case <-fencePassed:
	case <-time.After(5 * time.Second):
		close(fenceRelease)
		select {
		case <-refreshDone:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("watchdog sender never reached the post-fence rendezvous")
	}

	// The sender's post-check rendezvous runs while it owns sessionMu. A
	// lock-removal mutant makes TryLock succeed here, without any timing window.
	senderHoldsSessionMu := !m.sessionMu.TryLock()
	if !senderHoldsSessionMu {
		m.sessionMu.Unlock()
	}
	demotionHolding := make(chan struct{})
	demotionRelease := make(chan struct{})
	m.haRGActiveSessionHoldHook = func() {
		close(demotionHolding)
		<-demotionRelease
	}
	demoteDone := make(chan error, 1)
	go func() { demoteDone <- m.UpdateRGActive(1, false) }()
	close(fenceRelease)

	refreshErr := <-refreshDone
	if refreshErr != nil {
		close(demotionRelease)
		<-demoteDone
		t.Fatalf("post-fence watchdog refresh: %v", refreshErr)
	}
	select {
	case <-sessionSent:
	case <-time.After(5 * time.Second):
		close(demotionRelease)
		<-demoteDone
		t.Fatal("post-fence watchdog sender never reached the session request hook")
	}
	select {
	case <-demotionHolding:
	case <-time.After(5 * time.Second):
		close(demotionRelease)
		<-demoteDone
		t.Fatal("demotion never reached its sessionMu holding rendezvous")
	}

	// UpdateRGActive's rendezvous runs while it owns sessionMu. If its
	// production lock is removed, TryLock succeeds deterministically.
	demotionHoldsSessionMu := !m.sessionMu.TryLock()
	if !demotionHoldsSessionMu {
		m.sessionMu.Unlock()
	}
	close(demotionRelease)
	demoteErr := <-demoteDone
	if !senderHoldsSessionMu {
		t.Fatal("post-fence sender signaled without owning the production sessionMu")
	}
	if !demotionHoldsSessionMu {
		t.Fatal("demotion signaled holding without owning the production sessionMu")
	}
	if demoteErr != nil {
		t.Fatalf("authoritative demotion: %v", demoteErr)
	}
	if m.haWatchdogIntentGen.Load() <= oldIntent {
		t.Fatalf("demotion intent epoch = %d, want greater than %d",
			m.haWatchdogIntentGen.Load(), oldIntent)
	}
}

// The unexpected-exit path must retire the independent session epoch too.
// Otherwise a refresh queued behind sessionMu can pass its final check during
// the crash-to-restart gap, when procGen still equals the dead generation.
func TestHARefreshQueuedAcrossUnexpectedExitDropsBeforeRestart9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.restartTimerFn = func(time.Duration, func()) {}
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true}}
	m.publishHAWatchdogSnapshotLocked()
	oldGen := m.haWatchdogProcessGen.Load()
	m.mu.Unlock()

	m.sessionMu.Lock()
	m.mu.Lock()
	attempted := make(chan struct{})
	m.haWatchdogSessionLockHook = func() { close(attempted) }
	sent := false
	m.sessionRequestHook = func(ControlRequest, *ProcessStatus) error {
		sent = true
		return nil
	}
	type refreshResult struct {
		handled bool
		err     error
	}
	refreshDone := make(chan refreshResult, 1)
	go func() {
		handled, err := m.tryUpdateHAWatchdogWhileManagerMuHeld(1, 100)
		refreshDone <- refreshResult{handled: handled, err: err}
	}()
	<-attempted
	m.mu.Unlock()

	crashDone := make(chan struct{})
	go func() {
		m.mu.Lock()
		m.handleUnexpectedHelperExitLocked(&helperGeneration{
			gen: m.procGen,
			cmd: &exec.Cmd{},
		})
		m.mu.Unlock()
		close(crashDone)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for m.haWatchdogProcessGen.Load() == oldGen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.haWatchdogProcessGen.Load() == oldGen {
		m.sessionMu.Unlock()
		t.Fatal("unexpected-exit path never retired the helper-session epoch")
	}
	m.sessionMu.Unlock()

	refresh := <-refreshDone
	if !refresh.handled || refresh.err != nil {
		t.Fatalf("queued pre-crash refresh returned handled=%v err=%v, want throttle-success no-op",
			refresh.handled, refresh.err)
	}
	if sent {
		t.Fatal("queued pre-crash refresh reached the session request hook")
	}
	select {
	case <-crashDone:
	case <-time.After(5 * time.Second):
		t.Fatal("unexpected-exit bookkeeping did not complete")
	}
	m.mu.Lock()
	snapshot := m.haWatchdogSnapshot.Load()
	m.mu.Unlock()
	if snapshot == nil || snapshot.processLive {
		t.Fatalf("unexpected-exit snapshot = %+v, want processLive=false", snapshot)
	}
}

// A restarted helper increments both procGen and the independent session
// epoch, while a crash increments only the epoch before the restart timer
// runs. The locked watchdog path must capture the epoch, not procGen, or every
// post-restart refresh is silently classified stale.
func TestUpdateHAWatchdogAfterCrashRestartUsesSessionEpoch9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true}}
	// Model the production crash retirement, then the new helper's supervisor
	// generation. procGen advances once; the session epoch advances twice.
	m.haWatchdogProcessGen.Add(1)
	m.procGen++
	m.haWatchdogProcessGen.Add(1)
	m.publishHAWatchdogSnapshotLocked()
	sent := make(chan ControlRequest, 1)
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		sent <- req
		return nil
	}
	m.mu.Unlock()

	if err := m.UpdateHAWatchdog(1, 100); err != nil {
		t.Fatalf("post-restart watchdog refresh: %v", err)
	}
	select {
	case req := <-sent:
		if req.Type != "update_ha_state" || req.HAState == nil ||
			len(req.HAState.Groups) != 1 ||
			req.HAState.Groups[0].RGID != 1 ||
			req.HAState.Groups[0].WatchdogTimestamp != 100 {
			t.Fatalf("post-restart session hook saw %+v, want RG1 timestamp 100", req)
		}
	default:
		t.Fatal("post-restart watchdog refresh was dropped by a stale generation fence")
	}
}

// NeedsLock classification, both legs: the socket classifier maps a prefixed
// refusal to the sentinel (hook nil → real-socket branch), and a non-prefix
// error stays untyped so genuine failures never read as healthy.
func TestHARefreshNeedsLockClassifier9629(t *testing.T) {
	t.Run("prefixed refusal maps to sentinel", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		sockPath := m.sessionSocketPath()
		fakeSessionSocket9770(t, sockPath,
			ControlResponse{OK: false, Error: haRefreshNeedsControlPrefix + "transition"}, nil)
		err := m.requestHAWatchdogSessionAtPath(
			[]HAGroupStatus{{RGID: 1, Active: true}}, sockPath)
		if !errors.Is(err, errHARefreshNeedsControlSocket) {
			t.Fatalf("prefixed refusal classified as %v, want errHARefreshNeedsControlSocket", err)
		}
	})
	t.Run("unprefixed error stays untyped", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		sockPath := m.sessionSocketPath()
		fakeSessionSocket9770(t, sockPath,
			ControlResponse{OK: false, Error: "boom"}, nil)
		err := m.requestHAWatchdogSessionAtPath(
			[]HAGroupStatus{{RGID: 1, Active: true}}, sockPath)
		if err == nil {
			t.Fatal("unprefixed helper error returned nil")
		}
		if errors.Is(err, errHARefreshNeedsControlSocket) {
			t.Fatalf("unprefixed error %v classified as NeedsLock — the classifier matches too broadly", err)
		}
	})
}

// A hook-returned NeedsLock is throttle-success: UpdateHAWatchdog returns nil
// (no daemon Warn storm) and never sets helperHAStatePublished (first-inventory
// stays main-only).
func TestHARefreshNeedsLockIsThrottleSuccess9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	sessionCalls := 0
	m.sessionRequestHook = func(ControlRequest, *ProcessStatus) error {
		sessionCalls++
		return errHARefreshNeedsControlSocket
	}
	controlCalls := 0
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		controlCalls++
		return nil
	}
	if err := m.UpdateHAWatchdog(1, 100); err != nil {
		t.Fatalf("NeedsLock returned %v, want nil (throttle-success)", err)
	}
	if sessionCalls != 1 {
		t.Fatalf("session IPCs = %d, want 1", sessionCalls)
	}
	if controlCalls != 0 {
		t.Fatalf("main IPCs = %d, want 0 (session path must not touch the main socket)", controlCalls)
	}
	if m.helperHAStatePublished {
		t.Error("session NeedsLock set helperHAStatePublished — first-inventory authority must stay main-only")
	}
}

// Old helpers stay on the legacy main path: bit false (observed) and
// never-observed both route via controlRequestHook with zero session sends.
func TestSessionHAFallsBackToMainOnOldHelper9629(t *testing.T) {
	t.Run("observed without bit", func(t *testing.T) {
		m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
		m.helperStatusObserved = true
		m.lastStatus.HaSessionRefreshSupported = false
		reqTypes := make(chan string, 16)
		m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
			reqTypes <- req.Type
			return nil
		}
		sessionCalls := 0
		m.sessionRequestHook = func(ControlRequest, *ProcessStatus) error {
			sessionCalls++
			return nil
		}
		// Returned error ignored (post-send applyHelperStatus errors map-free;
		// the IPC is already sent + counted — throttle-test precedent).
		_ = m.UpdateHAWatchdog(1, 100)
		if n := drainUpdateHAStateCount(reqTypes); n != 1 {
			t.Fatalf("main update_ha_state IPCs = %d, want 1 (legacy path must publish)", n)
		}
		if sessionCalls != 0 {
			t.Fatalf("session IPCs = %d, want 0 (old helper must never see session HA)", sessionCalls)
		}
	})
	t.Run("never observed", func(t *testing.T) {
		m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
		// helperStatusObserved false (zero New()) with zero status: fail-safe
		// to main, exactly like an observed Old helper.
		reqTypes := make(chan string, 16)
		m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
			reqTypes <- req.Type
			return nil
		}
		sessionCalls := 0
		m.sessionRequestHook = func(ControlRequest, *ProcessStatus) error {
			sessionCalls++
			return nil
		}
		_ = m.UpdateHAWatchdog(1, 100)
		if n := drainUpdateHAStateCount(reqTypes); n != 1 {
			t.Fatalf("main update_ha_state IPCs = %d, want 1", n)
		}
		if sessionCalls != 0 {
			t.Fatalf("session IPCs = %d, want 0", sessionCalls)
		}
	})
}

// Session success never sets helperHAStatePublished and carries the full
// group set (single-RG shape here; 3-RG full-set pinned by the one-IPC cell).
func TestSessionHASuccessSetsNoPublishedFlag9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true}})
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	var sent []HAGroupStatus
	sessionCalls := 0
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		sessionCalls++
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	controlCalls := 0
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		controlCalls++
		return nil
	}
	if err := m.UpdateHAWatchdog(1, 100); err != nil {
		t.Fatalf("session success returned %v, want nil", err)
	}
	if sessionCalls != 1 {
		t.Fatalf("session IPCs = %d, want 1", sessionCalls)
	}
	if controlCalls != 0 {
		t.Fatalf("main IPCs = %d, want 0", controlCalls)
	}
	if m.helperHAStatePublished {
		t.Error("session success set helperHAStatePublished — first-inventory must stay main-only (#7465)")
	}
	if len(sent) != 1 || sent[0].RGID != 1 {
		t.Fatalf("published groups = %+v, want full set [{RGID:1}]", sent)
	}
}

// The session send runs outside m.mu AND the baseline is marked once: the hook
// flips m.haGroups mid-send (under m.mu — this would deadlock if the send held
// it, bounded by the 5s watchdog), and the recorded baseline keeps pre-send
// values (a re-mark would overwrite them with the flipped ones).
func TestSessionHASendsOutsideMuAndMarksOnce9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: true, WatchdogTimestamp: 100}})
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.sessionRequestHook = func(ControlRequest, *ProcessStatus) error {
		m.mu.Lock()
		g := m.haGroups[1]
		g.Active = !g.Active
		m.haGroups[1] = g
		m.mu.Unlock()
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- m.UpdateHAWatchdog(1, 100) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session send returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("UpdateHAWatchdog hung: session send holds m.mu while the hook needs it")
	}
	m.mu.Lock()
	base := m.haWatchdogIPCSynced[1]
	m.mu.Unlock()
	if base.active != true || base.timestamp != 100 {
		t.Fatalf("baseline = %+v, want pre-send {active:true timestamp:100} (mark-once, never re-marked)", base)
	}
	if m.helperHAStatePublished {
		t.Error("session send set helperHAStatePublished")
	}
}

// One full-set publish per tick across RGs: the first heartbeat marks a fresh
// full-set baseline (refresh-before-mark + full-set mark), so the remaining
// RGs' same-tick heartbeats stay throttled. Without full-set marking each RG
// would fire its own IPC (count 3, not 1).
func TestSessionHAPublishesOneIPCPerTickAcrossRGs9629(t *testing.T) {
	const tick uint64 = 100
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: true, WatchdogTimestamp: tick},
		2: {Active: true, WatchdogTimestamp: tick},
		3: {Active: true, WatchdogTimestamp: tick},
	})
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	sessionCalls := 0
	var sent []HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		sessionCalls++
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	controlCalls := 0
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		controlCalls++
		return nil
	}
	// Same tick, three heartbeats (no baseline yet → first fires).
	if err := m.UpdateHAWatchdog(1, tick); err != nil {
		t.Fatalf("rg1: %v", err)
	}
	if err := m.UpdateHAWatchdog(2, tick); err != nil {
		t.Fatalf("rg2: %v", err)
	}
	if err := m.UpdateHAWatchdog(3, tick); err != nil {
		t.Fatalf("rg3: %v", err)
	}
	if sessionCalls != 1 {
		t.Fatalf("session IPCs = %d, want exactly 1 full-set publish per tick", sessionCalls)
	}
	if controlCalls != 0 {
		t.Fatalf("main IPCs = %d, want 0", controlCalls)
	}
	if len(sent) != 3 || sent[0].RGID != 1 || sent[1].RGID != 2 || sent[2].RGID != 3 {
		t.Fatalf("published groups = %+v, want full set [1 2 3] in RGID order", sent)
	}
}

// The contended entry point must merge every RG into one immutable full-set
// payload. Repeated calls for different RGs while m.mu is held must not let a
// stale per-RG snapshot overwrite a fresher timestamp or reset the scalar
// backstop deadline.
func TestSessionHAContendedMergePreservesFullSetAndScalarThrottle9629(t *testing.T) {
	const baseline uint64 = 100
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: true, WatchdogTimestamp: baseline},
		2: {Active: true, WatchdogTimestamp: baseline},
		3: {Active: true, WatchdogTimestamp: baseline},
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{
		{RGID: 1, Active: true, WatchdogTimestamp: baseline},
		{RGID: 2, Active: true, WatchdogTimestamp: baseline},
		{RGID: 3, Active: true, WatchdogTimestamp: baseline},
	}
	m.publishHAWatchdogSnapshotLocked()
	var sent [][]HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = append(sent, append([]HAGroupStatus(nil), req.HAState.Groups...))
		}
		return nil
	}
	for _, rgID := range []int{1, 2, 3} {
		if err := m.UpdateHAWatchdog(rgID, baseline); err != nil {
			t.Fatalf("baseline RG%d: %v", rgID, err)
		}
	}
	if len(sent) != 1 {
		t.Fatalf("baseline session IPCs = %d, want one full-set send", len(sent))
	}
	if len(sent[0]) != 3 || sent[0][0].RGID != 1 || sent[0][1].RGID != 2 || sent[0][2].RGID != 3 {
		t.Fatalf("baseline payload = %+v, want sorted full set [1 2 3]", sent[0])
	}
	for _, group := range sent[0] {
		if group.WatchdogTimestamp != baseline {
			t.Fatalf("baseline payload = %+v, want timestamp %d for every RG", sent[0], baseline)
		}
	}

	for _, rgID := range []int{1, 2, 3} {
		if err := m.UpdateHAWatchdog(rgID, 101); err != nil {
			t.Fatalf("sub-backstop RG%d: %v", rgID, err)
		}
	}
	if len(sent) != 1 {
		t.Fatalf("sub-backstop session IPCs = %d, want one", len(sent))
	}
	if err := m.UpdateHAWatchdog(2, 103); err != nil {
		t.Fatalf("backstop RG2: %v", err)
	}
	if len(sent) != 2 {
		t.Fatalf("backstop session IPCs = %d, want two", len(sent))
	}
	if got := sent[1]; len(got) != 3 || got[0].WatchdogTimestamp != 101 ||
		got[1].WatchdogTimestamp != 103 || got[2].WatchdogTimestamp != 101 {
		t.Fatalf("backstop payload = %+v, want merged timestamps [101 103 101]", got)
	}

	// An acknowledged ownership change bypasses the scalar timer immediately.
	m.haWatchdogHelperInventory[0].Active = false
	m.publishHAWatchdogSnapshotLocked()
	if err := m.UpdateHAWatchdog(1, 104); err != nil {
		t.Fatalf("active transition RG1: %v", err)
	}
	if len(sent) != 3 || sent[2][0].Active {
		t.Fatalf("active transition sends = %+v, want immediate RG1 demotion", sent)
	}
	if sent[2][0].WatchdogTimestamp < sent[1][0].WatchdogTimestamp {
		t.Fatalf("RG1 timestamp regressed from %d to %d", sent[1][0].WatchdogTimestamp, sent[2][0].WatchdogTimestamp)
	}
}

// A pending Go demotion must reach the degraded session arm even while its
// authoritative main-socket request is blocked. With an expired stored-active
// lease, Rust's mismatch branch keeps the stored entry expired; sending the
// acknowledged Active=true bit would instead take the matching branch and
// resurrect it.
func TestSessionHAContendedDemotionIntentDoesNotRenewExpiredOwner9629(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: true, WatchdogTimestamp: 1},
	})
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.xskLivenessProven = true
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{
		{RGID: 1, Active: true, WatchdogTimestamp: 1},
	}
	m.publishHAWatchdogSnapshotLocked()
	mainEntered := make(chan struct{})
	mainRelease := make(chan struct{})
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" {
			close(mainEntered)
			<-mainRelease
			*status = *readyHelperStatus()
		}
		return nil
	}
	var sent []HAGroupStatus
	oracle := newHARefreshOracle9629(m.haWatchdogHelperInventory, 10)
	oracle.leaseUntil[1] = 9
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
			switch oracle.apply(req.HAState.Groups) {
			case haRefreshServed9629:
				return nil
			case haRefreshNeedsLock9629:
				return errHARefreshNeedsControlSocket
			default:
				return errors.New("HA refresh oracle returned unknown outcome")
			}
		}
		return nil
	}
	m.mu.Unlock()

	demoteDone := make(chan error, 1)
	go func() { demoteDone <- m.UpdateRGActive(1, false) }()
	select {
	case <-mainEntered:
	case <-time.After(5 * time.Second):
		t.Fatalf("authoritative demotion never reached its blocked main request")
	}

	if err := m.UpdateHAWatchdog(1, 100); err != nil {
		close(mainRelease)
		<-demoteDone
		t.Fatalf("contended demotion refresh: %v", err)
	}
	if len(sent) != 1 || sent[0].RGID != 1 || sent[0].Active ||
		sent[0].WatchdogTimestamp != 100 {
		t.Fatalf("contended demotion payload = %+v, want RG1 inactive at timestamp 100", sent)
	}
	if oracle.forwardingActive(1) || oracle.leaseUntil[1] != 9 {
		t.Fatalf("oracle demotion state = active=%v lease_until=%d, want expired unchanged lease",
			oracle.forwardingActive(1), oracle.leaseUntil[1])
	}
	close(mainRelease)
	if err := <-demoteDone; err != nil {
		t.Fatalf("authoritative demotion: %v", err)
	}
}

// The locked session arm uses the same helper-compatible inventory as the
// degraded arm. This covers the pending-XSK-startup/deferred-apply window
// where m.haGroups has already been reseeded but the helper still owns 16 keys.
func TestSessionHALockedRefreshRetainsSixteenEntryHelperInventoryAfterReseed9629(t *testing.T) {
	helperGroups := make([]HAGroupStatus, 0, 16)
	initial := make(map[int]HAGroupStatus, 16)
	for rgID := range 16 {
		group := HAGroupStatus{RGID: rgID, Active: rgID == 1 || rgID == 2}
		initial[rgID] = group
		helperGroups = append(helperGroups, group)
	}
	m := sessionTestManager9629(t, initial)
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = append([]HAGroupStatus(nil), helperGroups...)
	m.publishHAWatchdogSnapshotLocked()
	m.seedHAGroupInventoryLocked(&config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
			},
		},
	})
	var sent []HAGroupStatus
	oracle := newHARefreshOracle9629(helperGroups, 10)
	oracle.leaseUntil[2] = 9
	rg1LeaseBefore := oracle.leaseUntil[1]
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			if oracle.apply(req.HAState.Groups) != haRefreshServed9629 {
				return errors.New("HA refresh oracle rejected locked reseed payload")
			}
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	m.mu.Unlock()

	if err := m.UpdateHAWatchdog(1, 100); err != nil {
		t.Fatalf("locked reseeded refresh: %v", err)
	}
	if len(sent) != 16 || !sent[1].Active || sent[1].WatchdogTimestamp != 100 {
		t.Fatalf("locked reseeded payload = %+v, want 16 entries with active RG1 timestamp 100", sent)
	}
	if !oracle.forwardingActive(1) || oracle.leaseUntil[1] <= rg1LeaseBefore {
		t.Fatalf("oracle RG1 state = active=%v lease_until=%d, want advanced active lease",
			oracle.forwardingActive(1), oracle.leaseUntil[1])
	}
	if oracle.forwardingActive(2) || oracle.leaseUntil[2] != 9 {
		t.Fatalf("oracle removed RG2 state = active=%v lease_until=%d, want expired unchanged lease",
			oracle.forwardingActive(2), oracle.leaseUntil[2])
	}
}

// A config apply reseeds m.haGroups to the configured RGs before replaying the
// helper's fixed 16-entry inventory. The actual entry point must keep sending
// all acknowledged helper entries while m.mu is held, or Rust rejects the
// refresh as a membership change and the lease eventually starves.
func TestSessionHAContendedRefreshRetainsSixteenEntryHelperInventoryAfterReseed9629(t *testing.T) {
	helperGroups := make([]HAGroupStatus, 0, 16)
	initial := make(map[int]HAGroupStatus, 16)
	for rgID := range 16 {
		group := HAGroupStatus{RGID: rgID, Active: rgID == 1 || rgID == 2}
		initial[rgID] = group
		helperGroups = append(helperGroups, group)
	}
	m := sessionTestManager9629(t, initial)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = append([]HAGroupStatus(nil), helperGroups...)
	m.publishHAWatchdogSnapshotLocked()

	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
			},
		},
	}
	m.seedHAGroupInventoryLocked(cfg)
	m.publishHAWatchdogSnapshotLocked()

	var sent []HAGroupStatus
	oracle := newHARefreshOracle9629(helperGroups, 10)
	oracle.leaseUntil[2] = 9
	rg1LeaseBefore := oracle.leaseUntil[1]
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			if oracle.apply(req.HAState.Groups) != haRefreshServed9629 {
				return errors.New("HA refresh oracle rejected contended reseed payload")
			}
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	if err := m.UpdateHAWatchdog(1, 100); err != nil {
		t.Fatalf("reseeded contended refresh: %v", err)
	}
	if len(sent) != 16 {
		t.Fatalf("reseeded payload has %d groups, want all 16 acknowledged entries: %+v", len(sent), sent)
	}
	for i, group := range sent {
		if group.RGID != i {
			t.Fatalf("reseeded payload order/group[%d] = %+v, want RGID %d", i, group, i)
		}
	}
	if !sent[1].Active {
		t.Fatalf("RG1 active bit = false, want the active helper entry")
	}
	if sent[2].Active {
		t.Fatalf("removed RG2 active bit = true, want obsolete helper owner demoted")
	}
	if sent[1].WatchdogTimestamp != 100 {
		t.Fatalf("RG1 watchdog timestamp = %d, want 100", sent[1].WatchdogTimestamp)
	}
	if !oracle.forwardingActive(1) || oracle.leaseUntil[1] <= rg1LeaseBefore {
		t.Fatalf("oracle RG1 state = active=%v lease_until=%d, want advanced active lease",
			oracle.forwardingActive(1), oracle.leaseUntil[1])
	}
	if oracle.forwardingActive(2) || oracle.leaseUntil[2] != 9 {
		t.Fatalf("oracle removed RG2 state = active=%v lease_until=%d, want expired unchanged lease",
			oracle.forwardingActive(2), oracle.leaseUntil[2])
	}
}

// TestHARefreshNeedsControlPrefixMatchesTheHelper9629 asserts the AGREEMENT
// between the Go classifier's token and the Rust constant the helper actually
// emits, by READING the Rust source rather than pinning either side to a
// literal (syncedImportRefusedPrefix precedent).
func TestHARefreshNeedsControlPrefixMatchesTheHelper9629(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/afxdp/ha/session_domain.rs")
	if err != nil {
		t.Fatalf("read the helper source that owns the refusal token: %v", err)
	}
	re := regexp.MustCompile(`HA_REFRESH_NEEDS_CONTROL_SOCKET[^=]*=\s*"([^"]+)"`)
	match := re.FindStringSubmatch(string(src))
	if match == nil {
		t.Fatal("HA_REFRESH_NEEDS_CONTROL_SOCKET not found in session_domain.rs — the helper side moved or was renamed")
	}
	if match[1] != haRefreshNeedsControlPrefix {
		t.Fatalf("refusal token disagreement: helper emits %q, Go matches %q — "+
			"every NeedsLock would be misclassified as a transport failure",
			match[1], haRefreshNeedsControlPrefix)
	}
}
