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
	"testing"
	"time"
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
	for id, g := range groups {
		g.RGID = id
		m.haGroups[id] = g
	}
	return m
}

// The session sender never takes m.mu: with m.mu held by the test, a session
// HA round trip against a fake helper still completes. If the sender took
// m.mu (revert), this deadlocks and the 5s bound fails instead of hanging.
func TestRequestHAWatchdogSessionNeverTakesManagerMu9629(t *testing.T) {
	dir := shortSockDir9770(t)
	m := New()
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	fakeSessionSocket9770(t, m.sessionSocketPath(), ControlResponse{OK: true}, nil)

	m.mu.Lock()
	defer m.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		done <- m.requestHAWatchdogSession([]HAGroupStatus{{RGID: 1, Active: true}})
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

// NeedsLock classification, both legs: the socket classifier maps a prefixed
// refusal to the sentinel (hook nil → real-socket branch), and a non-prefix
// error stays untyped so genuine failures never read as healthy.
func TestHARefreshNeedsLockClassifier9629(t *testing.T) {
	t.Run("prefixed refusal maps to sentinel", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		fakeSessionSocket9770(t, m.sessionSocketPath(),
			ControlResponse{OK: false, Error: haRefreshNeedsControlPrefix + "transition"}, nil)
		err := m.requestHAWatchdogSession([]HAGroupStatus{{RGID: 1, Active: true}})
		if !errors.Is(err, errHARefreshNeedsControlSocket) {
			t.Fatalf("prefixed refusal classified as %v, want errHARefreshNeedsControlSocket", err)
		}
	})
	t.Run("unprefixed error stays untyped", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		fakeSessionSocket9770(t, m.sessionSocketPath(),
			ControlResponse{OK: false, Error: "boom"}, nil)
		err := m.requestHAWatchdogSession([]HAGroupStatus{{RGID: 1, Active: true}})
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
