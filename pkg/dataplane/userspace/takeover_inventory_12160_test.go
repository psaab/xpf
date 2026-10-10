package userspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTakeoverReadinessWaitsForReplacementHelperSessionInventory12160(t *testing.T) {
	const preloadedSessions = 5
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.procGen = 1
	m.clusterHA = true
	m.mode = ModeUserspaceCompat
	m.lastStatus = ProcessStatus{
		Enabled:             true,
		ForwardingArmed:     true,
		SessionTableEntries: preloadedSessions,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
	}
	m.xskLivenessProven = true
	m.eventStream = boundEventStream(t)
	m.helperHAStatePublished = true
	m.haGroups = map[int]HAGroupStatus{1: {RGID: 1, Active: false}}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("pre-restart helper with %d sessions is not takeover-ready: %v",
			preloadedSessions, reasons)
	}

	m.mu.Lock()
	m.proc = nil
	m.resetAfterHelperGoneLocked()
	if !m.sessionInventoryDebtOwed {
		t.Fatal("reset did not mark inventory debt owed for the next generation")
	}
	// Bind via the extracted method, NOT startHelperSupervisorLocked: starting
	// a supervisor here would leak a real goroutine + restart timer that
	// races this fixture (Opus MAJ-1 — flaky 26-33/300 under -race).
	m.procGen++
	m.bindOwedInventoryDebtLocked()
	debtGeneration := m.sessionInventoryDebtGen
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.mode = ModeUserspaceCompat
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
	}
	m.xskLivenessProven = true
	m.eventStream = boundEventStream(t)
	m.helperHAStatePublished = true
	m.haGroups = map[int]HAGroupStatus{1: {RGID: 1, Active: false}}
	m.mu.Unlock()

	requests := 0
	adapter := NewLegacyDataPlaneAdapter(m)
	adapter.SetSessionInventoryRequester(func(generation uint64) bool {
		if generation != debtGeneration {
			return false
		}
		requests++
		return true
	})

	if debtGeneration != 2 {
		t.Fatalf("replacement inventory debt generation = %d, want 2", debtGeneration)
	}
	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatal("replacement helper with an empty session table is takeover-ready")
	}
	if !strings.Contains(strings.Join(reasons, "\n"), "session inventory not reconciled for helper generation 2") {
		t.Fatalf("takeover denial omitted generation-scoped inventory debt: %v", reasons)
	}
	if requests != 1 {
		t.Fatalf("peer bulk requests = %d, want one request for generation 2", requests)
	}
	if m.lastStatus.SessionTableEntries != 0 {
		t.Fatalf("replacement helper session count = %d before bulk, want 0",
			m.lastStatus.SessionTableEntries)
	}
	if adapter.MarkSessionInventoryReconciled(1) {
		t.Fatal("bulk completion for the dead helper generation cleared replacement debt")
	}
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("wrong-generation bulk completion opened takeover readiness")
	}

	// Model the observable result of the completed authoritative bulk: all
	// pre-restart sessions are back in the replacement helper's table.
	m.mu.Lock()
	m.lastStatus.SessionTableEntries = preloadedSessions
	m.mu.Unlock()
	if !adapter.MarkSessionInventoryReconciled(debtGeneration) {
		t.Fatalf("completed bulk for helper generation %d did not clear its debt", debtGeneration)
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("takeover readiness did not recover after restoring %d sessions: %v",
			preloadedSessions, reasons)
	}
	if got := m.lastStatus.SessionTableEntries; got != preloadedSessions {
		t.Fatalf("replacement helper session count = %d after bulk, want %d", got, preloadedSessions)
	}
}

// TestInventoryDebtBindsAtSpawnAfterReset12160 pins the Opus F1 fix: crash,
// then StopHelperForReset while the crashed helper awaits restart, then
// respawn must bind the owed debt to the ALLOCATED generation (not a
// predicted procGen+1). Pre-fix this deadlocked with newGen=3 debt=2:
// no request ever sent (TakeoverReady requires procGen==debt) and no
// completion could clear it (Mark requires procGen==debt).
func TestInventoryDebtBindsAtSpawnAfterReset12160(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)
	m.mu.Lock()
	m.clusterHA = true
	exited := m.procSup.exited
	m.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitSupervisor(t, m, exited)
	m.mu.Lock()
	if !m.sessionInventoryDebtOwed || m.sessionInventoryDebtGen != 0 {
		t.Fatalf("after crash: owed=%v gen=%d; want owed=true gen=0",
			m.sessionInventoryDebtOwed, m.sessionInventoryDebtGen)
	}
	m.mu.Unlock()
	// Teardown while crashed (StopHelperForReset bumps procGen again).
	m.StopHelperForReset()
	cmd2 := exec.Command("sleep", "300")
	if err := cmd2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd2.Process.Kill() })
	var requests []uint64
	m.SetSessionInventoryRequester(func(g uint64) bool {
		requests = append(requests, g)
		return true
	})
	m.mu.Lock()
	m.proc = cmd2
	m.startHelperSupervisorLocked(cmd2)
	newGen, debt := m.procGen, m.sessionInventoryDebtGen
	m.mode = ModeUserspaceCompat
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
	}
	m.xskLivenessProven = true
	m.eventStream = boundEventStream(t)
	m.helperHAStatePublished = true
	m.haGroups = map[int]HAGroupStatus{1: {RGID: 1, Active: false}}
	m.mu.Unlock()
	if debt != newGen {
		t.Fatalf("debt=%d newGen=%d; want debt bound to the spawned generation", debt, newGen)
	}
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("respawned helper with debt is takeover-ready")
	}
	if len(requests) != 1 || requests[0] != newGen {
		t.Fatalf("requests=%v; want exactly one for generation %d", requests, newGen)
	}
	if !m.MarkSessionInventoryReconciled(newGen) {
		t.Fatalf("completion for generation %d did not clear its debt", newGen)
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("readiness did not recover after generation-%d bulk: %v", newGen, reasons)
	}
}

// TestInventoryBulkRequestThrottled12160 pins the retry throttle (Opus F3):
// sustained debt must not emit a peer bulk request on every TakeoverReady
// poll. Kills M15 (throttle removed → request per poll).
func TestInventoryBulkRequestThrottled12160(t *testing.T) {
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.procGen = 2
	m.clusterHA = true
	m.mode = ModeUserspaceCompat
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
	}
	m.xskLivenessProven = true
	m.eventStream = boundEventStream(t)
	m.helperHAStatePublished = true
	m.haGroups = map[int]HAGroupStatus{1: {RGID: 1, Active: false}}
	m.mu.Lock()
	m.sessionInventoryDebtGen = 2
	m.mu.Unlock()
	requests := 0
	adapter := NewLegacyDataPlaneAdapter(m)
	adapter.SetSessionInventoryRequester(func(uint64) bool {
		requests++
		return true
	})
	for range 10 {
		m.TakeoverReady()
	}
	if requests != 1 {
		t.Fatalf("10 rapid TakeoverReady polls sent %d requests; want exactly 1 (throttled)", requests)
	}
}
