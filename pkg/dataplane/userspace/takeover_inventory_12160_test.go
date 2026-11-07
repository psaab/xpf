package userspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

type inventoryRequest18661 struct {
	generation uint64
	token      uint64
}

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

	var requests []inventoryRequest18661
	adapter := NewLegacyDataPlaneAdapter(m)
	adapter.SetSessionInventoryRequester(func(generation, token uint64) bool {
		if generation != debtGeneration {
			return false
		}
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
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
	if len(requests) != 1 || requests[0].generation != debtGeneration || requests[0].token == 0 {
		t.Fatalf("peer bulk requests = %v, want one nonzero-token request for generation %d",
			requests, debtGeneration)
	}
	if m.lastStatus.SessionTableEntries != 0 {
		t.Fatalf("replacement helper session count = %d before bulk, want 0",
			m.lastStatus.SessionTableEntries)
	}
	if adapter.MarkSessionInventoryReconciled(1, requests[0].token) {
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
	if !adapter.MarkSessionInventoryReconciled(debtGeneration, requests[0].token) {
		t.Fatalf("completed bulk for helper generation %d/token %d did not clear its debt",
			debtGeneration, requests[0].token)
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
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
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
	if len(requests) != 1 || requests[0].generation != newGen || requests[0].token == 0 {
		t.Fatalf("requests=%v; want one nonzero-token request for generation %d",
			requests, newGen)
	}
	if !m.MarkSessionInventoryReconciled(newGen, requests[0].token) {
		t.Fatalf("completion for generation %d/token %d did not clear its debt",
			newGen, requests[0].token)
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
	adapter.SetSessionInventoryRequester(func(uint64, uint64) bool {
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
func repairOverflowManager18661(t *testing.T) *Manager {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.procGen = 19
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
	return m
}

func latchRepairOverflow18661(m *Manager) {
	m.mu.Lock()
	m.noteSyncedMirrorFailureLocked(dataplane.ErrSyncedImportRepairOverflow)
	m.mu.Unlock()
}

func TestTakeoverInventoryRepairOverflowBlocks18661(t *testing.T) {
	m := repairOverflowManager18661(t)
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
		return true
	})
	latchRepairOverflow18661(m)

	ready, reasons := m.TakeoverReady()
	if ready || !strings.Contains(strings.Join(reasons, "\n"), "repair overflow") {
		t.Fatalf("overflow did not block takeover readiness: ready=%v reasons=%v",
			ready, reasons)
	}
	if len(requests) != 1 || requests[0].generation != m.procGen || requests[0].token == 0 {
		t.Fatalf("overflow inventory requests = %v, want one nonzero-token request for helper generation %d",
			requests, m.procGen)
	}
}

func TestTakeoverInventoryRepairOverflowWrongGenerationAndIncompleteStayBlocked18661(t *testing.T) {
	m := repairOverflowManager18661(t)
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
		return true
	})
	latchRepairOverflow18661(m)

	// A bulk completion before the overflow-triggered request is fired is not
	// evidence that the missing worker repair was included.
	if m.MarkSessionInventoryReconciled(m.procGen, 1) {
		t.Fatal("completion without a fired overflow inventory request cleared the latch")
	}
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("incomplete replay opened takeover readiness")
	}
	if m.MarkSessionInventoryReconciled(m.procGen+1, requests[0].token) {
		t.Fatal("wrong-generation inventory completion cleared the overflow latch")
	}
	if ready, reasons := m.TakeoverReady(); ready ||
		!strings.Contains(strings.Join(reasons, "\n"), "replay state: stale-completion-rejected") {
		t.Fatalf("stale completion rejection was not visible in readiness: ready=%v reasons=%v",
			ready, reasons)
	}
	if m.MarkSessionInventoryReconciled(m.procGen, requests[0].token+1) {
		t.Fatal("completion with a stale request token cleared the overflow latch")
	}
	// A stale replay snapshot from a replaced helper is not the request armed
	// for the running generation, even if a callback carries that generation.
	m.mu.Lock()
	m.sessionRepairOverflowGen = m.procGen + 1
	m.mu.Unlock()
	if m.MarkSessionInventoryReconciled(m.procGen, requests[0].token) {
		t.Fatal("completion for the running helper cleared a different generation's overflow request")
	}
	if ready, reasons := m.TakeoverReady(); ready ||
		!strings.Contains(strings.Join(reasons, "\n"), "repair overflow") {
		t.Fatalf("wrong-generation completion opened readiness: ready=%v reasons=%v",
			ready, reasons)
	}
	if len(requests) != 2 ||
		requests[0].generation != m.procGen || requests[1].generation != m.procGen ||
		requests[0].token == requests[1].token {
		t.Fatalf("overflow inventory requests = %v, want two distinct tokens for helper generation %d",
			requests, m.procGen)
	}
}

func TestTakeoverInventoryCleanRepairOverflowReplayRestoresReadiness18661(t *testing.T) {
	m := repairOverflowManager18661(t)
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
		return true
	})
	latchRepairOverflow18661(m)
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("overflow helper was takeover-ready before inventory replay")
	}
	if !m.MarkSessionInventoryReconciled(m.procGen, requests[0].token) {
		t.Fatal("matching complete inventory replay did not clear overflow debt")
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("clean matching-generation replay did not restore readiness: %v", reasons)
	}
	if len(requests) != 1 || requests[0].generation != m.procGen || requests[0].token == 0 {
		t.Fatalf("overflow inventory requests = %v, want one nonzero-token request for helper generation %d",
			requests, m.procGen)
	}
}

func TestTakeoverInventoryOverflowDuringReplayStaysBlocked18661(t *testing.T) {
	m := repairOverflowManager18661(t)
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
		return true
	})
	m.mu.Lock()
	m.sessionInventoryDebtGen = m.procGen
	m.mu.Unlock()
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("helper with pending inventory replay was takeover-ready")
	}

	// This overflow lands after an inventory replay has already fired for the
	// same helper generation. That earlier replay must not clear the new debt.
	latchRepairOverflow18661(m)
	if !m.MarkSessionInventoryReconciled(m.procGen, requests[0].token) {
		t.Fatal("completed inventory replay did not retire restart debt")
	}
	if ready, reasons := m.TakeoverReady(); ready ||
		!strings.Contains(strings.Join(reasons, "\n"), "repair overflow") {
		t.Fatalf("overflow during replay opened readiness: ready=%v reasons=%v",
			ready, reasons)
	}
	// The failed replay retires its snapshot and immediately re-arms the
	// request. Only the subsequent clean replay can clear the overflow latch.
	if len(requests) != 2 || requests[1].generation != m.procGen ||
		requests[1].token == requests[0].token {
		t.Fatalf("overflow replay did not re-arm with a fresh token: %v", requests)
	}
	if !m.MarkSessionInventoryReconciled(m.procGen, requests[1].token) {
		t.Fatal("re-armed clean inventory replay did not clear overflow debt")
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("readiness did not recover after re-armed clean replay: %v", reasons)
	}
}

func TestTakeoverInventoryRetryKeepsOutstandingToken18661(t *testing.T) {
	m := repairOverflowManager18661(t)
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
		return true
	})
	latchRepairOverflow18661(m)
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("overflow helper was takeover-ready before inventory replay")
	}
	if len(requests) != 1 {
		t.Fatalf("initial overflow inventory requests = %v, want one", requests)
	}

	// A readiness retry during the same in-flight replay must reuse the token
	// captured by BulkStart; it cannot supersede the callback that will arrive.
	m.mu.Lock()
	m.sessionInventoryRequestAt = time.Now().Add(-sessionInventoryRequestRetryInterval)
	m.mu.Unlock()
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("overflow helper was takeover-ready during a replay retry")
	}
	if len(requests) != 2 || requests[0] != requests[1] {
		t.Fatalf("replayed requests = %v, want the same helper-generation/token pair", requests)
	}
	if !m.MarkSessionInventoryReconciled(requests[0].generation, requests[0].token) {
		t.Fatal("matching completion of the still-outstanding replay did not clear overflow debt")
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("readiness did not recover after the slow matching replay: %v", reasons)
	}
}

func TestTakeoverInventoryRearmedReplaySnapshotsPriorOverflow18661(t *testing.T) {
	m := repairOverflowManager18661(t)
	var requests []inventoryRequest18661
	m.SetSessionInventoryRequester(func(generation, token uint64) bool {
		requests = append(requests, inventoryRequest18661{generation: generation, token: token})
		return true
	})
	latchRepairOverflow18661(m)
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("overflow helper was takeover-ready before its first inventory replay")
	}
	if len(requests) != 1 {
		t.Fatalf("initial overflow inventory requests = %v, want one", requests)
	}

	// A second overflow taints the first replay. The 5s retry reuses its pair
	// and must preserve that taint until the bulk completes.
	latchRepairOverflow18661(m)
	m.mu.Lock()
	m.sessionInventoryRequestAt = time.Now().Add(-sessionInventoryRequestRetryInterval)
	m.mu.Unlock()
	if ready, _ := m.TakeoverReady(); ready {
		t.Fatal("overflow helper was takeover-ready during a replay retry")
	}
	if len(requests) != 2 || requests[0] != requests[1] {
		t.Fatalf("replayed requests = %v, want the same pair for the outstanding replay", requests)
	}
	if m.MarkSessionInventoryReconciled(requests[0].generation, requests[0].token) {
		t.Fatal("completion of the tainted replay cleared the latch")
	}
	if ready, reasons := m.TakeoverReady(); ready ||
		!strings.Contains(strings.Join(reasons, "\n"), "replay state: overflow-rearmed") {
		t.Fatalf("tainted replay did not expose its re-arm state: ready=%v reasons=%v", ready, reasons)
	}
	if len(requests) != 3 || requests[2].generation != requests[0].generation ||
		requests[2].token == requests[0].token {
		t.Fatalf("overflow replay did not re-arm with a fresh token: %v", requests)
	}
	if m.MarkSessionInventoryReconciled(requests[0].generation, requests[0].token) {
		t.Fatal("delayed completion from the tainted replay cleared the newly re-armed latch")
	}
	if !m.MarkSessionInventoryReconciled(requests[2].generation, requests[2].token) {
		t.Fatal("clean re-armed replay did not clear the earlier overflow")
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("readiness did not recover after clean re-armed replay: %v", reasons)
	}
}
