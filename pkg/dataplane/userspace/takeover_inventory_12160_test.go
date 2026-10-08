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
	debtGeneration := m.sessionInventoryDebtGen
	m.procGen = debtGeneration
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
