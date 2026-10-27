package ra

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestWithdrawInterfacesUnrelatedDoesNotCancelRestart_4961 is the #4961
// fail-on-revert. A changed-config restart of interface A (here "lo") is
// in-flight — its old sender is stopped and its replacement is about to start
// via releaseDrain's onProvenClose. A concurrent WithdrawInterfaces naming a
// DIFFERENT interface must NOT cancel A's restart.
//
// Pre-fix: WithdrawInterfaces bumped the GLOBAL epoch, so releaseDrain saw
// m.epoch != startEpoch and suppressed A's replacement AND deleted its
// tombstone — A silently lost its RA sender (IPv6 loss on A's hosts). With the
// per-interface epoch, an unrelated withdraw bumps only that interface's epoch,
// so A's restart completes.
//
// Revert (make WithdrawInterfaces bump the global epoch again) and this test
// goes RED: onProvenClose is never called and no replacement sender exists.
func TestWithdrawInterfacesUnrelatedDoesNotCancelRestart_4961(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	old, cfg, startEpoch := installRestartEntry(t, fl, m)

	// A withdraw of an UNRELATED interface: it must not touch lo's restart.
	m.withdrawInterfacesForTest([]string{"eth-unrelated-4961"})

	started := false
	onProvenClose := func() error {
		started = true
		return m.startLocked(cfg)
	}
	if err := m.releaseDrain("lo", old, startEpoch, onProvenClose); err != nil {
		t.Fatalf("releaseDrain: %v", err)
	}

	if !started {
		t.Fatal("lo's changed-config restart was cancelled by an unrelated " +
			"WithdrawInterfaces([eth-unrelated-4961]) — replacement suppressed " +
			"(IPv6 loss on lo) — #4961")
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	_, stillDraining := m.draining["lo"]
	m.mu.Unlock()
	if !live {
		t.Fatal("expected a live replacement sender for lo after the restart completed")
	}
	if stillDraining {
		t.Fatal("lo tombstone should have been released after the restart")
	}
	_ = m.Clear()
}

// TestWithdrawInterfacesSameIfaceCancelsRestart_4961 is the positive control:
// a withdraw NAMING the restarting interface must still supersede its restart
// (the per-interface epoch bump + the goodbyeWanted flip both fire), so the fix
// does not over-permit — a genuine same-interface withdraw still wins.
func TestWithdrawInterfacesSameIfaceCancelsRestart_4961(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	old, cfg, startEpoch := installRestartEntry(t, fl, m)

	// A withdraw NAMING lo: flips goodbyeWanted on lo's tombstone AND bumps
	// lo's per-interface epoch — either alone must suppress the replacement.
	m.withdrawInterfacesForTest([]string{"lo"})

	started := false
	onProvenClose := func() error {
		started = true
		return m.startLocked(cfg)
	}
	if err := m.releaseDrain("lo", old, startEpoch, onProvenClose); err != nil {
		t.Fatalf("releaseDrain: %v", err)
	}
	if started {
		t.Fatal("a WithdrawInterfaces([lo]) must supersede lo's restart — the " +
			"replacement must NOT start")
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if live {
		t.Fatal("no replacement sender should exist for lo after a same-interface withdraw")
	}
}

// TestWithdrawInterfacesUnrelatedDoesNotBumpGlobalEpoch_4961 pins the
// mechanism: an interface-scoped withdraw leaves the whole-manager fence
// (m.epoch) untouched and bumps only the named interface's per-interface epoch.
func TestWithdrawInterfacesUnrelatedDoesNotBumpGlobalEpoch_4961(t *testing.T) {
	m := New()
	m.mu.Lock()
	globalBefore := m.epoch
	m.mu.Unlock()

	m.withdrawInterfacesForTest([]string{"eth-x-4961"})

	m.mu.Lock()
	globalAfter := m.epoch
	ifEpoch := m.ifaceEpoch["eth-x-4961"]
	m.mu.Unlock()

	if globalAfter != globalBefore {
		t.Fatalf("WithdrawInterfaces must not bump the whole-manager fence: %d -> %d", globalBefore, globalAfter)
	}
	if ifEpoch == 0 {
		t.Fatal("WithdrawInterfaces must bump the named interface's per-interface epoch")
	}

	// WithdrawOnce (also interface-scoped) must behave the same.
	m.mu.Lock()
	globalBefore = m.epoch
	m.mu.Unlock()
	m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("eth-y-4961")})
	m.mu.Lock()
	globalAfter = m.epoch
	m.mu.Unlock()
	if globalAfter != globalBefore {
		t.Fatalf("WithdrawOnce must not bump the whole-manager fence: %d -> %d", globalBefore, globalAfter)
	}
}
