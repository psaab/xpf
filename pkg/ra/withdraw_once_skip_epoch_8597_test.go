package ra

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K19) — claimWithdrawOnceLocked bumped the per-interface
// supersession epoch for EVERY interface it was handed, including the ones it
// then skipped.
//
// The pairing invariant this package runs on is that a supersession bump
// accompanies real superseding RESPONSIBILITY. Withdraw flips the global fence
// and owns every drain. WithdrawInterfaces bumps and then flips goodbyeWanted
// on the entry it supersedes, so even its "already draining" path takes over
// the goodbye. WithdrawOnce's skip path bumped and did NEITHER: it emitted
// nothing, claimed nothing, and reported Skipped — while cancelling whatever
// the current owner was in the middle of.
//
// The consumers both key on that epoch. finishDrainDecision starts a
// changed-config replacement only if `m.ifaceEpoch[name] == e.startIfaceEpoch`;
// applyDeferred aborts a deferred start on the same comparison. A stray bump
// therefore makes the replacement silently not happen, the tombstone get
// deleted anyway, and BOTH error returns stay nil — the interface ends with no
// RA sender and every caller is told it succeeded. Hosts behind it keep the
// router until Router Lifetime (1800s default) expires.
//
// The trigger is not exotic: the daemon runs runStartupGoodbye in its own
// goroutine (pkg/daemon/daemon_ha.go), so a cold-boot WithdrawOnce runs
// concurrently with Apply's changed-config restart.

// TestWithdrawOnceSkipDoesNotCancelARestart_8597 is the RED-on-revert core.
//
// lo carries an in-flight changed-config restart (a drainEntry with no live
// sender). WithdrawOnce naming lo finds it busy and SKIPS — so it must leave
// lo's restart alone. Restoring the unconditional bump loop makes the
// replacement never start and this cell fails with lo senderless.
func TestWithdrawOnceSkipDoesNotCancelARestart_8597(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	old, cfg, startEpoch := installRestartEntry(t, fl, m)

	res := m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})

	// Non-vacuity: the cell is only about the SKIP path, so prove the call
	// actually took it. If WithdrawOnce ever claimed this interface it would be
	// taking responsibility, and a bump would then be correct.
	if len(res) != 1 {
		t.Fatalf("WithdrawOnce returned %d results, want 1", len(res))
	}
	if !res[0].Skipped {
		t.Fatalf("WithdrawOnce(lo) reported Sent=%v Skipped=%v Err=%v; this cell is about "+
			"the SKIP path and a claimed interface would make it vacuous",
			res[0].Sent, res[0].Skipped, res[0].Err)
	}

	started := false
	onProvenClose := func() error {
		started = true
		return m.startLocked(cfg)
	}
	if err := m.releaseDrain("lo", old, startEpoch, onProvenClose); err != nil {
		t.Fatalf("releaseDrain: %v", err)
	}

	if !started {
		t.Fatal("lo's changed-config restart was cancelled by a WithdrawOnce that " +
			"SKIPPED lo — the replacement never started, the tombstone was released " +
			"anyway, and both error returns were nil. lo is senderless and every " +
			"caller was told it succeeded (#8597/K19)")
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

// TestWithdrawOnceSkipLeavesTheEpochAlone_8597 pins the mechanism directly, so
// a future change that keeps the outcome by some other route still has to
// argue with the invariant rather than silently restore the bump.
func TestWithdrawOnceSkipLeavesTheEpochAlone_8597(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	old, _, _ := installRestartEntry(t, fl, m)
	defer func() { old.signalStop(modeHard); _ = m.Clear() }()

	m.mu.Lock()
	before := m.ifaceEpoch["lo"]
	m.mu.Unlock()

	m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})

	m.mu.Lock()
	after := m.ifaceEpoch["lo"]
	m.mu.Unlock()

	if after != before {
		t.Fatalf("a SKIPPED interface's epoch moved %d -> %d: a supersession bump must "+
			"accompany real superseding responsibility, and this call emitted nothing "+
			"and claimed nothing", before, after)
	}
}

// TestWithdrawOnceClaimStillBumps_8597 is the OVER-BROAD control, and the one
// that keeps the fix from being a plain deletion.
//
// On the CLAIMED path the bump is load-bearing: WithdrawOnce takes the
// interface over and emits the goodbye, so a deferred Apply start for that
// interface (which captured the epoch in deferredIfaceEpoch) must be
// superseded. Removing the bump outright — rather than moving it into the claim
// branch — would let a deferred start bring the sender back after the operator
// withdrew it.
func TestWithdrawOnceClaimStillBumps_8597(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	newFakeListen(t)
	m := New()

	m.mu.Lock()
	before := m.ifaceEpoch["lo"]
	m.mu.Unlock()

	res := m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})

	// Non-vacuity: this cell is about the CLAIMED path, so the call must have
	// taken it. An idle lo is not busy, so WithdrawOnce claims and attempts the
	// goodbye; whether the emit itself succeeds in this environment is not the
	// subject, only that it was not skipped.
	if len(res) != 1 || res[0].Skipped {
		t.Fatalf("WithdrawOnce(lo) on an idle manager reported Skipped=%v; this cell is "+
			"about the CLAIMED path", res[0].Skipped)
	}

	m.mu.Lock()
	after := m.ifaceEpoch["lo"]
	m.mu.Unlock()

	if after == before {
		t.Fatalf("a CLAIMED interface's epoch did not move (%d): WithdrawOnce owns this "+
			"interface's goodbye, so a deferred Apply start for it must be superseded — "+
			"the fix moves the bump into the claim branch, it does not delete it", after)
	}
	_ = m.Clear()
}

// TestWithdrawOnceSkipDoesNotSupersedeWhileWithdrawInterfacesDoes_8597 states
// the CONTRAST the fix rests on, so a reader does not conclude that
// interface-scoped withdraws simply stopped superseding.
//
// WithdrawInterfaces([lo]) must still cancel lo's restart — it flips
// goodbyeWanted on the existing entry and takes over the goodbye, which is
// exactly the responsibility WithdrawOnce's skip path did not take. The two
// halves of this cell differ ONLY in which entry point is called.
func TestWithdrawOnceSkipDoesNotSupersedeWhileWithdrawInterfacesDoes_8597(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	run := func(t *testing.T, withdraw func(m *Manager)) bool {
		t.Helper()
		fl := newFakeListen(t)
		m := New()
		old, cfg, startEpoch := installRestartEntry(t, fl, m)
		withdraw(m)
		started := false
		if err := m.releaseDrain("lo", old, startEpoch, func() error {
			started = true
			return m.startLocked(cfg)
		}); err != nil {
			t.Fatalf("releaseDrain: %v", err)
		}
		_ = m.Clear()
		return started
	}

	if started := run(t, func(m *Manager) {
		m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})
	}); !started {
		t.Error("a SKIPPED WithdrawOnce cancelled lo's restart; it emitted nothing and " +
			"claimed nothing, so it must supersede nothing")
	}

	if started := run(t, func(m *Manager) {
		m.withdrawInterfacesForTest([]string{"lo"})
	}); started {
		t.Error("a WithdrawInterfaces naming lo must STILL supersede lo's restart — it " +
			"flips goodbyeWanted and takes over the goodbye. If this half fails, the " +
			"fix has removed genuine supersession rather than the unpaired bump")
	}
}
