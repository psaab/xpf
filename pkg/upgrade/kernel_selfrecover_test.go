package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeSRCluster struct {
	drained    bool
	drainedErr error
	drainedAt  time.Time
	peerOK     bool
	peerErr    error
	resets     int
	resetErr   error
}

func (f *fakeSRCluster) LocalDrained() (bool, error) { return f.drained, f.drainedErr }
func (f *fakeSRCluster) LocalDrainedSince() (time.Time, error) {
	if !f.drained {
		return time.Time{}, nil
	}
	if f.drainedAt.IsZero() {
		return time.Unix(1_600_000_000, 0), nil
	}
	return f.drainedAt, nil
}
func (f *fakeSRCluster) PeerHealthyPrimary() (bool, error) { return f.peerOK, f.peerErr }
func (f *fakeSRCluster) ResetFailover() error              { f.resets++; return f.resetErr }

func newSR(t *testing.T, cl *fakeSRCluster, now *time.Time, grace time.Duration) *KernelSelfRecovery {
	t.Helper()
	return NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     grace,
		Now:       func() time.Time { return *now },
	}, cl)
}

func writeLease(t *testing.T, path string, l KernelRollLease) {
	t.Helper()
	b, _ := json.Marshal(l)
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("write lease: %v", err)
	}
}

// EXPIRED-lease-ours (crashed orchestrator) + drained + healthy peer, held for
// Grace -> auto-ResetFailover. (Self-recovery fires ONLY on an expired lease
// naming us — the crashed-orchestrator fingerprint.)
func TestSelfRecoveryRecoversAfterGrace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 90*time.Second)
	// an EXPIRED lease naming node 0 (the orchestrator wrote it then died)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})

	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("first tick should only START the timer (did=%v err=%v)", did, err)
	}
	if cl.resets != 0 {
		t.Fatal("must not reset within grace")
	}
	// advance past grace
	now = now.Add(91 * time.Second)
	did, err := sr.Tick()
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if !did || cl.resets != 1 {
		t.Fatalf("expected auto-ResetFailover after grace (did=%v resets=%d)", did, cl.resets)
	}
}

// NO lease present (manual maintenance / #1917 binary-rolling drain) -> NEVER
// self-recover, even drained-with-healthy-peer past grace (r2 AGY: the
// cross-feature interaction — self-recovery must not break an operator's or
// #1917's drain window).
func TestSelfRecoveryNoLeaseNeverRecovers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second) // no lease file written
	_, _ = sr.Tick()
	now = now.Add(10 * time.Second) // well past grace
	if did, _ := sr.Tick(); did || cl.resets != 0 {
		t.Fatal("no kernel-roll lease => must NOT self-recover (manual maint / #1917 drain)")
	}
}

// An UNEXPIRED lease for THIS node suppresses self-recovery (real roll ongoing).
func TestSelfRecoverySuppressedByActiveLease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(10 * time.Minute)})

	now = now.Add(5 * time.Minute) // well past grace, but lease still valid
	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("active lease must suppress recovery (did=%v err=%v)", did, err)
	}
	if cl.resets != 0 {
		t.Fatal("must not reset while a valid lease names this node")
	}
}

// An EXPIRED lease does NOT suppress (orchestrator crashed) -> recovers.
func TestSelfRecoveryExpiredLeaseDoesNotSuppress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 10*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-1 * time.Minute)}) // expired

	_, _ = sr.Tick() // starts timer
	now = now.Add(11 * time.Second)
	did, _ := sr.Tick()
	if !did || cl.resets != 1 {
		t.Fatalf("expired lease should not suppress recovery (did=%v resets=%d)", did, cl.resets)
	}
}

// A STILL-ARMED candidate is a trial in flight even if the lease expired (a
// legitimately long-hanging roll that outran its TTL). Self-recovery must NOT
// rejoin it — the promote/revert oneshot owns the resolution and the election
// hold keeps it secondary (r2 AGY long-hanging-roll TTL split-brain).
func TestSelfRecoveryArmedSuppressesEvenOnExpiredLease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     10 * time.Second,
		Now:       func() time.Time { return now },
		Armed:     func() (bool, error) { return true, nil }, // trial still in flight
	}, cl)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})

	_, _ = sr.Tick()
	now = now.Add(11 * time.Second) // well past grace
	if did, err := sr.Tick(); err != nil || did || cl.resets != 0 {
		t.Fatalf("a STILL-ARMED candidate must NOT be self-recovered even with an "+
			"expired lease (did=%v err=%v resets=%d)", did, err, cl.resets)
	}
}

// When the candidate is NO LONGER armed (the trial resolved to promoted/reverted
// but the orchestrator died before clearing the lease), the expired-lease path
// still recovers an orphaned-drained node.
func TestSelfRecoveryNotArmedExpiredLeaseRecovers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     10 * time.Second,
		Now:       func() time.Time { return now },
		Armed:     func() (bool, error) { return false, nil },
	}, cl)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})

	_, _ = sr.Tick()
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || !did || cl.resets != 1 {
		t.Fatalf("not-armed + expired lease + drained + healthy peer must recover "+
			"(did=%v err=%v resets=%d)", did, err, cl.resets)
	}
}

// A lease naming the OTHER node is NOT our kernel roll -> we must NOT
// self-recover off it (it is the peer's concern, not ours).
func TestSelfRecoveryOtherNodeLeaseDoesNotRecover(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	// an expired lease, but for node 1 — not us.
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 1, ExpiresAt: now.Add(-time.Minute)})

	_, _ = sr.Tick()
	now = now.Add(11 * time.Second)
	did, _ := sr.Tick()
	if did || cl.resets != 0 {
		t.Fatal("a lease for node 1 must NOT trigger node 0 self-recovery")
	}
}

// Not drained -> never recovers (the normal case).
func TestSelfRecoveryNoOpWhenNotDrained(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: false, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	now = now.Add(10 * time.Second)
	if did, _ := sr.Tick(); did || cl.resets != 0 {
		t.Fatal("must not recover when not drained")
	}
}

// EXPIRED-lease-ours but peer NOT a healthy primary -> do NOT auto-recover
// (dual-down — leave for orchestrator/operator).
func TestSelfRecoveryNoOpWhenPeerUnhealthy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: false}
	sr := newSR(t, cl, &now, 1*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})
	now = now.Add(10 * time.Second)
	if did, _ := sr.Tick(); did || cl.resets != 0 {
		t.Fatal("must not auto-recover when the peer is not a healthy primary")
	}
}

// The timer RESETS if the condition lapses (e.g. peer flaps), so a transient
// blip doesn't accumulate toward the grace deadline. (expired-lease-ours present)
func TestSelfRecoveryTimerResetsOnConditionLapse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 60*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})
	_, _ = sr.Tick() // start timer
	now = now.Add(40 * time.Second)
	cl.drained = false // condition lapses
	_, _ = sr.Tick()   // resets timer
	cl.drained = true
	now = now.Add(40 * time.Second) // 80s total but only 40s since re-observe
	if did, _ := sr.Tick(); did {
		t.Fatal("timer should have reset on the lapse; not yet past grace")
	}
}

// #4872 C: a semantic-empty lease body ({}) decodes to NodeID=0 + zero
// ExpiresAt. On node 0 that would slip past the NodeID guard and read as an
// ALREADY-EXPIRED lease naming us, spuriously arming self-recovery during a
// deliberate maintenance drain. A lease with no expires_at must be rejected.
func TestSelfRecoveryEmptyLeaseDoesNotRecover(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	if err := os.WriteFile(sr.cfg.LeasePath, []byte("{}"), 0644); err != nil {
		t.Fatalf("write lease: %v", err)
	}
	_, _ = sr.Tick()
	now = now.Add(10 * time.Second) // well past grace
	if did, err := sr.Tick(); did || err != nil || cl.resets != 0 {
		t.Fatalf("#4872 C: a semantic-empty {} lease must NOT trigger node-0 self-recovery "+
			"(did=%v err=%v resets=%d)", did, err, cl.resets)
	}
}

// #4872 C: a lease carrying node_id but no expires_at is missing a required
// field and must not authorize self-recovery either.
func TestSelfRecoveryLeaseMissingExpiryDoesNotRecover(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	if err := os.WriteFile(sr.cfg.LeasePath, []byte(`{"node_id":0,"holder":"orch"}`), 0644); err != nil {
		t.Fatalf("write lease: %v", err)
	}
	_, _ = sr.Tick()
	now = now.Add(10 * time.Second)
	if did, _ := sr.Tick(); did || cl.resets != 0 {
		t.Fatal("#4872 C: a lease missing expires_at must NOT trigger self-recovery")
	}
}

// #4872 D: an observation error must RESET the grace clock so grace accrues
// only while every predicate is continuously observed positive. A run of
// errored ticks (transient management outage) must not silently age the
// deadline and let the next positive tick rejoin immediately.
func TestSelfRecoveryObservationErrorResetsGrace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 60*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})

	// Tick 1: start the grace timer.
	if did, err := sr.Tick(); did || err != nil {
		t.Fatalf("tick 1 should only start the timer (did=%v err=%v)", did, err)
	}
	// Nearly a full grace window elapses, then a tick hits an observation error.
	now = now.Add(59 * time.Second)
	cl.peerErr = fmt.Errorf("transient management outage")
	if did, err := sr.Tick(); did || err == nil {
		t.Fatalf("errored tick must not recover and must surface the error (did=%v err=%v)", did, err)
	}
	// Clear the error and advance PAST the ORIGINAL deadline (61s since tick 1)
	// but only just past the errored tick: with the grace clock reset this must
	// NOT rejoin yet (pre-fix it would, because drainedSince still pointed at
	// tick 1).
	now = now.Add(2 * time.Second)
	cl.peerErr = nil
	if did, err := sr.Tick(); did || err != nil {
		t.Fatalf("#4872 D: grace clock must restart after the errored-tick gap; must NOT "+
			"rejoin yet (did=%v err=%v)", did, err)
	}
	if cl.resets != 0 {
		t.Fatal("#4872 D: rejoined despite the reset grace window")
	}
	// After a fresh CONTINUOUS grace window it does recover.
	now = now.Add(61 * time.Second)
	if did, err := sr.Tick(); !did || err != nil || cl.resets != 1 {
		t.Fatalf("should recover after a fresh continuous grace window (did=%v err=%v resets=%d)",
			did, err, cl.resets)
	}
}
