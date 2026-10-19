package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #15181 (C11-01): a stale expired lease left by a crashed/transport-lost
// roll must not re-fire self-recovery against a LATER, unrelated operator
// drain, and a lease self-recovery acts on must be consumed so it cannot
// fire again.
//
// RED mechanism (both arms fail on origin/master):
//   - predates-drain: the expired lease's ExpiresAt predates the current
//     drain's ManualFailoverAt, so the drain cannot be the roll that wrote
//     the lease. Pre-fix Tick ignores drain timing and resets anyway.
//   - consumed: after a successful recovery the lease file remains on
//     master, so a second operator drain past grace resets again.

func writeLease15181(t *testing.T, path string, l KernelRollLease) {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal lease: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write lease: %v", err)
	}
}

func newSR15181(t *testing.T, cl *fakeSRCluster, now *time.Time, grace time.Duration) *KernelSelfRecovery {
	t.Helper()
	return NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     grace,
		Now:       func() time.Time { return *now },
	}, cl)
}

func TestSelfRecoveryStaleLeasePredatingDrainDoesNotRecover15181(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR15181(t, cl, &now, 10*time.Second)
	writeLease15181(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Hour)})
	// The current drain began long after the lease expired.
	cl.drainedAt = now.Add(-time.Minute)

	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("first tick (did=%v err=%v)", did, err)
	}
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || did || cl.resets != 0 {
		t.Fatalf("#15181: an expired lease that predates the current drain must not "+
			"self-recover the later operator drain (did=%v err=%v resets=%d)", did, err, cl.resets)
	}
}

func TestSelfRecoveryLeasePostdatingDrainStillRecovers15181(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR15181(t, cl, &now, 10*time.Second)
	// Lease expired after the drain began: the crashed-roll fingerprint.
	writeLease15181(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})
	cl.drainedAt = now.Add(-time.Hour)

	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("first tick (did=%v err=%v)", did, err)
	}
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || !did || cl.resets != 1 {
		t.Fatalf("crashed-roll recovery must still fire when the lease postdates the drain "+
			"(did=%v err=%v resets=%d)", did, err, cl.resets)
	}
}

// fakeSRClusterZero is a SelfRecoveryCluster whose drain start is
// genuinely unknown (zero), for the fail-closed cell above.
type fakeSRClusterZero struct{ fakeSRCluster }

func (f *fakeSRClusterZero) LocalDrainedSince() (time.Time, error) {
	return time.Time{}, nil
}

func TestSelfRecoveryUnknownDrainStartZero15181(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := &fakeSRCluster{drained: true, peerOK: true}
	cl := &fakeSRClusterZero{fakeSRCluster: *base}
	sr := NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     10 * time.Second,
		Now:       func() time.Time { return now },
	}, cl)
	writeLease15181(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})
	_, _ = sr.Tick()
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || did || base.resets != 0 {
		t.Fatalf("#15181: zero drain start must fail closed (did=%v err=%v resets=%d)", did, err, base.resets)
	}
}

func TestSelfRecoveryConsumesLeaseAfterRecovery15181(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR15181(t, cl, &now, 10*time.Second)
	writeLease15181(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})
	cl.drainedAt = now.Add(-time.Hour)

	_, _ = sr.Tick()
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || !did || cl.resets != 1 {
		t.Fatalf("recovery tick (did=%v err=%v resets=%d)", did, err, cl.resets)
	}
	if _, err := os.Stat(sr.cfg.LeasePath); !os.IsNotExist(err) {
		t.Fatalf("#15181: lease must be consumed after self-recovery acts (stat err=%v)", err)
	}
	// A later operator drain must not re-fire off the consumed lease.
	cl.drainedAt = now
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("second drain first tick (did=%v err=%v)", did, err)
	}
	now = now.Add(11 * time.Second)
	if did, err := sr.Tick(); err != nil || did || cl.resets != 1 {
		t.Fatalf("#15181: consumed lease must not re-fire for a later drain "+
			"(did=%v err=%v resets=%d)", did, err, cl.resets)
	}
}
