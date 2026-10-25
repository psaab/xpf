package daemon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// #16655: scheduleConnectedRGRepublish dereferenced a nil applySem.
// HA test fixtures build &Daemon{store, cluster, ...} without applySem
// (production's only store-bearing constructor sets it in daemon.go).
// A demotion/promotion edge or RG reconcile then spawned a goroutine
// that called (*semaphore.Weighted).Acquire on nil — the SIGSEGV is in
// a non-test goroutine, so it kills the whole test binary and every
// later test in pkg/daemon is neither run nor reported.
//
// Fail-on-revert: drop `|| d.applySem == nil` from either guard and
// the nil cells below panic (async cell: in the spawned goroutine,
// crashing the binary; sync cell: inline on the test goroutine).

// TestConnectedRGRepublishNilApplySem16655 drives a store-only Daemon
// (no applySem) through the production demotion path. It must not
// panic, and the demotion's own rg_active clear must still happen —
// the guard may only skip the republish, not the fence.
func TestConnectedRGRepublishNilApplySem16655(t *testing.T) {
	ha := &actuationHA{err: errRGActiveRejected}
	d := newActuationDaemon(t, ha)
	if d.applySem != nil {
		t.Fatal("fixture precondition: newActuationDaemon must leave applySem nil for this cell")
	}
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	// Pre-fix this spawned scheduleConnectedRGRepublish's goroutine,
	// which panicked on nil applySem and killed the test binary.
	demoteRG1(t, d)

	if got := ha.writeCount(); got != 1 {
		t.Fatalf("SetRGActive call count = %d, want 1 (demotion must still attempt the clear)", got)
	}
	// Give any (pre-fix) stray goroutine a chance to crash before the
	// test reports success; post-fix no goroutine is spawned at all.
	time.Sleep(50 * time.Millisecond)
}

// TestConnectedRGRepublishSyncNilApplySem16655 pins the synchronous
// twin: republishConnectedRGSync is called inline on the cluster-event
// and VRRP-master paths before SetRGActive, so a nil applySem there
// panics on the caller's goroutine instead.
func TestConnectedRGRepublishSyncNilApplySem16655(t *testing.T) {
	d := &Daemon{store: fenceTestStore(t, fenceStartupClusterSet)}
	// Must return without acquiring (and without panicking).
	d.republishConnectedRGSync(context.Background(), "cluster-state")
	d.scheduleConnectedRGRepublish("cluster-state")
	time.Sleep(50 * time.Millisecond)
}

// TestConnectedRGRepublishWithApplySemPublishes16655 is the positive
// control: with a real semaphore the async scheduler still reaches the
// routes-only publisher, so the nil guard did not neuter the feature.
func TestConnectedRGRepublishWithApplySemPublishes16655(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := routeListenerBumpDaemon11565(t, dp)
	if d.applySem == nil {
		t.Fatal("fixture precondition: routeListenerBumpDaemon11565 must set applySem")
	}
	d.scheduleConnectedRGRepublish("cluster-state")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(dp.calls) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	requireRouteListenerCalls11565(t, dp.calls, "publish", "bump")

	// And the sync twin publishes inline under the semaphore.
	dp2 := &fakeOverlayDP{}
	d2 := routeListenerBumpDaemon11565(t, dp2)
	d2.republishConnectedRGSync(context.Background(), "cluster-state")
	requireRouteListenerCalls11565(t, dp2.calls, "publish", "bump")
}

// TestConnectedRGRepublishNilDaemonAndStore16655 keeps the pre-existing
// guards honest alongside the new one.
func TestConnectedRGRepublishNilDaemonAndStore16655(t *testing.T) {
	var nilD *Daemon
	nilD.scheduleConnectedRGRepublish("cluster-state")
	nilD.republishConnectedRGSync(context.Background(), "cluster-state")

	noStore := &Daemon{applySem: semaphore.NewWeighted(1)}
	noStore.scheduleConnectedRGRepublish("cluster-state")
	noStore.republishConnectedRGSync(context.Background(), "cluster-state")
	time.Sleep(20 * time.Millisecond)
}
