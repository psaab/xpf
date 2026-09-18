package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

func TestExplicitUserspaceDemotionRequiresSessionSync10261(t *testing.T) {
	d := &Daemon{userspaceDemotionPrepUntil: make(map[int]time.Time)}

	err := d.prepareUserspaceManualFailover(0)
	if err == nil {
		t.Fatal("explicit userspace demotion without session sync must fail closed (#10261)")
	}
	if !cluster.IsRetryablePreFailoverError(err) {
		t.Fatalf("missing session-sync error = %v, want retryable pre-failover error", err)
	}

	// Automatic reconciliation is deliberately best-effort: it may observe a
	// missing sync object while the daemon is starting and must not convert that
	// transient state into an operator-facing demotion failure.
	if err := d.prepareUserspaceRGDemotionWithTimeout(0, time.Millisecond); err != nil {
		t.Fatalf("automatic demotion prep should remain best-effort without sync: %v", err)
	}
}

func TestSessionSyncBulkPrimeStatusTracksInboundEpoch10261(t *testing.T) {
	m := cluster.NewManager(0, 1)
	d := &Daemon{cluster: m}

	d.onSessionSyncBulkReceived()
	if !m.IsSyncBulkPrimed() {
		t.Fatal("inbound bulk completion must publish strict rolling readiness")
	}

	// With no completed SessionSync object, a disconnect is a cold/unprimed
	// epoch and must clear the strict bit instead of leaving a stale green
	// rejoin status behind.
	d.onSessionSyncPeerDisconnected()
	if m.IsSyncBulkPrimed() {
		t.Fatal("cold sync disconnect must clear strict bulk-prime readiness")
	}
}

func TestExplicitDemotionDoesNotDeleteAnotherPrepLease10261(t *testing.T) {
	d := &Daemon{userspaceDemotionPrepUntil: make(map[int]time.Time)}
	if !d.acquireUserspaceRGDemotionPrep(0, time.Minute) {
		t.Fatal("fixture: expected automatic prep lease")
	}
	if err := d.prepareUserspaceManualFailover(0); err == nil {
		t.Fatal("explicit demotion without sync must still fail")
	}
	d.userspaceDemotionPrepMu.Lock()
	_, ok := d.userspaceDemotionPrepUntil[0]
	d.userspaceDemotionPrepMu.Unlock()
	if !ok {
		t.Fatal("strict demotion failure deleted a lease owned by another prep path")
	}
}
