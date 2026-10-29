package upgrade

import (
	"strings"
	"testing"
	"time"
)

func TestRollingConfigRejoinDeadlineDefaultAndOverride18415(t *testing.T) {
	var defaults RollingConfig
	defaults.withDefaults()
	if defaults.RejoinDeadline != 180*time.Second {
		t.Fatalf("default RejoinDeadline = %s, want 180s", defaults.RejoinDeadline)
	}
	if DefaultRejoinDeadline != 180*time.Second {
		t.Fatalf("exported DefaultRejoinDeadline = %s, want 180s", DefaultRejoinDeadline)
	}

	const explicit = 37 * time.Millisecond
	configured := RollingConfig{RejoinDeadline: explicit}
	configured.withDefaults()
	if configured.RejoinDeadline != explicit {
		t.Fatalf("explicit RejoinDeadline = %s, want preserved value %s", configured.RejoinDeadline, explicit)
	}
}

type delayedBulkPrime18415 struct {
	*fakeCluster
	started time.Time
	delay   time.Duration
	stuck   bool
}

func (f *delayedBulkPrime18415) SessionSyncBulkPrimed() (bool, error) {
	if f.stuck {
		return false, nil
	}
	return time.Since(f.started) >= f.delay, nil
}

func newDelayedBulkPrime18415(delay time.Duration) *delayedBulkPrime18415 {
	return &delayedBulkPrime18415{
		fakeCluster: &fakeCluster{peerAlive: true, synced: true},
		started:     time.Now(),
		delay:       delay,
	}
}

func TestRollingRejoinDeadlineAllowsSlowBulkPrime18415(t *testing.T) {
	const primeDelay = 100 * time.Millisecond
	const pollInterval = 2 * time.Millisecond
	scaledOld60s := 60 * time.Millisecond
	scaledDefault180s := DefaultRejoinDeadline / time.Second * time.Millisecond
	if !(scaledOld60s < primeDelay && primeDelay < scaledDefault180s) {
		t.Fatalf("test timing is not scaled between old and new deadlines: old=%s prime=%s new=%s",
			scaledOld60s, primeDelay, scaledDefault180s)
	}

	oldDeadlineCluster := newDelayedBulkPrime18415(primeDelay)
	if err := rejoinAndConfirm(oldDeadlineCluster, scaledOld60s, pollInterval); err == nil {
		t.Fatal("bulk prime that completes after the scaled old 60s deadline unexpectedly succeeded")
	}

	cluster := newDelayedBulkPrime18415(primeDelay)
	started := time.Now()
	if err := rejoinAndConfirm(cluster, scaledDefault180s, pollInterval); err != nil {
		t.Fatalf("bulk prime completing after scaled 60s but before scaled 180s must succeed: %v", err)
	}
	elapsed := time.Since(started)
	if elapsed < primeDelay || elapsed >= scaledDefault180s {
		t.Fatalf("slow-prime rejoin elapsed %s, want >= prime completion %s and < configured deadline %s",
			elapsed, primeDelay, scaledDefault180s)
	}
	if !cluster.resetCalled {
		t.Fatal("successful bulk prime must be followed by failover reset")
	}
}

func TestRollingRejoinDeadlineTimesOutStuckBulkPrime18415(t *testing.T) {
	const deadline = 50 * time.Millisecond
	const pollInterval = 2 * time.Millisecond
	cluster := &delayedBulkPrime18415{
		fakeCluster: &fakeCluster{peerAlive: true, synced: true},
		started:     time.Now(),
		stuck:       true,
	}
	started := time.Now()
	err := rejoinAndConfirm(cluster, deadline, pollInterval)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("stuck inbound bulk prime unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "rejoin not confirmed within 50ms") || !strings.Contains(err.Error(), "bulk-primed=false") {
		t.Fatalf("stuck-prime timeout must name the configured deadline and failed gate, got %v", err)
	}
	if elapsed < deadline || elapsed >= deadline+100*time.Millisecond {
		t.Fatalf("stuck-prime rejoin elapsed %s, want the configured %s bound with <100ms scheduler slack", elapsed, deadline)
	}
	if cluster.resetCalled {
		t.Fatal("stuck bulk prime must keep the local node held secondary without ResetFailover")
	}
}
