package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// #19115: an ISSU drain or manual failover that lands while a cold-prime debt
// is owed with no bulk in flight must be ADMITTED inside its admission window,
// not refused for all of it.
//
// The pre-hook refuses the drain while ColdPrimeOwedWithoutPendingBulk holds
// (#10387) and does nothing about the debt; runPreHook retries the retryable
// refusal for DefaultPreManualFailoverRetryTimeout. On a live connection only
// the sweep's owed re-drive clears the debt, and under the userspace sweep
// profile the sweep ticks every 15s at best. Each refused attempt also bumps
// syncPrimeRetryGen, which kills the daemon's own bulk-prime retry loop and
// restarts it with its 10s first wait, so that loop cannot fire inside the
// window either.
//
// Fixture: the #10387 loopback pair, whose post-connect cold prime failed
// cleanly (nil session store). The runtime is then wired the way
// startClusterComms wires it, so any re-drive from here on succeeds; that
// stands in for the field's transient export failure ("helper/config
// generation changed during export window"), which also succeeds on retry.
//
// control-fast-sweep passes at master and proves the fixture can admit.
// userspace-sweep-profile is RED at master 05b4645749: every attempt in the
// window is refused.
func TestManualFailoverAdmittedWhileOwedColdPrimeIsRedriven19115(t *testing.T) {
	for _, p := range []struct {
		name         string
		active, idle time.Duration
	}{
		{name: "control-fast-sweep", active: 50 * time.Millisecond, idle: 100 * time.Millisecond},
		// pkg/dataplane/userspace/manager.go SessionSyncSweepProfile.
		{name: "userspace-sweep-profile", active: 15 * time.Second, idle: 60 * time.Second},
	} {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			ss := connectedSyncPairForDrainTest(t, ctx)
			if !ss.ColdPrimeOwedWithoutPendingBulk() {
				t.Fatal("FIXTURE: the pair's cold prime must have failed, leaving the debt owed with no bulk pending")
			}

			ss.BulkSnapshotSource = func() (cluster.BulkSnapshot, error) { return cluster.BulkSnapshot{}, nil }
			ss.SetRuntimeDomains(profiledSessionStore19115{
				SessionStore: dataplane.SessionStoreOf(nil),
				source:       sweepProfileSource19115{active: p.active, idle: p.idle},
			}, nil)
			ss.IsPrimaryFn = func() bool { return true }
			// Registered after the pair's Stop cleanup, so it runs first:
			// Stop waits for the sweep goroutine, which exits on this context.
			sweepCtx, stopSweep := context.WithCancel(ctx)
			t.Cleanup(stopSweep)
			ss.StartSyncSweep(sweepCtx)

			d := &Daemon{sessionSync: ss, userspaceDemotionPrepUntil: make(map[int]time.Time)}
			d.setDataplane(&runtimeOnlyApplyTestDP{})
			t.Cleanup(func() { d.syncPrimeRetryGen.Add(1) })

			took, attempts, err := admitLikeRunPreHook19115(d, 0)
			if err != nil {
				t.Fatalf("#19115: the drain was refused for the whole %v admission window (%d attempts, sweep profile %v/%v): %v",
					cluster.DefaultPreManualFailoverRetryTimeout, attempts, p.active, p.idle, err)
			}
			t.Logf("drain admitted after %v (%d attempts)", took.Round(time.Millisecond), attempts)
		})
	}
}

// admitLikeRunPreHook19115 is runPreHook's admission loop (pkg/cluster
// failover.go) around the userspace pre-hook: retry a retryable refusal every
// DefaultPreManualFailoverRetryInterval until DefaultPreManualFailoverRetryTimeout.
func admitLikeRunPreHook19115(d *Daemon, rgID int) (time.Duration, int, error) {
	start := time.Now()
	deadline := start.Add(cluster.DefaultPreManualFailoverRetryTimeout)
	for attempts := 1; ; attempts++ {
		err := d.prepareUserspaceManualFailover(rgID)
		if err == nil {
			return time.Since(start), attempts, nil
		}
		if !cluster.IsRetryablePreFailoverError(err) {
			return time.Since(start), attempts, errors.Join(errors.New("non-retryable refusal"), err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Since(start), attempts, err
		}
		time.Sleep(min(cluster.DefaultPreManualFailoverRetryInterval, remaining))
	}
}

type sweepProfileSource19115 struct{ active, idle time.Duration }

func (sweepProfileSource19115) DrainSessionDeltas(uint32) (dpruntime.SessionDeltaSnapshot, error) {
	return dpruntime.SessionDeltaSnapshot{}, nil
}

func (sweepProfileSource19115) ExportOwnerRGSessions([]int, uint32) (dpruntime.SessionDeltaSnapshot, error) {
	return dpruntime.SessionDeltaSnapshot{}, nil
}

func (p sweepProfileSource19115) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	return true, p.active, p.idle
}

// profiledSessionStore19115 is an empty session store whose delta source
// carries a sweep profile, as the userspace manager's does.
type profiledSessionStore19115 struct {
	dataplane.SessionStore
	source dpruntime.SessionDeltaSource
}

func (s profiledSessionStore19115) SessionDeltas() dpruntime.SessionDeltaSource {
	return s.source
}
