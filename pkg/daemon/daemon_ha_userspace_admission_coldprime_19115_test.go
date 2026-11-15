package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// #19115: an ISSU drain (ForceSecondary) that lands while a cold-prime debt is
// owed with no bulk in flight must get past the userspace pre-hook's
// cold-prime refusal inside the admission window, not be refused for all of it.
//
// The pre-hook refuses while ColdPrimeOwedWithoutPendingBulk holds (#10387)
// and does nothing about the debt; runPreHook retries the retryable refusal
// for DefaultPreManualFailoverRetryTimeout (5 s). On a live connection only the
// sweep's owed re-drive clears the debt. Each refused attempt also bumps
// syncPrimeRetryGen, which kills the daemon's own bulk-prime retry loop and
// restarts it with its 10 s first wait, so that loop cannot help inside the
// window.
//
// THE REQUIREMENT (design v3, Codex P2-7): within the refusal window the debt
// reaches a qualifying PENDING bulk, so the pre-hook stops refusing for the
// cold-prime reason and proceeds to its barrier. The barrier and the peer's
// ack are a separate latency, bounded by the pre-hook's own 60 s barrier
// timeout, and are measured here, not asserted against the window.
//
// Fixture (Codex P2-6): the #10387 loopback pair, but with the local side's
// dependencies wired BEFORE Start, as startClusterComms orders them: the
// table-truth source, the runtime (with the sweep profile), the ownership
// predicate and the sweep. The source fails until the cell heals it, and the
// cell waits until the failed first bulk has returned (its failure is recorded
// in ColdPrimeDebtDetail) before it heals the source and drives the drain
// through the REAL Manager.ForceSecondary admission path.
//
// control-fast-sweep passes at master and proves the fixture can admit.
// userspace-sweep-profile is RED at master 05b4645749: every attempt in the
// window is refused.
func TestForceSecondaryAdmittedWhileOwedColdPrimeIsRedriven19115(t *testing.T) {
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
			var healed atomic.Bool
			ss := syncPairWiredBeforeStart19115(t, ctx, p.active, p.idle, &healed)
			healed.Store(true) // the transient is over; any re-drive from here on succeeds

			d := &Daemon{sessionSync: ss, userspaceDemotionPrepUntil: make(map[int]time.Time)}
			d.setDataplane(&runtimeOnlyApplyTestDP{})
			t.Cleanup(func() { d.syncPrimeRetryGen.Add(1) })
			cm := managerReadyToDrain19115(t)

			var mu sync.Mutex
			var attempts, coldPrimeRefusals int
			var firstAttempt, firstPass, passStarted time.Time
			cm.SetPreManualFailoverHook(func(rgID int) error {
				started := time.Now()
				err := d.prepareUserspaceManualFailover(rgID)
				mu.Lock()
				defer mu.Unlock()
				attempts++
				if firstAttempt.IsZero() {
					firstAttempt = started
				}
				if err != nil && strings.Contains(err.Error(), "cold prime owed") {
					coldPrimeRefusals++
				} else if firstPass.IsZero() {
					firstPass, passStarted = time.Now(), started
				}
				return err
			})
			drainErr := cm.ForceSecondary()

			mu.Lock()
			defer mu.Unlock()
			if coldPrimeRefusals == 0 {
				t.Fatal("FIXTURE: the drain was never refused for the cold-prime debt, so this run says nothing about the re-drive")
			}
			if firstPass.IsZero() {
				t.Fatalf("#19115: the pre-hook refused the drain for the cold-prime debt for the whole %v admission window (%d attempts, sweep profile %v/%v): %v",
					cluster.DefaultPreManualFailoverRetryTimeout, attempts, p.active, p.idle, drainErr)
			}
			// runPreHook checks its deadline only after a refusal, so the
			// passing attempt must have STARTED inside the window.
			if sinceFirst := passStarted.Sub(firstAttempt); sinceFirst >= cluster.DefaultPreManualFailoverRetryTimeout {
				t.Fatalf("#19115: the first attempt past the cold-prime refusal started %v after the first attempt, outside the %v window",
					sinceFirst.Round(time.Millisecond), cluster.DefaultPreManualFailoverRetryTimeout)
			}
			t.Logf("cold-prime refusals: %d; past them %v after the first attempt (that attempt took %v including the barrier); ForceSecondary returned %v",
				coldPrimeRefusals, passStarted.Sub(firstAttempt).Round(time.Millisecond),
				firstPass.Sub(passStarted).Round(time.Millisecond), drainErr)
		})
	}
}

var errInjected19115 = errors.New("injected #19115 transient: helper/config generation changed during export window")

// syncPairWiredBeforeStart19115 builds the #10387 loopback pair with the local
// side wired BEFORE Start, and returns once the local side's first
// (connect-time) cold-prime bulk has FAILED and returned, leaving the debt
// owed with no bulk pending. Every bulk fails until *healed is set.
func syncPairWiredBeforeStart19115(t *testing.T, ctx context.Context, active, idle time.Duration, healed *atomic.Bool) *cluster.SessionSync {
	t.Helper()
	ensureLoopbackForSyncPairTest(t)
	reserve := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve a port: %v", err)
		}
		addr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatalf("release a port: %v", err)
		}
		return addr
	}
	addrA, addrB := reserve(), reserve()
	local := cluster.NewSessionSync(addrA, addrB, nil)
	peer := cluster.NewSessionSync(addrB, addrA, nil)

	local.BulkSnapshotSource = func() (cluster.BulkSnapshot, error) {
		if !healed.Load() {
			return cluster.BulkSnapshot{}, errInjected19115
		}
		return cluster.BulkSnapshot{}, nil
	}
	local.SetRuntimeDomains(profiledSessionStore19115{
		SessionStore: dataplane.SessionStoreOf(nil),
		source:       sweepProfileSource19115{active: active, idle: idle},
	}, nil)
	local.IsPrimaryFn = func() bool { return true }
	// Cancelled in a cleanup registered after Start's Stop cleanups, so it
	// runs first: Stop waits for the sweep goroutine.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	local.StartSyncSweep(sweepCtx)

	if err := local.Start(ctx); err != nil {
		t.Fatalf("start local session sync: %v", err)
	}
	t.Cleanup(local.Stop)
	if err := peer.Start(ctx); err != nil {
		t.Fatalf("start peer session sync: %v", err)
	}
	t.Cleanup(peer.Stop)
	t.Cleanup(stopSweep)

	deadline := time.Now().Add(20 * time.Second)
	for !local.IsConnected() || !strings.Contains(local.ColdPrimeDebtDetail(), errInjected19115.Error()) {
		if time.Now().After(deadline) {
			t.Fatalf("FIXTURE: the pair never connected with a failed first cold prime (connected=%v, debt=%q)",
				local.IsConnected(), local.ColdPrimeDebtDetail())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !local.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: the failed cold prime must leave the debt owed with no bulk pending")
	}
	return local
}

// managerReadyToDrain19115 is a cluster manager that is primary for RG0 and
// RG1 with a live peer, so ForceSecondary reaches its pre-hook.
func managerReadyToDrain19115(t *testing.T) *cluster.Manager {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 200}},
		{ID: 1, NodePriorities: map[int]int{0: 200}},
	}})
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	for _, id := range []int{0, 1} {
		if !cm.IsLocalPrimary(id) {
			t.Fatalf("FIXTURE: the node must be primary for RG%d", id)
		}
		cm.SetPeerGroupStateForTesting(id, cluster.StateSecondary)
	}
	return cm
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
