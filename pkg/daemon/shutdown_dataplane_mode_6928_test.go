package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #6928: bind the MODE PLACEMENT the stale-pin remediation describes.
//
// The remediation (userspaceShimStalePinRemediation) and the types.go notes
// tell an operator that whether a plain restart clears a stale bpffs pin
// depends on how xpfd last stopped: a HITLESS shutdown preserves the pins
// (Manager.Close), a NON-hitless one tears them down (Manager.Teardown ->
// dataplane.Cleanup). That is a claim about which method each arm of
// runShutdownSequence calls.
//
// pkg/dataplane's two source-scanning tests cannot express it, and this round
// verified that by measurement rather than by reading them:
//
//   - inverting the condition to `if !hitless { rt.Close() } else {
//     rt.Teardown() }` — the remediation exactly backwards — leaves
//     `go test -run 6928 ./pkg/dataplane/` GREEN;
//   - replacing the call with `// rt.Teardown()` builds clean and also
//     leaves it GREEN.
//
// Both are caught here, because this drives the REAL runShutdownSequence with
// a substituted dataplane and observes which method it called. The published
// dataplane is a dataplane.RuntimeDataPlane interface reached through the
// #2114 atomic cell (d.setDataplane / d.dataplane()), so no production seam
// had to be added for this; the harness follows
// daemon_shutdown_wiring_5523_test.go, which already drives the same function
// end to end.
//
// It is not a substitute for the pkg/dataplane caller-set test: that one pins
// the OTHER end of the chain (that Teardown is what reaches Cleanup, and that
// the CLI subcommand is the only other caller). This pins which arm calls
// Teardown at all.

// shutdownModeDP is a RuntimeDataPlane that records only the two lifecycle
// calls the shutdown mode chooses between. The interface itself is embedded
// (nil) to satisfy the rest; nothing in this path calls those methods
// (with zero redundancy groups the HA() loop body never runs, and the
// dataplaneReadyProbe type assertion for logFinalStats fails on this type, so
// Telemetry() is not reached either) — a nil-embedded call would panic loudly
// rather than pass silently.
type shutdownModeDP struct {
	dataplane.RuntimeDataPlane

	closes    atomic.Int32
	teardowns atomic.Int32
}

func (d *shutdownModeDP) Start(context.Context) error { return nil }
func (d *shutdownModeDP) Close() error                { d.closes.Add(1); return nil }
func (d *shutdownModeDP) Teardown() error             { d.teardowns.Add(1); return nil }

// TestShutdownModeChoosesCloseOrTeardown6928 asserts both arms: an HA shutdown
// without `hitless-restart` must call Teardown and NOT Close; the same cluster
// config WITH `hitless-restart` must call Close and NOT Teardown.
//
// Asserting both directions is what makes the pair sensitive to an inverted
// condition. A single-arm test ("non-hitless calls Teardown") stays green when
// the two branches are swapped only if the fixture never exercises the other
// mode — so the hitless case is not decoration, it is the discriminator.
func TestShutdownModeChoosesCloseOrTeardown6928(t *testing.T) {
	for _, tc := range []struct {
		name         string
		clusterBody  string
		wantClose    int32
		wantTeardown int32
	}{
		{
			// Fail-closed: the mode on which a plain restart DOES suffice,
			// because Teardown -> dataplane.Cleanup() unpins everything.
			name:         "HA without hitless-restart tears the pins down",
			clusterBody:  "",
			wantClose:    0,
			wantTeardown: 1,
		},
		{
			// The opted-in mode that PRESERVES the pins on purpose, and so
			// hits the same ABI refusal again after a restart.
			name:         "HA with hitless-restart preserves the pins",
			clusterBody:  "hitless-restart;",
			wantClose:    1,
			wantTeardown: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// #9686: the fail-closed arm now closes kernel transit first.
			seamTransitClose9686(t)
			store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
			if err != nil {
				t.Fatalf("configstore.New: %v", err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			// A cluster stanza with NO redundancy groups: enough to make
			// haMode true (which is what selects the non-hitless default)
			// without entering the rg_active loop, which would need a live
			// HA controller. The authentication-key is not optional — commit
			// rejects a cluster without one (the control channel would fail
			// open) — so it is fixture scaffolding, not part of what is under
			// test here.
			if err := store.LoadOverride(`
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "cyaLE6jUXcHqZBB6xSJP7CVc5S9dHRBAtF5vTBqFEss=";
        ` + tc.clusterBody + `
    }
}
`); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			store.ExitConfigure()

			cfg := store.ActiveConfig()
			if cfg == nil || cfg.Chassis.Cluster == nil {
				t.Fatalf("fixture must commit a cluster config; got %+v", cfg)
			}
			// Guard the fixture's own premise: `hitless` is derived from this
			// flag, so a parser change that stopped setting it would silently
			// turn the hitless case into a second copy of the fail-closed one.
			wantHitless := tc.clusterBody != ""
			if cfg.Chassis.Cluster.HitlessRestart != wantHitless {
				t.Fatalf("fixture: HitlessRestart = %v, want %v (cluster body %q)",
					cfg.Chassis.Cluster.HitlessRestart, wantHitless, tc.clusterBody)
			}
			if n := len(cfg.Chassis.Cluster.RedundancyGroups); n != 0 {
				t.Fatalf("fixture must bind no redundancy groups, got %d", n)
			}

			daemonCtx, cancelDaemon := context.WithCancel(context.Background())
			t.Cleanup(cancelDaemon)

			dp := &shutdownModeDP{}
			d := &Daemon{
				store:     store,
				applySem:  semaphore.NewWeighted(1),
				daemonCtx: daemonCtx,
			}
			// #2114/#6743: the runtime dataplane is published ONLY through
			// the atomic cell; `Daemon.dp` no longer exists. setDataplane is
			// the accessor the daemon_dp_canary_test boundary permits, and
			// runShutdownSequence reads it back with d.dataplane().
			d.setDataplane(dp)

			var wg sync.WaitGroup // empty: this harness starts no run goroutines
			_, stopRun := context.WithCancel(context.Background())
			sentinel := errors.New("run-error-passthrough")

			done := make(chan error, 1)
			go func() { done <- d.runShutdownSequence(&wg, stopRun, sentinel) }()
			select {
			case got := <-done:
				if !errors.Is(got, sentinel) {
					t.Fatalf("runShutdownSequence returned %v, want the run error passed through", got)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("runShutdownSequence did not return within 30s")
			}

			if got := dp.teardowns.Load(); got != tc.wantTeardown {
				t.Errorf("Teardown() called %d times, want %d. The stale-pin remediation "+
					"tells an operator that a NON-hitless shutdown unpins the maps (so a "+
					"restart suffices) and a hitless one does not; if this arm no longer "+
					"calls Teardown, that sentence is now false (#6928)", got, tc.wantTeardown)
			}
			if got := dp.closes.Load(); got != tc.wantClose {
				t.Errorf("Close() called %d times, want %d. A hitless shutdown must close "+
					"Go handles WITHOUT tearing down pinned state; calling the wrong one "+
					"inverts what the remediation says about restarting (#6928)",
					got, tc.wantClose)
			}
		})
	}
}
