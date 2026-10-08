package daemon

// recovered_rollback_dispatch_6739_test.go — #6739, the WIRING of the
// pre-manager recovered-rollback window.
//
// #7676 guarded ONE dereference — `d.vrrpMgr` inside applyTailReconciles — and
// bound it with a cell that calls applyTailReconciles DIRECTLY. That binds the
// guarded function. It does not bind the dispatch that has to reach it:
//
//	Store.Load (phase 1) re-arms time.AfterFunc(time.Until(deadline))
//	    -> fireConfirmTimer(gen)
//	        -> the executor registered before the phase list
//	            -> executeConfirmedRollback
//	                -> applyConfigLocked        <- ~10 reconcile helpers
//	                    -> applyTailReconciles  <- the guarded site
//
// Every manager between phase 1 and phase 3 is still nil on that path. If any
// helper AHEAD of the tail dereferences one without a guard, the daemon panics
// at boot exactly as it did before #7676 — and #7676's cell stays GREEN,
// because it enters at the tail and never runs the helpers that panicked.
//
// These cells drive the REAL dispatch (Store's own timer-expiry logic via
// InvokeRollbackTimerForTesting, the registered executor, the apply body
// UNSTUBBED) against a daemon in the exact pre-manager shape, over BOTH
// branches of executeConfirmedRollback:
//
//   - prevCfg != nil -> the full applyConfigLocked pipeline
//   - prevCfg == nil -> enterBootstrapMode (the #1922 Item 1b first-commit
//     branch, which is also work item H's scenario when the abandoned config
//     declares a cluster)
//
// The bootstrap_rollback_test.go cells already drive this dispatch, but they
// set applyBodyForTest, which returns from applyConfigLocked before ANY
// reconcile helper runs. That seam is why the #6739 panic survived to be found
// by reading rather than by the suite.

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
)

// clusterConfig6739 is the rollback TARGET for the dispatch cells: a config
// that declares a chassis cluster with RETH members, so the reverted apply
// walks the cluster/VRRP/fabric reconciles rather than the empty-config
// no-op branches. assertRichFixture6739 keeps it from silently degenerating.
const clusterConfig6739 = `
system {
    host-name rollback-target;
}
chassis {
    cluster {
        cluster-id 22;
        authentication-key "test-psk-6739";
        reth-count 2;
        heartbeat-interval 200;
        heartbeat-threshold 5;
        control-interface em0;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            interface-monitor ge-0/0/1 weight 255;
        }
    }
}
interfaces {
    em0 {
        unit 0 { family inet { address 10.99.12.1/30; } }
    }
    ge-0/0/1 {
        gigether-options { redundant-parent reth1; }
    }
    ge-0/0/2 {
        gigether-options { redundant-parent reth0; }
    }
    reth0 {
        redundant-ether-options { redundancy-group 1; }
        unit 0 { family inet { address 172.16.50.8/24; } }
    }
    reth1 {
        redundant-ether-options { redundancy-group 1; }
        unit 0 { family inet { address 10.0.61.1/24; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces reth1.0;
        }
        security-zone untrust {
            interfaces reth0.0;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
            }
        }
    }
}
`

// daemonInPreManagerWindow6739 is the daemon EXACTLY as it is when a recovered
// commit-confirmed timer can fire: startup phase 1 has run (the store exists —
// it is the object that armed the timer, and applySem is built in New before
// any phase), and every manager phase 3 constructs is still nil.
//
// The apply body is deliberately NOT stubbed. Stubbing it is what makes the
// pre-existing rollback cells blind to this window.
func daemonInPreManagerWindow6739(t *testing.T) (*Daemon, *configstore.Store) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	return d, s
}

// assertRichFixture6739 fails if the committed fixture did not actually
// compile to the cluster shape these cells claim to exercise. Without it a
// parse/compile regression would quietly reduce every cell below to the
// empty-config no-op path — which survives for reasons that have nothing to do
// with the guard, and would report a clean census anyway.
func assertRichFixture6739(t *testing.T, s *configstore.Store) {
	t.Helper()
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("fixture did not compile: ActiveConfig is nil")
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("fixture degenerated: the rollback target declares no chassis cluster, so " +
			"the reverted apply never walks the cluster/VRRP reconciles this cell exists for")
	}
	if len(cfg.Interfaces.Interfaces) == 0 {
		t.Fatal("fixture degenerated: no interfaces, so the interface/networkd reconciles no-op")
	}
	var reths int
	for name := range cfg.Interfaces.Interfaces {
		if strings.HasPrefix(name, "reth") {
			reths++
		}
	}
	if reths == 0 {
		t.Fatal("fixture degenerated: no reth interfaces, so the RETH/VRRP reconciles no-op")
	}
}

// TestRecoveredRollbackDispatchSurvivesPreManagerWindow6739 is the wiring cell
// for the non-nil rollback target: the whole applyConfigLocked pipeline runs
// with every manager nil.
//
// FAIL-ON-REVERT: remove the `d.vrrpMgr == nil` arm in applyTailReconciles and
// this panics — which is what the daemon does at boot. It also reds for an
// unguarded dereference in ANY helper ahead of the tail, which is the case
// #7676's direct-entry cell cannot see.
func TestRecoveredRollbackDispatchSurvivesPreManagerWindow6739(t *testing.T) {
	d, s := daemonInPreManagerWindow6739(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(clusterConfig6739); err != nil {
		t.Fatalf("LoadOverride(rollback target): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(rollback target): %v", err)
	}
	assertRichFixture6739(t, s)

	// The abandoned config the operator armed with `commit confirmed` and never
	// confirmed. The reboot lands inside its window; Store.Load re-arms.
	if err := s.LoadOverride("system { host-name abandoned; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.ExitConfigure()

	// Precondition: this is the pre-manager shape, not a fully-built daemon.
	if d.vrrpMgr != nil || d.routing != nil || d.frr != nil || d.networkd != nil ||
		d.cluster != nil || d.ipsec != nil {
		t.Fatal("precondition: every manager initManagers builds must be nil — phase 3 has not run")
	}
	if d.applyBodyForTest != nil {
		t.Fatal("precondition: the apply body must NOT be stubbed — the stub is what hides this window")
	}

	buf, restore := captureSlog(t)
	defer restore()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the recovered commit-confirmed rollback PANICKED on the "+
					"pre-manager window — this is a daemon panic AT BOOT (#6739): %v", r)
			}
		}()
		// The exact dispatch Store's expired timer runs.
		s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
	}()

	// The dispatch must REACH the guarded site, not survive by returning early.
	// Without this the panic assertion above is satisfied by an apply that
	// aborted in helper 1 and never ran the tail at all — a vacuous green that
	// would look identical to a healthy one.
	//
	// Keyed on the guard's own fail-closed message, which is the same string
	// TestRecoveredRollbackDoesNotPanicBeforeManagers6739 asserts on, so the two
	// cells bind ONE contract rather than two independently-rotting ones.
	if !strings.Contains(buf.String(), "VRRP manager not initialized") {
		t.Fatalf("the rollback apply never reached the guarded VRRP reconcile — this cell "+
			"would then prove nothing about the tail. Log was:\n%s", buf.String())
	}

	// And the transaction must have completed: the store is back on the target.
	if got := s.ActiveConfig(); got == nil || got.System.HostName != "rollback-target" {
		t.Fatalf("rollback did not promote the target config: %#v", got)
	}
}

// TestRecoveredFirstCommitClusterRollbackDispatchSurvives6739 is the wiring
// cell for the OTHER branch: prevCfg == nil, so executeConfirmedRollback runs
// enterBootstrapMode instead of an apply.
//
// This is also work item H's exact scenario — a FirstCommit record whose
// recovered active declares a cluster — so the cell records what master
// actually does there today rather than leaving it to be re-derived.
func TestRecoveredFirstCommitClusterRollbackDispatchSurvives6739(t *testing.T) {
	d, s := daemonInPreManagerWindow6739(t)
	isolateFirstCommitRollbackHostAuth12169(t)

	// FIRST commit on a fresh store, and it declares a cluster.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(clusterConfig6739); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	assertRichFixture6739(t, s)
	s.ExitConfigure()

	if d.inBootstrap() {
		t.Fatal("precondition: not in bootstrap before the timeout")
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the recovered FIRST-COMMIT rollback PANICKED on the pre-manager "+
					"window — a daemon panic AT BOOT (#6739): %v", r)
			}
		}()
		s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
	}()

	if !d.inBootstrap() {
		t.Fatal("a first-commit commit-confirmed timeout must leave the daemon in BOOTSTRAP mode")
	}
	if s.EverCommitted() {
		t.Fatal("after a first-commit rollback the store must read never-committed")
	}
}
