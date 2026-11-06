package userspace

import (
	"errors"
	"path/filepath"
	"testing"
)

// #6871 F2: the SIXTH producer of the worker-respawn class.
//
// SetForwardingArmed / SetQueueState / SetBindingState take only m.mu. They are
// reachable exclusively from outside the daemon — `request chassis cluster
// data-plane userspace forwarding|queue|binding ...` in the CLI
// (cli_request_chassis.go) and gRPC SystemAction
// (server_diag_system_action.go) — and neither call site is serialized on the
// daemon's applySem; there is no applySem use anywhere in pkg/cli or
// pkg/grpcapi. Each lands in a helper handler that reaches afxdp.reconcile and
// SPAWNS WORKER THREADS: handlers/forwarding.rs calls reconcile_status_bindings
// unconditionally, handlers/binding.rs and handlers/queue.rs on
// registration_changed.
//
// So an operator (or an automation) issuing one of these in the window
// PrepareLinkCycle opens — workers joined, daemon not yet at setDown, up to
// externalCommandTimeout of `ethtool` per RETH member still to run — respawns
// worker threads into a NIC that is about to unmap their UMEM. That is the
// use-after-unmap #5103 exists to prevent.
//
// The ctrl gate in applyHelperStatusLocked does not cover it: it holds
// ctrl.Enabled=0 correctly, but the spawn happens INSIDE the helper, before the
// response this manager applies, so the gate cannot un-spawn it.
//
// THE OBSERVABLE IS THE REQUEST STREAM, not the error. A gate that returned an
// error but still sent the request would leave the workers spawned and the
// defect intact, so these assert on what actually reached the helper. Both
// halves are checked: the refusal is reported to the operator AND nothing
// crossed the socket.
//
// Deliberately NO BPF maps, so these RUN unprivileged rather than SKIP. That is
// also why the success side asserts "the request reached the helper" rather than
// "the call returned nil": without a ctrl map applyHelperStatusLocked cannot
// complete, which is a fixture limit, not a refusal. errors.Is against the
// sentinel keeps the two apart.

type operatorWorkerVerb struct {
	name    string
	reqType string
	call    func(*Manager) (ProcessStatus, error)
}

// operatorWorkerVerbs is the complete set of Manager methods that reach a helper
// handler capable of spawning workers and that an operator can invoke directly.
//
// BOTH DIRECTIONS of each verb are covered, and that is load-bearing rather than
// thorough (#6871 round 6). The first cut of this table only ever passed `true`,
// so narrowing all three production guards to `if armed && m.linkCycleInFlight()`
// (or `if registered && ...`) left the whole package green — a disable or
// deregister issued inside the protected window would have reached the helper's
// teardown arm over sockets the cycle had just quiesced, untested. The gates are
// deliberately direction-BLIND, unlike the #5648 protocol gate two lines below
// them, and the table has to be able to tell the difference.
func operatorWorkerVerbs() []operatorWorkerVerb {
	return []operatorWorkerVerb{
		{"forwarding_arm", "set_forwarding_state", func(m *Manager) (ProcessStatus, error) {
			return m.SetForwardingArmed(true)
		}},
		{"forwarding_disarm", "set_forwarding_state", func(m *Manager) (ProcessStatus, error) {
			return m.SetForwardingArmed(false)
		}},
		{"queue_register", "set_queue_state", func(m *Manager) (ProcessStatus, error) {
			return m.SetQueueState(0, true, true)
		}},
		{"queue_deregister", "set_queue_state", func(m *Manager) (ProcessStatus, error) {
			return m.SetQueueState(0, false, false)
		}},
		{"binding_register", "set_binding_state", func(m *Manager) (ProcessStatus, error) {
			return m.SetBindingState(1, true, true)
		}},
		{"binding_deregister", "set_binding_state", func(m *Manager) (ProcessStatus, error) {
			return m.SetBindingState(1, false, false)
		}},
	}
}

// newOperatorVerbTestManager builds a manager whose forwarding capability gate
// passes, so SetForwardingArmed(true) reaches the control socket instead of
// being turned back by the ForwardingSupported check. lastSnapshot stays nil so
// the #5648 required-protocol gate short-circuits and cannot be mistaken for the
// lease gate under test.
func newOperatorVerbTestManager(t *testing.T) (*Manager, *leaseControlServer) {
	t.Helper()
	sock := filepath.Join(shortSockDir9322(t), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, sock)
	srv := startLeaseControlServer(t, sock, ProcessStatus{
		PID:          4242,
		Workers:      2,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings:     []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}},
	})
	m.lastStatus.Capabilities.ForwardingSupported = true
	return m, srv
}

func countRequests(reqs []string, want string) int {
	n := 0
	for _, r := range reqs {
		if r == want {
			n++
		}
	}
	return n
}

// TestOperatorWorkerVerbsRefusedDuringLinkCycle_6871 is the discriminator.
//
// RED-on-revert: delete the `if m.linkCycleInFlight()` check from any one of the
// three setters in manager_status.go and that verb's subtest fails at "reached
// the helper DURING the link cycle".
//
// Each subtest carries its own POSITIVE CONTROL first: the same call, same
// fixture, no cycle in flight, must reach the helper. Without it the assertion
// below could hold because the verb never reaches the socket at all — a guard
// that is green because the fixture is inert. The positive control stays GREEN
// under the revert (removing the gate only ever lets more through), so it is a
// control and not a restatement.
func TestOperatorWorkerVerbsRefusedDuringLinkCycle_6871(t *testing.T) {
	for _, verb := range operatorWorkerVerbs() {
		t.Run(verb.name, func(t *testing.T) {
			skipLinkCycleRebindSleep(t)
			m, srv := newOperatorVerbTestManager(t)

			// POSITIVE CONTROL: no cycle in flight, the verb must go through.
			if _, err := verb.call(m); errors.Is(err, errLinkCycleInFlight) {
				t.Fatalf("%s was refused with no link cycle in flight: %v — this verb is "+
					"unusable, and the assertion below would pass for that reason rather "+
					"than because the lease gate works", verb.name, err)
			}
			if n := countRequests(srv.requests(), verb.reqType); n != 1 {
				t.Fatalf("control: %q requests before the cycle = %d, want 1. This fixture "+
					"does not reach the control socket, so the during-cycle assertion below "+
					"would hold vacuously. Requests: %v", verb.reqType, n, srv.requests())
			}
			before := countRequests(srv.requests(), verb.reqType)

			// THE DISCRIMINATOR: same call, one link cycle in flight.
			if err := m.PrepareLinkCycle(); err != nil {
				t.Fatalf("PrepareLinkCycle: %v", err)
			}
			_, err := verb.call(m)
			if !errors.Is(err, errLinkCycleInFlight) {
				t.Errorf("%s returned %v during a link cycle, want errLinkCycleInFlight",
					verb.name, err)
			}
			if err := m.NotifyLinkCycle(); err != nil {
				t.Fatalf("NotifyLinkCycle: %v", err)
			}

			// The error alone is not the guarantee: a gate that reported a
			// refusal but still sent the request would leave the workers
			// spawned. What crossed the socket is what matters.
			between := requestsBetween(t, srv.requests(), "stop_workers", "rebind")
			if len(between) != 0 {
				t.Errorf("%q reached the helper DURING the link cycle: %v.\n"+
					"PrepareLinkCycle had joined every worker; the daemon has not yet taken "+
					"the NIC down. This request reaches reconcile_status_bindings in the "+
					"helper, which SPAWNS WORKER THREADS — into a NIC about to unmap their "+
					"UMEM. The ctrl gate cannot cover it: the spawn happens inside the "+
					"helper, before the status this manager applies (#6871 F2). Full "+
					"stream: %v", verb.reqType, between, srv.requests())
			}
			if n := countRequests(srv.requests(), verb.reqType); n != before {
				t.Errorf("%q request count went %d -> %d across the refused call; the gate "+
					"must turn the verb back BEFORE the control socket, not after",
					verb.reqType, before, n)
			}
		})
	}
}

// TestOperatorWorkerVerbsResumeAfterLinkCycle_6871 is the over-reach guard, and
// the one that keeps the fix from being "disable the operator verbs".
//
// It must stay GREEN under the revert above — removing the gate only ever lets
// MORE traffic through, so a test asserting the verbs still WORK cannot be
// satisfied by it. That is why it deliberately does NOT assert the mid-cycle
// refusal: proving the gate fires is the discriminator's job, and asserting it
// here would make this test red under the same revert and stop it being a
// control at all. It goes RED if the refusal is made unconditional, or if the
// lease is never released (in which case every one of these verbs is dead for
// the life of the process, which is a worse outage than the race it closes).
func TestOperatorWorkerVerbsResumeAfterLinkCycle_6871(t *testing.T) {
	for _, verb := range operatorWorkerVerbs() {
		t.Run(verb.name, func(t *testing.T) {
			skipLinkCycleRebindSleep(t)
			m, srv := newOperatorVerbTestManager(t)

			if err := m.PrepareLinkCycle(); err != nil {
				t.Fatalf("PrepareLinkCycle: %v", err)
			}
			if err := m.NotifyLinkCycle(); err != nil {
				t.Fatalf("NotifyLinkCycle: %v", err)
			}
			if m.linkCycleInFlight() {
				t.Fatal("NotifyLinkCycle must release the lease, else the assertion below " +
					"is about a manager that is still mid-cycle")
			}

			before := countRequests(srv.requests(), verb.reqType)
			if _, err := verb.call(m); errors.Is(err, errLinkCycleInFlight) {
				t.Fatalf("%s is still refused after the cycle completed: %v. The lease was "+
					"never released, so this verb is unusable for the life of the process",
					verb.name, err)
			}
			if n := countRequests(srv.requests(), verb.reqType); n != before+1 {
				t.Errorf("%q requests after the cycle = %d, want %d: the verb must reach the "+
					"helper again once the cycle is over. Requests: %v",
					verb.reqType, n, before+1, srv.requests())
			}
		})
	}
}

// TestOperatorWorkerVerbsRefusedBeforeTheHelperCheck_6871 pins the ordering the
// two tests above cannot distinguish: with no helper process at all, the verbs
// must report "helper not running", NOT the link-cycle refusal. A lease can only
// be taken while a helper is running (PrepareLinkCycle takes none without one),
// so a manager with no proc must never surface the cycle error — an operator
// told to "retry once the cycle completes" on a node whose helper is simply dead
// would wait forever for a cycle that is not happening.
func TestOperatorWorkerVerbsRefusedBeforeTheHelperCheck_6871(t *testing.T) {
	for _, verb := range operatorWorkerVerbs() {
		t.Run(verb.name, func(t *testing.T) {
			m := New()
			m.acquireLinkCycleLease() // a lease that could not exist in production
			if _, err := verb.call(m); errors.Is(err, errLinkCycleInFlight) {
				t.Errorf("%s reported a link cycle with no helper running; the helper check "+
					"must come first so the operator is told what is actually wrong", verb.name)
			}
		})
	}
}
