package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #6871 round 8 B2: a link-cycle lease cannot outlive the apply that took it.
//
// WHY THIS EXISTS AT ALL. Rounds 6 and 7 answered "the TTL cannot bound the
// whole cycle" by renewing at three points in step 2.6, leaving the TTL to cover
// the gaps between them. Codex's B3/round-8-B2 held that those gaps are still
// unbounded, and that is correct on measurement rather than on argument:
// finishRethMemberLinkTail's child-netdev loop runs once per VLAN sub-interface
// of the member (up to one per VLAN id), reconcileAfterRethLinkCycle runs once
// per redundancy group, the enclosing loop runs up to the schema's reth-count
// ceiling of 128, and a single netlink syscall has no elapsed-time bound at all.
// No constant covers that, and a bigger one is the same defect with a bigger
// number.
//
// So round 8 stopped choosing a constant: a live lease renews ITSELF on a fixed
// period (linkCycleLeaseHeartbeat, pkg/dataplane/userspace/process_linkcycle.go)
// and the TTL bounds that period instead. The cost of a self-renewing lease is
// that a LEAKED one is suppressed forever rather than for 60s — so the daemon
// owes a release that no control flow can skip. That is the deferred
// abandonLinkCycleLease this file binds.
//
// Both halves are needed and neither is sufficient: without the heartbeat the
// TTL is a guess, and without the deferred release the heartbeat turns a leak
// into a permanent outage.

// leaseAbandonTestDP is a RuntimeDataPlane whose ApplyConfig can be made to
// PANIC, so the deferred release can be observed on the path a plain early
// return cannot reach.
type leaseAbandonTestDP struct {
	deferredMACReapplyTestDP
	link       *abortRecoveryLinkController
	applyPanic string
}

func (d *leaseAbandonTestDP) Link() dataplane.LinkController { return d.link }

func (d *leaseAbandonTestDP) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	if d.applyPanic != "" {
		panic(d.applyPanic)
	}
	return d.deferredMACReapplyTestDP.ApplyConfig(ctx, cfg)
}

func newLeaseAbandonDaemon(applyPanic string) (*Daemon, *abortRecoveryLinkController) {
	lc := &abortRecoveryLinkController{leaseHeld: true}
	d := &Daemon{}
	d.setDataplane(&leaseAbandonTestDP{link: lc, applyPanic: applyPanic}) // #2114: publish through the cell
	return d, lc
}

// TestApplyDataplaneCoreAlwaysAbandonsAHeldLease_6871 is the B2 discriminator.
//
// It drives the REAL applyDataplaneAndHACore — not the helper, not a canary over
// its AST — with a lease already outstanding, and requires the lease to be gone
// when the function is done. A structural check would have been satisfied by a
// `defer` that is present but positioned after an early return; running the
// production function is what makes "on EVERY exit" a measurement.
//
// RED-on-revert: delete `defer d.abandonLinkCycleLease()` from
// applyDataplaneAndHACore and both subtests fail at "left the apply with the
// lease still held".
func TestApplyDataplaneCoreAlwaysAbandonsAHeldLease_6871(t *testing.T) {
	t.Run("normal_return", func(t *testing.T) {
		d, lc := newLeaseAbandonDaemon("")

		if _, _, _, _, err := d.applyDataplaneAndHACore(context.Background(), &config.Config{}); err != nil {
			t.Fatalf("applyDataplaneAndHACore: %v", err)
		}

		if lc.abandonCalls != 1 {
			t.Errorf("AbandonLinkCycle calls = %d, want 1", lc.abandonCalls)
		}
		if lc.leaseHeld {
			t.Error("left the apply with the lease still held. Since round 8 the lease " +
				"renews itself on a timer, so nothing else will ever expire it: the 1 Hz " +
				"reconcile stays suppressed for the life of the process, and the AF_XDP " +
				"workers a cycle joined are never re-armed")
		}
	})

	t.Run("panic_unwind", func(t *testing.T) {
		d, lc := newLeaseAbandonDaemon("dataplane apply exploded")

		func() {
			defer func() {
				if recover() == nil {
					t.Error("fixture: the apply was supposed to panic")
				}
			}()
			//nolint:errcheck // the call panics; the deferred release is the observable
			_, _, _, _, _ = d.applyDataplaneAndHACore(context.Background(), &config.Config{})
		}()

		if lc.abandonCalls != 1 {
			t.Errorf("AbandonLinkCycle calls after a panic = %d, want 1", lc.abandonCalls)
		}
		if lc.leaseHeld {
			t.Error("a panic unwound the apply with the lease still held. This is the case " +
				"a wall-clock backstop used to cover and a self-renewing lease does not: " +
				"the heartbeat goroutine keeps re-arming the deadline with nobody left to " +
				"release it, so the suppression is permanent rather than one TTL long")
		}
	})
}

// TestAbandonLinkCycleLeaseReachesTheController_6871 binds the daemon helper to
// the production seam, and is the over-reach control for the cell above.
//
// The nil-dataplane arm is the one that matters: applyDataplaneAndHACore runs on
// every commit, including on a node with no dataplane wired at all, so a defer
// that dereferenced the dataplane cell would panic on the most common configuration in the
// test suite rather than on an exotic one.
func TestAbandonLinkCycleLeaseReachesTheController_6871(t *testing.T) {
	t.Run("no_lease_held_is_silent", func(t *testing.T) {
		d, lc := newAbortRecoveryDaemon(nil)
		lc.leaseHeld = false

		d.abandonLinkCycleLease()

		if lc.abandonCalls != 1 {
			t.Errorf("AbandonLinkCycle calls = %d, want 1: the helper must ask on every "+
				"apply — only the controller knows whether a lease is outstanding",
				lc.abandonCalls)
		}
	})
	t.Run("nil_dataplane", func(t *testing.T) {
		d := &Daemon{}
		d.abandonLinkCycleLease() // must not panic
	})
}
