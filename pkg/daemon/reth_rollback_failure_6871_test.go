package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// #6871 B2: the RETH MAC link-cycle rollback was ATTEMPTED, never guaranteed.
//
// programRethMACWithWorkerJoin's rollback is a single call to NotifyLinkCycle,
// whose rebind is the documented inverse of the stop_workers PrepareLinkCycle
// issued. That rebind can fail. It used to fail into a slog.Warn and a bare
// return on a VOID function, so:
//
//   - an abort whose recovery succeeded and an abort whose recovery ALSO failed
//     produced identical evidence, and
//   - a CLEAN cycle (step 2.6b2's call) whose rebind failed left every worker
//     stopped and ctrl off WHILE THE COMMIT REPORTED SUCCESS — a silent total
//     dataplane outage on that node.
//
// The mechanism and the claim now agree: NotifyLinkCycle returns an error and
// both call sites fold it into the commit.
//
// The test double had the same shape problem from the other side. It counted
// calls, so "the rollback ran" was the only thing any test in this package could
// observe, and "the rollback ran and did nothing" was unobservable BY
// CONSTRUCTION. abortRecoveryLinkController.notifyErr is what closes that.

var errRollbackRebind = errors.New("rebind: helper control socket closed")

// TestRethRollbackRebindFailureReachesTheCommit_6871 is the fail-on-revert guard
// for the ABORT path: the cycle aborted after the worker-join HOOK ran, the
// rollback rebind then failed too, and the commit error must name BOTH.
//
// "after the hook ran", not "after the join" (#6871 round 6): this fixture's
// PrepareLinkCycle returns a stop_workers error, i.e. the request did not
// complete, so whether the helper joined anything is precisely what the daemon
// does not know. Escalating anyway is correct — that unknown is the reason — but
// the sentence must not claim the join happened.
//
// RED-on-revert: restore `joined.Link().NotifyLinkCycle()` as a bare statement
// (discarding the error) and this fails at "the rollback's own failure never
// reached the commit".
func TestRethRollbackRebindFailureReachesTheCommit_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))
	lc.notifyErr = errRollbackRebind

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if lc.prepareCalls != 1 || lc.notifyCalls != 1 {
		t.Fatalf("prepare=%d notify=%d, want 1/1 — the fixture must abort the cycle and "+
			"reach the rollback, otherwise there is no failed rebind to observe",
			lc.prepareCalls, lc.notifyCalls)
	}
	if linkCycled {
		t.Error("linkCycled must be false when the cycle was aborted")
	}
	if commitErr == nil {
		t.Fatal("the commit must FAIL")
	}
	if !errors.Is(commitErr, errRethPrepareLinkCycle) {
		t.Errorf("commit error must keep the RETH prepare-abort classification; got %v", commitErr)
	}
	// THE #6871 B2 DISCRIMINATOR.
	if !errors.Is(commitErr, errRollbackRebind) {
		t.Errorf("the rollback's own failure never reached the commit: %v.\n"+
			"The workers PrepareLinkCycle joined are still stopped and ctrl is still "+
			"off, and NOTHING else re-arms them — step 2.6b2's rebind is gated on "+
			"linkCycled (false, the cycle aborted) and reapplyAfterDeferredMAC on "+
			"rethMACPending. The operator is told the cycle aborted and nothing else, "+
			"so the recovery reads as having worked", commitErr)
	}
	// The abort cause must survive alongside it — it is the more actionable of
	// the two and a replace-instead-of-join would lose it.
	if !strings.Contains(commitErr.Error(), "stop_workers") {
		t.Errorf("the rollback failure must be JOINED onto the abort cause, not replace "+
			"it: %v no longer names stop_workers", commitErr)
	}
}

// TestRethRollbackSuccessDoesNotInventACommitCause_6871 is the over-reach guard.
// It stays GREEN under the revert above (which only ever removes an error) and
// goes RED if the fold were widened to "the abort always reports a rebind
// failure", which would satisfy the discriminator for free.
//
// Same fixture, one field different: the rollback rebind SUCCEEDS.
func TestRethRollbackSuccessDoesNotInventACommitCause_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))
	lc.notifyErr = nil

	_, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if lc.notifyCalls != 1 {
		t.Fatalf("NotifyLinkCycle calls = %d, want 1 — this control must traverse the same "+
			"rollback as the discriminator", lc.notifyCalls)
	}
	if commitErr == nil {
		t.Fatal("the abort itself must still fail the commit")
	}
	if errors.Is(commitErr, errRollbackRebind) {
		t.Errorf("a rollback that SUCCEEDED reported a rebind failure: %v", commitErr)
	}
	if strings.Contains(commitErr.Error(), "rebind") {
		t.Errorf("a successful rollback must not put a rebind cause in the commit error; "+
			"got %v", commitErr)
	}
}

// TestApplyFailsWhenPostCycleRebindFails_6871 is the guard for step 2.6b2 — the
// path a CLEAN cycle takes — and simultaneously the pin for
// needLinkCycleRecovery, which had no behavioural binding at all.
//
// The mutation this closes: insert `needLinkCycleRecovery = false` immediately
// after its assignment at the programRethMemberMAC call site. `go vet` is happy,
// every existing #5103 test stays green (they either abort the cycle, in which
// case the flag is false anyway, or assert only on the commit error of a member
// that did not cycle), and yet the apply silently skips BOTH recovery steps: step
// 2.6b's VIP/stable-link-local repair after a DOWN/UP that removed every kernel
// address, and step 2.6b2's AF_XDP rebind. The commit reports success over a node
// with no VIPs and no workers.
//
// This makes the flag observable through the apply's own returned error: the
// cycle completes cleanly (linkCycled=true, so the flag must be armed), and the
// rebind that only the armed flag reaches then fails. Under the mutation the
// rebind is never attempted, so there is no error and the apply returns nil.
//
// RED-on-revert, two ways:
//   - `needLinkCycleRecovery = false` after the call site: fails at "the apply
//     reported SUCCESS", with NotifyLinkCycle calls = 0.
//   - drop the errors.Join at step 2.6b2: fails at "the apply reported SUCCESS"
//     with NotifyLinkCycle calls = 1.
func TestApplyFailsWhenPostCycleRebindFails_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := rethCallsiteDaemon(t, nil /* the join SUCCEEDS, so the cycle completes */)
	lc.notifyErr = errRollbackRebind

	err := d.applyConfigLocked(context.Background(), rethCallsiteConfig())

	// POSITIVE CONTROL: the fixture reached the hook and completed the cycle.
	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the apply never reached the RETH "+
			"member's worker-join hook, so no cycle happened and this test proves nothing",
			lc.prepareCalls)
	}
	if got := strings.Join(events, ","); got != "set-mac-live,link-down,set-mac-cycled,link-up" {
		t.Errorf("link sequence = %q — the fixture must COMPLETE the cycle, otherwise "+
			"needLinkCycleRecovery is false for the honest reason and the assertion below "+
			"cannot distinguish the mutation", got)
	}

	// THE DISCRIMINATOR.
	if lc.notifyCalls != 1 {
		t.Errorf("NotifyLinkCycle calls = %d, want 1: a member whose link was cycled must "+
			"arm needLinkCycleRecovery, and step 2.6b2 must rebind off it. With the flag "+
			"cleared, the DOWN/UP that removed every kernel address gets no VIP repair "+
			"(step 2.6b) and the dead XSK sockets get no rebind", lc.notifyCalls)
	}
	if err == nil {
		t.Fatal("the apply reported SUCCESS over a link cycle whose AF_XDP rebind FAILED. " +
			"Either needLinkCycleRecovery never reached step 2.6b2, or its rebind error " +
			"was discarded. Every worker on this node is stopped and ctrl is off (#6871)")
	}
	if !errors.Is(err, errRethPrepareLinkCycle) {
		t.Errorf("the apply failed, but not with the RETH link-cycle classification: got %v",
			err)
	}
	if !errors.Is(err, errRollbackRebind) {
		t.Errorf("the apply's error must carry the underlying rebind cause; got %v", err)
	}
}

// TestApplyStaysGreenWhenPostCycleRebindSucceeds_6871 is the over-reach control
// for the guard above, in its own func body so it runs independently.
//
// It stays GREEN under both mutations (each only ever removes an error) and goes
// RED if step 2.6b2's fold were widened to "a cycled member always fails the
// commit" — which would satisfy the discriminator while failing every healthy HA
// commit on a driver without IFF_LIVE_ADDR_CHANGE.
func TestApplyStaysGreenWhenPostCycleRebindSucceeds_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := rethCallsiteDaemon(t, nil)
	lc.notifyErr = nil

	err := d.applyConfigLocked(context.Background(), rethCallsiteConfig())

	if lc.prepareCalls != 1 || lc.notifyCalls != 1 {
		t.Fatalf("prepare=%d notify=%d, want 1/1 — this control must traverse the SAME "+
			"cycle and the SAME rebind as the discriminator", lc.prepareCalls, lc.notifyCalls)
	}
	if err != nil {
		t.Fatalf("a RETH member whose cycle and rebind both succeeded failed the apply: %v. "+
			"Step 2.6b2 must fold only a REAL rebind failure; folding on every cycled "+
			"member turns each HA commit on such a driver into a failure", err)
	}
}
