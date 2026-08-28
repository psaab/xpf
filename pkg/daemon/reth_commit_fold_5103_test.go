package daemon

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// ordinaryFailureRethOps is the warn-only fixture: the member is gone by the
// time programRethMAC looks it up, so the failure never reaches the cycle path
// and the worker-join hook never runs.
func ordinaryFailureRethOps() rethLinkOps {
	return rethLinkOps{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		byName: func(string) (netlink.Link, error) {
			return nil, errors.New("Link not found")
		},
		byIndex:         func(int) (netlink.Link, error) { return nil, errors.New("Link not found") },
		setDown:         func(netlink.Link) error { return nil },
		setUp:           func(netlink.Link) error { return nil },
		setName:         func(netlink.Link, string) error { return nil },
		setHardwareAddr: func(netlink.Link, net.HardwareAddr) error { return nil },
	}
}

// #5103 r5: the fail-closed COMMIT plumbing, bound BEHAVIOURALLY.
//
// programRethMACWithWorkerJoin classifies an aborted link cycle
// (reth_prepare_abort_recovery_5103_test.go asserts errors.Is on the sentinel)
// and applyDataplaneAndHACore's tail surfaces networkdErr to the commit (#5309
// proves that leg). The step between them — folding the classified error into
// the accumulator, and folding linkCycled into step 2.6b2's rebind gate — had no
// behavioural coverage at all. It sat inline in a loop reachable only through
// applyDataplaneAndHACore, so the only guard was an AST canary, and a structural
// canary can always be satisfied while the code it matches is unreachable,
// shadowed, or jumped over. programRethMemberMAC is that step as a function, so
// these tests drive it directly, against the same fake link seam (withRethOps)
// and fake dataplane (newAbortRecoveryDaemon) the wrapper's own tests use.
//
// What each assertion distinguishes:
//
//   - errors.Is(got, errRethPrepareLinkCycle): the classified error reaches the
//     accumulator at all. Deleting the fold — or making it unreachable, or
//     shadowing the assignment with `:=`, or returning before it — drops it, and
//     the commit reports SUCCESS over a member left administratively DOWN that
//     no later apply repairs (the MAC write succeeded, so step 2.6 early-returns
//     on bytes.Equal).
//   - errors.Is(got, errPriorCommit5103): it is JOINED, not assigned. A bare
//     `commitErr = prepareErr` passes the assertion above while silently
//     discarding a device-map teardown (#5309) or networkd.Apply failure
//     recorded earlier in the same apply.
//   - got == errPriorCommit5103 (identity) on the success paths: the fold does
//     not fire when it must not. errors.Join(err, nil) would allocate a new
//     wrapper here — behaviourally harmless, but it would mean the guard above
//     is passing for free, so identity is asserted rather than errors.Is.

// errPriorCommit5103 stands in for an error already accumulated earlier in the
// same apply — the device-map teardown (#5309) or the networkd.Apply write —
// that this member's fold must PRESERVE.
var errPriorCommit5103 = errors.New("prior apply-step failure")

// TestRethMemberMACFoldsAbortIntoCommitError_5103 is the fail-on-revert guard
// for the fold. The live MAC set is rejected so the hook fires, the join then
// fails so the cycle aborts, and the classified error must reach the commit
// accumulator without destroying what was already in it.
func TestRethMemberMACFoldsAbortIntoCommitError_5103(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prior error
	}{
		{name: "no_prior_error", prior: nil},
		{name: "prior_error_present", prior: errPriorCommit5103},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
			d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

			got, needRecovery, _ := d.programRethMemberMAC(
				"ge-0-0-1", virtMAC5103, tc.prior, false /* no earlier member cycled */, false)

			if lc.prepareCalls != 1 {
				t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the fixture must reach the "+
					"hook and have it FAIL, otherwise there is no classified error to fold "+
					"and this test proves nothing", lc.prepareCalls)
			}
			if got == nil {
				t.Fatal("the aborted cycle produced NO commit error: the member's workers " +
					"were joined and ctrl disabled, and the commit will report SUCCESS over a " +
					"node that is not forwarding (#5103)")
			}
			if !errors.Is(got, errRethPrepareLinkCycle) {
				t.Errorf("commit error does not carry errRethPrepareLinkCycle, so the wrapper's "+
					"classification never reached the accumulator that the apply tail turns "+
					"into a failed commit; got %v", got)
			}
			if tc.prior != nil && !errors.Is(got, tc.prior) {
				t.Errorf("the error already accumulated by an earlier apply step was CLOBBERED "+
					"rather than joined — a device-map teardown (#5309) or networkd.Apply "+
					"failure would vanish from the commit; got %v", got)
			}
			if needRecovery {
				t.Error("an ABORTED cycle must not arm step 2.6b2's rebind gate: the link was " +
					"never cycled, and the rollback in programRethMACWithWorkerJoin already " +
					"rebound this member")
			}
		})
	}
}

// TestRethMemberMACLeavesPriorErrorAloneOnSuccess_5103 is the over-reach guard
// for the fold: a MAC program that COMPLETED must not manufacture a commit
// error. Widening the fold to every programRethMAC outcome would fail commits
// that have always succeeded.
//
// It stays GREEN under the revert of the fold, which is what makes it a guard
// rather than a restatement.
func TestRethMemberMACLeavesPriorErrorAloneOnSuccess_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(nil /* the join SUCCEEDS, so the cycle completes */)

	got, needRecovery, _ := d.programRethMemberMAC(
		"ge-0-0-1", virtMAC5103, errPriorCommit5103, false, false)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the fixture must reach the hook and "+
			"have it SUCCEED", lc.prepareCalls)
	}
	if got != errPriorCommit5103 {
		t.Errorf("a completed MAC program must pass the incoming commit error through "+
			"UNCHANGED; got %v", got)
	}
	if !needRecovery {
		t.Error("a member whose link WAS cycled must arm step 2.6b2's rebind gate, or the " +
			"AF_XDP sockets are never rebound onto the cycled link")
	}
}

// TestRethMemberMACKeepsOrdinaryFailureWarnOnly_5103 is the over-reach guard for
// the ESCALATION boundary. An ordinary MAC-set failure — here the member is gone
// by the time programRethMAC looks it up, exactly what a rename/remove between
// the caller's LinkByName and this call produces — has always been warn-only.
// Only the class where the worker-join HOOK already ran fails the commit — "the
// hook ran", not "the workers were joined": the hook can fail at the dial before
// the helper ever reaches its stop_workers handler (#6871 round 6).
//
// Stays GREEN under the revert.
func TestRethMemberMACKeepsOrdinaryFailureWarnOnly_5103(t *testing.T) {
	withRethOps(t, ordinaryFailureRethOps())
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	got, needRecovery, _ := d.programRethMemberMAC(
		"ge-0-0-1", virtMAC5103, errPriorCommit5103, false, false)

	if lc.prepareCalls != 0 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 0 — this fixture must fail BEFORE the "+
			"cycle path, or it is the abort case again", lc.prepareCalls)
	}
	if got != errPriorCommit5103 {
		t.Errorf("an ordinary MAC-program failure must stay warn-only and leave the commit "+
			"accumulator exactly as it found it; got %v", got)
	}
	if needRecovery {
		t.Error("a lookup failure cannot have cycled the link, so it must not arm the gate")
	}
}

// TestRethMemberMACRecoveryGateAbsorbsAcrossMembers_5103 binds the second
// accumulator across a THREE-member sequence, threaded exactly as step 2.6's
// loop threads it. The gate is absorbing: once any member has cycled, no later
// member may clear it. Assigning instead of ORing (`needRecovery = linkCycled`)
// leaves a cycled member's AF_XDP sockets unbound whenever a member that needed
// no cycle happens to be visited after it — and the visit order is a Go map
// range, so that is a coin flip, not a corner case.
//
// The fixture varies the one axis that decides linkCycled: whether the live
// (link-UP) MAC write is rejected. Members 2 and 3 are BOTH non-cycling so the
// absorbing property is exercised past a single step rather than only at the
// transition.
func TestRethMemberMACRecoveryGateAbsorbsAcrossMembers_5103(t *testing.T) {
	d, lc := newAbortRecoveryDaemon(nil /* every join succeeds */)

	var commitErr error
	needRecovery := false

	// Member 1: a driver with no IFF_LIVE_ADDR_CHANGE — the cycle runs.
	var ev1 []string
	withRethOps(t, newRecordingRethOps(t, &ev1, curMAC5103, true /* force the cycle */))
	commitErr, needRecovery, _ = d.programRethMemberMAC("ge-0-0-1", virtMAC5103, commitErr, needRecovery, false)
	if !needRecovery {
		t.Fatalf("member 1 cycled its link (events %v) but did not arm the gate", ev1)
	}

	// Members 2 and 3: the live set works, so neither cycles.
	var ev2 []string
	withRethOps(t, newRecordingRethOps(t, &ev2, curMAC5103, false /* live set works */))
	commitErr, needRecovery, _ = d.programRethMemberMAC("ge-0-0-2", virtMAC5103, commitErr, needRecovery, false)
	if !needRecovery {
		t.Fatalf("member 2 needed no link cycle and CLEARED the gate member 1 armed: step "+
			"2.6b2 will skip the rebind, so member 1's AF_XDP sockets stay unbound after its "+
			"link cycle destroyed them (events %v)", ev2)
	}
	commitErr, needRecovery, _ = d.programRethMemberMAC("ge-0-0-3", virtMAC5103, commitErr, needRecovery, false)
	if !needRecovery {
		t.Fatal("member 3 needed no link cycle and CLEARED the gate: the accumulator must " +
			"absorb, not track the last member")
	}

	if commitErr != nil {
		t.Errorf("no member failed, so no commit error may be manufactured; got %v", commitErr)
	}
	if lc.prepareCalls != 1 {
		t.Errorf("PrepareLinkCycle calls = %d, want 1 — only member 1 needed a cycle, so "+
			"only member 1 may join workers", lc.prepareCalls)
	}
	if lc.notifyCalls != 0 {
		t.Errorf("NotifyLinkCycle calls = %d, want 0 — no cycle aborted, so the per-member "+
			"rollback must not fire; step 2.6b2 owns the single rebind", lc.notifyCalls)
	}
}
