package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #5103 F4: aborting the link cycle on a failed worker join must not also abort
// the RECOVERY.
//
// PrepareLinkCycle is not a pure query. Before it can fail on stop_workers it
// has already disabled ctrl (and cleared every binding row if that disable could
// not be verified), so the abort leaves the dataplane half torn down. Nothing
// downstream re-arms it: the post-cycle rebind is gated on linkCycled (false —
// the cycle was aborted) and reapplyAfterDeferredMAC is gated on rethMACPending,
// which is computed BEFORE networkd.Apply and is false for a member that this
// same apply renamed into existence. Before the ordering fix the identical
// triple self-healed for the wrong reason — the cycle ran regardless, so
// linkCycled was true and NotifyLinkCycle rebound the sockets.
//
// The state these tests observe is that intermediate one: live set rejected,
// the join RAN, cycle aborted. A fixture that lets the MAC program complete
// cannot distinguish the fix, because then the ordinary post-cycle rebind runs
// and the rollback is indistinguishable from it.
//
// "the join RAN" is the gate, not "the join FAILED": PrepareLinkCycle disables
// ctrl and stops the workers whether it goes on to succeed or fail, and setDown
// and the cycled MAC write can then fail underneath a SUCCESSFUL join.
// TestRethMACAbortRebindsWhenCycleFailsAfterJoin_5103 covers those two — and
// since #6915 they no longer share an outcome: only a failed setDown aborts the
// CYCLE (the link never goes down, so this site owns the rollback). A failed
// cycled MAC write leaves the link already cycled, so it reports
// linkCycled=true and hands the rebind to step 2.6b2 along with step 2.6b's
// re-add of the addresses the DOWN flushed.

// abortRecoveryLinkController counts both halves of the link-cycle protocol so a
// test can tell a rollback rebind from no rebind at all.
//
// #6871: notifyErr exists because counting the call was the whole fake. A
// rollback that FAILED was unobservable by construction — the double could only
// ever report "the rebind was attempted", which is precisely the claim under
// examination — so no test in this package could see a failed unwind, and the
// production signature (a void NotifyLinkCycle) could not have carried one
// anyway. Both halves are fixed together: the interface returns an error and the
// double can produce one.
// #6871 round 6: renewCalls is the observable for the per-member lease renewal.
// The renewal has to be COUNTED, not merely permitted: the TTL only stops being
// a function of the RETH count if every member's turn touches the lease, so a
// renewal that fires on some members and not others is the same intermittent
// defect with extra steps.
type abortRecoveryLinkController struct {
	prepareErr   error
	notifyErr    error
	prepareCalls int
	notifyCalls  int
	renewCalls   int
	abandonCalls int
	leaseHeld    bool
}

func (c *abortRecoveryLinkController) SetDeferWorkers(bool) {}

func (c *abortRecoveryLinkController) PrepareLinkCycle() error {
	c.prepareCalls++
	return c.prepareErr
}

func (c *abortRecoveryLinkController) NotifyLinkCycle() error {
	c.notifyCalls++
	return c.notifyErr
}

// #7007: the repair-without-release variant. This fake's lease model has
// nothing extra to do — the point of the separation is asserted by the
// leaseTracingLinkController in reth_multimember_lease_7007_test.go.
func (c *abortRecoveryLinkController) NotifyLinkCycleKeepingLease() error {
	return c.NotifyLinkCycle()
}

func (c *abortRecoveryLinkController) RenewLinkCycle() { c.renewCalls++ }

// AbandonLinkCycle records the #6871 round-8 deferred release and reports
// whether a lease was outstanding, which this fake models with leaseHeld.
func (c *abortRecoveryLinkController) AbandonLinkCycle() bool {
	c.abandonCalls++
	held := c.leaseHeld
	c.leaseHeld = false
	return held
}

// abortRecoveryTestDP is a RuntimeDataPlane whose only interesting surface is
// the link controller. It reuses deferredMACReapplyTestDP for the rest of the
// interface (#5134) and overrides Link.
type abortRecoveryTestDP struct {
	deferredMACReapplyTestDP
	link *abortRecoveryLinkController
}

func (d *abortRecoveryTestDP) Link() dataplane.LinkController { return d.link }

func newAbortRecoveryDaemon(prepareErr error) (*Daemon, *abortRecoveryLinkController) {
	lc := &abortRecoveryLinkController{prepareErr: prepareErr}
	d := &Daemon{}
	d.setDataplane(&abortRecoveryTestDP{link: lc}) // #2114: publish through the cell
	return d, lc
}

// TestRethMACAbortRebindsAfterFailedJoin_5103 is the F4 guard. The live MAC set
// is rejected (so the hook fires) and the join then fails (so the cycle aborts).
// The prepare has already disabled ctrl at that point, so the daemon must send
// the inverse — "rebind", via NotifyLinkCycle — rather than leave the dataplane
// mid-teardown with no owner.
//
// RED-on-revert: drop the NotifyLinkCycle rollback from
// programRethMACWithWorkerJoin and this fails at "AF_XDP sockets were never
// rebound after the aborted link cycle".
func TestRethMACAbortRebindsAfterFailedJoin_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the fixture must reach the hook, "+
			"otherwise this test proves nothing about the abort", lc.prepareCalls)
	}
	if linkCycled {
		t.Error("linkCycled must be false when the cycle was aborted")
	}
	if lc.notifyCalls != 1 {
		t.Errorf("NotifyLinkCycle calls = %d, want 1: the AF_XDP sockets were never rebound "+
			"after the aborted link cycle. PrepareLinkCycle had already disabled ctrl, and no "+
			"other path re-arms it — linkCycled is false so the post-cycle rebind is skipped, "+
			"and rethMACPending is false for a member renamed into existence by this apply. "+
			"Forwarding stays down on this node (#5103 F4)", lc.notifyCalls)
	}
	// The rollback must not have been bought by cycling the link anyway.
	for _, e := range events {
		if e == "link-down" || e == "link-up" || e == "set-mac-cycled" {
			t.Fatalf("the link was MUTATED after the join failed (%q in %v)", e, events)
		}
	}
	if commitErr == nil {
		t.Fatal("a failed worker join must reach the commit: the node's dataplane was left " +
			"mid-teardown, so reporting commit SUCCESS hides a forwarding outage")
	}
	if !errors.Is(commitErr, errRethPrepareLinkCycle) {
		t.Errorf("commit error must carry errRethPrepareLinkCycle so the caller can fail the "+
			"commit closed on this class alone; got %v", commitErr)
	}
	if !strings.Contains(commitErr.Error(), "stop_workers") {
		t.Errorf("commit error should name the underlying cause; got %v", commitErr)
	}
}

// failStep names the step of the cycle that fails AFTER a successful worker
// join, in the F-A tests below.
type failStep int

const (
	failSetDown       failStep = iota // ENODEV between the LinkByName and the down
	failSetMACCycled                  // the down succeeded, the cycled MAC write did not
	failSetUpAfterMAC                 // the whole cycle ran; only link-up failed
)

// newFailAfterJoinOps wraps the recording seam so one step of the cycle fails
// after the join has already succeeded. All three are real netlink failures on a
// driver without IFF_LIVE_ADDR_CHANGE: the link can be moved or removed by
// udev/networkd between programRethMAC's own LinkByName and its setDown — the
// same rename window step 2.6's pre-check handles, and the one
// TestRethMACOrdinaryFailureStaysWarnOnly_5103 cites — and a MAC write or an UP
// on a link that just went away fails the same way.
func newFailAfterJoinOps(t *testing.T, events *[]string, step failStep) rethLinkOps {
	t.Helper()
	ops := newRecordingRethOps(t, events, curMAC5103, true /* force the cycle */)
	markFailed := func(err error) error {
		(*events)[len(*events)-1] += "-FAILED"
		return err
	}
	switch step {
	case failSetDown:
		inner := ops.setDown
		ops.setDown = func(l netlink.Link) error {
			_ = inner(l)
			return markFailed(errors.New("ENODEV: no such device"))
		}
	case failSetMACCycled:
		inner := ops.setHardwareAddr
		ops.setHardwareAddr = func(l netlink.Link, m net.HardwareAddr) error {
			if err := inner(l, m); err != nil {
				return err // the live attempt, already rejected by the seam
			}
			return markFailed(errors.New("EADDRNOTAVAIL: cannot assign requested address"))
		}
	case failSetUpAfterMAC:
		inner := ops.setUp
		ops.setUp = func(l netlink.Link) error {
			_ = inner(l)
			return markFailed(errors.New("ENODEV: no such device"))
		}
	}
	return ops
}

// TestRethMACAbortRebindsWhenCycleFailsAfterJoin_5103 is the F-A guard: the
// rollback must key on whether the join RAN, not on whether it FAILED.
//
// PrepareLinkCycle succeeds here, so it has definitively disabled ctrl and joined
// every worker — the member is not forwarding. Two fallible steps follow it
// inside programRethMAC, and BOTH return linkCycled=false, so both land in the
// same state the failed-join abort does: prepare applied, cycle not completed,
// step 2.6b2's rebind skipped (linkCycled false) and reapplyAfterDeferredMAC
// skipped (rethMACPending false for a member this apply renamed into its config
// name). Gating the rollback on the hook's OWN error let both escape with a nil
// commit error, so the commit reported SUCCESS over a node dropping transit.
//
// RED-on-revert: restore the joinFailed gate in programRethMACWithWorkerJoin and
// both subtests fail at "NotifyLinkCycle calls = 0, want 1" and "the commit must
// FAIL".
func TestRethMACAbortRebindsWhenCycleFailsAfterJoin_5103(t *testing.T) {
	for _, tc := range []struct {
		name      string
		step      failStep
		wantSeq   string
		wantCause string
		// #6915: the two rows diverge on whether the link actually CYCLED, and
		// therefore on who owns the rebind. setDown FAILING means the link never
		// went down — no cycle, no address loss, and this site must roll back.
		// The cycled MAC write failing means it DID go down and come back up, so
		// step 2.6b2 owns the rebind (firing it here too is the double rebind
		// that gets EBUSY on mlx5 zero-copy queues) and step 2.6b owns the VIP
		// re-add. Sharing one expectation across both rows is what let the
		// second one keep a value that described the first.
		wantLinkCycled bool
		wantNotify     int
	}{
		{
			name:           "set_down_fails",
			step:           failSetDown,
			wantSeq:        "set-mac-live,link-down-FAILED",
			wantCause:      "link down",
			wantLinkCycled: false,
			wantNotify:     1,
		},
		{
			name:           "cycled_mac_write_fails",
			step:           failSetMACCycled,
			wantSeq:        "set-mac-live,link-down,set-mac-cycled-FAILED,link-up",
			wantCause:      "set mac",
			wantLinkCycled: true,
			wantNotify:     0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			withRethOps(t, newFailAfterJoinOps(t, &events, tc.step))
			d, lc := newAbortRecoveryDaemon(nil /* the join SUCCEEDS */)

			linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

			if lc.prepareCalls != 1 {
				t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the fixture must reach the "+
					"hook and have it SUCCEED, otherwise this test is just the failed-join "+
					"case again", lc.prepareCalls)
			}
			// #6871 F5: Errorf, not Fatalf. A wrong sequence means the FIXTURE
			// is off, but it must not stop the linkCycled assertion below from
			// running — that assertion is the one carrying the guard, and a
			// fatal here left it unexecuted, so a run reporting only "link
			// sequence" told us nothing about linkCycled either way.
			if got := strings.Join(events, ","); got != tc.wantSeq {
				t.Errorf("link sequence = %q, want %q — the fixture must fail the step it "+
					"claims to", got, tc.wantSeq)
			}
			if linkCycled != tc.wantLinkCycled {
				t.Errorf("linkCycled = %v, want %v — this value reports whether the link "+
					"WENT DOWN AND BACK UP, not whether the MAC write succeeded (#6915). "+
					"setDown failing means no cycle; the cycled MAC write failing means the "+
					"DOWN already flushed every address on the member",
					linkCycled, tc.wantLinkCycled)
			}
			if lc.notifyCalls != tc.wantNotify {
				t.Errorf("NotifyLinkCycle calls = %d, want %d. The join SUCCEEDED, so ctrl is "+
					"off and every worker is stopped with nothing to re-arm them unless "+
					"something rebinds. WHO rebinds depends on whether the link cycled: with "+
					"linkCycled=false this site owns the rollback (step 2.6b2 is gated off and "+
					"rethMACPending is false for a member renamed into existence by this "+
					"apply); with linkCycled=true step 2.6b2 owns it and firing here too is "+
					"the double rebind that gets EBUSY on mlx5 zero-copy queues. "+
					"TestCycledMACWriteFailureArmsTheRecoveryGate6915 binds the handoff",
					lc.notifyCalls, tc.wantNotify)
			}
			if commitErr == nil {
				t.Fatal("the commit must FAIL: the dataplane was deliberately torn down and " +
					"the cycle that was supposed to justify it did not complete. Reporting " +
					"commit SUCCESS here hides a forwarding outage")
			}
			if !errors.Is(commitErr, errRethPrepareLinkCycle) {
				t.Errorf("commit error must carry errRethPrepareLinkCycle so the caller can "+
					"fail the commit closed on this class alone; got %v", commitErr)
			}
			if !strings.Contains(commitErr.Error(), tc.wantCause) {
				t.Errorf("commit error should name the underlying cause %q; got %v",
					tc.wantCause, commitErr)
			}
		})
	}
}

// TestRethMACLinkUpFailureFailsCommitWithoutDoubleRebind_5103 covers the one
// member of the class whose cycle COMPLETED: only link-up failed, so
// linkCycled=true and step 2.6b2 already owns the rebind. The commit must still
// fail — the member is administratively down after a deliberate teardown — but
// the rollback must NOT fire, or the member is rebound twice.
//
// The notifyCalls half is an over-reach guard and stays green under the revert;
// the commitErr half is what the revert breaks.
func TestRethMACLinkUpFailureFailsCommitWithoutDoubleRebind_5103(t *testing.T) {
	var events []string
	withRethOps(t, newFailAfterJoinOps(t, &events, failSetUpAfterMAC))
	d, lc := newAbortRecoveryDaemon(nil /* the join SUCCEEDS */)

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	// #6871 F5: Errorf, not Fatalf — see the sibling above. The linkCycled and
	// commitErr assertions below are the guard; a fixture-sequence mismatch
	// must report itself without suppressing them.
	if got := strings.Join(events, ","); got != "set-mac-live,link-down,set-mac-cycled,link-up-FAILED" {
		t.Errorf("link sequence = %q — the fixture must complete the cycle and fail only "+
			"the UP", got)
	}
	if !linkCycled {
		t.Fatal("a completed DOWN/set/UP attempt must report linkCycled=true so step 2.6b2 " +
			"reconciles the VIPs and rebinds")
	}
	if lc.notifyCalls != 0 {
		t.Errorf("NotifyLinkCycle calls = %d, want 0: linkCycled is true, so step 2.6b2 "+
			"rebinds this member. Rebinding here too makes it twice — the spurious rebind "+
			"that gets EBUSY on mlx5 zero-copy queues", lc.notifyCalls)
	}
	if commitErr == nil {
		t.Fatal("the commit must FAIL: the member is left administratively DOWN after its " +
			"workers were joined for the cycle")
	}
	if !errors.Is(commitErr, errRethPrepareLinkCycle) {
		t.Errorf("commit error must carry errRethPrepareLinkCycle; got %v", commitErr)
	}
}

// TestRethMACNoRollbackWhenJoinSucceeds_5103 is the over-reach guard for the
// rollback. When the join succeeds the cycle proceeds and step 2.6b2 owns the
// post-cycle rebind; a rollback here would rebind twice — the spurious rebind
// the call site's own comment warns gets EBUSY on mlx5 zero-copy queues.
func TestRethMACNoRollbackWhenJoinSucceeds_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(nil)

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1", lc.prepareCalls)
	}
	if !linkCycled {
		t.Error("a successful join must let the cycle proceed and report linkCycled=true")
	}
	if lc.notifyCalls != 0 {
		t.Errorf("NotifyLinkCycle calls = %d, want 0: the rollback must fire on the ABORT "+
			"only. The caller rebinds once for a cycle that actually happened; rebinding here "+
			"too makes it twice", lc.notifyCalls)
	}
	if commitErr != nil {
		t.Errorf("a completed MAC program must not fail the commit; got %v", commitErr)
	}
	if got := strings.Join(events, ","); got != "set-mac-live,link-down,set-mac-cycled,link-up" {
		t.Errorf("sequence = %v", events)
	}
}

// TestRethMACNoJoinOrRollbackOnLiveSet_5103 is the over-reach guard for the hook
// itself on the path the cluster's own NICs take. An IFF_LIVE_ADDR_CHANGE driver
// needs no cycle, so neither half of the protocol may run: joining workers here
// is a forwarding outage on every RETH MAC apply.
func TestRethMACNoJoinOrRollbackOnLiveSet_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, false /* live set works */))
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if linkCycled || commitErr != nil {
		t.Errorf("live set: linkCycled=%v commitErr=%v, want false/nil", linkCycled, commitErr)
	}
	if lc.prepareCalls != 0 || lc.notifyCalls != 0 {
		t.Errorf("prepare=%d notify=%d, want 0/0 — no cycle means no worker join and nothing "+
			"to roll back", lc.prepareCalls, lc.notifyCalls)
	}
}

// TestRethMACOrdinaryFailureStaysWarnOnly_5103 is the over-reach guard for the
// COMMIT error. Failing a MAC set has always been warn-only, and widening that to
// every programRethMAC error would fail commits that have always succeeded — a
// behaviour change well outside #5103. Only the class where the worker-join HOOK
// RAN is escalated — which is wider than "the join failed" (a post-join setDown
// or link-up failure is in it) and also does not claim the join succeeded (the
// hook can fail at the dial, before the helper's stop_workers handler runs).
// #6871 round 6: an earlier revision of this sentence said "the failed-join
// class", which was both narrower than the code and an assertion the daemon
// cannot make.
//
// The fixture is an ordinary failure that cannot involve the hook: the member is
// gone by the time programRethMAC looks it up, which is exactly what happens when
// an interface is renamed or removed between the caller's LinkByName and this
// call.
func TestRethMACOrdinaryFailureStaysWarnOnly_5103(t *testing.T) {
	withRethOps(t, ordinaryFailureRethOps())
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if linkCycled {
		t.Error("a lookup failure cannot have cycled the link")
	}
	if commitErr != nil {
		t.Errorf("an ordinary MAC-program failure must stay warn-only, not fail the commit; "+
			"got %v", commitErr)
	}
	if lc.prepareCalls != 0 || lc.notifyCalls != 0 {
		t.Errorf("prepare=%d notify=%d, want 0/0 — the failure never reached the cycle path",
			lc.prepareCalls, lc.notifyCalls)
	}
}
