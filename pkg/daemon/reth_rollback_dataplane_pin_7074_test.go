package daemon

import (
	"errors"
	"testing"
)

// #7074: the RETH abort rollback must rebind the dataplane instance whose
// workers it actually stopped, not whichever one happens to be published when
// the rollback runs.
//
// Since #6743 the dataplane is read through an atomic cell (`d.dataplane()`),
// not a plain field, so a bootstrap-exit publish can swap or clear it between
// the join and the rollback. `programRethMACWithWorkerJoin` therefore pins the
// joined instance in a local. Before this test nothing bound that pin: reverting
// it to a re-read (`d.dataplane().Link().NotifyLinkCycleKeepingLease()`) left
// `go test ./pkg/daemon/...` fully green — measured at 2f76a925e, rc=0, zero
// named failures.
//
// The window is real but narrow, which is why no existing test reaches it: it
// needs a republish DURING the beforeCycle hook. That is what `onPrepare` is
// for.
//
// What the re-read would do, and why it is worse than a nil-deref: the rollback
// exists to send "rebind" to undo the "stop_workers" the hook sent. Re-reading
// the cell can address that rebind to a DIFFERENT helper — one whose workers
// were never stopped — leaving the first instance mid-teardown with no owner
// (forwarding down on the node, the #5103 F4 outage) while the second is told to
// rebind sockets it never released.
func TestRethAbortRollbackRebindsTheJOINEDDataplane_7074(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))

	// The instance the hook will actually join, and the one published over it.
	first := &abortRecoveryLinkController{prepareErr: errors.New("stop_workers: helper did not respond")}
	second := &abortRecoveryLinkController{}

	d := &Daemon{}
	d.setDataplane(&abortRecoveryTestDP{link: first})

	// Republish INSIDE the hook — after the join has read the cell and stopped
	// `first`'s workers, before the rollback runs. This models the #6743
	// bootstrap-exit publish landing mid-apply.
	first.onPrepare = func() {
		d.setDataplane(&abortRecoveryTestDP{link: second})
	}

	linkCycled, _, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	// Preconditions. Without these the assertions below could pass on a fixture
	// that never reached the hook or never aborted, which is the vacuous shape.
	if first.prepareCalls != 1 {
		t.Fatalf("precondition: the hook must run on the FIRST instance "+
			"(PrepareLinkCycle calls = %d, want 1)", first.prepareCalls)
	}
	if second.prepareCalls != 0 {
		t.Fatalf("precondition: the SECOND instance's workers were never stopped, so it "+
			"must not have been prepared (calls = %d, want 0)", second.prepareCalls)
	}
	if linkCycled {
		t.Fatal("precondition: the cycle must have aborted")
	}
	if commitErr == nil {
		t.Fatal("precondition: an aborted join must reach the commit")
	}

	// THE ASSERTION.
	if first.notifyCalls != 1 {
		t.Errorf("the rollback rebound %d time(s) on the JOINED dataplane, want 1. "+
			"The hook stopped THIS instance's workers, so this is the instance that "+
			"must be told to rebind; leaving it mid-teardown with no owner is the "+
			"#5103 F4 forwarding outage the rollback exists to prevent (#7074)",
			first.notifyCalls)
	}
	if second.notifyCalls != 0 {
		t.Errorf("the rollback rebound the dataplane published AFTER the join "+
			"(%d call(s), want 0). That helper's workers were never stopped, so the "+
			"rebind unwinds a stop_workers that was sent to a DIFFERENT helper — "+
			"the re-read reads the cell at rollback time instead of the pinned "+
			"instance (#7074)", second.notifyCalls)
	}
}

// TestRethAbortRollbackSurvivesAClearedDataplaneCell_7074 is the paired cell for
// the other thing a cell can do that a plain field could not: go to nil.
//
// A re-read would nil-deref here and panic the apply goroutine. The pin keeps
// the rollback addressed to the instance it joined, so the rebind still lands.
// Asserting "does not panic" alone would be weak — a rollback that silently did
// nothing would also not panic — so the rebind is asserted to have happened.
func TestRethAbortRollbackSurvivesAClearedDataplaneCell_7074(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))

	joined := &abortRecoveryLinkController{prepareErr: errors.New("stop_workers: timeout")}
	d := &Daemon{}
	d.setDataplane(&abortRecoveryTestDP{link: joined})
	joined.onPrepare = func() { d.setDataplane(nil) }

	_, _, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103, nil)

	if joined.prepareCalls != 1 {
		t.Fatalf("precondition: the hook must have joined the instance; calls = %d", joined.prepareCalls)
	}
	if commitErr == nil {
		t.Fatal("precondition: an aborted join must reach the commit")
	}
	if joined.notifyCalls != 1 {
		t.Errorf("with the dataplane cell CLEARED during the hook the rollback must still "+
			"rebind the joined instance (calls = %d, want 1). A re-read would dereference "+
			"a nil dataplane and panic the apply; joinRan implying non-nil was sound "+
			"against the pre-#6743 plain field and is not sound against a cell (#7074)",
			joined.notifyCalls)
	}
}
