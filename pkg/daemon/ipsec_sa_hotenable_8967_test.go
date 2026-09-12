package daemon

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/ipsec"
)

// applyTailMentions8967 reports whether the apply tail calls the named starter.
// Reads the source rather than modelling the call graph: a model of which
// starters the apply path reaches is a second implementation that drifts from
// the one that matters (#8946).
func applyTailMentions8967(t *testing.T, starter string) bool {
	t.Helper()
	src, err := os.ReadFile("daemon_apply_tail.go")
	if err != nil {
		t.Fatalf("cannot read daemon_apply_tail.go: %v -- this cell is blind without it", err)
	}
	// ANCHOR, because reading a source file BY NAME survives the change that
	// breaks it. If the apply tail is split into another file the read still
	// SUCCEEDS, `Contains` returns false for every starter, and this cell
	// reports "the starter is not called from the apply tail" -- which is
	// false, and points whoever reads it at the knob rather than at the move.
	//
	// A sibling lane lost a whole census to the silent form of this: its
	// scraper read a predicate's file by name, the predicate was split into a
	// new file, the old file still existed, and the census reported a stable,
	// confident ZERO for every population. Re-running never catches it. The
	// only thing that does is a second source for the same fact.
	//
	// Here the failure is LOUD rather than silent -- the caller asserts
	// `!applyTailMentions8967(...)` -- so the anchor buys a correct DIAGNOSIS
	// rather than a caught defect. That is still worth having: a wrong
	// diagnostic sends the next reader to the wrong place, which is the #9006
	// and #8992 shape.
	body := string(src)
	if !strings.Contains(body, "func (d *Daemon)") {
		t.Fatalf("daemon_apply_tail.go no longer contains any Daemon method, so it is " +
			"not the apply tail any more. This cell scrapes it BY NAME; the file was " +
			"renamed, split, or emptied. Repoint the scrape -- do NOT read the result " +
			"below as a finding about any knob.")
	}
	return strings.Contains(body, "d."+starter+"(")
}

// #8967: the IPsec SA sync publisher was the one comms-scoped loop that did
// not handle being enabled by a later commit.
//
// `startClusterSyncAuxLoops` launches four loops. Three state in place that
// their knob may be toggled from the apply path; the fourth read its boolean
// once at comms start. Enabling `ipsec-sa-synchronization` on a running
// cluster therefore committed successfully and started nothing, until an
// unrelated comms restart.
//
// WHAT MADE IT A FINDING RATHER THAN AN OBSERVATION was the siblings, not the
// absence. "IPsecSASync has no apply-path presence" alone is consistent with
// correct-by-design -- plenty of things are start-time only on purpose. Three
// siblings in the same function that DO handle it, with the reasoning written
// out beside them, is what converts an absence into a defect:
//
//	IPsecSASync    comms-wiring=2  apply-path=0   <- the only zero
//	DHCPLeaseSync  comms-wiring=2  apply-path=2
//	ConfigSync     comms-wiring=0  apply-path=8
//	SessionSync    comms-wiring=6  apply-path=1

// ipsecSALoopCancelForTest reads the publisher's cancel handle under loopMu.
//
// #9844: the cells below used to read d.ipsecSALoopCancelForTest() directly. Every
// production writer takes loopMu (ensureIPsecSASyncLoop, stopIPsecSASyncLoop,
// clearIPsecSALoopIfCurrent), and the last of those runs on the PUBLISHER's own
// goroutine as it exits — so an unlocked read here raced a write that was
// correctly synchronised on the other side. It reproduced as roughly one
// DATA RACE per 200 runs of the hot-enable cell and reddened any lane's
// `go test -race ./pkg/daemon`.
//
// The value is only ever compared against nil, so reading it under the lock
// changes nothing the cells assert; it just stops the read racing the write.
func (d *Daemon) ipsecSALoopCancelForTest() context.CancelFunc {
	d.ipsecSASync.loopMu.Lock()
	defer d.ipsecSASync.loopMu.Unlock()
	return d.ipsecSASync.loopCancel
}

// The starter must be idempotent, must not launch without comms, and must
// stop on disable. These are the three properties `ensureDHCPLeaseSyncLoop`
// has and that #4647 established as the shape for a hot-toggleable loop.
func TestIPsecSASyncStarterIsIdempotentAndCommsGated8967(t *testing.T) {
	d := &Daemon{}

	// NO COMMS: must not start, and must not panic. The apply path can run
	// before comms exist -- that is the case this gate is for, and the
	// comms-start call re-runs the starter once they are up.
	d.ensureIPsecSASyncLoop(true)
	if d.ipsecSALoopCancelForTest() != nil {
		t.Fatal("#8967: the starter launched with no comms context. The apply path " +
			"runs before comms are up, so launching there would run the publisher " +
			"against a nil session-sync")
	}

	// DISABLE with nothing running must be a no-op, not a nil deref.
	d.ensureIPsecSASyncLoop(false)
	if d.ipsecSALoopCancelForTest() != nil {
		t.Error("#8967: disable with no running loop left a cancel registered")
	}
}

// With comms up, the knob must actually start it, twice must not double-launch,
// and disable must stop it.
func TestIPsecSASyncHotEnableStartsAndStops8967(t *testing.T) {
	d := &Daemon{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.clusterCommsMu.Lock()
	d.clusterCommsCtx = ctx
	d.clusterCommsMu.Unlock()
	d.ipsec = &ipsec.Manager{}

	d.ensureIPsecSASyncLoop(true)
	first := d.ipsecSALoopCancelForTest()
	if first == nil {
		t.Fatal("#8967: a knob-ON call with comms up did not start the publisher. " +
			"That is the defect: the knob was read once at comms start, so " +
			"enabling it on a running cluster committed and started nothing")
	}

	if got := d.ipsecSASync.launches.Load(); got != 1 {
		t.Fatalf("CONTROL: expected exactly 1 launch after the first knob-ON call, got %d", got)
	}

	// IDEMPOTENT: a knob-unchanged commit must not launch a SECOND publisher.
	// Asserted on the launch count, not on `loopCancel != nil` -- that is true
	// both when the call was a no-op and when it started a second loop and
	// overwrote the first one's cancel, leaking it. A mutation removing the
	// idempotence guard survived the weaker assertion.
	d.ensureIPsecSASyncLoop(true)
	if d.ipsecSALoopCancelForTest() == nil {
		t.Fatal("#8967: the second knob-ON call cleared the running loop")
	}
	if got := d.ipsecSASync.launches.Load(); got != 1 {
		t.Errorf("#8967: a knob-unchanged commit launched a SECOND publisher "+
			"(launches=%d, want 1). The first loop's cancel is overwritten and "+
			"that goroutine leaks for the life of the comms context, advertising "+
			"in parallel with its replacement", got)
	}

	// DISABLE must stop it. Without this half, a knob-OFF commit would leave
	// the publisher advertising after the operator turned it off.
	d.ensureIPsecSASyncLoop(false)
	if d.ipsecSALoopCancelForTest() != nil {
		t.Error("#8967: a knob-OFF call did not stop the publisher")
	}
}

// THE SIBLING PROPERTY, asserted rather than described.
//
// This is the cell that would have caught the original defect, and it is
// deliberately about the SET rather than about IPsec: every knob whose loop is
// launched from `startClusterSyncAuxLoops` must also be reconciled on the apply
// path, or be unconditional. A fifth loop added start-time-only reds here.
func TestEveryAuxLoopKnobIsReconciledOnApply8967(t *testing.T) {
	// Each entry is a knob and the starter that must be reachable from the
	// apply path for it. An unconditional loop needs no knob and is not listed.
	for _, tc := range []struct{ knob, starter string }{
		{"DHCPLeaseSync", "ensureDHCPLeaseSyncLoop"},
		{"IPsecSASync", "ensureIPsecSASyncLoop"},
	} {
		if !applyTailMentions8967(t, tc.starter) {
			t.Errorf("#8967: knob %q is gated at comms start but its starter %q is "+
				"not called from the apply tail.\n"+
				"  A knob read once at comms start means enabling it on a running "+
				"cluster commits successfully and starts nothing until an unrelated "+
				"comms restart. Three of the four aux loops handle this and state "+
				"why in place; the fourth did not, which is #8967.\n"+
				"  Either call the starter from the apply tail, or make the loop "+
				"unconditional the way configSyncReconcileLoop is.", tc.knob, tc.starter)
		}
	}
}
