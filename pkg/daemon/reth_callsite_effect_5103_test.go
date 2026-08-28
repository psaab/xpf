package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #5103 F2: bind the CALLER -> programRethMemberMAC boundary behaviourally.
//
// reth_commit_fold_5103_test.go binds the helper: given a prepare failure it
// returns a joined commit error. reth_hook_wired_5103_test.go binds the call
// site STRUCTURALLY — one call, result assigned with `=` to the two
// accumulators, not nested in a constant-false branch. Neither binds the step
// between them: that the value the helper returns is still the value
// applyDataplaneAndHACore reports. An AST canary cannot express reachability;
// it can only say the call is WRITTEN, not that its result is CONSUMED. This
// one-line insertion at the call site satisfies every structural assertion and
// keeps the effect from ever reaching production:
//
//	prevNetworkdErr := networkdErr
//	networkdErr, needLinkCycleRecovery, _ = d.programRethMemberMAC(
//	    linuxName, mac, networkdErr, needLinkCycleRecovery)
//	networkdErr = prevNetworkdErr        // effect discarded
//
// `go vet` returns 0 and the whole pkg/daemon suite returns 0 under it.
//
// Note the shape this PR already walked into once: an earlier round answered
// "the canary is defeatable" by extracting the logic into a testable helper.
// That MOVED the unbound boundary up to the caller rather than closing it, and
// it arrived wearing the evidence of a fix (a new passing test). So the thing
// bound here is the caller->helper boundary itself, driven through the REAL
// applyConfigLocked body — the same no-seam approach apply_ctx_cancel_test.go
// uses — not another extracted unit.
//
// The observable is the apply's own returned error. A RETH member whose live
// MAC set is rejected fires the worker-join hook; the join then fails, so
// programRethMACWithWorkerJoin classifies the abort as errRethPrepareLinkCycle;
// programRethMemberMAC joins it into the commit accumulator; and the accumulator
// is what applyDataplaneAndHACore hands to applyTailReconciles. Discard the
// assignment anywhere along that path and the commit reports SUCCESS over a
// member left administratively DOWN with its AF_XDP workers joined — the exact
// #5103 fail-open.

// rethCallsiteDaemon builds the smallest Daemon that reaches step 2.6's RETH
// loop through the real applyConfigLocked body: a dataplane whose link
// controller fails PrepareLinkCycle, a cluster manager and a VRRP manager (the
// loop is gated on d.cluster != nil), and a store. d.routing/d.frr/d.networkd
// stay nil so the netlink reconcile phases are skipped, exactly as in
// minimalApplyCtxDaemon.
func rethCallsiteDaemon(t *testing.T, prepareErr error) (*Daemon, *abortRecoveryLinkController) {
	t.Helper()
	installFakeNetworkctl(t)
	lc := &abortRecoveryLinkController{prepareErr: prepareErr}
	d := &Daemon{
		cluster: cluster.NewManager(0, 1),
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(&abortRecoveryTestDP{link: lc}) // #2114: publish through the cell
	return d, lc
}

// rethCallsiteConfig is a one-member RETH config: reth0 in redundancy-group 1
// with ge-0/0/1 as its redundant-parent member, so RethToPhysical() yields
// reth0 -> ge-0/0/1 and LinuxIfName makes that ge-0-0-1 — the name
// newRecordingRethOps' fake link answers to.
func rethCallsiteConfig() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/1": {
					Name:            "ge-0/0/1",
					RedundantParent: "reth0",
				},
			},
		},
	}
}

// TestApplyCallSiteSurfacesRethMemberCommitError_5103 is the F2 fail-on-revert
// guard for the CALL SITE. It drives the real applyConfigLocked, not
// programRethMemberMAC, so the assertion fails if the helper's result is
// discarded, shadowed, or overwritten at the call site even though the helper
// itself is unchanged and its own tests still pass.
//
// RED on the discard mutation quoted in this file's header: the apply returns
// nil and this fails at "the apply reported SUCCESS".
func TestApplyCallSiteSurfacesRethMemberCommitError_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := rethCallsiteDaemon(t, errors.New("stop_workers: helper did not respond"))

	err := d.applyConfigLocked(context.Background(), rethCallsiteConfig())

	// --- POSITIVE CONTROL: the fixture actually reached the failing hook. A
	// config that never entered the RETH loop would produce no error under BOTH
	// the correct and the discarding call site, and this test would look bound
	// while binding nothing.
	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the apply never reached the "+
			"RETH member's worker-join hook, so there is no classified error for the "+
			"call site to carry and this test proves nothing", lc.prepareCalls)
	}

	// --- THE #5103 F2 DISCRIMINATOR.
	if err == nil {
		// #6871: an earlier revision of this message said the member is left
		// "administratively DOWN". It is not — a hook failure returns BEFORE
		// setDown, so the link is untouched and still UP on its previous MAC.
		// What IS left behind is the dataplane state the hook already applied:
		// ctrl driven to 0 and the workers' state unknown (stop_workers failed,
		// so they may or may not have been joined). That is the outage the
		// commit must not report as success.
		t.Fatal("the apply reported SUCCESS over a RETH member whose link cycle was " +
			"ABORTED: programRethMemberMAC's commit error never reached " +
			"applyDataplaneAndHACore's return. The link is untouched, but ctrl is off " +
			"and the AF_XDP worker state is unknown, so the node is not forwarding — " +
			"and the commit says it worked (#5103)")
	}
	if !errors.Is(err, errRethPrepareLinkCycle) {
		t.Errorf("the apply failed, but not with the RETH prepare-abort classification: "+
			"got %v. Either the call site dropped this member's error and something "+
			"else failed the apply, or the classification was lost between the helper "+
			"and the apply's return", err)
	}
}

// TestApplyCallSiteDoesNotInventRethCommitError_5103 is the OVER-REACH control,
// deliberately in its own func body: a guard that shares a body with its binder
// never runs once the binder fails, so it can never be observed to hold
// independently.
//
// It pins the OTHER direction — that the error above is conditional on the
// member's cycle ABORTING, not on the RETH loop merely running. It must stay
// GREEN under the discard mutation (which only ever removes an error) and go
// RED if the guard above were widened to "the apply errors whenever a RETH
// member is processed", which would pass the discriminator for free while
// failing every healthy commit.
//
// Same fixture, one field different: PrepareLinkCycle succeeds.
func TestApplyCallSiteDoesNotInventRethCommitError_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := rethCallsiteDaemon(t, nil /* the join SUCCEEDS */)

	err := d.applyConfigLocked(context.Background(), rethCallsiteConfig())

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — this control must traverse the "+
			"SAME call site as the discriminator, otherwise it is not controlling for "+
			"anything", lc.prepareCalls)
	}
	if err != nil {
		t.Fatalf("a RETH member whose link cycle completed cleanly failed the apply: %v. "+
			"The call site must fold only a REAL prepare failure; folding on every "+
			"member turns each HA commit into a failure", err)
	}
}
