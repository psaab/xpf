// #16828 R3-F10-03: applyAndSyncCommitted returned (nil, applyErr) on the
// applyErrSkipsPeerSync abort path even though the store had ALREADY
// promoted+persisted the config, so the #5742/#15281 (compiled, err)
// classifiers reported a persisted config as a pre-promotion reject
// (REST 400 / gRPC InvalidArgument). The fix returns the promoted config
// with the error wrapped in configstore.ErrCommittedNotApplied.
//
// FAIL-ON-REVERT: restoring `return nil, applyErr` on the skip branch
// makes every cell below RED (compiled==nil, no sentinel), while the
// fatal-skip peer assertions (0 pushes) stay green — the peer behaviour
// is unchanged, only the operator/API classification moves.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// commitAbortCells16828 drives commitAndApply / commitConfirmedAndApply
// with each post-promotion abort class injected at the apply seam and
// asserts: (a) the promoted config is returned non-nil, (b) the error
// wraps both ErrCommittedNotApplied and the underlying sentinel, (c) no
// peer push fired, (d) the store active config is the NEW config (the
// promotion was not unwound), and (e) the shared classifier reads the
// result as committed-not-applied on both the (config, err) pair and —
// for the syncAndApply-style discard shape — on (nil, err).
func commitAbortCells16828(t *testing.T, name string, applyErr error, sentinel error) {
	t.Helper()
	for _, confirmed := range []bool{false, true} {
		label := name + "/commit"
		if confirmed {
			label = name + "/commit-confirmed"
		}
		t.Run(label, func(t *testing.T) {
			s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
			d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
			d.applyBodyForTest = func(_ *config.Config) {}
			d.applyErrForTest = applyErr

			var syncCalls int
			d.syncPeerForTest = func() { syncCalls++ }

			var compiled *config.Config
			var err error
			if confirmed {
				compiled, err = d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
			} else {
				compiled, err = d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncAlways)
			}
			if err == nil {
				t.Fatal("commit must surface the post-promotion abort error")
			}
			if !errors.Is(err, configstore.ErrCommittedNotApplied) {
				t.Fatalf("error = %v, want it to wrap ErrCommittedNotApplied (#16828)", err)
			}
			if !errors.Is(err, sentinel) {
				t.Fatalf("error = %v, want it to still wrap the underlying sentinel %v", err, sentinel)
			}
			if compiled == nil {
				t.Fatal("post-promotion abort must return the promoted config, got nil " +
					"(the #16828 defect: classifiers read nil as a pre-promotion reject)")
			}
			if compiled.System.HostName != "NEW" {
				t.Fatalf("returned config host-name = %q, want NEW (the promoted config)", compiled.System.HostName)
			}
			if syncCalls != 0 {
				t.Fatalf("fatal post-promotion abort must NOT push to the peer; got %d pushes", syncCalls)
			}
			if got := s.ActiveConfig().System.HostName; got != "NEW" {
				t.Fatalf("store active host-name = %q, want NEW (promotion must not unwind)", got)
			}
			if got := configstore.ClassifyCommitError(compiled, err); got != configstore.CommitErrCommittedNotApplied {
				t.Fatalf("ClassifyCommitError(promoted, err) = %v, want CommitErrCommittedNotApplied", got)
			}
			// A caller that discards the config (the syncAndApply shape)
			// must still classify by the sentinel, not fall to Rejected.
			if got := configstore.ClassifyCommitError(nil, err); got != configstore.CommitErrCommittedNotApplied {
				t.Fatalf("ClassifyCommitError(nil, err) = %v, want CommitErrCommittedNotApplied", got)
			}
		})
	}
}

func TestCommitAbortReportedAsCommittedNotApplied16828(t *testing.T) {
	commitAbortCells16828(t, "protocol_gate",
		dpuserspace.ErrPolicySchedulerProtocolIncompatible,
		dpuserspace.ErrPolicySchedulerProtocolIncompatible)
	commitAbortCells16828(t, "policy_read_authority",
		fmt.Errorf("policy session invalidation authority refusal: %w", dpuserspace.ErrPolicyReadAuthority),
		dpuserspace.ErrPolicyReadAuthority)
	// The daemon-stop abort wraps context.Canceled; the sentinel must win
	// over the context arm so it is not reported as a pre-promotion
	// "commit busy" (nothing was committed then — here it WAS).
	commitAbortCells16828(t, "context_canceled",
		fmt.Errorf("apply aborted: %w", context.Canceled), context.Canceled)
}

// TestCommitPrePromotionRejectStaysRejected16828 is the control cell: a
// candidate that fails before promotion (here a cluster-topology
// preflight reject, which commitWithGenBinding surfaces before any
// store promotion) still returns (nil, err) with no sentinel and
// classifies as a true reject — the fix must not relabel rejects.
func TestCommitPrePromotionRejectStaysRejected16828(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	d.bootstrapMode.Store(true)

	compiled, err := d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncNever)
	if err == nil {
		t.Fatal("bootstrap-mode plain commit must be refused")
	}
	if compiled != nil {
		t.Fatalf("pre-promotion reject must return nil config; got %+v", compiled)
	}
	if errors.Is(err, configstore.ErrCommittedNotApplied) {
		t.Fatalf("pre-promotion reject must not carry ErrCommittedNotApplied: %v", err)
	}
	if got := configstore.ClassifyCommitError(compiled, err); got != configstore.CommitErrRejected {
		t.Fatalf("ClassifyCommitError(nil, reject) = %v, want CommitErrRejected", got)
	}
	if s.ActiveConfig().System.HostName != "OLD" {
		t.Fatalf("store active changed on a pre-promotion reject: %q", s.ActiveConfig().System.HostName)
	}
}

// TestSyncAndApplyFatalShape16828 documents the peer-sync path shape:
// syncAndApply returns (nil, bareFatalErr) on a fatal apply error — its
// caller (handleConfigSync) only logs the error, so there is no wire
// classifier to misreport today. This cell pins that the bare fatal
// error (without the commit path's ErrCommittedNotApplied wrap) is NOT
// positively classified as committed, so a future change that routes
// sync errors through ClassifyCommitError must wrap deliberately
// rather than silently inheriting a reject reading for a config
// SyncApply already promoted.
func TestSyncAndApplyFatalShape16828(t *testing.T) {
	err := dpuserspace.ErrPolicySchedulerProtocolIncompatible
	if !applyErrSkipsPeerSync(err) {
		t.Fatal("premise: protocol-gate error must be in the fatal skip class")
	}
	if got := configstore.ClassifyCommitError(nil, err); got != configstore.CommitErrRejected {
		t.Fatalf("bare fatal error without the daemon wrap classifies %v; if this changes, "+
			"update the #16828 residual note (sync path has no wire classifier today)", got)
	}
}
