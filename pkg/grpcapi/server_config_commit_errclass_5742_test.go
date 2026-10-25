// #5742: the commit RPCs (Commit / CommitConfirmed) used to blanket EVERY
// non-context commit-callback error to codes.InvalidArgument ("you sent bad
// config"). But the daemon commit path returns a NON-FATAL tail-reconcile /
// ordinary dataplane-apply error (networkd write #1778, Kea restart #2987,
// IPsec reload #4433, iface reconcile #5310, non-abort apply #5679) ALONGSIDE
// the committed config (compiled != nil, applyAndSyncCommitted) — the config is
// valid and committed+active, only a transient control-socket step failed and
// self-heals on retry (#5646). commitApplyStatus classifies structurally on
// (compiled, err): a non-nil-config error → codes.Unavailable (retryable), a
// nil-config error → codes.InvalidArgument (real config reject), with
// context.Canceled / DeadlineExceeded preserved and checked FIRST.
//
// FAIL-ON-REVERT: restore the old blanket `default: status.Errorf(codes.
// InvalidArgument, ...)` in Commit/CommitConfirmed and the
// "tail-reconcile → Unavailable" rows below go RED (they observe
// InvalidArgument instead), while the "schema-reject → InvalidArgument" and
// context rows stay green.
package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newCommitClassServer(t *testing.T, compiled *config.Config, injected error) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			return compiled, injected
		},
		commitConfirmedFn: func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
			return compiled, injected
		},
	}
}

// TestCommitErrorClassification_5742 drives BOTH commit RPCs through injected
// (compiled, err) callbacks and asserts the machine-readable status code is
// classified by error class, while the human-readable message is preserved.
func TestCommitErrorClassification_5742(t *testing.T) {
	nonNil := &config.Config{} // daemon returns the committed config on a non-fatal tail error

	tailErr := errors.New("networkd write failed: transient control-socket hiccup")
	rejectErr := errors.New("schema validation rejected: unknown zone reference")
	// #16828: the daemon's post-promotion abort shape — promoted config
	// returned with an ErrCommittedNotApplied-wrapped error.
	notAppliedErr := fmt.Errorf("%w: %w", configstore.ErrCommittedNotApplied,
		errors.New("policy session READ authority unavailable"))

	cases := []struct {
		name     string
		compiled *config.Config
		err      error
		wantCode codes.Code
		wantMsg  string // substring the operator-facing message must still carry ("" = skip)
	}{
		{
			// Non-fatal tail-reconcile/apply: config committed+active, transient
			// subsystem failure → retryable. THIS is the #5742 fix.
			name: "tail_reconcile_nonfatal", compiled: nonNil, err: tailErr,
			wantCode: codes.Unavailable, wantMsg: "networkd write failed",
		},
		{
			// Real config reject (compile/schema): no config was committed →
			// keep the historical InvalidArgument. Fail-safe default.
			name: "schema_reject", compiled: nil, err: rejectErr,
			wantCode: codes.InvalidArgument, wantMsg: "schema validation rejected",
		},
		{
			// #16828: committed but not applied — the config was promoted+
			// persisted (active; live on a later apply/boot), so it must NOT
			// be InvalidArgument (client would edit/abandon a persisted
			// config) and must NOT be the tail class's Unavailable-live
			// reading. FailedPrecondition: resolve the gate cause/restart.
			name: "committed_not_applied", compiled: nonNil, err: notAppliedErr,
			wantCode: codes.FailedPrecondition, wantMsg: "committed but not applied",
		},
		{
			// #16828: the sentinel keys the class even for a discarding
			// caller that passes a nil config.
			name: "committed_not_applied_nil_config", compiled: nil, err: notAppliedErr,
			wantCode: codes.FailedPrecondition, wantMsg: "committed but not applied",
		},
		{
			// A busy apply-lock / daemon-stop abort: preserved verbatim.
			name: "context_canceled", compiled: nil, err: fmt.Errorf("commit aborted: %w", context.Canceled),
			wantCode: codes.Canceled, wantMsg: "",
		},
		{
			// Precedence guard: a wrapped context error wins even if a
			// (malformed) callback also hands back a non-nil config — the
			// classifier must check context errors BEFORE compiled != nil.
			name: "context_canceled_beats_config", compiled: nonNil, err: fmt.Errorf("commit aborted: %w", context.Canceled),
			wantCode: codes.Canceled, wantMsg: "",
		},
		{
			// #16828 precedence: a POST-promotion abort wraps
			// context.Canceled under the sentinel — the sentinel wins, the
			// config WAS committed, so this is not a pre-promotion Canceled.
			name: "committed_not_applied_beats_context", compiled: nonNil,
			err:      fmt.Errorf("%w: %w", configstore.ErrCommittedNotApplied, context.Canceled),
			wantCode: codes.FailedPrecondition, wantMsg: "committed but not applied",
		},
		{
			name: "context_deadline", compiled: nil, err: fmt.Errorf("commit slow: %w", context.DeadlineExceeded),
			wantCode: codes.DeadlineExceeded, wantMsg: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Run("Commit", func(t *testing.T) {
				s := newCommitClassServer(t, tc.compiled, tc.err)
				_, err := s.Commit(context.Background(), &pb.CommitRequest{})
				assertCommitStatus(t, err, tc.wantCode, tc.wantMsg)
			})
			t.Run("CommitConfirmed", func(t *testing.T) {
				s := newCommitClassServer(t, tc.compiled, tc.err)
				_, err := s.CommitConfirmed(context.Background(), &pb.CommitConfirmedRequest{Minutes: 5})
				assertCommitStatus(t, err, tc.wantCode, tc.wantMsg)
			})
		})
	}
}

func assertCommitStatus(t *testing.T, err error, wantCode codes.Code, wantMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("commit succeeded; want error with code %v", wantCode)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a *status.Status: %T (%v)", err, err)
	}
	if got := st.Code(); got != wantCode {
		t.Fatalf("status code = %v, want %v (message %q)", got, wantCode, st.Message())
	}
	if wantMsg != "" && !strings.Contains(st.Message(), wantMsg) {
		t.Fatalf("status message %q missing preserved substring %q", st.Message(), wantMsg)
	}
}

// TestCommitSucceedsWithCommittedConfig_5742 pins that the admitted (no-error)
// path is unchanged: a nil error yields a normal response even when the daemon
// returns a non-nil compiled config (the same value shape as the non-fatal
// error path), so the classification helper never trips on success.
func TestCommitSucceedsWithCommittedConfig_5742(t *testing.T) {
	s := newCommitClassServer(t, &config.Config{}, nil)
	if _, err := s.Commit(context.Background(), &pb.CommitRequest{}); err != nil {
		t.Fatalf("Commit with (nonNil config, nil err) = %v, want success", err)
	}
	if _, err := s.CommitConfirmed(context.Background(), &pb.CommitConfirmedRequest{Minutes: 5}); err != nil {
		t.Fatalf("CommitConfirmed with (nonNil config, nil err) = %v, want success", err)
	}
}
