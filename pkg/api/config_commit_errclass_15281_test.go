// #15281 D08-02: the REST commit / commit-confirmed handlers used to
// blanket EVERY non-context commit-callback error to 400 success:false.
// But the daemon commit path returns a NON-FATAL tail-reconcile / peer-push
// error ALONGSIDE the committed config (compiled != nil) — the config is
// promoted, persisted and live, only a transient tail step failed. That
// 400 was indistinguishable from a real config reject (compiled == nil),
// so an operator/automation client believed a live config was rejected.
// This is the REST twin of grpcapi TestCommitErrorClassification_5742:
// writeCommitError classifies structurally on (compiled, err).
//
// FAIL-ON-REVERT: restore the old blanket `default: 400` in
// configCommitHandler/configCommitConfirmedHandler and the
// tail-reconcile rows go RED (400 instead of 503 committed:true), while
// the schema-reject and context rows stay green.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

type commitErrEnvelope15281 struct {
	Success bool `json:"success"`
	Data    *struct {
		Status    string   `json:"status"`
		Committed bool     `json:"committed"`
		Error     string   `json:"error"`
		Warnings  []string `json:"warnings"`
	} `json:"data"`
	Error string `json:"error"`
}

func decodeCommitErr15281(t *testing.T, rr *httptest.ResponseRecorder) commitErrEnvelope15281 {
	t.Helper()
	var env commitErrEnvelope15281
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response %q: %v", rr.Body.String(), err)
	}
	return env
}

// TestRESTCommitErrorClassification_15281 drives BOTH REST commit handlers
// through injected (compiled, err) callbacks and asserts the HTTP status
// and envelope distinguish a committed-with-tail-error from a reject,
// while the human-readable message is preserved.
func TestRESTCommitErrorClassification_15281(t *testing.T) {
	nonNil := &config.Config{Warnings: []string{"tail warning"}}

	tailErr := errors.New("networkd write failed: transient control-socket hiccup")
	rejectErr := errors.New("schema validation rejected: unknown zone reference")
	// #16828: the daemon's post-promotion abort shape — promoted config
	// returned with an ErrCommittedNotApplied-wrapped error.
	notAppliedErr := fmt.Errorf("%w: %w", configstore.ErrCommittedNotApplied,
		errors.New("policy session READ authority unavailable"))
	// wantStatus, when non-empty, asserts data.status exactly (the two
	// committed classes share committed:true but differ in status).

	cases := []struct {
		name          string
		compiled      *config.Config
		err           error
		wantCode      int
		wantCommitted bool
		wantMsg       string
		wantStatus    string
	}{
		{
			name: "tail_reconcile_nonfatal", compiled: nonNil, err: tailErr,
			wantCode: http.StatusServiceUnavailable, wantCommitted: true, wantMsg: "networkd write failed",
			wantStatus: "committed_with_error",
		},
		{
			name: "schema_reject", compiled: nil, err: rejectErr,
			wantCode: http.StatusBadRequest, wantCommitted: false, wantMsg: "schema validation rejected",
		},
		{
			// #16828: committed but not applied — non-400 with
			// committed:true and the distinct status, so automation does
			// not treat a persisted config as rejected.
			name: "committed_not_applied", compiled: nonNil, err: notAppliedErr,
			wantCode: http.StatusServiceUnavailable, wantCommitted: true, wantMsg: "committed but not applied",
			wantStatus: "committed_not_applied",
		},
		{
			name: "committed_not_applied_nil_config", compiled: nil, err: notAppliedErr,
			wantCode: http.StatusServiceUnavailable, wantCommitted: true, wantMsg: "committed but not applied",
			wantStatus: "committed_not_applied",
		},
		{
			name: "context_canceled", compiled: nil, err: fmt.Errorf("commit aborted: %w", context.Canceled),
			wantCode: http.StatusServiceUnavailable, wantCommitted: false, wantMsg: "commit busy",
		},
		{
			// Precedence guard: a wrapped context error wins even if a
			// callback also hands back a non-nil config — the classifier
			// must check context errors BEFORE compiled != nil.
			name: "context_canceled_beats_config", compiled: nonNil, err: fmt.Errorf("commit aborted: %w", context.Canceled),
			wantCode: http.StatusServiceUnavailable, wantCommitted: false, wantMsg: "commit busy",
		},
		{
			// #16828 precedence: a POST-promotion abort wraps
			// context.Canceled under the sentinel — committed wins over
			// the pre-promotion "commit busy" reading.
			name: "committed_not_applied_beats_context", compiled: nonNil,
			err:      fmt.Errorf("%w: %w", configstore.ErrCommittedNotApplied, context.Canceled),
			wantCode: http.StatusServiceUnavailable, wantCommitted: true, wantMsg: "committed but not applied",
			wantStatus: "committed_not_applied",
		},
		{
			name: "context_deadline", compiled: nil, err: fmt.Errorf("commit slow: %w", context.DeadlineExceeded),
			wantCode: http.StatusServiceUnavailable, wantCommitted: false, wantMsg: "commit busy",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Run("Commit", func(t *testing.T) {
				store := restHolderStore(t)
				s := &Server{
					store: store,
					commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
						return tc.compiled, tc.err
					},
				}
				rr := httptest.NewRecorder()
				req := withRESTConfigSession(
					httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
				s.configCommitHandler(rr, req)
				assertRESTCommitErr15281(t, rr, tc.wantCode, tc.wantCommitted, tc.wantMsg, tc.wantStatus)
			})
			t.Run("CommitConfirmed", func(t *testing.T) {
				store := restHolderStore(t)
				s := &Server{
					store: store,
					commitConfirmedFn: func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
						return tc.compiled, tc.err
					},
				}
				rr := httptest.NewRecorder()
				req := withRESTConfigSession(
					httptest.NewRequest("POST", "/api/v1/config/commit-confirmed",
						strings.NewReader(`{"minutes":5}`)), testRESTConfigSessionID)
				s.configCommitConfirmedHandler(rr, req)
				assertRESTCommitErr15281(t, rr, tc.wantCode, tc.wantCommitted, tc.wantMsg, tc.wantStatus)
			})
		})
	}
}

func assertRESTCommitErr15281(t *testing.T, rr *httptest.ResponseRecorder, wantCode int, wantCommitted bool, wantMsg string, wantStatus ...string) {
	t.Helper()
	if rr.Code != wantCode {
		t.Fatalf("status = %d, want %d; body: %s", rr.Code, wantCode, rr.Body.String())
	}
	env := decodeCommitErr15281(t, rr)
	if env.Success {
		t.Fatalf("success = true, want false for an error response; body: %s", rr.Body.String())
	}
	if wantMsg != "" && !strings.Contains(env.Error, wantMsg) && (env.Data == nil || !strings.Contains(env.Data.Error, wantMsg)) {
		t.Fatalf("error %q missing preserved substring %q; body: %s", env.Error, wantMsg, rr.Body.String())
	}
	if wantCommitted {
		if env.Data == nil {
			t.Fatalf("committed response has no data; body: %s", rr.Body.String())
		}
		if !env.Data.Committed {
			t.Fatalf("data.committed = false, want true (config is committed); body: %s", rr.Body.String())
		}
		want := "committed_with_error"
		if len(wantStatus) > 0 && wantStatus[0] != "" {
			want = wantStatus[0]
		}
		if env.Data.Status != want {
			t.Fatalf("data.status = %q, want %q; body: %s", env.Data.Status, want, rr.Body.String())
		}
	} else if env.Data != nil && env.Data.Committed {
		t.Fatalf("data.committed = true for a non-committed error; body: %s", rr.Body.String())
	}
}

// TestRESTCommitSucceedsWithCommittedConfig_15281 pins that the admitted
// (no-error) path is unchanged: a nil error yields 200 success even when
// the daemon returns a non-nil compiled config (the same value shape as
// the non-fatal error path), so the classification never trips on success.
func TestRESTCommitSucceedsWithCommittedConfig_15281(t *testing.T) {
	store := restHolderStore(t)
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			return &config.Config{}, nil
		},
		commitConfirmedFn: func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
			return &config.Config{}, nil
		},
	}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
	s.configCommitHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Commit with (nonNil config, nil err): status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit-confirmed",
			strings.NewReader(`{"minutes":5}`)), testRESTConfigSessionID)
	s.configCommitConfirmedHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("CommitConfirmed with (nonNil config, nil err): status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}
