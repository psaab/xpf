package api

// #16156: the REST bare-commit confirm-only branch and the commit-error
// / warnings paths now route through the shared configstore helpers
// (Store.ConfirmOnly, configstore.ClassifyCommitError via
// writeCommitError, configstore.WarningsOf via commitResponseFromConfig
// and writeCommitError). The classifier corpus itself is pinned in
// pkg/configstore (TestClassifyCommitError16156) and end-to-end in
// TestRESTCommitErrorClassification_15281; this file pins the two REST
// behaviours the helper swap could silently change:
//
//   - confirm-only: a bare REST commit during a pending window with an
//     UNCHANGED candidate confirms without invoking commitFn, and with
//     a DIRTY candidate it falls through to commitFn (the #4000
//     silent-drop hazard). FAIL-ON-REVERT: drop the dirty conjunct
//     from ConfirmOnly and the dirty cell REDS (commitFn never called,
//     staged edit dropped).
//   - warnings: a successful commit response carries the compiled
//     config's warnings verbatim (WarningsOf). FAIL-ON-REVERT: return
//     nil from WarningsOf and this REDS.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// armRESTConfirmWindow16156 returns a REST-holder store with a pending
// confirm window and a clean candidate.
func armRESTConfirmWindow16156(t *testing.T) *configstore.Store {
	t.Helper()
	store := restHolderStore(t)
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := store.SetFromInputAs(testRESTConfigSessionID, "system host-name rest-confirmed-16156"); err != nil {
		t.Fatalf("Set(confirmed): %v", err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !store.IsConfirmPending() || store.IsDirty() {
		t.Fatal("premise: want pending window with clean candidate")
	}
	return store
}

func TestRESTBareCommitConfirmOnly16156(t *testing.T) {
	t.Run("UnchangedConfirmsWithoutCommitFn", func(t *testing.T) {
		store := armRESTConfirmWindow16156(t)
		called := false
		s := &Server{
			store: store,
			commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
				called = true
				return store.Commit()
			},
		}
		rr := httptest.NewRecorder()
		req := withRESTConfigSession(
			httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
		s.configCommitHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("bare commit (unchanged): status = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		if called {
			t.Fatal("commitFn invoked for an unchanged candidate during a confirm window; want confirm-only")
		}
		if store.IsConfirmPending() {
			t.Fatal("confirm-only bare commit must clear the pending window")
		}
	})

	t.Run("DirtyFallsThroughToCommitFn", func(t *testing.T) {
		store := armRESTConfirmWindow16156(t)
		if err := store.SetFromInputAs(testRESTConfigSessionID, "system host-name rest-edited-16156"); err != nil {
			t.Fatalf("Set(edited): %v", err)
		}
		called := false
		s := &Server{
			store: store,
			commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
				called = true
				return store.Commit()
			},
		}
		rr := httptest.NewRecorder()
		req := withRESTConfigSession(
			httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
		s.configCommitHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("bare commit (dirty): status = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		if !called {
			t.Fatal("commitFn not invoked for a dirty candidate during a confirm window; staged edits would be silently dropped (#4000)")
		}
		if got := store.ActiveConfig().System.HostName; !strings.Contains(got, "rest-edited-16156") {
			t.Fatalf("active host-name = %q, want rest-edited-16156", got)
		}
		if store.IsConfirmPending() {
			t.Fatal("dirty bare commit must clear the pending window (#3861)")
		}
	})
}

func TestRESTCommitResponseWarnings16156(t *testing.T) {
	store := restHolderStore(t)
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			return &config.Config{Warnings: []string{"rest warning one", "rest warning two"}}, nil
		},
	}
	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
	s.configCommitHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("commit: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"rest warning one", "rest warning two"} {
		if !strings.Contains(body, want) {
			t.Fatalf("commit response missing warning %q; body: %s", want, body)
		}
	}
}
