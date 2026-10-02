package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func TestRESTCommitConfirmedRejectsNegativeMinutes_11677(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name Candidate"); err != nil {
		t.Fatal(err)
	}
	called := false
	s := &Server{
		store: store,
		commitConfirmedFn: func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
			called = true
			return store.CommitConfirmed(-1)
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/commit-confirmed",
		strings.NewReader(`{"minutes":-1}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configCommitConfirmedHandler(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "non-negative") {
		t.Fatalf("negative timeout response = %d %s; want HTTP 400 identifying the invalid timeout",
			rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("REST handler invoked commitConfirmedFn for a negative timeout")
	}
	if !store.IsDirty() || store.IsConfirmPending() {
		t.Fatal("negative REST timeout changed the candidate or armed a confirm window")
	}
}
