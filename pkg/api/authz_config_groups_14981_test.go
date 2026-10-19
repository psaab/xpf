package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
)

// #14981: REST Set/Load/Commit must apply deny-configuration to
// groups/apply-groups expansion, like the gRPC interceptor.

func restStore14981(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	// Commit a login class denying root-authentication, then reopen a
	// candidate for the gated operations.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"system login class limited permissions [ configure view ]",
		`system login class limited deny-configuration "system root-authentication"`,
		"system host-name base14981",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("seed %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("re-enter configure: %v", err)
	}
	return s
}

func TestRESTCommitGroupInheritedDenied14981(t *testing.T) {
	store := restStore14981(t)
	for _, line := range []string{
		"groups G system root-authentication plain-text-password hunter2",
		"apply-groups G",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("seed candidate %q: %v", line, err)
		}
	}
	srv := &Server{store: store}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/config/commit", strings.NewReader("{}"))
	p := authz.Principal{Class: "limited"}
	if err := srv.authorizeRESTConfigCommit14981(r, store.ActiveConfig(), p); err == nil {
		t.Fatal("REST commit of group-inherited denied path was ALLOWED (#14981)")
	}
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/config/commit-confirmed", strings.NewReader("{}"))
	if err := srv.authorizeRESTConfigCommit14981(r2, store.ActiveConfig(), p); err == nil {
		t.Fatal("REST commit-confirmed of group-inherited denied path was ALLOWED (#14981)")
	}
}

func TestRESTLoadGroupInheritedDenied14981(t *testing.T) {
	store := restStore14981(t)
	srv := &Server{store: store}
	p := authz.Principal{Class: "limited"}
	body := `{"mode":"merge","content":"set groups G system root-authentication plain-text-password hunter2\nset apply-groups G"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(body))
	if err := srv.authorizeRESTConfigLoad(r, store.ActiveConfig(), p); err == nil {
		t.Fatal("REST load carrying a group-inherited denied path was ALLOWED (#14981)")
	}
	okBody := `{"mode":"merge","content":"set groups G system host-name ok14981\nset apply-groups G"}`
	rOK := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(okBody))
	if err := srv.authorizeRESTConfigLoad(rOK, store.ActiveConfig(), p); err != nil {
		t.Fatalf("REST load of an allowed group refused: %v", err)
	}
}
