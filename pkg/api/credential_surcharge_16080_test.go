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

// #16080 fold (1): the REST fast path bypassed the credential surcharge
// for a no-regex configure class. authorizeRESTConfigMutation /
// authorizeRESTConfigLoad / authorizeRESTConfigCommit14981 all returned
// nil at `if !restricted { return nil }` (restConfigClassRestricted saw
// no *-configuration regexes) before the shared AuthorizeConfigMutation
// decision was ever called, so `POST /api/v1/config/set` with
// `system root-authentication …` sailed through for exactly the limited
// class the issue names. restConfigClassRestricted now also reports the
// surcharge, routing such classes through the shared decision.
//
// RED-on-revert: dropping the CredentialSurchargeCheck16080 arm from
// restConfigClassRestricted makes every denied cell below return nil.

func restStore16080(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// A no-regex [view configure] class — no allow/deny-configuration.
	for _, line := range []string{
		"system login class limited permissions [ configure view ]",
		"system host-name base-16080",
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

func TestRESTCredentialSurchargeNoRegexClass16080(t *testing.T) {
	store := restStore16080(t)
	srv := &Server{store: store}
	cfg := store.ActiveConfig()
	p := authz.Principal{Class: "limited"}

	// Direct credential set, ancestor delete, and api-auth set are denied.
	for _, tc := range []struct{ route, body string }{
		{"/api/v1/config/set", `{"input":"system root-authentication plain-text-password hunter2-16080"}`},
		{"/api/v1/config/set", `{"input":"system login user eve class super-user"}`},
		{"/api/v1/config/set", `{"input":"system services web-management api-auth user admin password correct-horse-16080"}`},
		{"/api/v1/config/delete", `{"input":"system"}`},
		{"/api/v1/config/delete", `{"input":"system login"}`},
		{"/api/v1/config/deactivate", `{"input":"system services web-management"}`},
	} {
		r := httptest.NewRequest(http.MethodPost, tc.route, strings.NewReader(tc.body))
		if err := srv.authorizeRESTConfigMutation(r, cfg, p); err == nil {
			t.Errorf("REST %s %s ALLOWED for no-regex configure class; credential surcharge bypassed (#16080 fold 1)", tc.route, tc.body)
		}
	}
	// Non-credential control stays allowed.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/config/set", strings.NewReader(`{"input":"system host-name ok-16080"}`))
	if err := srv.authorizeRESTConfigMutation(r, cfg, p); err != nil {
		t.Fatalf("REST non-credential set refused for limited class: %v", err)
	}
	// Load carrying a credential line, and load override, are denied.
	loadBody := `{"mode":"merge","content":"set system root-authentication plain-text-password hunter2-16080"}`
	rLoad := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(loadBody))
	if err := srv.authorizeRESTConfigLoad(rLoad, cfg, p); err == nil {
		t.Error("REST load merge carrying a credential set ALLOWED (#16080 fold 1)")
	}
	overrideBody := `{"mode":"override","content":"set system host-name ok-16080"}`
	rOverride := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(overrideBody))
	if err := srv.authorizeRESTConfigLoad(rOverride, cfg, p); err == nil {
		t.Error("REST load override ALLOWED for no-regex configure class (#16080)")
	}
	okLoad := `{"mode":"merge","content":"set system host-name ok-16080"}`
	rOK := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(okLoad))
	if err := srv.authorizeRESTConfigLoad(rOK, cfg, p); err != nil {
		t.Fatalf("REST non-credential load refused: %v", err)
	}
	// Commit gate: an unrelated candidate commits; a credential one does not.
	if err := store.SetFromInput("system host-name staged-16080"); err != nil {
		t.Fatalf("stage host-name: %v", err)
	}
	rCommit := httptest.NewRequest(http.MethodPost, "/api/v1/config/commit", strings.NewReader("{}"))
	if err := srv.authorizeRESTConfigCommit14981(rCommit, cfg, p); err != nil {
		t.Fatalf("REST commit of unrelated candidate refused (fold 3): %v", err)
	}
	if err := store.SetFromInput("groups G system root-authentication plain-text-password hunter2-16080"); err != nil {
		t.Fatalf("stage group: %v", err)
	}
	if err := store.SetFromInput("apply-groups G"); err != nil {
		t.Fatalf("stage apply-groups: %v", err)
	}
	rCommit2 := httptest.NewRequest(http.MethodPost, "/api/v1/config/commit", strings.NewReader("{}"))
	if err := srv.authorizeRESTConfigCommit14981(rCommit2, cfg, p); err == nil {
		t.Error("REST commit of credential group candidate ALLOWED (#16080)")
	}
}
