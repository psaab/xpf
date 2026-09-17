package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

const testRESTConfigSessionID = "rest-00000000000000000000000000000001"

func withRESTConfigSession(req *http.Request, sessionID string) *http.Request {
	req.Header.Set(restConfigSessionHeader, sessionID)
	*req = *req.WithContext(context.WithValue(req.Context(), authorizedMutationPrincipalKey{}, authz.Principal{Superuser: true}))
	return req
}

func enterRESTConfigSession(t *testing.T, s *Server, sessionID string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/config/enter", nil)
	if sessionID != "" {
		withRESTConfigSession(req, sessionID)
	}
	rr := httptest.NewRecorder()
	s.configEnterHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("REST enter: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode REST enter response: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success || !validRESTConfigSessionID(resp.Data.SessionID) {
		t.Fatalf("REST enter returned invalid session identity: %q; body: %s",
			resp.Data.SessionID, rr.Body.String())
	}
	return resp.Data.SessionID
}

func exitRESTConfigSession(t *testing.T, s *Server, sessionID string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/exit", nil), sessionID)
	s.configExitHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("REST exit: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// TestRESTConfigSessionsAreMutuallyExcluded is the fail-on-revert guard for
// #6197. It obtains two independently issued REST identities, lets session A
// hold and edit the candidate, then proves session B cannot set or commit it.
// Reverting to a single shared valid holder identity (so A and B are no longer
// distinguished) makes both B operations succeed and turns this test RED.
func TestRESTConfigSessionsAreMutuallyExcluded(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	commitCalled := false
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			commitCalled = true
			return store.Commit()
		},
	}

	// Obtain B's server-issued identity, release it, then let independently
	// issued session A become the live holder.
	sessionB := enterRESTConfigSession(t, s, "")
	exitRESTConfigSession(t, s, sessionB)
	sessionA := enterRESTConfigSession(t, s, "")
	if sessionA == sessionB {
		t.Fatalf("independent REST enters shared session identity %q", sessionA)
	}
	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/enter", nil), sessionB)
	s.configEnterHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("REST B enter while A holds candidate: status = %d, want 409; body: %s",
			rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withRESTConfigSession(httptest.NewRequest("POST", "/api/v1/config/set",
		strings.NewReader(`{"input":"system host-name held-by-rest-a"}`)), sessionA)
	s.configSetHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("REST A set: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	before := store.ShowCandidateSet()

	rr = httptest.NewRecorder()
	req = withRESTConfigSession(httptest.NewRequest("POST", "/api/v1/config/set",
		strings.NewReader(`{"input":"system host-name stomped-by-rest-b"}`)), sessionB)
	s.configSetHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("REST B set while A holds candidate: status = %d, want 409; body: %s",
			rr.Code, rr.Body.String())
	}
	if after := store.ShowCandidateSet(); after != before {
		t.Fatalf("REST B set changed A's candidate:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	rr = httptest.NewRecorder()
	req = withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), sessionB)
	s.configCommitHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("REST B commit while A holds candidate: status = %d, want 409; body: %s",
			rr.Code, rr.Body.String())
	}
	if commitCalled {
		t.Fatal("REST B commit invoked commit callback while A held the candidate")
	}
}
