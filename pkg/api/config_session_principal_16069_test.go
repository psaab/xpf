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

// #16069: a REST config-session token is bound to the principal that minted
// it. Principal A mints and stages; principal B — equally privileged (same
// login class) but a different identity — presents A's stolen token and must
// be denied on set, exit (release), commit, and re-enter, while A's own use
// still succeeds. Pre-fix the token alone was the holder identity, so every
// B operation below succeeded. Both principals share class "super" via
// distinct credential identities so the ONLY difference is the principal
// binding, not the login class or the store holder epoch.

func principalA16069() authz.Principal {
	return authz.Principal{Source: authz.SourceCredential, Username: "alice", Class: "ops"}
}

func principalB16069() authz.Principal {
	return authz.Principal{Source: authz.SourceCredential, Username: "bob", Class: "ops"}
}

func withPrincipal(req *http.Request, p authz.Principal) *http.Request {
	*req = *req.WithContext(context.WithValue(req.Context(), authorizedMutationPrincipalKey{}, p))
	return req
}

func enterAs(t *testing.T, s *Server, p authz.Principal) string {
	t.Helper()
	req := withPrincipal(httptest.NewRequest("POST", "/api/v1/config/enter", nil), p)
	rr := httptest.NewRecorder()
	s.configEnterHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enter as %s: status = %d, want 200; body: %s", p.Username, rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || !resp.Success || resp.Data.SessionID == "" {
		t.Fatalf("enter as %s: bad response %q err=%v", p.Username, rr.Body.String(), err)
	}
	return resp.Data.SessionID
}

func TestRESTConfigSessionBoundToPrincipal16069(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	commitCalled := false
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			commitCalled = true
			return store.Commit()
		},
	}
	a, b := principalA16069(), principalB16069()

	// A mints and stages an edit.
	tokenA := enterAs(t, s, a)
	setAs := func(p authz.Principal, token, input string) int {
		rr := httptest.NewRecorder()
		req := withPrincipal(httptest.NewRequest("POST", "/api/v1/config/set", strings.NewReader(`{"input":"`+input+`"}`)), p)
		req.Header.Set(restConfigSessionHeader, token)
		s.configSetHandler(rr, req)
		return rr.Code
	}
	if code := setAs(a, tokenA, "system host-name staged-by-a"); code != http.StatusOK {
		t.Fatalf("A set with own token: %d, want 200", code)
	}
	before := store.ShowCandidateSet()

	// B presents A's stolen token: set must be denied and candidate untouched.
	if code := setAs(b, tokenA, "system host-name stomped-by-b"); code != http.StatusForbidden {
		t.Fatalf("B set with A's token: %d, want 403", code)
	}
	if after := store.ShowCandidateSet(); after != before {
		t.Fatalf("B stolen-token set changed candidate:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// B re-enter with A's token: denied.
	rr := httptest.NewRecorder()
	req := withPrincipal(httptest.NewRequest("POST", "/api/v1/config/enter", nil), b)
	req.Header.Set(restConfigSessionHeader, tokenA)
	s.configEnterHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("B re-enter with A's token: %d, want 403; body: %s", rr.Code, rr.Body.String())
	}

	// B commit with A's token: denied, commit callback never runs.
	rr = httptest.NewRecorder()
	req = withPrincipal(httptest.NewRequest("POST", "/api/v1/config/commit", nil), b)
	req.Header.Set(restConfigSessionHeader, tokenA)
	s.configCommitHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("B commit with A's token: %d, want 403; body: %s", rr.Code, rr.Body.String())
	}
	if commitCalled {
		t.Fatal("B stolen-token commit invoked commit callback")
	}

	// B exit (release) with A's token: denied, lock still held by A.
	rr = httptest.NewRecorder()
	req = withPrincipal(httptest.NewRequest("POST", "/api/v1/config/exit", nil), b)
	req.Header.Set(restConfigSessionHeader, tokenA)
	s.configExitHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("B exit with A's token: %d, want 403; body: %s", rr.Code, rr.Body.String())
	}
	if !store.InConfigMode() {
		t.Fatal("B stolen-token exit released A's config lock")
	}

	// A re-enter (lease refresh) with own token: still allowed.
	rr = httptest.NewRecorder()
	req = withPrincipal(httptest.NewRequest("POST", "/api/v1/config/enter", nil), a)
	req.Header.Set(restConfigSessionHeader, tokenA)
	s.configEnterHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("A re-enter with own token: %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// A commit with own token: succeeds.
	rr = httptest.NewRecorder()
	req = withPrincipal(httptest.NewRequest("POST", "/api/v1/config/commit", nil), a)
	req.Header.Set(restConfigSessionHeader, tokenA)
	s.configCommitHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("A commit with own token: %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if !commitCalled {
		t.Fatal("A commit did not invoke commit callback")
	}

	// After A exits, the binding is gone: A can mint a fresh session and B
	// still cannot use that fresh token.
	rr = httptest.NewRecorder()
	req = withPrincipal(httptest.NewRequest("POST", "/api/v1/config/exit", nil), a)
	req.Header.Set(restConfigSessionHeader, tokenA)
	s.configExitHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("A exit with own token: %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	tokenA2 := enterAs(t, s, a)
	if code := setAs(b, tokenA2, "system host-name stomped-by-b2"); code != http.StatusForbidden {
		t.Fatalf("B set with A's fresh token: %d, want 403", code)
	}
	// Cleanup: A exits its second session.
	rr = httptest.NewRecorder()
	req = withPrincipal(httptest.NewRequest("POST", "/api/v1/config/exit", nil), a)
	req.Header.Set(restConfigSessionHeader, tokenA2)
	s.configExitHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("A exit second session: %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// TestRESTSessionUnbindIsGenerationChecked16069 is the deterministic
// fail-on-revert guard for the concurrent same-token re-entry race in the
// #16069 binding: Exit's store release and its binding erase used to be
// separate steps, so this interleaving was reachable —
//
//	Exit(old gen):  verify ok -> store.ExitConfigureSession releases ->
//	Re-enter:       EnterConfigureSession re-acquires -> bind(new gen) ->
//	Exit(old gen):  delete(sessionID)               <- erased the NEW mint
//
// after which the live holder's token had no binding and any other
// principal could use it. The fold makes bind/unbind generation-checked
// under restSessionsMu, held across the store holder transition. This
// test drives the unbind step directly with a stale (owner, epoch): it
// must refuse to erase a binding installed for a later generation, while
// still erasing the exact generation it released.
func TestRESTSessionUnbindIsGenerationChecked16069(t *testing.T) {
	s := &Server{}
	ownerA := restSessionBindingKey(principalA16069())
	ownerB := restSessionBindingKey(principalB16069())
	const token = testRESTConfigSessionID

	// Generation 1 mint (A), released by A's exit, then generation 2 mint
	// (B) restores a binding for the same token via re-entry.
	s.restSessionsMu.Lock()
	s.bindRESTSessionLocked(token, ownerA, 1)
	// Re-entered tenure: the binding a concurrent re-entry restored.
	s.bindRESTSessionLocked(token, ownerB, 2)
	s.restSessionsMu.Unlock()

	// The stale exit from generation 1 now attempts its erase. It observed
	// (ownerA, 1) before releasing; the live binding is (ownerB, 2).
	s.restSessionsMu.Lock()
	erased := s.unbindRESTSessionLocked(token, ownerA, 1)
	s.restSessionsMu.Unlock()
	if erased {
		t.Fatal("stale-generation unbind erased the re-entered binding (exit/re-entry race)")
	}
	if !s.verifyRESTSessionOwner(token, ownerB) {
		t.Fatal("re-entered generation-2 binding was lost to a stale exit")
	}
	if s.verifyRESTSessionOwner(token, ownerA) {
		t.Fatal("generation-1 owner can still use the token after generation-2 re-entry")
	}

	// The exact live generation still unbinds (normal exit path unchanged).
	s.restSessionsMu.Lock()
	erased = s.unbindRESTSessionLocked(token, ownerB, 2)
	s.restSessionsMu.Unlock()
	if !erased {
		t.Fatal("exact-generation unbind refused to erase the live binding")
	}
	if !s.verifyRESTSessionOwner(token, ownerA) {
		t.Fatal("after exact unbind the token should carry no binding (store-entered posture)")
	}
}
