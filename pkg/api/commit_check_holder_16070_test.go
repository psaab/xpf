package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// #16070, REST half: POST /config/commit-check must require the holder's
// X-Config-Session header, deny a non-holder with 409 before any compile
// diagnostics about another session's candidate can leak, admit the
// holder, and map the compile admission refusal to 429.
//
// FAIL-ON-REVERT: revert configCommitCheckHandler to ignoring the request
// and calling s.store.CommitCheck() and the non-holder case returns the
// holder's compile result with 200. Drop the ErrCommitCheckBusy arm from
// writeConfigMutationError and the busy case falls through to 400.

const testRESTIntruderSessionID = "rest-00000000000000000000000000000002"

func TestRESTCommitCheckHolderGate_16070(t *testing.T) {
	store := restHolderStore(t)
	s := &Server{store: store}

	// Missing session header: fails closed before the store is called,
	// so it can never reach the sessionID=="" internal bypass.
	rr := httptest.NewRecorder()
	s.configCommitCheckHandler(rr, httptest.NewRequest("POST", "/api/v1/config/commit-check", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("commit-check without session header: status = %d, want 400; body: %s", rr.Code, rr.Body.String())
	}

	// Non-holder: 409 Conflict, and the body carries no compile result.
	rr = httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit-check", nil), testRESTIntruderSessionID)
	s.configCommitCheckHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("commit-check as non-holder: status = %d, want 409; body: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "staged-by-rest") {
		t.Fatalf("non-holder commit-check leaked holder candidate data: %s", rr.Body.String())
	}

	// Holder: compiles its own candidate.
	rr = httptest.NewRecorder()
	req = withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit-check", nil), testRESTConfigSessionID)
	s.configCommitCheckHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("commit-check as holder: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRESTCommitCheckDiagnosticsStillReachHolder_16070(t *testing.T) {
	// Control: the holder still receives real compile diagnostics — a
	// candidate carrying the retired ebpf dataplane type is rejected
	// with its diagnostic, now under the holder's own session.
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigureSession(testRESTConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	if err := store.SetFromInputAs(testRESTConfigSessionID, "system dataplane-type ebpf"); err != nil {
		t.Fatalf("SetFromInputAs: %v", err)
	}
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit-check", nil), testRESTConfigSessionID)
	s.configCommitCheckHandler(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("holder commit-check on retired ebpf: status = %d, want 400 with retirement diagnostic; body: %s",
			rr.Code, rr.Body.String())
	}

	// The same diagnostic must NOT reach a non-holder.
	rr = httptest.NewRecorder()
	req = withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit-check", nil), testRESTIntruderSessionID)
	s.configCommitCheckHandler(rr, req)
	if rr.Code != http.StatusConflict || strings.Contains(rr.Body.String(), "legacy eBPF") {
		t.Fatalf("non-holder commit-check on retired ebpf: status = %d, want 409 without diagnostic; body: %s",
			rr.Code, rr.Body.String())
	}
}
