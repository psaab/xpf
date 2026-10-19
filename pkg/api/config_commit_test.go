package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// newAPIEBPFRejectStore stages a candidate with `system dataplane-type ebpf`
// so the commit/commit-check handlers can exercise the retirement-reject
// path. Prior to #1476 the same shape returned an EBPF deprecation
// warning; after the strict-validator landed this is a hard reject.
func newAPIEBPFRejectStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	// #14990: the commit handlers mint authority for the REST session in the
	// request header, so the candidate must be held by that session — an
	// unowned internal candidate is no longer committable by a named session.
	if err := store.EnterConfigureSession(testRESTConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession() error = %v", err)
	}
	if _, err := store.LoadSetAs(testRESTConfigSessionID, "set system dataplane-type ebpf"); err != nil {
		t.Fatalf("LoadSetAs() error = %v", err)
	}
	return store
}

// TestConfigCommitCheckHandlerRejectsRetiredEBPF asserts that
// `commit check` against a candidate carrying the retired
// `dataplane-type ebpf` returns the retirement-rejection error,
// not a success-with-warning response. Mirrors the DPDK reject
// pattern in pkg/config/parser_ast_test.go (#1526).
func TestConfigCommitCheckHandlerRejectsRetiredEBPF(t *testing.T) {
	s := &Server{store: newAPIEBPFRejectStore(t)}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/commit-check", nil)
	s.configCommitCheckHandler(rr, req)

	body := rr.Body.String()
	if rr.Code == 200 {
		var resp struct {
			Success bool `json:"success"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil && resp.Success {
			t.Fatalf("commit-check unexpectedly succeeded on retired ebpf type; body: %s", body)
		}
	}
	if !strings.Contains(body, "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("response missing eBPF retirement message; body: %s", body)
	}
}

// TestConfigCommitHandlerRejectsRetiredEBPF asserts that the commit
// path surfaces the retirement-reject error sentinel.
func TestConfigCommitHandlerRejectsRetiredEBPF(t *testing.T) {
	store := newAPIEBPFRejectStore(t)
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			return store.Commit()
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/commit", nil)
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configCommitHandler(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("response missing eBPF retirement message; body: %s", body)
	}
}

// TestConfigCommitConfirmedHandlerRejectsRetiredEBPF asserts that
// commit-confirmed surfaces the retirement-reject error too. The
// candidate must not enter the rollback-timer flow on a retired type.
func TestConfigCommitConfirmedHandlerRejectsRetiredEBPF(t *testing.T) {
	store := newAPIEBPFRejectStore(t)
	s := &Server{
		store: store,
		commitConfirmedFn: func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
			return store.CommitConfirmed(10)
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/commit-confirmed",
		strings.NewReader(`{"minutes":10}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configCommitConfirmedHandler(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("response missing eBPF retirement message; body: %s", body)
	}
}

// TestSentinelMatch documents that config.ErrEBPFDataplaneRetired is the
// sentinel propagated through Store.Commit() / Store.CommitCheck() for
// the retired EBPF type. Future API code that wraps the error should
// keep errors.Is() resolvable. The two API tests above match the
// verbatim message via Contains; this one is a sanity assertion on
// the sentinel chain.
func TestSentinelMatch(t *testing.T) {
	store := newAPIEBPFRejectStore(t)
	_, err := store.CommitCheck()
	if err == nil {
		t.Fatalf("CommitCheck unexpectedly succeeded on retired ebpf type")
	}
	if !errors.Is(err, config.ErrEBPFDataplaneRetired) {
		t.Fatalf("err = %v; want errors.Is(config.ErrEBPFDataplaneRetired)", err)
	}
}

// decodeConfigCommitResponse is kept for any successor test that
// needs to inspect a successful commit response shape after the
// rewrite.
func decodeConfigCommitResponse(t *testing.T, rr *httptest.ResponseRecorder) struct {
	Success bool                 `json:"success"`
	Data    configCommitResponse `json:"data"`
} {
	t.Helper()

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool                 `json:"success"`
		Data    configCommitResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body: %s", err, rr.Body.String())
	}
	return resp
}

func containsWarning(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}
