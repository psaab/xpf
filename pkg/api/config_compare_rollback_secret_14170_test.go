package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigCompareRollbackSecretOnly14170 pins #14170 on one public API:
// GET /api/v1/config/compare?rollback=1 where the rollback slot and candidate
// differ only in a secret must return a non-empty masked diff, not
// "[no changes]", and must not leak either secret value.
func TestConfigCompareRollbackSecretOnly14170(t *testing.T) {
	const (
		before = "API-ROLLBACK-SECRET-BEFORE-14170"
		after  = "API-ROLLBACK-SECRET-AFTER-14170"
	)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("security ike policy pol1 pre-shared-key ascii-text " + before); err != nil {
		t.Fatalf("SetFromInput before: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit before: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit identical: %v", err)
	}
	if err := store.SetFromInput("security ike policy pol1 pre-shared-key ascii-text " + after); err != nil {
		t.Fatalf("SetFromInput after: %v", err)
	}
	s := &Server{store: store}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config/compare?rollback=1", nil)
	s.configCompareHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "[no changes]") {
		t.Fatalf("secret-only rollback difference via REST rendered as no changes: %s", body)
	}
	resp := decodeResponse(t, body)
	if !resp.Success {
		t.Fatalf("success=false: %s", body)
	}
	// TextResponse wraps output in JSON; check raw body for leaks and markers.
	for _, secret := range []string{before, after} {
		if strings.Contains(body, secret) {
			t.Errorf("REST rollback compare exposed secret %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, "[secret fingerprint removed:") || !strings.Contains(body, "[secret fingerprint added:") {
		t.Errorf("REST rollback compare omitted fingerprint metadata: %s", body)
	}
	if !strings.Contains(body, "##SECRET-DATA##") {
		t.Errorf("REST rollback compare omitted constant mask: %s", body)
	}
}
