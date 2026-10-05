package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestRESTConfigLoadRescueChangesOnlyCandidate11802(t *testing.T) {
	store := newAPIConfigStore(t)
	if _, err := store.LoadSet("set system host-name candidate-before-rescue"); err != nil {
		t.Fatal(err)
	}
	rescuePath := filepath.Join(filepath.Dir(store.ConfigPath()), configstore.RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte("system { host-name rescue-from-rest; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	activeBefore := store.ShowActiveSet()
	s := &Server{store: store}
	req := httptest.NewRequest("POST", "/api/v1/config/load", strings.NewReader(`{"mode":"rescue"}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	rr := httptest.NewRecorder()
	s.configLoadHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	candidate := store.ShowCandidateSet()
	if !strings.Contains(candidate, "host-name rescue-from-rest") || strings.Contains(candidate, "candidate-before-rescue") {
		t.Fatalf("REST rescue load did not replace candidate: %s", candidate)
	}
	if got := store.ShowActiveSet(); got != activeBefore {
		t.Fatalf("REST rescue load changed active config: before=%q after=%q", activeBefore, got)
	}
}

func TestRESTConfigLoadRescueRejectsContent11802(t *testing.T) {
	store := newAPIConfigStore(t)
	if _, err := store.LoadSet("set system host-name candidate-before-rescue"); err != nil {
		t.Fatal(err)
	}
	rescuePath := filepath.Join(filepath.Dir(store.ConfigPath()), configstore.RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte("system { host-name saved-rescue; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := store.ShowCandidateSet()
	req := httptest.NewRequest("POST", "/api/v1/config/load",
		strings.NewReader(`{"mode":"rescue","content":"system { host-name ignored; }"}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	rr := httptest.NewRecorder()
	(&Server{store: store}).configLoadHandler(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "does not accept content") {
		t.Fatalf("REST rescue request with content: status=%d body=%s, want 400 content rejection",
			rr.Code, rr.Body.String())
	}
	if got := store.ShowCandidateSet(); got != before {
		t.Fatalf("rejected REST rescue request changed candidate: before=%q after=%q", before, got)
	}
}
