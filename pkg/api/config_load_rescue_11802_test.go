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
