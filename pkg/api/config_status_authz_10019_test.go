package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10019: REST GET /api/v1/config/status and gRPC GetConfigModeStatus return
// the identical three store facts (InConfigMode/Dirty/ConfirmPending). The
// cross-surface contract is PermView on both: this side was already correct,
// and these pins are the guard against a future tightening that would take a
// `show`-equivalent status read away from view-only consumers (and contradict
// TestReadRoutesAreAllViewTier_6660's deliberate all-reads-PermView policy).
// The gRPC twin is pinned in
// pkg/grpcapi/config_mode_status_authz_10019_test.go.

// TestConfigStatusRouteCostsView_10019 pins the REST gate price for the
// config-mode status facts.
//
// RED-on-revert (mutation-verified): moving the entry to PermConfig fails
// this test; see docs/log/10019.md.
func TestConfigStatusRouteCostsView_10019(t *testing.T) {
	perm, ok := restReadPermissions["GET /api/v1/config/status"]
	if !ok {
		t.Fatal("GET /api/v1/config/status has no entry in restReadPermissions — " +
			"readAuthz would serve it unguarded (#10019)")
	}
	if perm != config.PermView {
		t.Fatalf("GET /api/v1/config/status costs %v, want view (#10019: one tier "+
			"for identical facts across surfaces)", perm)
	}
}

// TestReadOnlyServedConfigStatus_10019 is the end-to-end served cell: a
// read-only principal GETs the status route through the production server
// and receives the three facts. It proves a view-only caller reaches the
// real handler through the production path; the table pin above covers
// the tier itself.
func TestReadOnlyServedConfigStatus_10019(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})

	code, body := get6660(t, base, "/api/v1/config/status")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/config/status as read-only returned %d, want 200 (#10019): %s",
			code, body)
	}
	for _, fact := range []string{"in_config_mode", "dirty", "confirm_pending"} {
		if !strings.Contains(body, fact) {
			t.Errorf("GET /api/v1/config/status body omits %q — the served call "+
				"did not return the three facts: %s", fact, body)
		}
	}
}
