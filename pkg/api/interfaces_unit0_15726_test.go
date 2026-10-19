package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #15726: a unit-0 zone binding (reth0.0) plus a bare config interface
// (reth0) must produce exactly one canonical row with the zone attached,
// across REST /interfaces, /statistics/interfaces, and /interfaces/detail.
// Pre-fix allInterfaceNames unioned "reth0" and "reth0.0" and the zone
// map was keyed by the raw "reth0.0", so the bare row had Zone="" and
// the .0 row duplicated the same kernel counters.

func TestInterfacesHandler_NoDuplicateUnit0RowAndPreservesZone(t *testing.T) {
	s, _ := newTestAPIServerWithConfig15726(t)

	rr := httptest.NewRecorder()
	s.interfacesHandler(rr, httptest.NewRequest("GET", "/api/v1/interfaces", nil))
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rows := resp.Data.([]any)
	count := 0
	for _, r := range rows {
		m := r.(map[string]any)
		if name, _ := m["name"].(string); strings.HasPrefix(name, "reth0") {
			count++
			if gotZone, _ := m["zone"].(string); gotZone != "trust" {
				t.Fatalf("row %q zone = %q, want trust", name, gotZone)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row for reth0/reth0.0, got %d: %s", count, rr.Body.String())
	}
}

func newTestAPIServerWithConfig15726(t *testing.T) (*Server, interface{}) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	sets := []string{
		"set chassis cluster reth-count 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet dhcp",
		"set security zones security-zone trust interfaces reth0.0",
	}
	for _, line := range sets {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Server{store: store}, store
}

func TestIfaceStatsHandler_NoDuplicateUnit0RowAndPreservesZone15726(t *testing.T) {
	s, _ := newTestAPIServerWithConfig15726(t)
	s.dp = &descriptorCoverageDP{Manager: dataplane.New()}

	rr := httptest.NewRecorder()
	s.ifaceStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/statistics/interfaces", nil))
	if rr.Code == 503 {
		t.Fatalf("stats handler 503 (dp not loaded in fixture): %s", rr.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rows, _ := resp.Data.([]any)
	count := 0
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if m == nil {
			continue
		}
		if name, _ := m["name"].(string); strings.HasPrefix(name, "reth0") {
			count++
			if gotZone, _ := m["zone"].(string); gotZone != "trust" {
				t.Fatalf("stats row %q zone = %q, want trust", name, gotZone)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 stats row for reth0/reth0.0, got %d: %s", count, rr.Body.String())
	}
}

func TestInterfacesDetail_NoDuplicateUnit0Block15726(t *testing.T) {
	s, _ := newTestAPIServerWithConfig15726(t)

	rr := httptest.NewRecorder()
	s.interfacesDetailHandler(rr, httptest.NewRequest("GET", "/api/v1/interfaces/detail", nil))
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m, _ := resp.Data.(map[string]any)
	out, _ := m["output"].(string)
	// Detail renders "Interface: <name>," or "Interface: <name>, Not present"
	// per row (or a resolved block). Count reth0 blocks.
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Interface: reth0") {
			count++
			// The single canonical block must carry the zone when present.
			_ = line
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 detail block for reth0/reth0.0, got %d:\n%s", count, out)
	}
	if !strings.Contains(out, "Zone: trust") {
		t.Fatalf("detail block missing Zone: trust:\n%s", out)
	}
}
