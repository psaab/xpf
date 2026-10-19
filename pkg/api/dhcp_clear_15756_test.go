package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
)

// TestClearDHCPIdentifiersResolves15756 is the #15756 RED/GREEN cell for
// the REST surface: a scoped clear must delete the DUID persisted under
// the lease key for Junos spellings, and must refuse (deleting nothing)
// for unknown / non-DHCP names. Pre-fix the raw spelling reached
// ClearDUID: `ge-0/0/0` 400'd at the filename validator (file survives)
// and unknown/dotted names returned 200 with the actual file intact.
func TestClearDHCPIdentifiersResolves15756(t *testing.T) {
	st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := st.LoadMerge("interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } ge-0/0/3 { vlan-tagging; unit 7 { vlan-id 50; family inet6 { dhcpv6; } } } }"); err != nil {
		t.Fatalf("LoadMerge: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	newMgr := func(t *testing.T) (*dhcp.Manager, string) {
		t.Helper()
		dir := t.TempDir()
		mgr, err := dhcp.New(dir, nil, nil)
		if err != nil {
			t.Fatalf("dhcp.New: %v", err)
		}
		for _, key := range []string{"ge-0-0-0", "ge-0-0-3.50"} {
			if err := os.WriteFile(filepath.Join(dir, "dhcpv6-duid-"+key), []byte{0, 1}, 0o600); err != nil {
				t.Fatalf("seed DUID %s: %v", key, err)
			}
		}
		return mgr, dir
	}
	present := func(dir, key string) bool {
		_, err := os.Stat(filepath.Join(dir, "dhcpv6-duid-"+key))
		return err == nil
	}
	call := func(s *Server, iface string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/dhcp/identifiers/clear", strings.NewReader(`{"interface":"`+iface+`"}`))
		s.clearDHCPIdentifiersHandler(rr, req)
		return rr
	}

	mgr, dir := newMgr(t)
	rr := call(&Server{store: st, dhcp: mgr}, "ge-0/0/3.7")
	if rr.Code != 200 {
		t.Fatalf("clear ge-0/0/3.7 status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if present(dir, "ge-0-0-3.50") {
		t.Error("clear ge-0/0/3.7: DUID under lease key ge-0-0-3.50 survived")
	}
	if !present(dir, "ge-0-0-0") {
		t.Error("clear ge-0/0/3.7 deleted the unrelated ge-0-0-0 DUID")
	}

	for _, in := range []string{"ge-0/0/9"} {
		mgr, dir := newMgr(t)
		rr := call(&Server{store: st, dhcp: mgr}, in)
		if rr.Code != 400 {
			t.Errorf("clear %q status = %d, want 400; body: %s", in, rr.Code, rr.Body.String())
		}
		if !present(dir, "ge-0-0-0") || !present(dir, "ge-0-0-3.50") {
			t.Errorf("clear %q deleted a DUID despite refusing", in)
		}
	}
	// Lease-key-shaped but unconfigured names clear idempotently on the
	// exact key named, leaving other units' DUIDs untouched.
	mgr2, dir2 := newMgr(t)
	if rr := call(&Server{store: st, dhcp: mgr2}, "reth0.0"); rr.Code != 200 {
		t.Errorf("clear reth0.0 status = %d, want idempotent 200; body: %s", rr.Code, rr.Body.String())
	}
	if !present(dir2, "ge-0-0-0") || !present(dir2, "ge-0-0-3.50") {
		t.Error("clear reth0.0 deleted a different unit's DUID")
	}

	// No store: a lease-key-shaped name still clears idempotently; a
	// Junos spelling refuses rather than silently succeeding.
	mgr, dir = newMgr(t)
	if rr = call(&Server{dhcp: mgr}, "ge-0-0-0"); rr.Code != 200 {
		t.Errorf("no-store lease-key clear status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if present(dir, "ge-0-0-0") {
		t.Error("no-store lease-key clear left ge-0-0-0 DUID behind")
	}
	mgr, dir = newMgr(t)
	rr = call(&Server{dhcp: mgr}, "ge-0/0/0")
	if rr.Code != 400 {
		t.Errorf("no-store Junos clear status = %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
	if !present(dir, "ge-0-0-0") {
		t.Error("no-store Junos clear deleted the DUID despite refusing")
	}
}
