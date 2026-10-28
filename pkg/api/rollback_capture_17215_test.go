package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

// #17215 (REST arm): a classed principal's GET /config/compare?rollback=N
// answered 200 "" both for a nonexistent slot and for "not in
// configuration mode" (resolved slot, no candidate), while uid 0 got
// 400 for both. The slot/mode errors now travel inside the gate's
// RollbackCapture, so every row below must agree between the classed
// (open-view, unrestricted) and uid-0 principals. Slot 1 with a
// candidate open is the positive control: identical diff for both.

const passwd17215REST = `root:x:0:0:root:/root:/bin/bash
openuser:x:4261:4261::/home/openuser:/bin/bash
`

const config17215REST = `
system {
    host-name host-a-17215;
    login {
        class open-view {
            permissions [ view configure ];
        }
        user openuser { class open-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "ZONE-DESC-17215";
            interfaces [ ge-0/0/0.0 ];
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func TestRESTCompareRollbackCapture17215(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd17215REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := authzStore(t, config17215REST)
	// Second commit so history holds exactly slot 1.
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(strings.Replace(config17215REST, "host-a-17215", "host-b-17215", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()

	_, baseOpen := authzServer(t, Config{Addr: "127.0.0.1:8080", Store: store, PeerLookupFn: fixedPeerUID(4261)})
	_, baseRoot := authzServer(t, Config{Addr: "127.0.0.1:8080", Store: store, PeerLookupFn: fixedPeerUID(0)})

	// No candidate open. The classed arm must carry the slot error
	// itself; uid 0's ungated store helper checks configuration mode
	// before slot resolution, so its missing-slot row spells the mode
	// error — both are 400, never the pre-fix classed 200 "".
	for _, tc := range []struct {
		route      string
		classedSub string
		rootSub    string
	}{
		{"/api/v1/config/compare?rollback=40", "out of range", "not in configuration mode"},
		{"/api/v1/config/compare?rollback=1", "not in configuration mode", "not in configuration mode"},
		{"/api/v1/config/show-rollback?n=40", "out of range", "out of range"},
	} {
		if code, body := get14707(t, baseOpen, tc.route); code != http.StatusBadRequest || !strings.Contains(body, tc.classedSub) {
			t.Errorf("no-candidate classed GET %s = %d %q, want 400 containing %q", tc.route, code, body, tc.classedSub)
		}
		if code, body := get14707(t, baseRoot, tc.route); code != http.StatusBadRequest || !strings.Contains(body, tc.rootSub) {
			t.Errorf("no-candidate uid0 GET %s = %d %q, want 400 containing %q", tc.route, code, body, tc.rootSub)
		}
	}
	// rollback=0 (candidate-vs-active) without a candidate stays the
	// documented 200 "" for both principals.
	for _, who := range []struct {
		name string
		base string
	}{{"classed", baseOpen}, {"uid0", baseRoot}} {
		if code, body := get14707(t, who.base, "/api/v1/config/compare"); code != http.StatusOK {
			t.Errorf("no-candidate %s GET /config/compare = %d, want 200: %s", who.name, code, body)
		}
	}
	// Show-rollback slot 1 renders for the classed principal.
	if code, body := get14707(t, baseOpen, "/api/v1/config/show-rollback?n=1"); code != http.StatusOK || !strings.Contains(body, "host-a-17215") {
		t.Errorf("classed show-rollback?n=1 = %d, want 200 with slot content: %s", code, body)
	}

	// Candidate open: missing slot still errors for both; slot 1
	// renders the identical diff for both.
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer store.ExitConfigure()
	if err := store.SetFromInput("system host-name candidate-17215"); err != nil {
		t.Fatal(err)
	}
	for _, who := range []struct {
		name string
		base string
	}{{"classed", baseOpen}, {"uid0", baseRoot}} {
		code, body := get14707(t, who.base, "/api/v1/config/compare?rollback=40")
		if code != http.StatusBadRequest || !strings.Contains(body, "out of range") {
			t.Errorf("candidate %s compare?rollback=40 = %d %q, want 400 out-of-range", who.name, code, body)
		}
	}
	_, bodyOpen := get14707(t, baseOpen, "/api/v1/config/compare?rollback=1")
	codeRoot, bodyRoot := get14707(t, baseRoot, "/api/v1/config/compare?rollback=1")
	if codeRoot != http.StatusOK || bodyOpen != bodyRoot || !strings.Contains(bodyOpen, "candidate-17215") {
		t.Errorf("candidate slot-1 compare mismatch: classed=%q uid0=(%d)%q", bodyOpen, codeRoot, bodyRoot)
	}
}
