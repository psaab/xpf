package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

// #15995 (A8-01, REST arm): deny-configuration "^security ipsec" was
// evaluated only on the requested ?path=, so GET /config/show?path=security
// rendered the denied ipsec descendant. The gate now prices every
// rendered descendant of the target (and rollback slot) tree.
// Scoped compare has no REST selector (whole-tree, refused for a
// restricted class — covered by the 14707 suite).

const uid15995REST = 4260

const passwd15995REST = `root:x:0:0:root:/root:/bin/bash
ancuser:x:4260:4260::/home/ancuser:/bin/bash
openuser:x:4261:4261::/home/openuser:/bin/bash
`

const config15995REST = `
system {
    host-name ancestor-15995-rest;
    login {
        class ancestor-view {
            permissions [ view configure ];
            deny-configuration "^security ipsec";
        }
        class open-view {
            permissions [ view configure ];
        }
        user ancuser { class ancestor-view; }
        user openuser { class open-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "ZONE-DESC-15995";
            interfaces [ ge-0/0/0.0 ];
        }
    }
    ipsec {
        vpn vpn1 { bind-interface st0.0; pre-shared-key ascii-text dummy15995; }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func TestRESTShowAncestorDeniedDescendant15995(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd15995REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := authzStore(t, config15995REST)
	// Second commit so rollback slot 1 holds the first config.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(strings.Replace(config15995REST, "ancestor-15995-rest", "ancestor-15995-rest-b", 1)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	// Stage a candidate so the ?target=candidate arm has a rendered
	// tree with the denied descendant (an idle candidate renders "").
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure candidate: %v", err)
	}
	defer store.ExitConfigure()
	if err := store.SetFromInput("security zones security-zone trust description CANDIDATE-15995"); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid15995REST),
	})

	denied := []string{
		"/api/v1/config/show?path=security",
		"/api/v1/config/show?path=security&format=set",
		"/api/v1/config/show?path=security&target=candidate",
		"/api/v1/config/show?path=security%20ipsec",
		"/api/v1/config/show-rollback?n=1&path=security",
		"/api/v1/config/show-rollback?n=0&path=security",
	}
	for _, route := range denied {
		code, body := get14707(t, base, route)
		if code != http.StatusForbidden {
			t.Errorf("GET %s returned %d, want 403 (renders denied ipsec descendant, #15995): %s", route, code, body)
		}
		if strings.Contains(body, "ipsec") || strings.Contains(body, "vpn1") {
			t.Errorf("GET %s disclosed the denied ipsec descendant: %s", route, body)
		}
	}

	allowed := []string{
		"/api/v1/config/show?path=security%20zones",
		"/api/v1/config/show?path=interfaces",
		"/api/v1/config/show-rollback?n=1&path=security%20zones",
	}
	for _, route := range allowed {
		code, body := get14707(t, base, route)
		if code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200 (no denied descendant): %s", route, code, body)
		}
	}
	// The allowed sibling actually renders its content.
	if code, body := get14707(t, base, "/api/v1/config/show?path=security%20zones"); code != http.StatusOK ||
		!strings.Contains(body, "ZONE-DESC-15995") {
		t.Errorf("GET zones sibling lost content (code=%d): %s", code, body)
	}

	// Unrestricted control reads the ancestor.
	_, baseOpen := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4261),
	})
	if code, body := get14707(t, baseOpen, "/api/v1/config/show?path=security"); code != http.StatusOK ||
		!strings.Contains(body, "ipsec") {
		t.Errorf("control: open-view GET ?path=security = %d, want 200 with ipsec: %s", code, body)
	}
}

// Fold 3 (3): HEAD reaches the GET handler through the mux, so HEAD
// must price as GET at the *-configuration gate. Pre-fix the gate
// switched on the raw method and HEAD skipped concealment entirely
// (status/Content-Length oracle: denied subtree answered 200).
func TestRESTHeadPricesAsGet15995(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd15995REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
	store := authzStore(t, config15995REST)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(strings.Replace(config15995REST, "ancestor-15995-rest", "ancestor-15995-rest-b", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid15995REST),
	})
	head := func(p string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodHead, base+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HEAD %s: %v", p, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, route := range []string{
		"/api/v1/config/show?path=security",
		"/api/v1/config/show",
		"/api/v1/config/show-rollback?n=1&path=security",
	} {
		if code := head(route); code != http.StatusForbidden {
			t.Errorf("HEAD %s = %d, want 403 (must price as GET, #15995 fold3-3)", route, code)
		}
	}
	if code := head("/api/v1/config/show?path=security%20zones"); code != http.StatusOK {
		t.Errorf("HEAD allowed sibling = %d, want 200", code)
	}
}
