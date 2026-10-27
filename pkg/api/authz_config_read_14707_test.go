package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// #14707 (REST twin): GET config-show routes rendered the whole
// secret-redacted tree for a class with deny-configuration "^security"
// (and ignored path/format-scoped deny-commands). The gRPC cells live in
// pkg/grpcapi/authz_config_read_14707_test.go; these drive the real REST
// listener so the wiring in authorizeRESTRead is bound, not just the
// shared decision in pkg/config.

const (
	uid14707REST     = 4250
	uid14707RESTSet  = 4252
	uid14707RESTPath = 4253
)

const passwd14707REST = `root:x:0:0:root:/root:/bin/bash
showuser:x:4250:4250::/home/showuser:/bin/bash
openuser:x:4251:4251::/home/openuser:/bin/bash
setfmtuser:x:4252:4252::/home/setfmtuser:/bin/bash
pathdenyuser:x:4253:4253::/home/pathdenyuser:/bin/bash
`

const config14707REST = `
system {
    host-name show-read-14707-rest;
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class open-view {
            permissions [ view configure ];
        }
        class setfmt-view {
            permissions [ view configure ];
            deny-commands "display set";
        }
        class pathdeny-view {
            permissions [ view configure ];
            deny-commands "^show configuration security";
        }
        user showuser {
            class limited-view;
        }
        user openuser {
            class open-view;
        }
        user setfmtuser {
            class setfmt-view;
        }
        user pathdenyuser {
            class pathdeny-view;
        }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC-14707";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func get14707(t *testing.T, base, path string) (int, string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRESTShowConfigDenyConfigurationConceals14707(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd14707REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := authzStore(t, config14707REST)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid14707REST),
	})

	for _, route := range []string{
		"/api/v1/config/show",
		"/api/v1/config/show?format=set",
		"/api/v1/config/export",
		"/api/v1/config/compare",
		"/api/v1/config/show-rollback?n=1",
		"/api/v1/config/search?q=security-zone",
		"/api/v1/config",
	} {
		code, body := get14707(t, base, route)
		if code != http.StatusForbidden {
			t.Errorf("GET %s returned %d, want 403 for deny-configuration ^security (#14707): %s", route, code, body)
		}
		if strings.Contains(body, "SECRET-TRUST-DESC-14707") || strings.Contains(body, "security-zone trust") {
			t.Errorf("GET %s disclosed the denied security subtree: %s", route, body)
		}
	}

	// Control: an unrestricted view+configure class reads the same routes.
	_, baseOpen := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4251),
	})
	code, body := get14707(t, baseOpen, "/api/v1/config/show")
	if code != http.StatusOK {
		t.Fatalf("control: unrestricted GET /config/show returned %d, want 200: %s", code, body)
	}
	if !strings.Contains(body, "security-zone") {
		t.Errorf("control: unrestricted show lost the security subtree: %s", body)
	}
}

// #17967 (residual of #17685/#17965): rollback snapshots discarded their
// slot error behind scoped authorization, so a restricted class got 403
// for a missing slot instead of the history error. Existing slot 1 is a
// control: its denied subtree must still be refused.
func TestRESTRollbackMissingSlotSlotErrorPrecedence17967(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd14707REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := authzStore(t, config14707REST)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure second commit: %v", err)
	}
	if err := store.LoadOverride(strings.Replace(config14707REST, "show-read-14707-rest", "show-read-14707-rest-b", 1)); err != nil {
		t.Fatalf("LoadOverride second commit: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	store.ExitConfigure()

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid14707REST),
	})
	for _, route := range []string{
		"/api/v1/config/show-rollback?n=40&path=security",
		"/api/v1/config/show-rollback?n=40",
		"/api/v1/config/show-rollback?n=40&path=security&format=set",
		"/api/v1/config/show-rollback?n=40&path=security&format=inheritance",
		"/api/v1/config/compare?rollback=40&path=security",
		"/api/v1/config/compare?rollback=40",
	} {
		code, body := get14707(t, base, route)
		if code != http.StatusBadRequest {
			t.Errorf("GET %s returned %d, want slot-error status 400: %s", route, code, body)
		}
		if !strings.Contains(body, "out of range") {
			t.Errorf("GET %s error = %s, want history out-of-range slot error (#17967)", route, body)
		}
		if strings.Contains(body, "permission denied") {
			t.Errorf("GET %s masked the slot error with scoped authorization: %s", route, body)
		}
	}
	for _, route := range []string{
		"/api/v1/config/show-rollback?n=1&path=security",
		"/api/v1/config/compare?rollback=1&path=security",
	} {
		code, body := get14707(t, base, route)
		if code != http.StatusForbidden || !strings.Contains(body, "permission denied") {
			t.Errorf("GET %s existing-slot control returned %d, %s; want scoped authorization 403", route, code, body)
		}
		if strings.Contains(body, "out of range") {
			t.Errorf("GET %s existing-slot control returned spurious slot error: %s", route, body)
		}
	}
	_, baseSet := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid14707RESTSet),
	})
	code, body := get14707(t, baseSet, "/api/v1/config/show-rollback?n=40&path=security&format=set")
	if code != http.StatusForbidden || !strings.Contains(body, "denies") || strings.Contains(body, "out of range") {
		t.Errorf("deny-commands display set must remain ahead of slot error: status=%d body=%s", code, body)
	}
	_, baseOpen := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4251),
	})
	for _, route := range []string{
		"/api/v1/config/show-rollback?n=1&path=system",
		"/api/v1/config/compare?rollback=1&path=system",
	} {
		code, body := get14707(t, baseOpen, route)
		if code != http.StatusOK || strings.Contains(body, "out of range") {
			t.Errorf("GET %s allowed-path control returned %d, %s", route, code, body)
		}
	}
	for _, route := range []string{
		"/api/v1/config/show-rollback?n=40&path=system",
		"/api/v1/config/compare?rollback=40&path=system",
	} {
		code, body := get14707(t, baseOpen, route)
		if code != http.StatusBadRequest || !strings.Contains(body, "out of range") || strings.Contains(body, "permission denied") {
			t.Errorf("GET %s allowed missing-slot result = %d, %s; want history out-of-range 400", route, code, body)
		}
	}
	// REST configCompareHandler ignores ?path= and renders the full
	// compare arms. The command-only missing-slot pre-check must match
	// that handler shape: a path-scoped deny cannot mask the missing
	// slot error for rollback=40, and an existing-slot compare with the
	// same ignored ?path= remains admitted.
	_, basePathDeny := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid14707RESTPath),
	})
	code, body = get14707(t, basePathDeny, "/api/v1/config/compare?rollback=40&path=security")
	if code != http.StatusBadRequest || !strings.Contains(body, "out of range") || strings.Contains(body, "permission denied") {
		t.Errorf("path-scoped command deny masked missing-slot compare through ignored ?path=: status=%d body=%s", code, body)
	}
	code, body = get14707(t, basePathDeny, "/api/v1/config/compare?rollback=1&path=security")
	if code != http.StatusOK || strings.Contains(body, "out of range") || strings.Contains(body, "permission denied") {
		t.Errorf("existing-slot compare must ignore ?path= like the handler: status=%d body=%s", code, body)
	}
}
