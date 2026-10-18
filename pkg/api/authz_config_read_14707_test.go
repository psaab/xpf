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

const uid14707REST = 4250

const passwd14707REST = `root:x:0:0:root:/root:/bin/bash
showuser:x:4250:4250::/home/showuser:/bin/bash
openuser:x:4251:4251::/home/openuser:/bin/bash
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
        user showuser {
            class limited-view;
        }
        user openuser {
            class open-view;
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
