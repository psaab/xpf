package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

// #15942 H2-04 (REST arm): GET /config/show-rollback honoured ?path=
// in the handler but authorizeRESTConfigRead priced only the whole
// tree. A subtree-only allow was refused wholesale and a path-scoped
// deny never fired on the scoped render. The gate now prices ?path=.
//
// The fixture needs a second commit so rollback slot 1 exists; the
// classes are an allowlist class (allow-configuration "^interfaces")
// and a deny-commands class ("^show configuration security").
const config15942REST = `
system {
    host-name rollback-15942-rest;
    login {
        class allow-ifaces {
            permissions [ view configure ];
            allow-configuration "^interfaces";
        }
        class deny-sec-cmd {
            permissions [ view configure ];
            deny-commands "^show configuration security";
        }
        user ifaceuser { class allow-ifaces; }
        user denycmduser { class deny-sec-cmd; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC-15942";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

const passwd15942REST = `root:x:0:0:root:/root:/bin/bash
ifaceuser:x:4260:4260::/home/ifaceuser:/bin/bash
denycmduser:x:4261:4261::/home/denycmduser:/bin/bash
`

func TestRESTShowRollbackScopedPathGate15942(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd15942REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := authzStore(t, config15942REST)
	// Second commit so rollback slot 1 holds the first config.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(strings.Replace(config15942REST, "rollback-15942-rest", "rollback-15942-rest-b", 1)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()

	_, baseAllow := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4260),
	})
	// Allowlist class: scoped rollback into the allowed subtree renders.
	code, body := get14707(t, baseAllow, "/api/v1/config/show-rollback?n=1&path=interfaces")
	if code != http.StatusOK {
		t.Errorf("allowlist scoped rollback [interfaces] returned %d, want 200: %s", code, body)
	}
	if !strings.Contains(body, "ge-0/0/0") {
		t.Errorf("allowlist scoped rollback [interfaces] lost its subtree: %s", body)
	}
	// Scoped outside the allowlist: refused, nothing disclosed.
	code, body = get14707(t, baseAllow, "/api/v1/config/show-rollback?n=1&path=security")
	if code != http.StatusForbidden {
		t.Errorf("allowlist scoped rollback [security] returned %d, want 403: %s", code, body)
	}
	if strings.Contains(body, "SECRET-TRUST-DESC-15942") {
		t.Errorf("allowlist scoped rollback [security] disclosed denied content: %s", body)
	}
	// Whole-tree rollback stays refused for the allowlist class.
	if code, _ := get14707(t, baseAllow, "/api/v1/config/show-rollback?n=1"); code != http.StatusForbidden {
		t.Errorf("allowlist whole-tree rollback returned %d, want 403", code)
	}

	_, baseDenyCmd := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4261),
	})
	// Operational-only deny: the scoped security rollback is refused…
	code, body = get14707(t, baseDenyCmd, "/api/v1/config/show-rollback?n=1&path=security")
	if code != http.StatusForbidden {
		t.Errorf("deny-commands scoped rollback [security] returned %d, want 403: %s", code, body)
	}
	if strings.Contains(body, "SECRET-TRUST-DESC-15942") {
		t.Errorf("deny-commands scoped rollback [security] disclosed denied content: %s", body)
	}
	// …while a scope the deny does not name, and the whole tree, render.
	if code, _ := get14707(t, baseDenyCmd, "/api/v1/config/show-rollback?n=1&path=interfaces"); code != http.StatusOK {
		t.Errorf("deny-commands scoped rollback [interfaces] returned %d, want 200", code)
	}
	if code, _ := get14707(t, baseDenyCmd, "/api/v1/config/show-rollback?n=1"); code != http.StatusOK {
		t.Errorf("deny-commands whole-tree rollback returned %d, want 200", code)
	}
}
