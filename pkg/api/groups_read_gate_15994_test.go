package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

// #15994 fold (REST arm): the denied content lives ONLY as an applied
// group body. The directed read is refused (premise); every alias
// spelling must refuse, and the active-only routes must price the
// ACTIVE tree even when ?target=candidate is supplied (fold 4).

const uid15994REST = 4270

const passwd15994REST = `root:x:0:0:root:/root:/bin/bash
showuser:x:4270:4270::/home/showuser:/bin/bash
openuser:x:4271:4271::/home/openuser:/bin/bash
opuser:x:4280:4280::/home/opuser:/bin/bash
`

const groups15994RESTConfig = `
system {
    host-name groups-15994-rest;
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class op-view {
            permissions [ view configure ];
            deny-commands "^show configuration security";
        }
        class open-view {
            permissions [ view configure ];
        }
        user showuser { class limited-view; }
        user opuser { class op-view; }
        user openuser { class open-view; }
    }
}
groups {
    G {
        security {
            zones {
                security-zone trust {
                    description "GROUP-SEC-REST-15994";
                    interfaces [ ge-0/0/0.0 ];
                }
            }
        }
        system { host-name group-h-rest-15994; }
    }
}
apply-groups G;
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func TestRESTGroupsReadDenied15994(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd15994REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := authzStore(t, groups15994RESTConfig)
	// Second commit so rollback slot 1 holds the first config.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(strings.Replace(groups15994RESTConfig, "groups-15994-rest", "groups-15994-rest-b", 1)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Stage a candidate whose groups carry only ALLOWED content, so a
	// gate that wrongly priced the candidate on the active-only routes
	// would admit — the live bug this fold closes.
	if err := store.SetFromInput("security zones security-zone trust description CANDIDATE-ONLY-15994"); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}
	store.ExitConfigure()

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid15994REST),
	})

	// Premise: the directed read is refused.
	if code, _ := get14707(t, base, "/api/v1/config/show?path=security"); code != http.StatusForbidden {
		t.Fatalf("premise: GET ?path=security = %d, want 403", code)
	}

	for _, route := range []string{
		"/api/v1/config/show?path=groups+G+security",
		"/api/v1/config/show?path=groups",
		"/api/v1/config/show?path=groups+G",
		"/api/v1/config/show",
		"/api/v1/config/show?format=set",
		"/api/v1/config/export",
		"/api/v1/config/search?q=security-zone",
		"/api/v1/config",
		"/api/v1/config/compare",
		"/api/v1/config/show-rollback?n=1&path=groups+G",
		"/api/v1/config/show-rollback?n=1",
		"/api/v1/config/compare?rollback=1",
		"/api/v1/config/export?target=candidate",
		"/api/v1/config/search?target=candidate&q=security-zone",
		"/api/v1/config?target=candidate",
	} {
		code, body := get14707(t, base, route)
		if code != http.StatusForbidden {
			t.Errorf("GET %s returned %d, want 403 (#15994): %s", route, code, body)
		}
		if strings.Contains(body, "GROUP-SEC-REST-15994") {
			t.Errorf("GET %s disclosed the group-authored subtree: %s", route, body)
		}
	}

	// Controls stay admitted.
	for _, route := range []string{
		"/api/v1/config/show?path=groups+G+system",
		"/api/v1/config/show?path=system",
		"/api/v1/config/show-rollback?n=1&path=system",
		"/api/v1/config/show-rollback?n=1&path=groups+G+system",
	} {
		if code, body := get14707(t, base, route); code != http.StatusOK {
			t.Errorf("control GET %s returned %d, want 200: %s", route, code, body)
		}
	}
}

// Fold3: the typed GET /api/v1/config route is charged as bare
// `show configuration`; the whole-tree gate must still price the
// effective op commands when the tree carries groups-supplied
// content. An op-only class denying ^show configuration security
// must be refused; the open class still renders.
func TestRESTTypedConfigOpGroupDenied15994(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd15994REST), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
	store := authzStore(t, groups15994RESTConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4280),
	})
	code, body := get14707(t, base, "/api/v1/config")
	if code != http.StatusForbidden {
		t.Errorf("typed GET /api/v1/config returned %d, want 403 (#15994 fold3): %s", code, body)
	}
	if strings.Contains(body, "GROUP-SEC-REST-15994") {
		t.Errorf("typed GET disclosed the group-authored subtree: %s", body)
	}
	// Scoped comparison: /config/show of the same subtree refuses.
	if code, _ := get14707(t, base, "/api/v1/config/show?path=security"); code != http.StatusForbidden {
		t.Errorf("scoped show = %d, want 403 (comparison baseline)", code)
	}
	// Open class renders the typed config.
	_, baseOpen := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4271),
	})
	if code, _ := get14707(t, baseOpen, "/api/v1/config"); code != http.StatusOK {
		t.Errorf("open class typed GET = %d, want 200", code)
	}
}
