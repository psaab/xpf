package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

// #14710: REST annotate bypassed deny-configuration via tokenizer mismatch
// and lost plant-class attribution.
//
// Gate built "annotate "+TrimSpace(req.Path) and lexed it with the config
// lexer, which stops at non-ASCII/VT/FF whitespace (TokenError) or treats a
// quoted final token as the annotate comment. Handler splits with
// strings.Fields (unicode-aware) and acted on the fuller path. Fix: gate
// adjudicates exactly Fields(req.Path) joined by spaces plus a synthetic
// empty quoted comment; handler calls AnnotateAsPlantClass.

const config14710 = `
system {
    host-name authz-14710;
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "system login";
        }
        user cfguser {
            class limited;
        }
    }
}
event-options {
    policy p {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    "set system host-name stamped";
                }
            }
        }
    }
}
`

func TestRESTAnnotateDenyTokenizerMismatch14710(t *testing.T) {
	usePasswd9154(t)
	store := authzStore(t, config14710)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid9154),
	})
	sess := enter9154(t, base)

	// Controls: normal denied path already 403s, unrelated works.
	if code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
		"path": "system login", "comment": "reviewed",
	}, sess); code != http.StatusForbidden {
		t.Fatalf("control: normal denied annotate returned %d, want 403: %s", code, body)
	}
	if code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
		"path": "system host-name", "comment": "reviewed",
	}, sess); code != http.StatusOK {
		t.Fatalf("control: unrelated annotate returned %d, want 200: %s", code, body)
	}

	cases := []struct{ name, path string }{
		{"NBSP", "system\u00a0login"},
		{"VT", "system\vlogin"},
		{"FF", "system\flogin"},
		{"quoted leaf", `system "login"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
				"path": tc.path, "comment": "reviewed",
			}, sess)
			if code != http.StatusForbidden {
				t.Errorf("annotate path %q returned %d, want 403 (#14710): %s", tc.path, code, body)
			}
		})
	}

	// Narrowness: quoting an allowed leaf must still succeed. Fields keeps
	// the quote characters, so the handler looks up `"host-name"` literally
	// and fails — therefore the success control is the plain allowed path
	// already exercised above; a quoted allowed leaf is not a handler-
	// supported spelling and must not 403 (it 400s on path-not-found).
	if code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
		"path": `system "host-name"`, "comment": "reviewed",
	}, sess); code == http.StatusForbidden {
		t.Errorf("quoted allowed annotate returned 403, want non-403: %s", body)
	}
}

// Plant-class: annotate must forward the authenticated class.
// A pure annotate does not change an event policy's execution signature
// (writeNodeSignature9984 excludes plant-class and Annotation is not in
// Keys), so StampChangedEventPlantClasses does not rebind on annotation
// alone and no compiled PlantClass delta is observable for a pure annotate.
// The decisive handler-level observable is therefore: (1) annotate succeeds
// under a named non-superuser principal (mutationPlantClass is consulted —
// pre-fix it was never called, so a principal with no class also succeeded
// silently with superuser attribution), and (2) annotate with NO admitted
// principal now fails instead of planting with empty class. Cell (2) is RED
// pre-fix (AnnotateAs ignored the principal entirely) and GREEN post-fix.
func TestRESTAnnotateHandlerPlantClass14710(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigureSession(testRESTConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	// Seed an annotatable node.
	if err := store.SetFromInputAs(testRESTConfigSessionID, "system host-name fw14710"); err != nil {
		t.Fatalf("seed set: %v", err)
	}
	s := &Server{store: store}
	body, _ := json.Marshal(AnnotateRequest{Path: "system host-name", Comment: "reviewed14710"})

	// No admitted principal: must fail (plant class unavailable), not plant
	// with empty/superuser attribution.
	req := httptest.NewRequest("POST", "/api/v1/config/annotate", strings.NewReader(string(body)))
	req.Header.Set(restConfigSessionHeader, testRESTConfigSessionID)
	rr := httptest.NewRecorder()
	s.configAnnotateHandler(rr, req)
	if rr.Code == 200 {
		t.Fatalf("annotate without admitted principal returned 200, want failure (#14710 plant-class): %s", rr.Body.String())
	}
	if strings.Contains(store.ShowCandidate(), "reviewed14710") {
		t.Fatalf("annotation planted without plant class:\n%s", store.ShowCandidate())
	}

	// Named class principal: succeeds and applies.
	req2 := httptest.NewRequest("POST", "/api/v1/config/annotate", strings.NewReader(string(body)))
	withRESTConfigSession(req2, testRESTConfigSessionID)
	*req2 = *req2.WithContext(context.WithValue(req2.Context(), authorizedMutationPrincipalKey{}, authz.Principal{Class: "limited"}))
	rr2 := httptest.NewRecorder()
	s.configAnnotateHandler(rr2, req2)
	if rr2.Code != 200 {
		t.Fatalf("annotate as limited: %d %s", rr2.Code, rr2.Body.String())
	}
	if !strings.Contains(store.ShowCandidate(), "reviewed14710") {
		t.Fatalf("annotation not applied:\n%s", store.ShowCandidate())
	}
}
