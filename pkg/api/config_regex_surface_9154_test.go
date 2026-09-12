package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// #9154: THE REST SURFACE PERFORMED CONFIG MUTATIONS WITH NO `*-configuration`
// REGEX CHECK. `pkg/api/authz.go` and `pkg/api/config.go` had zero matches for
// `Regex`, so a class restricted from configuring a subtree was restricted only
// at the console.
//
// Reachability is not theoretical: for a LOCAL caller the login model is the
// only authority, so a user in a PermConfig class who is regex-restricted on
// the CLI and on gRPC could `curl -X POST /api/v1/config/set` unrestricted.

const uid9154 = 4247

const passwd9154 = `root:x:0:0:root:/root:/bin/bash
cfguser:x:4247:4247::/home/cfguser:/bin/bash
`

// The class holds `configure`, so the COARSE permission bits admit it — the
// regex is the only thing standing between this caller and the mutation. That
// is what makes the test measure the regex rather than the permission tier.
const config9154 = `
system {
    host-name authz-9154;
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "system root-authentication";
        }
        user cfguser {
            class limited;
        }
    }
}
`

func usePasswd9154(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd9154), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// enter9154 opens a REST config session and returns its id. A config mutation
// is addressed by the X-Config-Session header, so without this the control
// below fails on a 400 before the regex is ever consulted — which is exactly
// what it caught the first time this test was written.
func enter9154(t *testing.T, base string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/enter", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("config/enter: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config/enter returned %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Data struct {
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Data.SessionID == "" {
		t.Fatalf("config/enter gave no session id: %s", b)
	}
	return out.Data.SessionID
}

func post9154(t *testing.T, base, path, input, session string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"input": input})
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("X-Config-Session", session)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestConfigurationDenyIsEnforcedOverREST9154(t *testing.T) {
	usePasswd9154(t)
	store := authzStore(t, config9154)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid9154),
	})

	sess := enter9154(t, base)

	// POSITIVE CONTROL FIRST. An unrelated mutation must SUCCEED, or a 403
	// below could be the coarse permission tier refusing everything and the
	// regex would be untested.
	if code, body := post9154(t, base, "/api/v1/config/set", "system host-name fw9154", sess); code != http.StatusOK {
		t.Fatalf("control failed: an unrelated `set` returned %d, want 200 — this caller is "+
			"supposed to be able to configure: %s", code, body)
	}

	t.Run("set matching deny-configuration is refused", func(t *testing.T) {
		code, body := post9154(t, base, "/api/v1/config/set",
			"system root-authentication plain-text-password hunter2", sess)
		if code != http.StatusForbidden {
			t.Errorf("POST /api/v1/config/set returned %d, want 403 — a caller regex-restricted "+
				"on the CLI mutated the denied subtree over REST (#9154): %s", code, body)
		}
		// The path carries the operator's secret; the denial must not echo it.
		if bytes.Contains([]byte(body), []byte("hunter2")) {
			t.Errorf("the denial leaked the secret from the config path: %s", body)
		}
	})

	t.Run("delete matching deny-configuration is refused", func(t *testing.T) {
		code, body := post9154(t, base, "/api/v1/config/delete", "system root-authentication", sess)
		if code != http.StatusForbidden {
			t.Errorf("POST /api/v1/config/delete returned %d, want 403: %s", code, body)
		}
	})

	t.Run("an unrelated delete still works", func(t *testing.T) {
		// The narrowness control, in the other direction: over-denying here
		// would lock the operator out of the configuration they DO hold.
		if code, body := post9154(t, base, "/api/v1/config/delete", "system host-name", sess); code != http.StatusOK {
			t.Errorf("an unrelated `delete` returned %d, want 200: %s", code, body)
		}
	})
}

// postJSON9890 posts an arbitrary body, because annotate's path arrives in
// `path` and not in `input`. post9154 can only send `{"input": ...}`, and a
// cell built on it would send annotate an empty path — which the gate allows
// and the handler 400s, so the cell would pass for the wrong reason.
func postJSON9890(t *testing.T, base, path string, body map[string]string, session string) (int, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("X-Config-Session", session)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// #9890: the SAME denied subtree, reached by a different verb.
//
// The regexes are an authorization control over configuration mutation, so the
// denial must hold whatever verb carries the path. Before this, `deactivate`,
// `activate` and `annotate` were registered POST routes absent from the gate's
// route table — and the table's comment explained only why `load`, `commit` and
// `rollback` were absent, so the omission read as considered.
//
// `deactivate` is the one with teeth: an inactive node is excluded from
// compilation, so deactivating a denied subtree does not edit its contents, it
// REMOVES ITS ENFORCEMENT — and the next legitimate commit by anyone ships that
// removal.
func TestConfigurationDenyHoldsForEveryPathCarryingVerb9890(t *testing.T) {
	usePasswd9154(t)
	store := authzStore(t, config9154)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid9154),
	})
	sess := enter9154(t, base)

	// POSITIVE CONTROL FIRST, as in the #9154 cell above: an unrelated mutation
	// must SUCCEED, or every 403 below could be the coarse permission tier
	// refusing everything and the regex would be untested.
	if code, body := post9154(t, base, "/api/v1/config/set", "system host-name fw9890", sess); code != http.StatusOK {
		t.Fatalf("control failed: an unrelated `set` returned %d, want 200: %s", code, body)
	}

	for _, tc := range []struct {
		verb  string
		route string
	}{
		{"deactivate", "/api/v1/config/deactivate"},
		{"activate", "/api/v1/config/activate"},
	} {
		t.Run(tc.verb+" matching deny-configuration is refused", func(t *testing.T) {
			code, body := post9154(t, base, tc.route, "system root-authentication", sess)
			if code != http.StatusForbidden {
				t.Errorf("POST %s returned %d, want 403 — a caller regex-restricted on `set` "+
					"reached the denied subtree with `%s` (#9890): %s", tc.route, code, tc.verb, body)
			}
		})
		t.Run("an unrelated "+tc.verb+" still works", func(t *testing.T) {
			// Narrowness control: over-denying locks the operator out of the
			// configuration they DO hold, which is its own outage.
			if code, body := post9154(t, base, tc.route, "system host-name", sess); code != http.StatusOK {
				t.Errorf("an unrelated `%s` returned %d, want 200: %s", tc.verb, code, body)
			}
		})
	}

	t.Run("annotate matching deny-configuration is refused", func(t *testing.T) {
		code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
			"path":    "system root-authentication",
			"comment": "reviewed",
		}, sess)
		if code != http.StatusForbidden {
			t.Errorf("POST /api/v1/config/annotate returned %d, want 403 (#9890): %s", code, body)
		}
	})

	// The gate must read the field the HANDLER reads, and ONLY that field.
	//
	// This is the #9890 defect in the other direction, and it is the reason the
	// route declares its field instead of trying both: a gate that fell back
	// from `path` to `input` would adjudicate a string the store never acts on.
	// Here `input` carries a DENIED path while `path` is empty. The handler
	// reads `path`, finds it empty and reports its own arity error — so the
	// correct answer is 400, not 403. A 403 means the gate denied a request
	// over content the handler was never going to apply, which is the same
	// gate/handler disagreement that let annotate through ungated.
	t.Run("the gate does not adjudicate a field the handler ignores", func(t *testing.T) {
		code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
			"input":   "system root-authentication",
			"comment": "reviewed",
		}, sess)
		if code == http.StatusForbidden {
			t.Errorf("POST /api/v1/config/annotate returned 403 for a denied path in `input`, "+
				"which AnnotateRequest never reads — the gate and the handler disagree about "+
				"where the path lives (#9890): %s", body)
		}
		if code != http.StatusBadRequest {
			t.Errorf("POST /api/v1/config/annotate with an empty `path` returned %d, want 400 "+
				"from the handler's own arity check: %s", code, body)
		}
	})

	t.Run("an unrelated annotate still works", func(t *testing.T) {
		code, body := postJSON9890(t, base, "/api/v1/config/annotate", map[string]string{
			"path":    "system host-name",
			"comment": "reviewed",
		}, sess)
		if code != http.StatusOK {
			t.Errorf("an unrelated `annotate` returned %d, want 200: %s", code, body)
		}
	})
}
