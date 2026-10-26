package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #17836: the bare (pre-buffer) pre-check in mutationAuthzGuard must not
// deny argument-scoped allow-commands grants on REST ping/traceroute.
// PR #17590 added authorizeRESTCommandBare, which ran the full
// EvaluateForms decision on the bare charge ("ping") before the body was
// buffered. A class with only `allow-commands "^ping 10\.98\."` therefore
// got a 403 for every REST ping/traceroute — including targets its allow
// explicitly permits — because the bare form can never match an
// argument-scoped allow, and "an allow is configured and this command
// does not match it" is a denial in EvaluateForms. Pass 2
// (authorizeRESTCommand, post-buffer) would have allowed it.
//
// These cells drive the real middleware (not authorizeRESTCommand
// directly, which is how the regression stayed invisible to the #16067
// tests) and pin both legs: argument-scoped allow reaches the handler,
// non-matching targets are still denied by pass 2; argument-free denies
// still deny in pass 1 before the body is read, argument-scoped denies
// deny in pass 2.

func guardRequest17836(t *testing.T, s *Server, path, body string) (*httptest.ResponseRecorder, *trackingReadCloser13249, *bool) {
	t.Helper()
	tracked := &trackingReadCloser13249{Reader: bytes.NewReader([]byte(body))}
	req := httptest.NewRequest(http.MethodPost, path, tracked)
	req.RemoteAddr = "198.51.100.10:54321"
	pending := &pendingPeer{
		done: make(chan struct{}),
		id:   authz.PeerIdentity{OK: true, Local: true, UID: 4242},
	}
	close(pending.done)
	req = req.WithContext(context.WithValue(req.Context(), peerIdentityKey{}, pending))
	rec := httptest.NewRecorder()
	ran := false
	s.mutationAuthzGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	return rec, tracked, &ran
}

func guardServer17836(t *testing.T, classBody string) *Server {
	t.Helper()
	usePasswdFixture(t)
	cfgText := `
system {
    host-name authz-17836;
    login {
        class limited {
            permissions [ view ];
` + classBody + `
        }
        user opsuser {
            class limited;
        }
    }
}
`
	store := authzStore(t, cfgText)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
	})
	if _, ok, err := config.OperationalLoginRegexesFor(store.ActiveConfig(), "limited"); err != nil || !ok {
		t.Fatalf("fixture premise: limited must carry operational regexes (ok=%v err=%v)", ok, err)
	}
	return s
}

func TestMutationGuardArgumentScopedAllowPingTraceroute17836(t *testing.T) {
	s := guardServer17836(t, `            allow-commands "^ping 10\\.98\\.|^traceroute 10\\.98\\.";`)

	for _, tc := range []struct {
		name, path, body string
		wantStatus       int
		wantHandler      bool
	}{
		{"ping allowed target", "/api/v1/diagnostics/ping", `{"target":"10.98.1.1"}`, http.StatusOK, true},
		{"traceroute allowed target", "/api/v1/diagnostics/traceroute", `{"target":"10.98.1.1"}`, http.StatusOK, true},
		// Control: pass 2 must still deny a target the argument-scoped
		// allow does not name. If pass 1 deferred and pass 2 were broken,
		// this would reach the handler.
		{"ping non-matching target denied by pass 2", "/api/v1/diagnostics/ping", `{"target":"10.99.1.1"}`, http.StatusForbidden, false},
		{"traceroute non-matching target denied by pass 2", "/api/v1/diagnostics/traceroute", `{"target":"10.99.1.1"}`, http.StatusForbidden, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, _, ran := guardRequest17836(t, s, tc.path, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s -> %d, want %d (body=%s); argument-scoped allow must survive the bare pre-check (#17836)",
					tc.path, tc.body, rec.Code, tc.wantStatus, rec.Body.String())
			}
			if *ran != tc.wantHandler {
				t.Fatalf("%s %s handler ran=%v, want %v", tc.path, tc.body, *ran, tc.wantHandler)
			}
		})
	}
}

func TestMutationGuardBareDenyStillPreBuffer17836(t *testing.T) {
	// Control: an argument-free deny must still fire in pass 1, before
	// the body is read (#13249 availability property must not regress).
	s := guardServer17836(t, `            deny-commands "^ping$";`)
	rec, tracked, ran := guardRequest17836(t, s, "/api/v1/diagnostics/ping", `{"target":"192.0.2.1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bare deny ping -> %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if *ran {
		t.Fatal("handler ran for a bare-denied ping")
	}
	if tracked.reads != 0 {
		t.Fatalf("mutation guard read the body %d time(s) before denying the bare command; #13249 pre-buffer deny regressed", tracked.reads)
	}
}

func TestMutationGuardArgumentScopedDenyStillDenies17836(t *testing.T) {
	// Control: an argument-scoped deny must still deny via pass 2.
	s := guardServer17836(t, `            deny-commands "^ping 10\\.99\\.";`)
	rec, _, ran := guardRequest17836(t, s, "/api/v1/diagnostics/ping", `{"target":"10.99.1.1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("argument-scoped deny ping 10.99.1.1 -> %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if *ran {
		t.Fatal("handler ran for an argument-scoped-denied ping")
	}
	// And a target the deny does not name must pass (deny-only class).
	rec, _, ran = guardRequest17836(t, s, "/api/v1/diagnostics/ping", `{"target":"10.98.1.1"}`)
	if rec.Code != http.StatusOK || !*ran {
		t.Fatalf("deny-only class, unnamed target -> %d ran=%v, want 200/true (body=%s)", rec.Code, *ran, rec.Body.String())
	}
}

func TestMutationGuardDenyWithArgumentScopedException17836(t *testing.T) {
	// Deny-with-exceptions: bare deny + argument-scoped allow exception.
	// The exception target must run; other targets must deny.
	s := guardServer17836(t, "            deny-commands \"^ping$\";\n            allow-commands \"^ping 10\\.98\\.1\\.1$\";")
	rec, _, ran := guardRequest17836(t, s, "/api/v1/diagnostics/ping", `{"target":"10.98.1.1"}`)
	if rec.Code != http.StatusOK || !*ran {
		t.Fatalf("exception target -> %d ran=%v, want 200/true (body=%s)", rec.Code, *ran, rec.Body.String())
	}
	rec, _, ran = guardRequest17836(t, s, "/api/v1/diagnostics/ping", `{"target":"10.98.1.2"}`)
	if rec.Code != http.StatusForbidden || *ran {
		t.Fatalf("non-exception target -> %d ran=%v, want 403/false (body=%s)", rec.Code, *ran, rec.Body.String())
	}
}
