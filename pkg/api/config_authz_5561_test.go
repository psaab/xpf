package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// config_authz_5561_test.go is the fail-on-revert gate for #5561: the REST
// mutation surface must refuse a caller it cannot authorize, and must keep
// serving one it can.
//
// Every case drives real HTTP over a real loopback listener through a server
// built by the PRODUCTION constructor (buildHTTPServer), so the ConnContext
// plumbing that carries the connection's identity into the request is on the
// tested path rather than reconstructed by the test. Only the peer-UID
// resolution itself is injected (Config.PeerLookupFn), so a case can choose which
// principal is calling instead of testing whichever account runs the suite; the
// kernel lookup behind it is covered against live sockets in pkg/authz, and
// TestProductionServerEnforcesRealPeerIdentity_5561 below closes the loop with
// no injection at all.

const (
	authzUIDReadOnly  = 4242
	authzUIDSuperuser = 4243
	authzUIDStranger  = 4244 // a real OS account that is not a `system login user`
)

// authzTestConfig is the active config every case is evaluated against: two
// provisioned login users with different classes, so a denial can be attributed
// to the CLASS rather than to the absence of a config.
const authzTestConfig = `
system {
    host-name authz-test;
    login {
        user opsuser {
            class read-only;
        }
        user adminuser {
            class super-user;
        }
    }
}
`

// authzPasswdFixture maps the UIDs above to account names. It replaces
// /etc/passwd for the duration of a case so the resolution path runs for real
// against identities the test controls.
const authzPasswdFixture = `root:x:0:0:root:/root:/bin/bash
opsuser:x:4242:4242::/home/opsuser:/bin/bash
adminuser:x:4243:4243::/home/adminuser:/bin/bash
stranger:x:4244:4244::/home/stranger:/bin/bash
`

// authzServer stands up a Server over a real listener and returns its base URL.
// peerUID/peerErr are what the injected resolver reports for every connection.
func authzServer(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	s := NewServer(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// buildHTTPServer is the production path: it installs listenerHandler
	// (cross-site guard -> authz guard -> mux) AND the ConnContext hook.
	srv := s.buildHTTPServer(ln.Addr().String(), s.newAuthSlot())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		// Close shuts the listener and every active connection, which unparks a
		// request still reading its caller's body — but it does NOT join the
		// handler, so the gate's counters can still be non-zero after this
		// returns. Wait for them here (#6645 r22, finding 2): the counters are
		// process-global and waitForMutationBodyWaiter accepts any value above
		// zero, so a case that leaves a request parked hands the next case a
		// waiter that is not its own. Waiting at the leaking case's own cleanup
		// also puts the failure on the case that leaked rather than on whichever
		// innocent one -shuffle happened to run next.
		waitForGateQuiescent(t)
	})
	return s, "http://" + ln.Addr().String()
}

// authzStore returns a store whose ACTIVE config is `text`, committed through
// the real configure/load/commit path so the login model the gate reads is a
// genuinely compiled one.
func authzStore(t *testing.T, text string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("store has no active config after commit")
	}
	return store
}

// usePasswdFixture points the UID resolver at authzPasswdFixture.
func usePasswdFixture(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(authzPasswdFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// fixedPeerUID builds a resolver that attributes every connection to uid.
func fixedPeerUID(uid uint32) func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{UID: uid, OK: true, Local: true}
	}
}

// unattributableLocalPeer builds a resolver reporting a caller that IS on this
// host but could not be attributed — a half-closed socket, a TIME_WAIT row, or
// an unreadable socket table. It must DENY, never reach the credential.
func unattributableLocalPeer() func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{Local: true, Detail: "test: socket not established"}
	}
}

// remotePeer builds a resolver reporting a caller that is NOT on this host —
// the only case in which an api-auth credential may speak for it.
func remotePeer() func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{Detail: "test: peer is not on this host"}
	}
}

// remoteLocality restates remotePeer's premise for the re-derivation the
// credential row performs (Server.peerIsLocalNow). A case that fabricates an
// off-box caller over a real LOOPBACK listener has to say so in both places:
// the production re-check enumerates the host's real interfaces and would,
// correctly, call 127.0.0.1 one of ours and deny. Omitting it is what
// TestBrandNewLocalAddressCannotBorrowCredential_5561 exploits deliberately.
func remoteLocality() func(client, server net.Addr) bool {
	return func(net.Addr, net.Addr) bool { return false }
}

// postRoute issues a mutating request against a route key ("POST /path"),
// returning the status and the decoded `error` field.
func postRoute(t *testing.T, base, route string, hdrs map[string]string) (int, string) {
	t.Helper()
	method, path, ok := strings.Cut(route, " ")
	if !ok {
		t.Fatalf("malformed route key %q", route)
	}
	req, err := http.NewRequest(method, base+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: %v", route, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var r Response
	_ = json.Unmarshal(body, &r)
	return resp.StatusCode, r.Error
}

// enterConfigure opens a configure session over the guarded route and returns
// the session token the subsequent mutation must carry.
func enterConfigure(t *testing.T, base string, hdrs ...map[string]string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/enter", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, h := range hdrs {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config/enter refused an authorized principal: %d %s", resp.StatusCode, raw)
	}
	var r struct {
		Data struct {
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode config/enter response %s: %v", raw, err)
	}
	if r.Data.SessionID == "" {
		t.Fatalf("config/enter returned no session id: %s", raw)
	}
	return r.Data.SessionID
}

// TestEveryMutatingRouteRefusesWithoutPrincipal_5561 is the primary gate: with
// no establishable peer identity and no api-auth credential, EVERY route in the
// mutation table is refused — not just config/set, load and commit.
//
// On master every one of these returns something other than 403: the request
// reaches its handler and, for the config family, mutates and commits.
func TestEveryMutatingRouteRefusesWithoutPrincipal_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})

	routes := sortedRouteKeys()
	if len(routes) == 0 {
		t.Fatal("mutation permission table is empty")
	}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			status, errMsg := postRoute(t, base, route, nil)
			if status != http.StatusForbidden {
				t.Fatalf("%s returned %d for a caller with NO server-derived identity — "+
					"an unauthenticated local process reached the handler (error=%q)",
					route, status, errMsg)
			}
			if !strings.Contains(errMsg, "could not establish who is calling") {
				t.Errorf("%s denial did not name the missing identity: %q", route, errMsg)
			}
		})
	}
}

// TestClassGatesMutationPerPermission_5561 proves the gate is per-permission
// rather than a blanket refusal: the SAME caller, on the SAME connection, is
// refused the configure- and maintenance-tier routes its `read-only` class does
// not hold, and admitted to the view-tier ones it does.
func TestClassGatesMutationPerPermission_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})

	for _, route := range sortedRouteKeys() {
		required := restMutationPermissions[route]
		wantAllowed := required == config.PermView // read-only holds PermView only
		t.Run(route, func(t *testing.T) {
			status, errMsg := postRoute(t, base, route, nil)
			if wantAllowed && status == http.StatusForbidden {
				t.Fatalf("%s (requires %s) refused a read-only principal that HOLDS that "+
					"permission: %q", route, authz.PermissionName(required), errMsg)
			}
			if !wantAllowed && status != http.StatusForbidden {
				t.Fatalf("%s (requires %s) admitted a read-only principal with %d — the "+
					"CLI RBAC boundary is still bypassable over REST",
					route, authz.PermissionName(required), status)
			}
			if !wantAllowed && !strings.Contains(errMsg, "lacks the") {
				t.Errorf("%s denial did not name the missing permission: %q", route, errMsg)
			}
		})
	}
}

// TestAuthorizedPrincipalStillMutatesConfig_5561 is the negative control: a
// principal whose login class holds `configure` reaches the handlers and the
// candidate configuration ACTUALLY changes. A gate that refuses everyone would
// pass every assertion above and fail here.
func TestAuthorizedPrincipalStillMutatesConfig_5561(t *testing.T) {
	usePasswdFixture(t)
	for _, tc := range []struct {
		name string
		uid  uint32
	}{
		{"super-user login class", authzUIDSuperuser},
		{"root", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := authzStore(t, authzTestConfig)
			_, base := authzServer(t, Config{
				Addr:         "127.0.0.1:8080",
				Store:        store,
				PeerLookupFn: fixedPeerUID(tc.uid),
			})

			session := enterConfigure(t, base)

			// Drive a real mutation through the guarded route.
			body := strings.NewReader(`{"input":"set system host-name authorized-write"}`)
			req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/set", body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(restConfigSessionHeader, session)
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("config/set refused an authorized principal: %d %s", resp.StatusCode, raw)
			}
			if candidate := store.ShowCandidate(); !strings.Contains(candidate, "authorized-write") {
				t.Fatalf("config/set returned 200 but the candidate does not carry the edit:\n%s", candidate)
			}
		})
	}
}

// TestReadOnlyEndpointsUnaffected_5561 pins the blast radius of the MUTATION
// gate on the read surface: with no establishable principal at all, the health
// and metrics endpoints behave exactly as before. The gate must not have turned
// a monitoring endpoint into a 403.
//
// #6660 NARROWED THIS TEST, and the narrowing is the point rather than a
// concession. When #5561 shipped, "the read surface is unaffected" was the whole
// truth, because reads were not authorized at all — which is precisely the gap
// #6660 closes. The /api/v1 GETs that used to be listed here are now REFUSED for
// an unattributable caller, and TestUnattributableCallerIsDeniedReads_6660 pins
// that in the opposite direction.
//
// What survives here is the half that must NEVER change: /health and /metrics
// carry no configuration, are exempt in authCheck, and are read by the in-tree
// incus harnesses. A gate that took them down would break monitoring on every
// box, which is the failure this test exists to catch.
func TestReadOnlyEndpointsUnaffected_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})

	for _, path := range []string{
		"/health",
		"/metrics",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("GET %s returned 403 — an unauthenticated monitoring endpoint is refusing "+
					"traffic; /health and /metrics must stay open (#6660): %s", path, body)
			}
		})
	}
}

// TestUnknownMutatingRouteFailsClosed_5561 covers the scope note: a
// state-changing request that no table entry governs is DENIED, so a future
// route registered without a permission is inert rather than unguarded.
func TestUnknownMutatingRouteFailsClosed_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(0), // even ROOT is refused an ungoverned route
	})

	for _, route := range []string{
		"POST /api/v1/config/some-future-verb",
		"DELETE /api/v1/config/set",
		"PUT /api/v1/system/action",
		// A non-canonical spelling of a guarded route must not slip past the
		// exact-match table into the mux's redirect.
		"POST /api/v1/config//set",
	} {
		t.Run(route, func(t *testing.T) {
			status, errMsg := postRoute(t, base, route, nil)
			if status != http.StatusForbidden {
				t.Fatalf("%s returned %d, want 403: an ungoverned mutating request must "+
					"fail closed (error=%q)", route, status, errMsg)
			}
		})
	}
}

// TestViewScopedAPICredential_10826 covers the remote api-auth identity and its
// effective permission scope. Possession is still required off-box, but the key
// now resolves to its configured login class rather than a superuser.
func TestViewScopedAPICredential_10826(t *testing.T) {
	usePasswdFixture(t)
	key, err := config.HashAPIAuthSecret("0123456789abcdef-view-key")
	if err != nil {
		t.Fatal(err)
	}
	auth := &AuthConfig{
		APIKeys:       map[string]bool{key: true},
		APIKeyNames:   map[string]string{key: "view-automation"},
		APIKeyClasses: map[string]string{key: "read-only"},
		APIKeyExpires: map[string]time.Time{key: time.Now().Add(time.Hour)},
	}
	headers := map[string]string{"X-API-Key": "0123456789abcdef-view-key"}
	store := authzStore(t, authzTestConfig)
	session := "rest-" + strings.Repeat("0", 32)
	if err := store.EnterConfigureSession(session); err != nil {
		t.Fatalf("enter test config session: %v", err)
	}
	t.Cleanup(func() { store.ExitConfigureSession(session) })
	_, base := authzServer(t, Config{
		Addr:           "127.0.0.1:8080",
		Store:          store,
		Auth:           auth,
		PeerLookupFn:   remotePeer(),
		PeerLocalityFn: remoteLocality(),
	})

	req, err := http.NewRequest(http.MethodGet, base+"/api/v1/config", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", headers["X-API-Key"])
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("view-scoped API key could not read config: %d", resp.StatusCode)
	}

	for _, tc := range []struct {
		route string
		body  string
	}{
		{"POST /api/v1/config/set", `{"input":"set system host-name view-key-write"}`},
		{"POST /api/v1/system/action", `{"action":"clear-config-lock"}`},
	} {
		t.Run(tc.route, func(t *testing.T) {
			method, path, ok := strings.Cut(tc.route, " ")
			if !ok {
				t.Fatalf("malformed route %q", tc.route)
			}
			req, err := http.NewRequest(method, base+path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", headers["X-API-Key"])
			req.Header.Set(restConfigSessionHeader, session)
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s admitted a view-scoped API key with %d; want 403: %s",
					tc.route, resp.StatusCode, raw)
			}
		})
	}
}

func TestAPIAuthCredentialStillRequiresAValidCredential_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	t.Run("credential authorizes only a view-scoped remote read", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:           "127.0.0.1:8080",
			Store:          authzStore(t, authzTestConfig),
			Auth:           auth,
			PeerLookupFn:   remotePeer(),
			PeerLocalityFn: remoteLocality(),
		})
		req, err := http.NewRequest(http.MethodGet, base+"/api/v1/config", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", basic)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a valid api-auth credential was refused for a view read: %d", resp.StatusCode)
		}
	})

	t.Run("without the credential the same remote caller is refused", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:           "127.0.0.1:8080",
			Store:          authzStore(t, authzTestConfig),
			Auth:           auth,
			PeerLookupFn:   remotePeer(),
			PeerLocalityFn: remoteLocality(),
		})
		status, _ := postRoute(t, base, "POST /api/v1/config/enter", nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("an uncredentialed remote caller got %d, want 401", status)
		}
	})

	t.Run("peer identity outranks the credential", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
		})
		status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
			map[string]string{"Authorization": basic})
		if status != http.StatusForbidden {
			t.Fatalf("a read-only peer holding the api-auth secret was admitted with %d, want 403", status)
		}
		if !strings.Contains(errMsg, "opsuser") {
			t.Errorf("denial did not attribute the read-only account: %q", errMsg)
		}
	})
}

// TestAttributedLocalCallerOutsideLoginModelIsDenied_5561 pins row (2) of the
// precedence table, and is the MAJOR-A guard.
//
// An earlier version denied an UNATTRIBUTABLE local caller but still let an
// api-auth credential speak for an ATTRIBUTED one that was not a configured
// `system login user`. That is exactly the population #5561 exists to constrain:
// it made the per-principal gate optional for anyone holding the shared
// password, and it contradicted docs/system-login.md, which already said such a
// caller is denied.
//
// The rule is now: a caller on this host is governed by the login model and
// nothing else. If a local account needs access, it gets a class — that is the
// one place access is supposed to be written down.
func TestAttributedLocalCallerOutsideLoginModelIsDenied_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	t.Run("attributed local account outside the login model is refused", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:  "127.0.0.1:8080",
			Store: authzStore(t, authzTestConfig),
			Auth:  auth,
			// A REAL OS account (uid 4244 = "stranger") that carries no
			// `system login user` stanza.
			PeerLookupFn: fixedPeerUID(authzUIDStranger),
		})
		for _, route := range []string{
			"POST /api/v1/config/enter",
			"POST /api/v1/config/set",
			"POST /api/v1/config/commit",
			"POST /api/v1/system/action",
		} {
			status, errMsg := postRoute(t, base, route, map[string]string{"Authorization": basic})
			if status != http.StatusForbidden {
				t.Errorf("%s admitted a local account OUTSIDE the login model with %d because "+
					"it presented the shared api-auth secret — the per-principal gate is "+
					"optional for anyone who knows the password", route, status)
			}
			if !strings.Contains(errMsg, "not a configured") {
				t.Errorf("%s denial did not name the reason: %q", route, errMsg)
			}
		}
	})

	// The discriminating control: an attributed local UID that IS in the login
	// model, with a class that holds `configure`, still works normally. A gate
	// that simply refused every local caller would pass the subtest above and
	// fail this one.
	t.Run("attributed local account INSIDE the login model still works", func(t *testing.T) {
		store := authzStore(t, authzTestConfig)
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        store,
			Auth:         auth,
			PeerLookupFn: fixedPeerUID(authzUIDSuperuser), // uid 4243 = adminuser, super-user
		})
		// The credential is presented here too, so this subtest and the one above
		// differ in EXACTLY one variable: whether the attributed uid is in the
		// login model.
		session := enterConfigure(t, base, map[string]string{"Authorization": basic})
		body := strings.NewReader(`{"input":"set system host-name inside-model"}`)
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/set", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", basic)
		req.Header.Set(restConfigSessionHeader, session)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a super-user login account was refused config/set: %d %s", resp.StatusCode, raw)
		}
		if candidate := store.ShowCandidate(); !strings.Contains(candidate, "inside-model") {
			t.Fatalf("config/set returned 200 but the candidate does not carry the edit:\n%s", candidate)
		}
	})
}

// TestUnattributableLocalCallerCannotBorrowCredential_5561 pins row (3) of the
// precedence table in Server.principal: a caller that IS on this host but could
// not be attributed must be DENIED, never handed the api-auth credential.
//
// The first version of this gate fell back to the credential whenever the peer
// lookup failed, and the caller controlled whether it failed — so a restricted
// account escalated to full power simply by making itself unidentifiable. A
// precedence rule that only holds when the lookup succeeds is not a precedence
// rule.
func TestUnattributableLocalCallerCannotBorrowCredential_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	t.Run("local but unattributable is refused despite a valid credential", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: unattributableLocalPeer(),
		})
		for _, route := range []string{
			"POST /api/v1/config/enter",
			"POST /api/v1/config/set",
			"POST /api/v1/config/commit",
			"POST /api/v1/system/action",
		} {
			status, errMsg := postRoute(t, base, route, map[string]string{"Authorization": basic})
			if status != http.StatusForbidden {
				t.Errorf("%s admitted an UNIDENTIFIABLE local caller with %d because it "+
					"presented the shared api-auth secret — a restricted account only has to "+
					"make its own identity unreadable to reach full power", route, status)
			}
			if !strings.Contains(errMsg, "local but could not be identified") {
				t.Errorf("%s denial did not name the reason: %q", route, errMsg)
			}
		}
	})

	// The negative control for the rule above: a caller that is genuinely NOT
	// on this host is exactly who the credential exists to identify (#4047).
	// Its default read-only class may read config, but does not mutate it.
	t.Run("a remote caller receives only the credential's view scope", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:           "127.0.0.1:8080",
			Store:          authzStore(t, authzTestConfig),
			Auth:           auth,
			PeerLookupFn:   remotePeer(),
			PeerLocalityFn: remoteLocality(),
		})
		req, err := http.NewRequest(http.MethodGet, base+"/api/v1/config", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", basic)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a remote caller with a valid read-only credential got %d, want 200", resp.StatusCode)
		}
	})
}

// TestHalfCloseCannotBorrowCredential_5561 is the MAJOR-2 regression guard on
// the REAL path: production server construction, real ConnContext, real kernel
// socket-table lookup, real /etc/passwd, real credential — and a real
// `shutdown(SHUT_WR)` on a hand-written HTTP request.
//
// Reproduced before the fix: the same `read-only` account with the same valid
// credential got 403 when polite and 200/400 (i.e. past the gate, inside the
// handler) when it half-closed first. The lazy lookup let the caller choose the
// moment of resolution, and a failed resolution fell through to the full-power
// credential. Both halves are fixed — the identity is resolved at accept, and a
// local caller that cannot be attributed is denied rather than downgraded to
// "anonymous with a password".
func TestHalfCloseCannotBorrowCredential_5561(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("running as root: UID 0 is authorized unconditionally, so the class " +
			"this case restricts cannot be observed")
	}
	name, ok := authz.UsernameForUID(uint32(uid))
	if !ok {
		t.Skipf("uid %d has no /etc/passwd entry on this machine", uid)
	}

	cfgText := fmt.Sprintf("system {\n    host-name authz-halfclose;\n    login {\n        user %s {\n            class read-only;\n        }\n    }\n}\n", name)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	// No PeerLookupFn: the kernel answers for real.
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, cfgText),
		Auth:  auth,
	})
	addr := strings.TrimPrefix(base, "http://")

	// rawPost writes a complete request by hand so the caller can half-close
	// between the request and the response — something net/http's client will
	// not do for us.
	rawPost := func(path string, halfClose bool) string {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		req := "POST " + path + " HTTP/1.1\r\nHost: " + addr +
			"\r\nAuthorization: " + basic +
			"\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if halfClose {
			// Leave ESTABLISHED while still reading the response — the move
			// that used to defeat the lookup.
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			time.Sleep(150 * time.Millisecond)
		}
		buf := make([]byte, 128)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := c.Read(buf)
		return string(buf[:n])
	}

	for _, path := range []string{
		"/api/v1/config/enter",
		"/api/v1/config/set",
		"/api/v1/config/commit",
		"/api/v1/system/action",
	} {
		t.Run(path, func(t *testing.T) {
			// Precondition: a polite request from this read-only account is
			// refused, so a pass below is the half-close and nothing else.
			if polite := rawPost(path, false); !strings.HasPrefix(polite, "HTTP/1.1 403") {
				t.Fatalf("precondition: a POLITE read-only caller was not refused: %q", polite)
			}
			hostile := rawPost(path, true)
			if !strings.HasPrefix(hostile, "HTTP/1.1 403") {
				t.Fatalf("a read-only account reached %s by calling shutdown(SHUT_WR) before "+
					"the request was authorized, borrowing the api-auth credential: %q",
					path, hostile)
			}
		})
	}
}

// TestPeerIdentityIsResolvedAtAccept_5561 pins WHEN the identity is taken.
//
// The lookup must happen once per CONNECTION, at accept — not per mutating
// request. Resolving it later hands the caller the choice of when it runs, and
// therefore the choice of making it fail (see
// TestHalfCloseCannotBorrowCredential_5561). Two observable consequences of
// resolving at accept: it runs exactly once no matter how many requests the
// connection carries, and it runs even on a connection that only ever issues a
// safe request.
//
// Both counts are read through waitForPeerLookupsToFinish rather than sampled
// when the responses land (#6645 r22, finding 3). The lookup runs in a goroutine
// connContext starts at accept, and every request below is SAFE — safe methods
// return from mutationAuthzGuard before authorizeInputs, so nothing on the
// request path waits for the lookup. A response therefore does not imply the
// resolver has run, and an immediate sample can read 0 where it wants 1. The
// wait is for the count AND for zero pool occupancy: with the pool empty, every
// lookup started so far has returned, so "at least N counted" and "exactly N
// counted" are the same reading and the equality assertions below still mean
// what they say.
func TestPeerIdentityIsResolvedAtAccept_5561(t *testing.T) {
	usePasswdFixture(t)
	waitSlots(t, 0, "the lookup pool never returned to zero occupancy before this case started")

	var mu sync.Mutex
	calls := 0
	counting := func(net.Addr, net.Addr) authz.PeerIdentity {
		mu.Lock()
		calls++
		mu.Unlock()
		return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: counting,
	})

	// One connection, kept alive across two requests.
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Method = http.MethodGet
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	waitForPeerLookupsToFinish(t, count, 1, "one connection carrying two safe requests")
	if got := count(); got != 1 {
		t.Fatalf("peer identity resolved %d times for ONE connection carrying two SAFE "+
			"requests, want exactly 1 at accept — a per-request lookup lets the caller "+
			"choose the moment it runs, and choose to make it fail", got)
	}

	// A second connection resolves again — the cache is per connection, not
	// per server, so a later caller is not attributed to an earlier one.
	client.CloseIdleConnections()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + "/api/v1/config/status")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	waitForPeerLookupsToFinish(t, count, 2, "a second connection")
	if got := count(); got != 2 {
		t.Fatalf("a second connection resolved the peer %d times in total, want 2 — the "+
			"identity must be per connection, never shared between callers", got)
	}
}

// TestPeerLookupDoesNotBlockTheAcceptLoop_5561 is the liveness half of the
// MAJOR-D guard: ConnContext runs SERIALLY in http.Server's accept loop, so
// resolving inline serializes every socket-table read behind Accept and can fill
// the listen backlog — locking out remote administrators before api-auth is even
// evaluated.
//
// The probe is deterministic rather than timing-based: the injected resolver
// blocks until the test releases it. Resolving inline leaves the accept loop
// stuck inside the FIRST connection's lookup, so the second connection is never
// accepted and the resolver is entered exactly once.
//
// This asserts only that lookups OVERLAP. It says nothing about what they cost —
// see TestConcurrentConnectionsShareOneSocketTableRead_5561, which is the guard
// for the cost that moving off the accept loop did not remove.
func TestPeerLookupDoesNotBlockTheAcceptLoop_5561(t *testing.T) {
	usePasswdFixture(t)

	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	blocking := func(net.Addr, net.Addr) authz.PeerIdentity {
		entered <- struct{}{}
		<-release
		return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
	}
	defer close(release)

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: blocking,
	})
	addr := strings.TrimPrefix(base, "http://")

	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		// Write a byte so the server's serve goroutine is definitely engaged.
		_, _ = c.Write([]byte("G"))
	}

	deadline := time.After(10 * time.Second)
	for got := 0; got < 2; got++ {
		select {
		case <-entered:
		case <-deadline:
			t.Fatalf("only %d of 2 peer lookups started while the first was still "+
				"running — ConnContext is resolving inline, so the accept loop is "+
				"serialized behind every socket-table walk and connection churn can "+
				"fill the listen backlog", got)
		}
	}
}

// TestConcurrentConnectionsShareOneSocketTableRead_5561 is the COST guard, and
// it asserts the property the liveness guard above does not.
//
// Resolving per connection moved the socket-table read off the accept loop but
// did not make it cheaper. Reading /proc/net/tcp{,6} is not proportional to row
// count — the kernel walks its whole TCP hash table, sized by RAM — so a read
// costs milliseconds even on an idle box. Per connection and unbounded, that is
// a denial of service available to any local process with NO credentials: a
// connect loop saturates a core inside the daemon, which is the same
// unprivileged local population #5561 exists to constrain.
//
// So the assertion is on READS, not on latency or concurrency: N connections
// arriving together must collapse into a handful of table reads. This uses the
// REAL kernel lookup — no injected resolver — because the batching being
// measured lives inside it.
func TestConcurrentConnectionsShareOneSocketTableRead_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
	})
	addr := strings.TrimPrefix(base, "http://")

	const conns = 60
	// Generous ceiling, DELIBERATELY. Batch boundaries are scheduling-dependent
	// — the same 60 connections legitimately land in 1, 2 or 3 batches run to
	// run — so an exact expected count would be flaky rather than stricter. The
	// property under test is that cost does not SCALE with connections; without
	// single-flighting this is exactly `conns`, two orders away from the bound.
	//
	// Read what that does NOT cover. The slack absorbs a constant-factor
	// regression: a change that doubled reads from 2 to 4 would pass here. In
	// particular this case is NOT coverage of where the credential row's locality
	// re-derivation sits — hoisting it above the credential check doubles the
	// reads and this bound swallows it.
	// TestUncredentialedCallerDrivesNoLocalityRecheck_5561 and
	// TestOffLoopbackCredentialRowEnumeratesOnlyOnce_5561 own that property and
	// assert ZERO rather than a ceiling, for exactly this reason.
	const maxReads = 12

	before := authz.SocketScansForTest()

	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A GET is enough: the lookup is started at accept regardless of
			// what the connection goes on to request.
			resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(base + "/api/v1/config/status")
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	_ = addr

	// Every connection's lookup is started at accept but completes
	// asynchronously; give the last batch a moment to drain before counting.
	deadline := time.Now().Add(10 * time.Second)
	var reads uint64
	for {
		reads = authz.SocketScansForTest() - before
		if reads > maxReads || time.Now().After(deadline) {
			break
		}
		prev := reads
		time.Sleep(100 * time.Millisecond)
		if authz.SocketScansForTest()-before == prev {
			break // settled
		}
	}

	if reads == 0 {
		t.Fatalf("no socket-table reads observed for %d connections — the probe is not "+
			"measuring the real lookup", conns)
	}
	if reads > maxReads {
		t.Fatalf("%d connections cost %d socket-table reads (limit %d). Each read walks the "+
			"kernel's entire TCP hash table and costs milliseconds, so an unprivileged "+
			"local connect loop with no credentials burns a core inside the daemon",
			conns, reads, maxReads)
	}
	t.Logf("%d concurrent connections cost %d socket-table read(s)", conns, reads)
}

// TestLookupDeadlineIsPerConnection_5561 is the MINOR-4 guard. The deadline is
// stamped when the lookup starts at accept, so a wedged socket-table read costs
// a connection peerLookupTimeout ONCE — not that long again on every request the
// connection makes.
//
// The probe drives two requests on ONE keep-alive connection against a resolver
// that never returns. With a per-request timer the second request restarts the
// full clock; with a per-connection deadline it is already expired and denies
// immediately.
func TestLookupDeadlineIsPerConnection_5561(t *testing.T) {
	usePasswdFixture(t)

	wedged := make(chan struct{})
	defer close(wedged)
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			<-wedged
			return authz.PeerIdentity{}
		},
	})

	// One connection, reused: http.Client keeps it alive between requests.
	client := &http.Client{Timeout: 60 * time.Second}
	post := func() time.Duration {
		start := time.Now()
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/enter", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a wedged lookup returned %d, want 403", resp.StatusCode)
		}
		return time.Since(start)
	}

	first := post()
	if first < peerLookupTimeout/2 {
		t.Fatalf("the first request waited only %v; expected roughly the %v lookup "+
			"deadline, so this probe is not measuring what it claims", first, peerLookupTimeout)
	}
	second := post()
	if second > peerLookupTimeout/2 {
		t.Fatalf("a second request on the SAME connection waited %v — the deadline is "+
			"per REQUEST, so a wedged socket table costs %v on every request the "+
			"connection makes instead of once", second, peerLookupTimeout)
	}
}

// TestInjectedResolverIsNormalized_5561 covers the boundary normalization: an
// injected resolver is not bound by LookupPeer's invariants and can report the
// nonsensical (OK=true, Local=false). An attributed peer is local by
// construction — its UID came out of THIS host's socket table — so the
// combination must be normalized before it reaches the precedence rule, which
// has no row for "attributed but off-box".
//
// Unnormalized, such an identity would take the OK branch anyway, so the visible
// consequence is subtle: it is the invariant, not the outcome, that is pinned
// here. The observable assertion is that a restricted class still governs and
// the credential is never consulted.
func TestInjectedResolverIsNormalized_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	s := NewServer(Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		Auth:  auth,
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			return authz.PeerIdentity{UID: authzUIDReadOnly, OK: true, Local: false}
		},
	})
	got := s.lookupPeer(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	if !got.Local {
		t.Fatal("an ATTRIBUTED peer identity was left marked non-local — the precedence " +
			"rule has no row for that combination, and treating it as off-box would let a " +
			"credential speak for a caller we identified")
	}

	// End to end, the read-only class still governs and the credential does not
	// rescue it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := s.buildHTTPServer(ln.Addr().String(), s.newAuthSlot())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	status, errMsg := postRoute(t, "http://"+ln.Addr().String(), "POST /api/v1/config/enter",
		map[string]string{"Authorization": basic})
	if status != http.StatusForbidden {
		t.Fatalf("a read-only principal marked non-local was admitted with %d", status)
	}
	if !strings.Contains(errMsg, "opsuser") {
		t.Errorf("denial did not attribute the read-only account: %q", errMsg)
	}
}

// TestProductionServerEnforcesRealPeerIdentity_5561 runs the whole path with NO
// injection: the production server construction, the real ConnContext hook, the
// real kernel socket-table lookup, the real /etc/passwd, and the real class
// evaluation — with the suite's own connection as the caller. It is the
// end-to-end proof that the identity the gate acts on is the one the kernel
// reports for the process making the request.
func TestProductionServerEnforcesRealPeerIdentity_5561(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("running as root: UID 0 is authorized unconditionally, so the class " +
			"evaluation this case pins cannot be observed")
	}
	name, ok := authz.UsernameForUID(uint32(uid))
	if !ok {
		t.Skipf("uid %d has no /etc/passwd entry on this machine", uid)
	}

	for _, tc := range []struct {
		class      string
		wantDenied bool
	}{
		{"read-only", true},
		{"super-user", false},
	} {
		t.Run(tc.class, func(t *testing.T) {
			cfgText := fmt.Sprintf("system {\n    host-name authz-real;\n    login {\n        user %s {\n            class %s;\n        }\n    }\n}\n",
				name, tc.class)
			// No PeerLookupFn: authz.LookupPeer queries the kernel for real.
			_, base := authzServer(t, Config{
				Addr:  "127.0.0.1:8080",
				Store: authzStore(t, cfgText),
			})
			status, errMsg := postRoute(t, base, "POST /api/v1/config/enter", nil)
			if tc.wantDenied && status != http.StatusForbidden {
				t.Fatalf("uid %d (%s, class %s) was admitted to configure with %d",
					uid, name, tc.class, status)
			}
			if !tc.wantDenied && status == http.StatusForbidden {
				t.Fatalf("uid %d (%s, class %s) was refused configure: %q",
					uid, name, tc.class, errMsg)
			}
			if tc.wantDenied && !strings.Contains(errMsg, strconv.Itoa(uid)) {
				t.Errorf("denial did not report the kernel-derived uid: %q", errMsg)
			}
		})
	}
}

// TestEveryMutatingRouteHasAPermission_5561 is the anti-drift guard. It reads
// the route registrations out of EVERY non-test file in the package — not just
// server.go, and not just calls on a variable literally named `mux`, either of
// which would have made the guard narrower than the claim it protects: a route
// added in a new file, or on a differently-named ServeMux, would have been
// invisible to it and become a silently inert 403 in production.
// TestRouteScannerReachesEveryRegistrationSite_5561 proves that reach against a
// fixture, because the real package happens to register every route one way.
// It requires the permission table to
// cover them EXACTLY in both directions: a new state-changing route with no
// entry fails here rather than silently becoming an inert 403 in production,
// and an entry whose route was renamed or removed fails here rather than
// silently guarding nothing.
func TestEveryMutatingRouteHasAPermission_5561(t *testing.T) {
	registered := registeredRoutes(t, ".", ".go")
	if len(registered) < 40 {
		t.Fatalf("only parsed %d routes out of the package — the scanner has stopped "+
			"matching the registration form and is no longer guarding anything", len(registered))
	}

	for _, route := range registered {
		method, _, _ := strings.Cut(route, " ")
		if isSafeHTTPMethod(method) {
			if _, listed := restMutationPermissions[route]; listed {
				t.Errorf("%s is a SAFE method but appears in the mutation permission "+
					"table; the guard never consults it there", route)
			}
			continue
		}
		if _, ok := restMutationPermissions[route]; !ok {
			t.Errorf("%s is a state-changing route with no entry in "+
				"restMutationPermissions: it fails closed at runtime, but that is a "+
				"silently dead endpoint. Add its required permission.", route)
		}
	}

	reg := make(map[string]bool, len(registered))
	for _, r := range registered {
		reg[r] = true
	}
	for route := range restMutationPermissions {
		if !reg[route] {
			t.Errorf("restMutationPermissions has an entry for %q, which is not a "+
				"registered route — it guards nothing and hides a renamed endpoint", route)
		}
	}
}

// TestEveryListenerCarriesPeerIdentity_5561 guards the plumbing rather than the
// policy. The gate can only see a caller if the listener that accepted the
// connection installed the ConnContext hook, and http.Server is constructed in
// more than one place: at startup AND on the #5866 day-2 make-before-break
// rebind (listener.go), which a `system services web-management` bind change
// takes. A rebuild that omitted the hook would leave the reconciled listener
// unable to identify anyone — every mutation on it refused, silently, only
// after an operator changed an unrelated setting.
func TestEveryListenerCarriesPeerIdentity_5561(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse pkg/api: %v", err)
	}
	found := 0
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Server" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "http" {
					return true
				}
				found++
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ConnContext" {
						return true
					}
				}
				t.Errorf("%s: an http.Server is constructed without ConnContext — "+
					"connections it accepts carry no peer identity, so every mutating "+
					"request on that listener is refused (#5561)", fset.Position(lit.Pos()))
				return true
			})
			_ = name
		}
	}
	if found < 2 {
		t.Fatalf("found only %d http.Server literals in pkg/api; the scanner has stopped "+
			"matching and is no longer guarding the rebind path", found)
	}
}

// sortedRouteKeys returns the mutation table's route keys in a stable order so
// subtest names and failures are deterministic.
func sortedRouteKeys() []string {
	keys := make([]string, 0, len(restMutationPermissions))
	for k := range restMutationPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// registeredRoutes extracts the "METHOD /path" patterns passed to any
// Handle/HandleFunc call in every non-test file of `dir` carrying the given
// suffix.
//
// Deliberately NOT keyed on the file name or on a receiver named `mux`. A route
// added in a new file, or registered on `apiMux`/`s.router`, is still a route,
// and an anti-drift guard that could not see it would let exactly that route
// become an unguarded-then-inert endpoint. The receiver is therefore any
// expression and the filter is on the PATTERN — a string literal beginning with
// "/" or with "METHOD /" — which is what a route registration actually looks
// like.
func registeredRoutes(t *testing.T, dir, suffix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, suffix) || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	if len(files) == 0 {
		t.Fatalf("no source files matched %s/*%s — the scanner is looking nowhere", dir, suffix)
	}

	var out []string
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("Handle/HandleFunc call at %s has a non-literal first argument; "+
					"if that is a route registration the coverage guard cannot see it",
					fset.Position(call.Pos()))
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Errorf("unquote %s: %v", lit.Value, err)
				return true
			}
			if !looksLikeRoutePattern(pattern) {
				return true
			}
			out = append(out, pattern)
			return true
		})
	}
	sort.Strings(out)
	return out
}

// looksLikeRoutePattern reports whether a string literal is an http.ServeMux
// pattern: "/path" or "METHOD /path".
func looksLikeRoutePattern(s string) bool {
	if strings.HasPrefix(s, "/") {
		return true
	}
	method, rest, ok := strings.Cut(s, " ")
	if !ok || !strings.HasPrefix(rest, "/") || method == "" {
		return false
	}
	return method == strings.ToUpper(method)
}

// TestRouteScannerReachesEveryRegistrationSite_5561 proves the anti-drift
// scanner's REACH, which the real package cannot: every route today is
// registered in server.go on a variable named `mux`, so narrowing the scanner
// back to that shape would break nothing and the widening would be an unguarded
// claim.
//
// The fixture under testdata/ registers routes the narrow scanner could not see
// — a file that is not server.go, a mux named `apiMux`, and a nested `s.router`
// — and all three must come back.
func TestRouteScannerReachesEveryRegistrationSite_5561(t *testing.T) {
	got := registeredRoutes(t, filepath.Join("testdata", "routescan"), ".go.fixture")
	want := []string{
		"DELETE /api/v1/fixture/nested",
		"GET /api/v1/fixture/safe",
		"POST /api/v1/fixture/elsewhere",
	}
	if len(got) != len(want) {
		t.Fatalf("scanner found %v, want %v — a route registered outside server.go or on "+
			"a mux not named `mux` is invisible to the coverage guard, so it would become "+
			"a silently inert endpoint in production", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scanner found %v, want %v", got, want)
		}
	}
}

// TestBrandNewLocalAddressCannotBorrowCredential_5561 is the round-5 MAJOR guard
// at the REST layer.
//
// The accept-time locality verdict is drawn from an interface-address snapshot
// refreshed at most once per second, for hits AND misses. That rate limit stops
// a connect flood from amplifying, but it caches the one answer that ADMITS: a
// caller LookupPeer calls "not on this host" skips the socket table entirely and
// lands on the credential row, which authorizes as a full-power principal. For
// up to a second after any address is added to this host — a VRRP VIP on
// failover, a DHCP lease, an RA-derived address, all of which an unprivileged
// account can watch for with `ip monitor address` — a caller connecting from
// that address is local yet classified off-box.
//
// The case reproduces exactly that state: the injected resolver supplies the
// stale accept-time verdict ("not on this host"), while the connection is a real
// one whose peer really is on this host. Config.PeerLocalityFn is deliberately
// left nil so the PRODUCTION re-derivation — authz.PeerCouldBeLocalNow, a fresh
// interface enumeration — is what answers.
//
// Before the fix this returns 200: the credential spoke for a local caller.
func TestBrandNewLocalAddressCannotBorrowCredential_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		Auth:  auth,
		// The stale accept-time verdict. Note the ABSENCE of PeerLocalityFn:
		// the real check runs, and the real caller is real-ly local.
		PeerLookupFn: remotePeer(),
	})

	status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
		map[string]string{"Authorization": basic})
	if status != http.StatusForbidden {
		t.Fatalf("a caller whose address is assigned to THIS host was admitted with %d on "+
			"the strength of the api-auth secret — the accept-time snapshot had not caught "+
			"up with the address, so a local account escapes its login class for as long as "+
			"that snapshot is stale (error=%q)", status, errMsg)
	}
	if !strings.Contains(errMsg, "assigned to this host") {
		t.Errorf("denial did not name the reason: %q", errMsg)
	}
}

// TestUncredentialedCallerDrivesNoLocalityRecheck_5561 pins the ORDER of the two
// checks in principal(), which is property P2.
//
// The locality re-derivation enumerates interfaces for real. Run before the
// credential check it would hand every request that reaches the gate a fresh
// enumeration — the per-connection amplification
// TestLocalAddrCacheRateLimitsMisses_5561 forbids for the accept-time cache,
// reintroduced one layer up. Run after, only a request that already presented a
// VALID credential can drive one, and such a caller is authorized anyway.
//
// # Getting the premise right, twice over
//
// Two earlier versions of this probe were VACUOUS, each for its own reason, and
// both are worth naming because each produced a green test whose expected value
// was the failure default:
//
//  1. Counting authz.HostAddrScansForTest() over a LOOPBACK listener.
//     PeerCouldBeLocalNow short-circuits on loopbackDelivery before it
//     enumerates, so the counter reads zero whether the check runs early, late,
//     or never. TestOffLoopbackCredentialRowEnumeratesOnlyOnce_5561 below is the
//     version that actually reaches the enumeration.
//  2. Sending uncredentialed requests to a server that HAS api-auth configured.
//     dynamicAuthMiddleware wraps the authz guard (server.go listenerHandler), so
//     it answers a missing or wrong credential with its own 401 and principal()
//     is never reached at all. Zero re-derivations, in every world.
//
// So the ordering is observable exactly where the credential check can FAIL
// INSIDE principal(): a listener with NO api-auth snapshot, where
// dynamicAuthMiddleware passes everything through and s.credential returns false
// on a nil snapshot. That is the case below.
func TestUncredentialedCallerDrivesNoLocalityRecheck_5561(t *testing.T) {
	usePasswdFixture(t)

	t.Run("no api-auth: the gate is reached and must not re-derive", func(t *testing.T) {
		var rechecks atomic.Int64
		_, base := authzServer(t, Config{
			Addr:  "127.0.0.1:8080",
			Store: authzStore(t, authzTestConfig),
			// No Auth: dynamicAuthMiddleware passes through, so principal() runs
			// and s.credential fails on the nil snapshot — the one path where the
			// ordering of the two checks is observable.
			PeerLookupFn: remotePeer(),
			PeerLocalityFn: func(net.Addr, net.Addr) bool {
				rechecks.Add(1)
				return false
			},
		})

		const rounds = 25
		for i := 0; i < rounds; i++ {
			if status, _ := postRoute(t, base, "POST /api/v1/config/enter", nil); status != http.StatusForbidden {
				t.Fatalf("an uncredentialed caller got %d, want 403", status)
			}
		}
		if n := rechecks.Load(); n != 0 {
			t.Fatalf("%d requests that carried no credential drove %d locality "+
				"re-derivations — the re-check runs BEFORE the credential check, so any "+
				"caller that can open a socket forces an interface enumeration per request",
				rounds, n)
		}
	})

	// The other half. Without it, deleting the check outright satisfies the
	// assertion above, so this pins that the credential row DOES consult it.
	t.Run("a valid credential drives exactly one re-derivation", func(t *testing.T) {
		var rechecks atomic.Int64
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}},
			PeerLookupFn: remotePeer(),
			PeerLocalityFn: func(net.Addr, net.Addr) bool {
				rechecks.Add(1)
				return false // off-box, so the credential is honoured
			},
		})
		status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
			map[string]string{"Authorization": basic})
		if status == http.StatusForbidden {
			t.Fatalf("the off-box control was refused: %q", errMsg)
		}
		if n := rechecks.Load(); n != 1 {
			t.Fatalf("a request with a VALID credential drove %d locality re-derivations, "+
				"want exactly 1 — the credential row is not consulting the check, so a "+
				"caller that is on this host is admitted by the shared secret", n)
		}
	})
}

// routableHostAddr returns a real non-loopback IPv4 address of this host, so a
// case can build a connection whose BOTH ends are off-loopback and therefore
// reach the interface-enumeration clause of PeerCouldBeLocalNow instead of its
// loopback short-circuit.
func routableHostAddr(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return ip
	}
	t.Skip("this host has no routable IPv4 address to build an off-loopback connection from")
	return nil
}

// authzServerAt is authzServer bound to a chosen address rather than 127.0.0.1,
// so a case can build connections whose both ends are off-loopback.
func authzServerAt(t *testing.T, cfg Config, bind string) (*Server, string) {
	t.Helper()
	s := NewServer(cfg)
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", bind, err)
	}
	srv := s.buildHTTPServer(ln.Addr().String(), s.newAuthSlot())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s, "http://" + ln.Addr().String()
}

// TestOffLoopbackCredentialRowEnumeratesOnlyOnce_5561 drives the same ordering
// property through the REAL enumeration with no locality injection, and is
// simultaneously the end-to-end P1 proof on the production path.
//
// The listener binds a real routable address of this host, so a connection to it
// has non-loopback addresses at both ends and PeerCouldBeLocalNow actually
// enumerates instead of short-circuiting. The caller's source address is then
// genuinely one of ours, which is exactly the stale-snapshot window: the injected
// resolver supplies the accept-time verdict "not on this host" while the caller
// really is on it.
func TestOffLoopbackCredentialRowEnumeratesOnlyOnce_5561(t *testing.T) {
	usePasswdFixture(t)
	host := routableHostAddr(t)
	bind := (&net.TCPAddr{IP: host}).String()

	// Precondition: the kernel must source a connection to this address from a
	// NON-loopback address, or PeerCouldBeLocalNow short-circuits and the probe
	// measures nothing.
	probeLn, err := net.Listen("tcp", bind)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", bind, err)
	}
	probe, err := net.Dial("tcp", probeLn.Addr().String())
	if err != nil {
		probeLn.Close()
		t.Skipf("cannot dial %v: %v", probeLn.Addr(), err)
	}
	src := probe.LocalAddr().(*net.TCPAddr)
	probe.Close()
	probeLn.Close()
	if src.IP.IsLoopback() {
		t.Skipf("kernel sourced the connection from %v; PeerCouldBeLocalNow would "+
			"short-circuit on loopback and this probe would measure nothing", src.IP)
	}

	// P2, on the real enumeration: no api-auth, so principal() is reached and
	// s.credential fails inside it. Not one interface enumeration may result.
	t.Run("no api-auth: uncredentialed requests cost zero enumerations", func(t *testing.T) {
		_, base := authzServerAt(t, Config{
			Addr:         bind,
			Store:        authzStore(t, authzTestConfig),
			PeerLookupFn: remotePeer(),
		}, bind)

		before := authz.HostAddrScansForTest()
		const rounds = 10
		for i := 0; i < rounds; i++ {
			if status, _ := postRoute(t, base, "POST /api/v1/config/enter", nil); status != http.StatusForbidden {
				t.Fatalf("an uncredentialed caller got %d, want 403", status)
			}
		}
		if scans := authz.HostAddrScansForTest() - before; scans != 0 {
			t.Fatalf("%d uncredentialed requests drove %d REAL interface enumerations — "+
				"the locality re-derivation runs before the credential check", rounds, scans)
		}
	})

	// P1, on the real enumeration: a valid credential must cost at least one
	// enumeration AND be DENIED, because that enumeration finds the caller's
	// address on this host.
	t.Run("a valid credential is denied because the caller is on this host", func(t *testing.T) {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))
		_, base := authzServerAt(t, Config{
			Addr:         bind,
			Store:        authzStore(t, authzTestConfig),
			Auth:         &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}},
			PeerLookupFn: remotePeer(),
		}, bind)

		before := authz.HostAddrScansForTest()
		status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
			map[string]string{"Authorization": basic})
		// EXACTLY one, not "at least one". A >0 assertion is satisfied by 1, 2 or
		// 100 alike, so it catches the check being removed but not the check
		// being run per-something — which is the cost half of the property and
		// the reason it was safe to make the answer authoritative at all.
		if scans := authz.HostAddrScansForTest() - before; scans != 1 {
			t.Fatalf("one request with a VALID credential drove %d interface enumerations, "+
				"want exactly 1. Zero means the credential row is not re-deriving locality, "+
				"so the accept-time snapshot decides and a caller on this host is admitted "+
				"by the secret; more than one means the re-derivation runs more than once "+
				"per request", scans)
		}
		if status != http.StatusForbidden {
			t.Fatalf("a caller connecting FROM %v — an address assigned to this host — was "+
				"admitted with %d on the strength of the api-auth secret (error=%q)",
				src.IP, status, errMsg)
		}
		if !strings.Contains(errMsg, "assigned to this host") {
			t.Errorf("denial did not name the reason: %q", errMsg)
		}
	})
}

// TestAcceptTimeVerdictIsNotDiscarded_5561 is the MAJOR-2 guard: the two
// locality observations are used TOGETHER, and the later one may not overrule
// the earlier.
//
// A fresh enumeration that finds nothing is not proof of off-box — a successful
// omission reads the same whether the caller is remote or its address moved. On
// this product that is not hypothetical: a VRRP VIP relocates on every failover,
// so an address really can be on this host at accept and gone by the time the
// request is adjudicated.
//
// The accept-time verdict is what covers that, and it must keep covering it: a
// caller this host COULD place at accept is denied before the credential row is
// reached, whatever a later enumeration says. This case drives exactly that
// disagreement — accept says local, the fresh check says off-box, and a valid
// credential is presented — and requires the denial.
func TestAcceptTimeVerdictIsNotDiscarded_5561(t *testing.T) {
	usePasswdFixture(t)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	var rechecks atomic.Int64
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		Auth:  &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}},
		// Accept: the caller IS on this host, but unattributable.
		PeerLookupFn: unattributableLocalPeer(),
		// Request time: its address has since moved away, so a fresh enumeration
		// finds nothing. The later observation must not rescue the credential.
		PeerLocalityFn: func(net.Addr, net.Addr) bool {
			rechecks.Add(1)
			return false
		},
	})

	status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
		map[string]string{"Authorization": basic})
	if status != http.StatusForbidden {
		t.Fatalf("a caller this host placed AT ACCEPT was admitted with %d once its address "+
			"had moved on — the accept-time verdict was discarded in favour of a later "+
			"enumeration, so riding a VRRP VIP failover is enough to reach the credential "+
			"row (error=%q)", status, errMsg)
	}
	if !strings.Contains(errMsg, "local but could not be identified") {
		t.Errorf("denial did not name the reason: %q", errMsg)
	}
	// And it must be denied WITHOUT consulting the fresh check: the accept-time
	// verdict alone settles it, so no enumeration is owed for this caller.
	if n := rechecks.Load(); n != 0 {
		t.Errorf("a caller denied on the accept-time verdict still drove %d locality "+
			"re-derivations; the accept-time deny must short-circuit", n)
	}
}

// TestWedgedLookupsDoNotAccumulate_5561 is the round-7 MAJOR-5b guard.
//
// The per-connection deadline stops the REQUEST waiting; it does not stop the
// accept-time goroutine, and TestLookupDeadlineIsPerConnection_5561 asserts only
// the former. Nothing cancels the latter — the wedge that matters is inside
// localAddrsFn() holding localAddrCache.mu, where a context could not help
// anyway — so continued connections against a wedged enumeration accumulated
// goroutines without limit, driven by a caller that never authenticates.
//
// Admission control replaces cancellation: past maxConcurrentPeerLookups a
// connection resolves IMMEDIATELY, and to a DENIAL, which is the same answer a
// timed-out lookup gives and is reached without spawning anything.
func TestWedgedLookupsDoNotAccumulate_5561(t *testing.T) {
	usePasswdFixture(t)

	// Fill BOTH pools, as a wedged enumeration would (#6974). There are two
	// since the budget was split by whether a connection can reach the
	// enumeration: this fixture's server is on 127.0.0.1, so its connections are
	// loopback-delivered and draw on the loopback pool — filling only the
	// wedge-facing one would leave the fixture's own path unbounded and the case
	// would fail while nothing was wrong. Both are filled so the assertion below
	// still means "the accept-time goroutine is bounded", whichever pool this
	// connection uses.
	held := map[chan struct{}]int{}
	defer func() {
		for pool, n := range held {
			for i := 0; i < n; i++ {
				<-pool
			}
		}
	}()
	for _, pool := range []chan struct{}{peerLookupSlots, peerLookupLoopbackSlots} {
		for held[pool] < maxConcurrentPeerLookups {
			select {
			case pool <- struct{}{}:
				held[pool]++
			default:
				t.Fatalf("could not fill a lookup pool; %d of %d taken before it refused",
					held[pool], maxConcurrentPeerLookups)
			}
		}
	}

	// A resolver that would BLOCK FOREVER if it were ever reached. With the pool
	// full it must not be, so this doubles as the "nothing was spawned" probe:
	// if the bound were absent the request would hang here rather than deny.
	wedged := make(chan struct{})
	defer close(wedged)
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			<-wedged
			return authz.PeerIdentity{}
		},
	})

	done := make(chan int, 1)
	go func() {
		status, _ := postRoute(t, base, "POST /api/v1/config/enter", nil)
		done <- status
	}()
	select {
	case status := <-done:
		if status != http.StatusForbidden {
			t.Fatalf("a connection admitted past the lookup cap returned %d, want 403 — "+
				"exhausting the pool must DENY, not admit", status)
		}
	case <-time.After(peerLookupTimeout / 2):
		t.Fatal("a connection arriving with the lookup pool full still waited on a lookup " +
			"— the accept-time goroutine is unbounded, so a wedged enumeration accumulates " +
			"one blocked goroutine per connection for as long as callers keep connecting")
	}

	// The ceiling is the SUM of the pools' capacities, derived rather than
	// written down: #6974 split the budget in two, and a literal here would
	// either have to be updated by hand or would silently stop bounding when a
	// pool is resized. What the case asserts is unchanged — in-flight lookups
	// never exceed what the budgets allow.
	ceiling := cap(peerLookupSlots) + cap(peerLookupLoopbackSlots)
	if n := PeerLookupSlotsInUseForTest(); n > ceiling {
		t.Fatalf("in-flight lookups grew to %d, past the %d total cap across %d pools",
			n, ceiling, 2)
	}
}
