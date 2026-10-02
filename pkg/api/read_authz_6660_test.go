package api

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func get6660(t *testing.T, base, path string) (int, string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestUnattributableCallerIsDeniedReads_6660 is the fail-on-revert gate.
//
// #5561 authorized the 19 MUTATING routes and scoped reads out, so any local
// process could GET the full running configuration without being identified and
// no login-class permission was consulted.
//
// The caller here is LOCAL but unattributable — the same fixture #5561 uses for
// its mutation denials — which is the population that must not be reading a
// firewall's zones, policies, NAT rules and addressing.
func TestUnattributableCallerIsDeniedReads_6660(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})

	for _, path := range []string{
		"/api/v1/config",
		"/api/v1/config/show",
		"/api/v1/config/status",
		"/api/v1/show-text",
		"/api/v1/status",
		"/api/v1/interfaces",
		"/api/v1/security/zones",
		"/api/v1/security/policies",
		"/api/v1/security/sessions",
		"/api/v1/routes",
	} {
		t.Run(path, func(t *testing.T) {
			code, body := get6660(t, base, path)
			if code != http.StatusForbidden {
				t.Fatalf("GET %s returned %d, want 403 — an unidentified local caller is "+
					"reading the firewall's configuration and operational state: %s",
					path, code, body)
			}
		})
	}
}

// TestRootStillReadsWithNoLoginModel_6660 is the no-brick guard, and it is the
// reason this change is safe to make at all.
//
// PrincipalForUID returns a SUPERUSER principal for uid 0 unconditionally, with
// no `system login user` entry required. So root-run monitoring, automation and
// support tooling on a box that never adopted RBAC keeps working byte-for-byte;
// what changes is a NON-root local uid outside the login model, which is exactly
// the population the issue exists to stop.
//
// Without this case the change would read as "gate the read surface" with no
// evidence about who it breaks — and the issue explicitly warns that a read
// denial can break monitoring that has never needed an identity.
func TestRootStillReadsWithNoLoginModel_6660(t *testing.T) {
	usePasswdFixture(t)
	// A config with NO `system login` stanza at all: the box never adopted RBAC.
	store := authzStore(t, "system {\n    host-name fw;\n}\n")
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(0),
	})

	for _, path := range []string{"/api/v1/config", "/api/v1/status"} {
		t.Run(path, func(t *testing.T) {
			if code, body := get6660(t, base, path); code == http.StatusForbidden {
				t.Fatalf("GET %s returned 403 for ROOT on a box with no login model — this "+
					"would break every root-run monitor on every deployment that never "+
					"configured `system login user`: %s", path, body)
			}
		})
	}
}

// TestHealthAndMetricsStayOpen_6660 pins the two routes that must never be
// gated: they carry no configuration, authCheck already exempts them, and the
// in-tree incus harnesses read /metrics. Gating them would break monitoring on
// every box.
func TestHealthAndMetricsStayOpen_6660(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})
	for _, path := range []string{"/health", "/metrics"} {
		t.Run(path, func(t *testing.T) {
			if code, body := get6660(t, base, path); code == http.StatusForbidden {
				t.Fatalf("GET %s returned 403; it must stay open: %s", path, body)
			}
		})
	}
}

// TestEveryReadRouteHasAPermission_6660 is the completeness gate.
//
// readAuthz serves an UNGUARDED safe route rather than refusing it, because
// /health and /metrics must keep working. The cost of that choice is that a NEW
// read route added without a table entry would serve unauthenticated — silently.
// This moves that risk from runtime to the suite: it enumerates the routes the
// mux actually registers and fails on any /api/v1 GET the table does not cover.
//
// It reads the registration source rather than a hand-kept list, so adding a
// route and forgetting the permission cannot pass.
func TestEveryReadRouteHasAPermission_6660(t *testing.T) {
	src := readServerSourceForTest(t)
	re := regexp.MustCompile(`mux\.HandleFunc\("(GET) (/api/v1/[^"]*)"`)
	var missing []string
	found := 0
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		route := m[1] + " " + m[2]
		found++
		if _, ok := restReadPermissions[route]; !ok {
			missing = append(missing, route)
		}
	}
	if found == 0 {
		t.Fatal("the route scan matched NOTHING — the regex or the registration shape changed, " +
			"and a completeness gate that matches nothing passes vacuously")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d registered /api/v1 GET route(s) have no entry in restReadPermissions and "+
			"therefore serve UNAUTHENTICATED: %v", len(missing), missing)
	}
}

// TestReadPermissionTableNamesOnlyRealRoutes_6660 is the other direction: an
// entry for a route that does not exist is dead policy that reads as coverage.
func TestReadPermissionTableNamesOnlyRealRoutes_6660(t *testing.T) {
	src := readServerSourceForTest(t)
	for route := range restReadPermissions {
		path := strings.TrimPrefix(route, "GET ")
		if !strings.Contains(src, `mux.HandleFunc("GET `+path+`"`) {
			t.Errorf("restReadPermissions names %q, which the mux does not register — dead "+
				"policy that reads as coverage", route)
		}
	}
}

// TestReadRoutesAreViewTierExceptMatchSimulator_6660 pins the ordinary
// read-route tier: every entry is PermView except the tuple policy simulator,
// whose PermControl exception is pinned by TestMatchPoliciesRESTCostsControl_11674.
func TestReadRoutesAreViewTierExceptMatchSimulator_6660(t *testing.T) {
	for route, perm := range restReadPermissions {
		if route == "GET /api/v1/security/match" {
			continue
		}
		if perm != config.PermView {
			t.Errorf("read route %q requires %v, want PermView", route, perm)
		}
	}
}

// readServerSourceForTest returns server.go's source, so the route-coverage
// gates above compare against what is actually REGISTERED rather than a
// hand-kept list that can fall behind the mux.
func readServerSourceForTest(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	return string(b)
}
