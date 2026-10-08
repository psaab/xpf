package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRoutesHandlerNotInstalledReason12095 checks every excluded REST row in
// the global and per-instance IPv4/IPv6 lists against the shared verdict map
// used by gRPC's "NOT INSTALLED" labels. A live route is the negative control:
// its JSON shape must not gain a not_installed_reason field.
func TestRoutesHandlerNotInstalledReason12095(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Commit a minimal config, then inject routes post-commit so no
	// recompile normalizes the excluded fixture away.
	if err := store.LoadOverride(`
system {
    host-name xpf;
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	globalV4 := &config.StaticRoute{Destination: "10.9.0.0/16", Discard: true, NoInstall: true, Preference: 5}
	globalV6 := &config.StaticRoute{Destination: "2001:db8:9::/48", Reject: true, NoInstall: true, Preference: 5}
	instanceV4 := &config.StaticRoute{Destination: "192.0.2.0/24", NextTable: "Comcast", Preference: 5}
	instanceV6 := &config.StaticRoute{Destination: "2001:db8:c0::/48", Preference: 5}
	live := &config.StaticRoute{Destination: "10.4.0.0/24", Preference: 7, NextHops: []config.NextHopEntry{
		{Address: "10.4.0.254", Interface: "ge-0-0-0"},
	}}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{globalV4, live}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{globalV6}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name:              "Comcast",
		InstanceType:      "vrf",
		StaticRoutes:      []*config.StaticRoute{instanceV4},
		Inet6StaticRoutes: []*config.StaticRoute{instanceV6},
	}}

	// Third-party anchor: each route must be genuinely excluded by the shared
	// verdict the snapshot builder and gRPC text renderer consult.
	expectedReasons := map[*config.StaticRoute]string{
		globalV4:   "route has the `no-install` option set",
		globalV6:   "route has the `no-install` option set",
		instanceV4: "next-table is not supported under a routing-instance — no ip rule is installed for it",
		instanceV6: "route has no forwarding disposition (no next-hop, next-table, discard, or reject)",
	}
	excluded := config.StaticRouteExclusions(cfg)
	for route, want := range expectedReasons {
		if got := excluded[route]; got != want {
			t.Fatalf("shared exclusion for %q = %q, want gRPC NOT INSTALLED text %q", route.Destination, got, want)
		}
	}

	s := &Server{store: store}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/routing/routes", nil)
	s.routesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool             `json:"success"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success=false; body: %s", rr.Body.String())
	}
	seen := make(map[string]bool, len(expectedReasons))
	for _, row := range resp.Data {
		destination, _ := row["destination"].(string)
		var expected string
		for route, reason := range expectedReasons {
			if route.Destination == destination {
				expected = reason
				seen[destination] = true
				break
			}
		}
		if expected != "" {
			if got := row["not_installed_reason"]; got != expected {
				t.Errorf("row %q not_installed_reason = %v, want shared/gRPC text %q", destination, got, expected)
			}
			continue
		}
		if destination == live.Destination {
			if got := row["next_hop"]; got != "10.4.0.254" {
				t.Errorf("live row next_hop = %v, want 10.4.0.254", got)
			}
			if got := row["interface"]; got != "ge-0-0-0" {
				t.Errorf("live row interface = %v, want ge-0-0-0", got)
			}
			if _, present := row["not_installed_reason"]; present {
				t.Errorf("live row gained not_installed_reason: %v", row["not_installed_reason"])
			}
		}
	}
	for route := range expectedReasons {
		if !seen[route.Destination] {
			t.Errorf("excluded route %q missing from response", route.Destination)
		}
	}
}
