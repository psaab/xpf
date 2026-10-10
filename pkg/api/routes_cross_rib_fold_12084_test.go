package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRoutesHandlerLabelsCrossRIBFoldAsIPv6_12084(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, set := range []string{
		"set routing-options static route 2602:ffd3::/40 next-hop 2602:ffd3:ffff::1 preference 5",
		"set routing-options rib inet6.0 static route 2602:ffd3::/40 next-hop 2602:ffd3:ffff::2 preference 200",
	} {
		path, err := config.ParseSetCommand(set)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", set, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", set, err)
		}
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	store := routesV6VRFStore(t)
	active := store.ActiveConfig()
	active.RoutingOptions.StaticRoutes = compiled.RoutingOptions.StaticRoutes
	active.RoutingOptions.Inet6StaticRoutes = compiled.RoutingOptions.Inet6StaticRoutes
	server := &Server{store: store}
	recorder := httptest.NewRecorder()
	server.routesHandler(recorder, httptest.NewRequest("GET", "/api/v1/routing/routes", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d; response: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success bool        `json:"success"`
		Data    []RouteInfo `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode routes response: %v; body=%s", err, recorder.Body.String())
	}
	if !response.Success {
		t.Fatalf("routes request failed: %s", recorder.Body.String())
	}
	var matching []RouteInfo
	for _, route := range response.Data {
		if route.Destination == "2602:ffd3::/40" {
			matching = append(matching, route)
		}
	}
	if len(matching) != 2 {
		t.Fatalf("cross-RIB IPv6 REST rows = %+v, want both folded next-hops", matching)
	}
	gateways := map[string]bool{"2602:ffd3:ffff::1": false, "2602:ffd3:ffff::2": false}
	preferences := map[string]int{
		"2602:ffd3:ffff::1": 5,
		"2602:ffd3:ffff::2": 200,
	}
	for _, route := range matching {
		if route.Family != "inet6" || route.Table != "inet6.0" {
			t.Fatalf("cross-RIB IPv6 REST row = %+v, want inet6/inet6.0", route)
		}
		if _, ok := gateways[route.NextHop]; !ok {
			t.Fatalf("unexpected REST next-hop row: %+v", route)
		}
		gateways[route.NextHop] = true
		if route.Preference != preferences[route.NextHop] {
			t.Errorf("REST row for %s reports preference %d, want per-tier %d",
				route.NextHop, route.Preference, preferences[route.NextHop])
		}
	}
	for gateway, found := range gateways {
		if !found {
			t.Errorf("REST response dropped folded next-hop %s: %+v", gateway, matching)
		}
	}
}
