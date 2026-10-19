package frr

import (
	"context"
	"strings"
	"testing"
)

// #15774: detail must query all VRFs and keep nexthop-type dispositions.
const vrfRouteJSON15774 = `{
	"vrf-blue": {
		"10.9.0.0/24": [{
			"prefix": "10.9.0.0/24", "protocol": "static", "selected": true, "installed": true,
			"distance": 5, "metric": 0, "table": 100,
			"nexthops": [{"ip": "192.0.2.1", "interfaceName": "ge-0-0-0", "active": true, "fib": true}]
		}],
		"198.51.100.0/24": [{
			"prefix": "198.51.100.0/24", "protocol": "static", "selected": true, "installed": true,
			"distance": 5, "metric": 0, "table": 100,
			"nexthops": [{"type": "blackhole", "active": true, "fib": true}]
		}]
	}
}`

const vrf6RouteJSON15774 = `{
	"vrf-blue": {
		"2001:db8:9::/48": [{
			"prefix": "2001:db8:9::/48", "protocol": "static", "selected": true, "installed": true,
			"distance": 5, "metric": 0, "table": 100,
			"nexthops": [{"ip": "2001:db8::1", "interfaceName": "ge-0-0-0", "active": true, "fib": true}]
		}]
	}
}`

func TestGetRouteDetailJSONVRFAll15774(t *testing.T) {
	fake := &fakeExecutor{vtyshResp: map[string]string{
		"show ip route vrf all json":   vrfRouteJSON15774,
		"show ipv6 route vrf all json": vrf6RouteJSON15774,
	}}
	m := &Manager{exec: fake}
	routes, err := m.GetRouteDetailJSON(context.Background())
	if err != nil {
		t.Fatalf("GetRouteDetailJSON: %v", err)
	}
	var sawVRF, sawV6 bool
	for _, r := range routes {
		if r.Prefix == "10.9.0.0/24" && r.VRF == "vrf-blue" {
			sawVRF = true
		}
		if r.Prefix == "2001:db8:9::/48" && r.VRF == "vrf-blue" {
			sawV6 = true
		}
	}
	if !sawVRF || !sawV6 {
		t.Fatalf("VRF routes not parsed with VRF identity: %+v", routes)
	}
	out := FormatRouteDetail(routes)
	if !strings.Contains(out, "vrf-blue") || !strings.Contains(out, "10.9.0.0/24") {
		t.Errorf("detail output missing VRF identity:\n%s", out)
	}
	if !strings.Contains(out, "Discard") {
		t.Errorf("detail blackhole nexthop must render Discard:\n%s", out)
	}
	// Flat default-VRF payload still parses.
	fake2 := &fakeExecutor{vtyshResp: map[string]string{
		"show ip route vrf all json":   v4RouteJSON,
		"show ipv6 route vrf all json": v6RouteJSON,
	}}
	routes2, err := (&Manager{exec: fake2}).GetRouteDetailJSON(context.Background())
	if err != nil || len(routes2) != 2 {
		t.Fatalf("flat payload: routes=%+v err=%v", routes2, err)
	}
}
