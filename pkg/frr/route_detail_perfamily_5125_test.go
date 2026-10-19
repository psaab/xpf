package frr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// v4RouteJSON is a minimal valid `show ip route json` payload with one
// IPv4 route, used to make the IPv4 leg of GetRouteDetailJSON succeed.
const v4RouteJSON = `{
	"10.0.1.0/24": [{
		"prefix": "10.0.1.0/24",
		"protocol": "connected",
		"selected": true,
		"installed": true,
		"table": 254,
		"nexthops": [{"directlyConnected": true, "interfaceName": "trust0", "active": true, "fib": true}]
	}]
}`

const v6RouteJSON = `{
	"2001:db8::/32": [{
		"prefix": "2001:db8::/32",
		"protocol": "static",
		"selected": true,
		"installed": true,
		"table": 254,
		"nexthops": [{"ip": "2001:db8::1", "interfaceName": "wan0", "active": true, "fib": true}]
	}]
}`

// TestGetRouteDetailJSONPerFamilyFailureSurfaces proves GetRouteDetailJSON
// returns the successful (IPv4) family's routes AND a non-nil error when the
// IPv6 vtysh command fails. RED against a revert to the swallow-and-continue
// form (`if err != nil { continue }; return all, nil`).
func TestGetRouteDetailJSONPerFamilyFailureSurfaces(t *testing.T) {
	fake := &fakeExecutor{
		// Only the IPv4 command is programmed; the IPv6 command falls through
		// to vtyshErr, simulating a transient vtysh failure for that family.
		vtyshResp: map[string]string{"show ip route vrf all json": v4RouteJSON},
		vtyshErr:  errors.New("vtysh: connection refused"),
	}
	m := &Manager{exec: fake}

	routes, err := m.GetRouteDetailJSON(context.Background())
	if err == nil {
		t.Fatal("got nil error on a failed IPv6 dump; a per-family failure must surface")
	}
	if !strings.Contains(err.Error(), "show ipv6 route vrf all json") {
		t.Errorf("error should name the failing command; got %v", err)
	}
	// The successful IPv4 family's route must still be returned.
	var sawV4 bool
	for _, r := range routes {
		if r.Prefix == "10.0.1.0/24" {
			sawV4 = true
		}
	}
	if !sawV4 {
		t.Errorf("the successful IPv4 family's routes must still be returned; got %+v", routes)
	}
}

// TestGetRouteDetailJSONParseFailureSurfaces proves a per-family JSON PARSE
// failure (valid vtysh call, malformed JSON) is also joined into the error
// rather than swallowed, while the other family's routes still return.
func TestGetRouteDetailJSONParseFailureSurfaces(t *testing.T) {
	fake := &fakeExecutor{
		vtyshResp: map[string]string{
			"show ip route vrf all json":   v4RouteJSON,
			"show ipv6 route vrf all json": "{ this is not valid json",
		},
	}
	m := &Manager{exec: fake}

	routes, err := m.GetRouteDetailJSON(context.Background())
	if err == nil {
		t.Fatal("got nil error on a malformed IPv6 JSON payload; the parse failure must surface")
	}
	if !strings.Contains(err.Error(), "show ipv6 route vrf all json") || !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should name the failing command and mark it a parse failure; got %v", err)
	}
	var sawV4 bool
	for _, r := range routes {
		if r.Prefix == "10.0.1.0/24" {
			sawV4 = true
		}
	}
	if !sawV4 {
		t.Errorf("the successful IPv4 family's routes must still be returned; got %+v", routes)
	}
}

// TestGetRouteDetailJSONBothFamiliesOKNoError is the happy-path guard: when
// both families succeed, no error is returned and both routes render.
func TestGetRouteDetailJSONBothFamiliesOKNoError(t *testing.T) {
	fake := &fakeExecutor{
		vtyshResp: map[string]string{
			"show ip route vrf all json":   v4RouteJSON,
			"show ipv6 route vrf all json": v6RouteJSON,
		},
	}
	m := &Manager{exec: fake}

	routes, err := m.GetRouteDetailJSON(context.Background())
	if err != nil {
		t.Fatalf("unexpected error when both families succeed: %v", err)
	}
	var sawV4, sawV6 bool
	for _, r := range routes {
		switch r.Prefix {
		case "10.0.1.0/24":
			sawV4 = true
		case "2001:db8::/32":
			sawV6 = true
		}
	}
	if !sawV4 || !sawV6 {
		t.Errorf("both families' routes must render on full success; sawV4=%v sawV6=%v", sawV4, sawV6)
	}
}
