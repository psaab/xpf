package api

import (
	"testing"
)

// #15076 (A41-01) REST leg: /routing/bgp?type=routes and the NAT rules route
// were charged the summary/source commands whatever ?type= selected.

func TestBGPRoutesAndNATSelectorsChargedPerRequest15076(t *testing.T) {
	// A class permitting only summary/source must not receive routes.
	srcOnly := cfg14146(t, "", "^show bgp summary$|^show protocols bgp summary$|^show security nat source rule$")
	for _, path := range []string{
		"/api/v1/routing/bgp?type=routes",
		"/api/v1/routing/bgp?type=bogus",
		"/api/v1/security/nat/rules?type=destination",
		"/api/v1/security/nat/rules?nat_type=destination",
		"/api/v1/security/nat/rules?type=bogus",
	} {
		if err := call9952(t, srcOnly, "limited", "GET", path, ""); err == nil {
			t.Errorf("GET %s ALLOWED under summary/source-only allow; charged the fixed summary/source command (#15076)", path)
		}
	}
	// Controls under the same allow.
	for _, path := range []string{
		"/api/v1/routing/bgp",
		"/api/v1/routing/bgp?type=summary",
		"/api/v1/security/nat/rules",
		"/api/v1/security/nat/rules?type=source",
	} {
		if err := call9952(t, srcOnly, "limited", "GET", path, ""); err != nil {
			t.Errorf("GET %s control refused under its own allow: %v", path, err)
		}
	}

	// Deny direction.
	routeDeny := cfg14146(t, "^show protocols bgp routes$|^show bgp routes$", "")
	if err := call9952(t, routeDeny, "limited", "GET", "/api/v1/routing/bgp?type=routes", ""); err == nil {
		t.Error("GET /api/v1/routing/bgp?type=routes ALLOWED under routes deny (#15076)")
	}
	if err := call9952(t, routeDeny, "limited", "GET", "/api/v1/routing/bgp", ""); err != nil {
		t.Errorf("BGP summary control refused by routes deny: %v", err)
	}
	dstDeny := cfg14146(t, "^show security nat destination rule$", "")
	if err := call9952(t, dstDeny, "limited", "GET", "/api/v1/security/nat/rules?type=destination", ""); err == nil {
		t.Error("GET /api/v1/security/nat/rules?type=destination ALLOWED under destination deny (#15076)")
	}
	if err := call9952(t, dstDeny, "limited", "GET", "/api/v1/security/nat/rules", ""); err != nil {
		t.Errorf("source NAT control refused by destination deny: %v", err)
	}
	// Unrestricted class unaffected, including unknown types.
	open := cfg14146(t, "^show version$", "")
	_ = open
	wide := cmdCfg9952(t)
	for _, path := range []string{"/api/v1/routing/bgp?type=routes", "/api/v1/routing/bgp?type=bogus", "/api/v1/security/nat/rules?type=destination"} {
		if err := call9952(t, wide, "wideopen", "GET", path, ""); err != nil {
			t.Errorf("GET %s refused for class with no regexes: %v", path, err)
		}
	}
	// Request-decoded registration: both routes must be classified as such.
	for _, route := range []string{"GET /api/v1/routing/bgp", "GET /api/v1/security/nat/rules"} {
		if !isRequestDecodedRoute9952(route) {
			t.Errorf("%s is not request-decoded; its ?type= selector cannot be charged (#15076)", route)
		}
		if _, charged := restRouteCommand[route]; charged {
			t.Errorf("%s still has a fixed restRouteCommand charge (#15076)", route)
		}
	}
	set := map[string]bool{}
	for _, c := range allRESTCanonicalCommands9952() {
		set[c] = true
	}
	for _, want := range []string{"show protocols bgp routes", "show security nat destination rule"} {
		if !set[want] {
			t.Errorf("REST advertised command set missing %q (#15076)", want)
		}
	}
}
