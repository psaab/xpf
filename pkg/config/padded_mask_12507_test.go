package config

import (
	"slices"
	"strings"
	"testing"
)

// #12507: static-route destinations and IPsec selectors follow the userspace
// helper's ipnet mask grammar (#12178). Padding the helper parses ("/08",
// "/032") is accepted and written canonically, so FRR, the next-table applier,
// the family gate and the userspace FIB all see one spelling. Padding it
// refuses ("/008", "/0032") is rejected at strict commit; a tolerant load warns
// once per spelling and keeps the route (never excluded), so a discard route
// fails the helper snapshot closed instead of silently vanishing.

func compile12507(t *testing.T, cmds []string) (strict, tolerant *Config, strictErr error) {
	t.Helper()
	tree := buildTree(t, cmds)
	strict, strictErr = CompileConfig(tree)
	tolerant, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must boot: %v", err)
	}
	return strict, tolerant, strictErr
}

func warnings12507(cfg *Config) []string {
	var out []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12507") {
			out = append(out, warning)
		}
	}
	return out
}

func staticRoute12507(t *testing.T, routes []*StaticRoute, destination string) *StaticRoute {
	t.Helper()
	var got []string
	for _, route := range routes {
		if route == nil {
			continue
		}
		if route.Destination == destination {
			return route
		}
		got = append(got, route.Destination)
	}
	t.Fatalf("no compiled static route %q; have %v", destination, got)
	return nil
}

func TestStaticRouteHelperSupportedMaskPaddingIsCanonical12507(t *testing.T) {
	strict, tolerant, err := compile12507(t, []string{
		"set routing-options static route 10.0.0.0/08 discard",
		"set routing-options static route 0.0.0.0/00 next-hop 192.0.2.1",
		"set routing-options rib inet6.0 static route 2001:db8::/032 next-hop 2001:db8:ffff::1",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue routing-options static route 10.1.0.0/09 discard",
	})
	if err != nil {
		t.Fatalf("strict commit must accept helper-supported padding: %v", err)
	}
	for _, cfg := range []*Config{strict, tolerant} {
		if w := warnings12507(cfg); len(w) != 0 {
			t.Fatalf("helper-supported padding must not warn: %v", w)
		}
		discard := staticRoute12507(t, cfg.RoutingOptions.StaticRoutes, "10.0.0.0/8")
		if !discard.Discard {
			t.Fatalf("normalized discard route lost its disposition: %+v", discard)
		}
		staticRoute12507(t, cfg.RoutingOptions.StaticRoutes, "0.0.0.0/0")
		staticRoute12507(t, cfg.RoutingOptions.Inet6StaticRoutes, "2001:db8::/32")
		staticRoute12507(t, cfg.RoutingInstances[0].StaticRoutes, "10.1.0.0/9")
		for route, reason := range StaticRouteExclusions(cfg) {
			t.Errorf("normalized route %q excluded: %q", route.Destination, reason)
		}
		if got := staticRouteDestinationNames(discard); !strings.Contains(got, `also authored as "10.0.0.0/08"`) {
			t.Fatalf("diagnostics lost the authored spelling: %s", got)
		}
		// netip-based consumers (the FRR render belt, the family gate) parse
		// the canonical destination; they refused the padded one.
		if FRRAddrFamily(discard.Destination) != "v4" {
			t.Fatalf("netip cannot parse the normalized destination %q", discard.Destination)
		}
	}
}

// A helper-supported padded destination used to bypass the netip-based
// #9820/#11421 next-hop family gate; written canonically, it is caught.
func TestStaticRouteHelperSupportedPaddingReachesFamilyGate12507(t *testing.T) {
	_, _, err := compile12507(t, []string{
		"set routing-options static route 10.0.0.0/08 next-hop 2001:db8::1",
	})
	if err == nil || !strings.Contains(err.Error(), `"10.0.0.0/8"`) ||
		!strings.Contains(err.Error(), "IPv6 next-hop") {
		t.Fatalf("strict commit must apply the family gate to the normalized route: %v", err)
	}
}

func TestStaticRouteHelperRefusedMaskPaddingRejected12507(t *testing.T) {
	strict, tolerant, err := compile12507(t, []string{
		"set routing-options static route 10.0.0.0/008 discard",
		"set routing-options rib inet6.0 static route 2001:db8::/0032 next-hop 2001:db8:ffff::1",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue routing-options static route 10.1.0.0/008 discard",
	})
	if strict != nil || err == nil ||
		!strings.Contains(err.Error(), `routing-options static route "10.0.0.0/008"`) ||
		!strings.Contains(err.Error(), "userspace helper cannot parse") ||
		!strings.Contains(err.Error(), `write it as "10.0.0.0/8"`) {
		t.Fatalf("strict commit must refuse the helper-refused spelling: %v", err)
	}
	// One warning per spelling, not one for the first route only.
	warnings := warnings12507(tolerant)
	for _, want := range []string{
		`routing-options static route "10.0.0.0/008"`,
		`routing-options static route "2001:db8::/0032"`,
		`routing-instances blue static route "10.1.0.0/008"`,
	} {
		if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("tolerant load did not warn about %s: %v", want, warnings)
		}
	}
	if len(warnings) != 3 {
		t.Fatalf("want exactly three #12507 warnings, got %d: %v", len(warnings), warnings)
	}
	// The spelling is kept and the route is NOT excluded: excluding a discard
	// route would forward its traffic via a less-specific route, and would
	// split the next-table applier (which still installs it) from the FIB.
	discard := staticRoute12507(t, tolerant.RoutingOptions.StaticRoutes, "10.0.0.0/008")
	if !discard.Discard {
		t.Fatalf("tolerant discard route lost its disposition: %+v", discard)
	}
	staticRoute12507(t, tolerant.RoutingOptions.Inet6StaticRoutes, "2001:db8::/0032")
	staticRoute12507(t, tolerant.RoutingInstances[0].StaticRoutes, "10.1.0.0/008")
	for route, reason := range StaticRouteExclusions(tolerant) {
		t.Errorf("helper-refused route %q must stay published (fail-closed), excluded: %q", route.Destination, reason)
	}
}

// F1: a refused spelling folded into a same-prefix route must not commit.
func TestStaticRouteFoldedHelperRefusedAliasRejected12507(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmds     []string
		spelling string
		merged   string
	}{
		{"same-table", []string{
			"set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1",
			"set routing-options static route 10.0.0.0/008 next-hop 192.0.2.2",
		}, "10.0.0.0/008", "10.0.0.0/8"},
		{"cross-table", []string{
			"set routing-options static route 2001:db8::/32 next-hop 2001:db8:ffff::1",
			"set routing-options rib inet6.0 static route 2001:db8::/0032 next-hop 2001:db8:ffff::2",
		}, "2001:db8::/0032", "2001:db8::/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tolerant, err := compile12507(t, tc.cmds)
			want := `"` + tc.spelling + `" (merged into "` + tc.merged + `")`
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("strict commit must refuse the folded alias %s: %v", want, err)
			}
			if w := warnings12507(tolerant); len(w) != 1 || !strings.Contains(w[0], want) {
				t.Fatalf("tolerant load must warn once about %s: %v", want, w)
			}
			routes := append(slices.Clone(tolerant.RoutingOptions.StaticRoutes),
				tolerant.RoutingOptions.Inet6StaticRoutes...)
			route := staticRoute12507(t, routes, tc.merged)
			if len(route.NextHops) != 2 {
				t.Fatalf("folded route lost a source's next-hop: %+v", route.NextHops)
			}
			if reason := StaticRouteExclusions(tolerant)[route]; reason != "" {
				t.Fatalf("folded route excluded: %q", reason)
			}
		})
	}
}

// F2: whichever spelling is authored first, the parseable one survives the
// fold, so a redundant padded alias cannot withdraw the route.
func TestStaticRouteParseableSpellingSurvivesFold12507(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first      string
		strictOK   bool
		wantWarned bool
	}{
		{"helper-supported-first", "0.0.0.0/00", true, false},
		{"helper-refused-first", "0.0.0.0/000", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tolerant, err := compile12507(t, []string{
				"set routing-options static route " + tc.first + " next-hop 192.0.2.1",
				"set routing-options static route 0.0.0.0/0 next-hop 192.0.2.2",
			})
			if (err == nil) != tc.strictOK {
				t.Fatalf("strict commit err = %v, want ok=%v", err, tc.strictOK)
			}
			if got := len(warnings12507(tolerant)) > 0; got != tc.wantWarned {
				t.Fatalf("tolerant #12507 warning = %v, want %v: %v", got, tc.wantWarned, tolerant.Warnings)
			}
			if len(tolerant.RoutingOptions.StaticRoutes) != 1 {
				t.Fatalf("want one folded default route, got %d", len(tolerant.RoutingOptions.StaticRoutes))
			}
			route := staticRoute12507(t, tolerant.RoutingOptions.StaticRoutes, "0.0.0.0/0")
			if len(route.NextHops) != 2 {
				t.Fatalf("default route lost a next-hop: %+v", route.NextHops)
			}
			if reason := StaticRouteExclusions(tolerant)[route]; reason != "" {
				t.Fatalf("default route excluded: %q", reason)
			}
		})
	}
}

func TestIPsecSelectorHelperSupportedMaskPaddingIsCanonical12507(t *testing.T) {
	for _, v := range []string{"10.0.0.0/08", "2001:db8::/032", "::ffff:10.0.0.0/096"} {
		if reason := trafficSelectorValueReject(v); reason != "" {
			t.Fatalf("trafficSelectorValueReject(%q) = %q, want accepted", v, reason)
		}
	}
	strict, _, err := compile12507(t, []string{
		"set security ipsec vpn v4 bind-interface st0",
		"set security ipsec vpn v4 traffic-selector t1 local-ip 10.0.0.0/08",
		"set security ipsec vpn v4 traffic-selector t1 remote-ip 192.0.2.0/24",
		"set security ipsec vpn v6 bind-interface st1",
		"set security ipsec vpn v6 traffic-selector t1 local-ip 2001:db8::/032",
		"set security ipsec vpn v6 traffic-selector t1 remote-ip 2001:db8:ffff::/048",
		"set security ipsec vpn id bind-interface st2",
		"set security ipsec vpn id local-identity 10.1.0.0/09",
	})
	if err != nil {
		t.Fatalf("strict commit must accept helper-supported selector padding: %v", err)
	}
	vpns := strict.Security.IPsec.VPNs
	for _, tc := range []struct{ got, want string }{
		{vpns["v4"].TrafficSelectors["t1"].LocalIP, "10.0.0.0/8"},
		{vpns["v6"].TrafficSelectors["t1"].LocalIP, "2001:db8::/32"},
		{vpns["v6"].TrafficSelectors["t1"].RemoteIP, "2001:db8:ffff::/48"},
		{vpns["id"].LocalID, "10.1.0.0/9"},
	} {
		if tc.got != tc.want {
			t.Errorf("compiled selector = %q, want canonical %q", tc.got, tc.want)
		}
	}
	// The netip-based #11380 selector model parses the canonical value.
	pairs := ModeledIPsecSelectorPairs11380(vpns["v6"])
	if len(pairs) != 1 || !pairs[0].Local.Known || !pairs[0].Remote.Known {
		t.Fatalf("selector model could not parse the normalized selector: %+v", pairs)
	}
}

func TestIPsecSelectorHelperRefusedMaskPaddingRejected12507(t *testing.T) {
	for _, tc := range []struct {
		name, cmd, value, canonical string
		compiled                    func(*IPsecVPN) string
	}{
		{"local-ip-v4", "set security ipsec vpn v1 traffic-selector t1 local-ip 10.0.0.0/008",
			"10.0.0.0/008", "10.0.0.0/8",
			func(vpn *IPsecVPN) string { return vpn.TrafficSelectors["t1"].LocalIP }},
		{"remote-ip-v6", "set security ipsec vpn v1 traffic-selector t1 remote-ip 2001:db8::/0032",
			"2001:db8::/0032", "2001:db8::/32",
			func(vpn *IPsecVPN) string { return vpn.TrafficSelectors["t1"].RemoteIP }},
		{"local-identity", "set security ipsec vpn v1 local-identity 10.0.0.0/008",
			"10.0.0.0/008", "10.0.0.0/8",
			func(vpn *IPsecVPN) string { return vpn.LocalID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tolerant, err := compile12507(t, []string{
				"set security ipsec vpn v1 bind-interface st0", tc.cmd,
			})
			if err == nil || !strings.Contains(err.Error(), "userspace helper cannot parse") ||
				!strings.Contains(err.Error(), `write it as "`+tc.canonical+`"`) {
				t.Fatalf("strict commit must refuse %q: %v", tc.value, err)
			}
			if w := warnings12507(tolerant); len(w) != 1 || !strings.Contains(w[0], tc.value) {
				t.Fatalf("tolerant load must warn once about %q: %v", tc.value, w)
			}
			// Kept verbatim and still a selector shape: the swanctl child and
			// a bind-less fence row survive, so the helper refuses the
			// snapshot instead of the VPN's cleartext going unfenced.
			if got := tc.compiled(tolerant.Security.IPsec.VPNs["v1"]); got != tc.value {
				t.Fatalf("compiled selector = %q, want verbatim %q", got, tc.value)
			}
			if !IsTrafficSelectorShape(tc.value) {
				t.Fatalf("IsTrafficSelectorShape(%q) = false; the render belt would drop the fence", tc.value)
			}
		})
	}
	for _, ok := range []string{"10.0.0.0/8", "2001:db8::/32", "10.0.0.1", "10.0.0.1-10.0.0.9"} {
		if !IsTrafficSelectorShape(ok) || trafficSelectorValueReject(ok) != "" {
			t.Fatalf("canonical selector %q must stay valid", ok)
		}
	}
}

func TestNormalizeHelperSupportedCIDRMaskPadding12507(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.0/08", "10.0.0.0/8"},
		{"0.0.0.0/00", "0.0.0.0/0"},
		{"10.0.0.5/08", "10.0.0.5/8"},
		{"2001:db8::/032", "2001:db8::/32"},
		{"2001:db8::/000", "2001:db8::/0"},
		{"10.0.0.0/008", "10.0.0.0/008"},
		{"2001:db8::/0032", "2001:db8::/0032"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.0.0.1", "10.0.0.1"},
		{"10.0.0.1-10.0.0.9", "10.0.0.1-10.0.0.9"},
		{"CN=x/0OU", "CN=x/0OU"},
		{"10.0.0.0/033", "10.0.0.0/033"},
	} {
		if got := normalizeHelperSupportedCIDRMaskPadding(tc.in); got != tc.want {
			t.Errorf("normalizeHelperSupportedCIDRMaskPadding(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
