package frr

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileStaticReject5298 compiles flat-set lines to a typed *Config using the
// ParseSetCommand + SetPath loop (NewParser merges newlines across set lines —
// the documented parser gotcha), so the render below exercises the real
// compile → typed → FRR lowering, not a hand-built StaticRoute.
func compileStaticReject5298(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	c, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

func findStaticReject5298(t *testing.T, routes []*config.StaticRoute, dest string) *config.StaticRoute {
	t.Helper()
	for _, r := range routes {
		if r.Destination == dest {
			return r
		}
	}
	t.Fatalf("static route %s not found in compiled config", dest)
	return nil
}

// A committed `route <prefix> reject` must render an FRR unreachable route
// (`ip route <prefix> reject`) so matching traffic is dropped AND the source
// receives an ICMP unreachable — the Junos reject semantics. Before #5298 the
// compiler dropped the reject disposition and the renderer emitted NOTHING for
// the resulting no-next-hop route, so the reject prefix fell through to a
// less-specific route (a fail-wide). RED-on-revert: got == "" (route erased).
func TestStaticRejectRendersUnreachable_5298(t *testing.T) {
	m := New()
	c := compileStaticReject5298(t, []string{
		"set routing-options static route 10.9.0.0/16 reject",
		"set routing-options static route 2001:db8:dead::/48 reject",
	})

	v4 := findStaticReject5298(t, c.RoutingOptions.StaticRoutes, "10.9.0.0/16")
	if got, want := m.generateStaticRoute(v4, "", nil, nil, nil), "ip route 10.9.0.0/16 reject 5\n"; got != want {
		t.Errorf("v4 reject render = %q, want %q", got, want)
	}

	v6 := findStaticReject5298(t, c.RoutingOptions.StaticRoutes, "2001:db8:dead::/48")
	if got, want := m.generateStaticRoute(v6, "", nil, nil, nil), "ipv6 route 2001:db8:dead::/48 reject 5\n"; got != want {
		t.Errorf("v6 reject render = %q, want %q", got, want)
	}
}

// A committed `discard` must still render Null0 (RTN_BLACKHOLE, silent drop) —
// the symmetric #5298 disposition split must NOT regress discard into a reject.
func TestStaticDiscardRendersNull0_5298(t *testing.T) {
	m := New()
	c := compileStaticReject5298(t, []string{
		"set routing-options static route 10.8.0.0/16 discard",
		"set routing-options static route 2001:db8:beef::/48 discard",
	})

	v4 := findStaticReject5298(t, c.RoutingOptions.StaticRoutes, "10.8.0.0/16")
	if got, want := m.generateStaticRoute(v4, "", nil, nil, nil), "ip route 10.8.0.0/16 Null0 5\n"; got != want {
		t.Errorf("v4 discard render = %q, want %q", got, want)
	}

	v6 := findStaticReject5298(t, c.RoutingOptions.StaticRoutes, "2001:db8:beef::/48")
	if got, want := m.generateStaticRoute(v6, "", nil, nil, nil), "ipv6 route 2001:db8:beef::/48 Null0 5\n"; got != want {
		t.Errorf("v6 discard render = %q, want %q", got, want)
	}
}

// Direct render assertion (no compile) pinning the reject line shape at a
// non-default preference and in a VRF, mirroring the discard render contract.
func TestStaticRejectRenderShape_5298(t *testing.T) {
	m := New()

	// Default preference (0 in a hand-built route → no trailing distance).
	sr := &config.StaticRoute{Destination: "192.0.2.0/24", Reject: true}
	if got, want := m.generateStaticRoute(sr, "", nil, nil, nil), "ip route 192.0.2.0/24 reject\n"; got != want {
		t.Errorf("reject (no pref) = %q, want %q", got, want)
	}

	// Explicit preference + VRF.
	srPref := &config.StaticRoute{Destination: "192.0.2.0/24", Reject: true, Preference: 20}
	if got, want := m.generateStaticRoute(srPref, "blue", nil, nil, nil), "ip route 192.0.2.0/24 reject 20 vrf blue\n"; got != want {
		t.Errorf("reject (pref+vrf) = %q, want %q", got, want)
	}
}
