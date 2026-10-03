package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820/#11421: the static render belt omits an entire route if any numeric
// next-hop has a different family from its destination. The shared predicate
// also drives strict rejection, helper snapshot exclusion and show
// annotations, so a partially-installed ECMP route cannot look fully active.
//
// FAIL-ON-REVERT: remove the shared predicate call from
// generateStaticRouteInTable and the omitted cells below render the invalid
// route again — each omission assertion fires RED.

func staticRoute9820(dest string, nhs ...config.NextHopEntry) *config.StaticRoute {
	return &config.StaticRoute{Destination: dest, Preference: 5, NextHops: nhs}
}

func TestStaticFamilyBeltDropsRouteWithCrossFamilyMember_9820(t *testing.T) {
	m := &Manager{}
	out := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "192.0.2.1"},
		config.NextHopEntry{Address: "2001:db8::1"},
	), "", 0, nil, nil, nil)
	if strings.TrimSpace(out) != "" {
		t.Fatalf("route with a cross-family member must be omitted entirely, got:\n%s", out)
	}
}

func TestStaticFamilyBeltAllBadRendersNothing_9820(t *testing.T) {
	m := &Manager{}
	out := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "192.0.2.1", Interface: "ge-0/0/1.0"},
	), "", 0, nil, nil, nil)
	if strings.TrimSpace(out) != "" {
		t.Fatalf("all-omitted route must render nothing, got:\n%s", out)
	}
}

func TestStaticFamilyBeltOmitsEitherCrossFamilyDirection11421(t *testing.T) {
	m := &Manager{}
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
	}{
		{"v4-destination-v6-gateway", staticRoute9820("10.0.0.0/8",
			config.NextHopEntry{Address: "2001:db8::1"},
			config.NextHopEntry{Address: "192.0.2.1"})},
		{"v4-destination-v6-gateway-qualified", staticRoute9820("10.0.0.0/8",
			config.NextHopEntry{Address: "2001:db8::1", Interface: "ge-0/0/1.0"})},
		{"v4-destination-mapped-v6-gateway", staticRoute9820("10.0.0.0/8",
			config.NextHopEntry{Address: "::ffff:192.0.2.1"})},
		{"v6-destination-v4-gateway", staticRoute9820("2001:db8::/32",
			config.NextHopEntry{Address: "192.0.2.1"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.generateStaticRouteInTable(tc.sr, "", 0, nil, nil, nil); strings.TrimSpace(got) != "" {
				t.Fatalf("cross-family next-hop must render nothing, got:\n%s", got)
			}
		})
	}
}

func TestStaticFamilyBeltKeptFormsByteIdentical_9820(t *testing.T) {
	m := &Manager{}
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
		want string
	}{
		{"v4-via-v4", staticRoute9820("10.0.0.0/8",
			config.NextHopEntry{Address: "192.0.2.1"}),
			"ip route 10.0.0.0/8 192.0.2.1 5\n"},
		{"v6-via-mapped", staticRoute9820("2001:db8::/32",
			config.NextHopEntry{Address: "::ffff:192.0.2.1"}),
			"ipv6 route 2001:db8::/32 ::ffff:192.0.2.1 5\n"},
		{"v6-interface-only", staticRoute9820("2001:db8::/32",
			config.NextHopEntry{Interface: "ge-0/0/1.0"}),
			"ipv6 route 2001:db8::/32 ge-0/0/1 5\n"},
		{"v6-via-v6-iface", staticRoute9820("2001:db8::/32",
			config.NextHopEntry{Address: "2001:db8::1", Interface: "ge-0/0/1.0"}),
			"ipv6 route 2001:db8::/32 2001:db8::1 ge-0/0/1 5\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.generateStaticRouteInTable(tc.sr, "", 0, nil, nil, nil); got != tc.want {
				t.Fatalf("render = %q, want %q", got, tc.want)
			}
		})
	}
}

// A same-family `@` form never reaches the address-family predicate: the
// existing FRR operand-shape belt drops the raw token first. This cell is
// NOT family-belt proof.
func TestStaticFamilyBeltAtFormsShapeDropped_9820(t *testing.T) {
	m := &Manager{}
	out := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "2001:db8::1@eth0"},
	), "", 0, nil, nil, nil)
	if strings.TrimSpace(out) != "" {
		t.Fatalf("raw @-form must stay shape-dropped, got:\n%s", out)
	}
}

// renderStaticFromLenientConfig drives the real tolerant ingress for
// statics: parse, compile LENIENTLY, then render the compiled route.
func renderStaticFromLenientConfig(t *testing.T, setCmds ...string) (rendered string, warnings []string) {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range setCmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must NOT fail: %v", err)
	}
	m := &Manager{}
	var b strings.Builder
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		b.WriteString(m.generateStaticRoute(sr, "", nil, nil, nil))
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		b.WriteString(m.generateStaticRoute(sr, "", nil, nil, nil))
	}
	return b.String(), cfg.Warnings
}

func TestStaticFamilyBeltLenientExcludesCrossFamilyRoute_9820(t *testing.T) {
	got, warnings := renderStaticFromLenientConfig(t,
		"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		"set routing-options static route 2001:db8::/32 next-hop 2001:db8::1",
		"set routing-options static route 2001:db8:1::/48 next-hop 2001:db8:1::1",
	)
	if strings.Contains(got, "2001:db8::/32") || strings.Contains(got, "192.0.2.1") {
		t.Fatalf("tolerant render emitted a route with a cross-family member:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route 2001:db8:1::/48 2001:db8:1::1 5\n") {
		t.Fatalf("tolerant render dropped the healthy control route:\n%s", got)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "static route next-hop family") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn next-hop family, warnings=%v", warnings)
	}
}

func TestStaticFamilyBeltLenientIPv4ViaIPv6Integration11421(t *testing.T) {
	got, warnings := renderStaticFromLenientConfig(t,
		"set routing-options static route 10.0.0.0/8 next-hop 2001:db8::1",
		"set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1",
		"set routing-options static route 10.1.0.0/16 next-hop 192.0.2.2",
	)
	if strings.Contains(got, "10.0.0.0/8") || strings.Contains(got, "2001:db8::1") {
		t.Fatalf("tolerant render emitted a route with an unrepresentable gateway:\n%s", got)
	}
	if !strings.Contains(got, "ip route 10.1.0.0/16 192.0.2.2 5\n") {
		t.Fatalf("tolerant render dropped the healthy control route:\n%s", got)
	}
	found := false
	for _, warning := range warnings {
		if strings.Contains(warning, "static route next-hop family") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn next-hop family, warnings=%v", warnings)
	}
}

// Non-vacuity: the lenient compile retains the bad value (so the belt,
// not the compiler, deserves the credit) and strict still refuses it.
func TestStaticFamilyBeltFixturesReachRenderer_9820(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 ||
		len(cfg.RoutingOptions.StaticRoutes[0].NextHops) != 1 ||
		cfg.RoutingOptions.StaticRoutes[0].NextHops[0].Address != "192.0.2.1" {
		t.Fatalf("lenient compile dropped the bad next-hop; belt cells vacuous: %+v",
			cfg.RoutingOptions.StaticRoutes)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted; the tolerant/strict split is gone")
	}
}
