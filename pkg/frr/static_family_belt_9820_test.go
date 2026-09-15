package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820: the static render belt omits an IPv4 next-hop on an IPv6
// destination (per next-hop, with a warning) on the tolerant path, where
// the strict gate's refusal is downgraded to a warning.
//
// FAIL-ON-REVERT: drop the family belt from generateStaticRouteInTable
// and the omitted cells below render the inert/interface-fill lines
// again — every omission assertion fires RED.

func staticRoute9820(dest string, nhs ...config.NextHopEntry) *config.StaticRoute {
	return &config.StaticRoute{Destination: dest, Preference: 5, NextHops: nhs}
}

func TestStaticFamilyBeltOmitsBadMemberKeepsGood_9820(t *testing.T) {
	m := &Manager{}
	out := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "192.0.2.1"},
		config.NextHopEntry{Address: "2001:db8::1"},
	), "", 0, nil, nil, nil)
	if strings.Contains(out, "192.0.2.1") {
		t.Fatalf("bad v4 next-hop reached frr.conf:\n%s", out)
	}
	if !strings.Contains(out, "ipv6 route 2001:db8::/32 2001:db8::1 5\n") {
		t.Fatalf("good ECMP member missing:\n%s", out)
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

func TestStaticFamilyBeltKeptFormsByteIdentical_9820(t *testing.T) {
	m := &Manager{}
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
		want string
	}{
		{"v4-via-v6", staticRoute9820("10.0.0.0/8",
			config.NextHopEntry{Address: "2001:db8::1"}),
			"ip route 10.0.0.0/8 2001:db8::1 5\n"},
		{"v6-via-mapped", staticRoute9820("2001:db8::/32",
			config.NextHopEntry{Address: "::ffff:192.0.2.1"}),
			"ipv6 route 2001:db8::/32 ::ffff:192.0.2.1 5\n"},
		{"v4-via-mapped", staticRoute9820("10.0.0.0/8",
			config.NextHopEntry{Address: "::ffff:192.0.2.1"}),
			"ip route 10.0.0.0/8 ::ffff:192.0.2.1 5\n"},
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

// `@`-forms never reach the family belt: the shape belt drops the raw
// token first (pre-existing). This cell documents the ordering — it is
// NOT family-belt proof.
func TestStaticFamilyBeltAtFormsShapeDropped_9820(t *testing.T) {
	m := &Manager{}
	out := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "192.0.2.1@eth0"},
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

func TestStaticFamilyBeltLenientIntegration_9820(t *testing.T) {
	got, warnings := renderStaticFromLenientConfig(t,
		"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		"set routing-options static route 2001:db8::/32 next-hop 2001:db8::1",
	)
	if strings.Contains(got, "192.0.2.1") {
		t.Fatalf("tolerant render emitted the bad next-hop:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route 2001:db8::/32 2001:db8::1 5\n") {
		t.Fatalf("tolerant render dropped the good member:\n%s", got)
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
