package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGenerateStaticRouteSecureTunnelUnit9942 is the fail-on-revert cell for
// the reported route mismatch. The xfrmi device is authored as st0.0 and the
// rendered static route must name that same device, not the generic st0 alias.
func TestGenerateStaticRouteSecureTunnelUnit9942(t *testing.T) {
	m := New()
	declared := map[string]string{"st0.0": "st0.0"}
	sr := &config.StaticRoute{
		Destination: "10.99.0.0/16",
		NextHops:    []config.NextHopEntry{{Interface: "st0.0"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil, declared)
	want := "ip route 10.99.0.0/16 st0.0\n"
	if got != want {
		t.Fatalf("rendered route = %q, want %q", got, want)
	}
	// This is the install-facing managed section, not only the helper's
	// intermediate output: the exact route line must survive full rendering.
	managed := m.buildManagedSection(&FullConfig{
		StaticRoutes:    []*config.StaticRoute{sr},
		DeclaredNetdevs: declared,
	})
	if !strings.Contains(managed, want) {
		t.Fatalf("managed section does not install rendered route %q:\n%s", want, managed)
	}
}

// TestAddSecureTunnelNetdevsUsesUnitResolver9942 is the resolver-call cell.
// Returning a spelling different from the reference proves the helper uses
// the resolver result instead of reconstructing a name from route text.
func TestAddSecureTunnelNetdevsUsesUnitResolver9942(t *testing.T) {
	declared := map[string]string{}
	var calls []string
	resolve := func(ref string) (string, bool) {
		calls = append(calls, ref)
		if ref == "st0.0" {
			return "device-from-resolver", true
		}
		return "", false
	}
	addSecureTunnelNetdevs(declared, []string{"st0.0"}, resolve)
	if len(calls) != 1 || calls[0] != "st0.0" {
		t.Fatalf("unit resolver calls = %v, want [st0.0]", calls)
	}
	if got := declared["st0.0"]; got != "device-from-resolver" {
		t.Fatalf("declared secure-tunnel device = %q, want resolver result", got)
	}
}

// TestDeclaredNetdevsForConfigSecureTunnelParity9942 pins the shared map
// constructor used by daemon and standalone CLI assembly.
func TestDeclaredNetdevsForConfigSecureTunnelParity9942(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wan0": {Name: "wan0"},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"explicit": {Name: "explicit", BindInterface: "st0.0"},
		"bare":     {Name: "bare", BindInterface: "st1"},
	}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "10.99.0.0/16",
		NextHops: []config.NextHopEntry{
			{Interface: "st0.0"},
			{Interface: "st1.0"},
		},
	}}
	got := DeclaredNetdevsForConfig(cfg, nil)
	want := map[string]string{
		"wan0":  "wan0",
		"st0.0": "st0.0",
		"st1.0": "st1",
		"st1":   "st1",
	}
	if len(got) != len(want) {
		t.Fatalf("declared map = %v, want %v", got, want)
	}
	for name, wantDev := range want {
		if got[name] != wantDev {
			t.Errorf("declared[%q] = %q, want %q (shared daemon/CLI map)", name, got[name], wantDev)
		}
	}
}

// TestGenerateStaticRouteNonTunnelUnitControls9942 pins the generic Junos
// unit behavior that must remain unchanged while st*.0 takes the resolver arm.
func TestGenerateStaticRouteNonTunnelUnitControls9942(t *testing.T) {
	m := New()
	cases := []struct {
		name  string
		iface string
		want  string
	}{
		{"bare secure tunnel", "st0", "ip route 10.99.0.0/16 st0\n"},
		{"ordinary unit zero", "wan0.0", "ip route 10.99.0.0/16 wan0\n"},
		{"ordinary vlan unit", "wan0.50", "ip route 10.99.0.0/16 wan0.50\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sr := &config.StaticRoute{
				Destination: "10.99.0.0/16",
				NextHops:    []config.NextHopEntry{{Interface: tc.iface}},
			}
			if got := m.generateStaticRoute(sr, "", nil, nil, nil); got != tc.want {
				t.Fatalf("render(%q) = %q, want %q", tc.iface, got, tc.want)
			}
		})
	}
}
