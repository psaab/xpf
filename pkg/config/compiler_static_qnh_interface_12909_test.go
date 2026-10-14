package config

import (
	"reflect"
	"strings"
	"testing"
)

// #12909: a qualified-next-hop whose gateway is a bare interface name
// (`qualified-next-hop st0.0`) is a floating backup over that device. Before
// #12909 the compiler stored the tunnel name in NextHopEntry.Address, where
// FRR's operand gate discarded it (not an IP) and the userspace FIB could not
// parse it — the backup silently never installed, and it skipped the #11422
// route-vs-selector gate. The gateway must compile to an interface-only entry,
// exactly like a plain `next-hop <ifname>` (#12036).
//
// FAIL-ON-REVERT: drop the promotion in compileStaticRoutes and every want
// below compiles with Address set — the reflect.DeepEqual asserts fire RED.

func TestQualifiedNextHopInterfaceGatewayPromotion12909(t *testing.T) {
	cases := []qnhCase12308{
		{
			name: "fully-inline route keys promote tunnel gateway",
			tree: qnhHier12308(`routing-options {
				static {
					route 10.9.0.0/16 next-hop 10.0.0.1 qualified-next-hop st0.0 preference 200;
				}
			}`),
			routes: qnhGlobal12308,
			dest:   "10.9.0.0/16",
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Interface: "st0.0", Preference: 200, HasPreference: true},
			},
		},
		{
			name: "braced qualified-next-hop promotes tunnel gateway",
			tree: qnhHier12308(`routing-options {
				static {
					route 10.9.0.0/16 {
						next-hop 10.0.0.1;
						qualified-next-hop st0.0 { preference 200; }
					}
				}
			}`),
			routes: qnhGlobal12308,
			dest:   "10.9.0.0/16",
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Interface: "st0.0", Preference: 200, HasPreference: true},
			},
		},
		{
			name: "flat-set bare leaf and modifier block merge on the promoted gateway",
			tree: qnhFlat12308(
				"set routing-options static route 10.9.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.9.0.0/16 qualified-next-hop st0.0",
				"set routing-options static route 10.9.0.0/16 qualified-next-hop st0.0 preference 200",
			),
			routes: qnhGlobal12308,
			dest:   "10.9.0.0/16",
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Interface: "st0.0", Preference: 200, HasPreference: true},
			},
		},
		{
			name: "two distinct tunnel backups never fold",
			tree: qnhFlat12308(
				"set routing-options static route 10.9.0.0/16 qualified-next-hop st0.0 preference 200",
				"set routing-options static route 10.9.0.0/16 qualified-next-hop st0.1 preference 250",
			),
			routes: qnhGlobal12308,
			dest:   "10.9.0.0/16",
			want: []NextHopEntry{
				{Interface: "st0.0", Preference: 200, HasPreference: true},
				{Interface: "st0.1", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "IP gateway keeps the address form",
			tree: qnhFlat12308(
				"set routing-options static route 10.9.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.9.0.0/16 qualified-next-hop 10.0.0.2 preference 250",
			),
			routes: qnhGlobal12308,
			dest:   "10.9.0.0/16",
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "explicit interface modifier keeps the address form",
			tree: qnhFlat12308(
				"set routing-options static route 10.9.0.0/16 qualified-next-hop 10.0.0.9 interface ge-0/0/1.0 preference 200",
			),
			routes: qnhGlobal12308,
			dest:   "10.9.0.0/16",
			want: []NextHopEntry{
				{Address: "10.0.0.9", Interface: "ge-0/0/1.0", Preference: 200, HasPreference: true},
			},
		},
		{
			name: "ipv6 destination promotes the tunnel gateway too",
			tree: qnhHier12308(`routing-options {
				rib inet6.0 static {
					route 2001:db8:9::/48 {
						next-hop 2001:db8::1;
						qualified-next-hop st0.1 { preference 210; }
					}
				}
			}`),
			routes: qnhInet6_12308,
			dest:   "2001:db8:9::/48",
			want: []NextHopEntry{
				{Address: "2001:db8::1"},
				{Interface: "st0.1", Preference: 210, HasPreference: true},
			},
		},
	}
	runQNHCases12308(t, cases)
}

// A promoted qualified-next-hop over a VPN's bind-interface must now enter
// the #11422 route-vs-rendered-selector gate: covered destinations commit,
// uncovered ones are refused at strict commit (fail-closed — before #12909
// the interface-valued backup skipped the gate entirely) and warn on the
// tolerant path while still compiling to the interface-only entry.
func TestQualifiedNextHopTunnelRouteSelectorGate12909(t *testing.T) {
	build := func(t *testing.T, route, remote string) *ConfigTree {
		t.Helper()
		commands := []string{
			"set security ike gateway gw address 198.51.100.1",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0",
			"set routing-options static route " + route,
		}
		commands = append(commands, selectorCommands11380("site", "to-peer", "10.1.0.0/24", remote)...)
		return buildBindIfaceTree(t, commands...)
	}

	t.Run("covered destination commits as interface-only backup", func(t *testing.T) {
		cfg, err := CompileConfig(build(t,
			"10.2.0.0/24 qualified-next-hop st0.0 preference 200", "10.2.0.0/24"))
		if err != nil {
			t.Fatalf("strict commit rejected a floating backup inside the rendered remote selector: %v", err)
		}
		route := findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.2.0.0/24")
		want := []NextHopEntry{{Interface: "st0.0", Preference: 200, HasPreference: true}}
		if !reflect.DeepEqual(route.NextHops, want) {
			t.Fatalf("next-hops = %+v, want %+v", route.NextHops, want)
		}
	})

	t.Run("uncovered destination is refused at strict commit", func(t *testing.T) {
		_, err := CompileConfig(build(t,
			"10.3.0.0/24 qualified-next-hop st0.0 preference 200", "10.2.0.0/24"))
		if err == nil {
			t.Fatal("strict commit accepted an interface-valued qualified-next-hop outside the rendered remote selector union")
		}
		for _, want := range []string{"#11422", "10.3.0.0/24", "st0.0", "site"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("route/selector rejection %q does not identify %q", err, want)
			}
		}
	})

	t.Run("uncovered destination warns on tolerant load", func(t *testing.T) {
		cfg, err := CompileConfigLenient(build(t,
			"10.3.0.0/24 qualified-next-hop st0.0 preference 200", "10.2.0.0/24"))
		if err != nil {
			t.Fatalf("tolerant compile rejected the mismatched backup: %v", err)
		}
		route := findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.3.0.0/24")
		if len(route.NextHops) != 1 || route.NextHops[0].Interface != "st0.0" {
			t.Fatalf("tolerant compile did not keep the promoted backup: %+v", route.NextHops)
		}
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, "#11422") && strings.Contains(warning, "10.3.0.0/24") {
				return
			}
		}
		t.Fatalf("tolerant compile did not warn about the uncovered tunnel backup: %v", cfg.Warnings)
	})
}
