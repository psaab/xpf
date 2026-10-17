package config

import (
	"reflect"
	"testing"
)

// #14378 (DR4-H6): the validator accepts the scalar Rust-FIB forms
// `next-hop 10.0.0.1@eth0` and `next-hop @eth0`, and the userspace FIB
// installs them (its snapshot string is split at '@'), but the compiler
// stored the raw scalar in Address. FRR's next-hop operand gate
// (netip.ParseAddr) rejects '@', so the renderer silently dropped the
// route — the two FIBs disagreed on a strict-committed route.
//
// RED pre-fix: NextHops = [{Address:"10.0.0.1@eth0"} {Address:"@eth0"}].
// GREEN: the scalar is split into the structured Address+Interface form
// FRR already renders as `ip route <dst> <ip> <iface>`.

func TestStaticNextHopAtInterfaceSplit_14378(t *testing.T) {
	if err := ValidateStaticNextHop("10.0.0.1@eth0", nil); err != nil {
		t.Fatalf("validator must keep accepting 10.0.0.1@eth0: %v", err)
	}
	if err := ValidateStaticNextHop("@eth0", nil); err != nil {
		t.Fatalf("validator must keep accepting @eth0: %v", err)
	}

	// Flat `set` cannot spell '@' (the Junos lexer rejects it), so the
	// scalar reaches the compiler as a hierarchical quoted value — the
	// same spelling TestStaticNextHopFamilyQuotedAtFormRefused_9820 uses.
	c := compileHier3881(t, `routing-options { static {
		route 192.0.2.0/24 { next-hop "10.0.0.1@eth0"; }
		route 198.51.100.0/24 { next-hop "@eth0"; }
		route 203.0.113.0/24 { qualified-next-hop "10.0.0.2@eth0" { preference 200; } }
		route 2001:db8:114::/48 { next-hop "2001:db8::1@eth0"; }
	} }`)

	cases := []struct {
		dest string
		want []NextHopEntry
	}{
		{"192.0.2.0/24", []NextHopEntry{{Address: "10.0.0.1", Interface: "eth0"}}},
		{"198.51.100.0/24", []NextHopEntry{{Interface: "eth0"}}},
		{"203.0.113.0/24", []NextHopEntry{{Address: "10.0.0.2", Interface: "eth0", Preference: 200, HasPreference: true}}},
		{"2001:db8:114::/48", []NextHopEntry{{Address: "2001:db8::1", Interface: "eth0"}}},
	}
	for _, tc := range cases {
		r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, tc.dest)
		if r == nil {
			t.Fatalf("route %s missing", tc.dest)
		}
		if !reflect.DeepEqual(r.NextHops, tc.want) {
			t.Errorf("route %s NextHops = %+v, want %+v", tc.dest, r.NextHops, tc.want)
		}
	}

	// Hierarchical spelling exercises the child-node compiler path, and a
	// bracket ECMP list exercises the multi-gateway run.
	hier := compileHier3881(t, `routing-options { static {
		route 192.0.2.0/24 { next-hop "10.0.0.1@eth0"; }
		route 198.51.100.0/24 next-hop [ "10.0.0.1@eth0" "10.0.0.2@eth1" ];
	} }`)
	if r := findStaticRoute3871(t, hier.RoutingOptions.StaticRoutes, "192.0.2.0/24"); r == nil ||
		!reflect.DeepEqual(r.NextHops, []NextHopEntry{{Address: "10.0.0.1", Interface: "eth0"}}) {
		t.Fatalf("hier NextHops = %+v", r)
	}
	if r := findStaticRoute3871(t, hier.RoutingOptions.StaticRoutes, "198.51.100.0/24"); r == nil ||
		!reflect.DeepEqual(r.NextHops, []NextHopEntry{
			{Address: "10.0.0.1", Interface: "eth0"},
			{Address: "10.0.0.2", Interface: "eth1"},
		}) {
		t.Fatalf("list NextHops = %+v", r)
	}

	// Controls: bare IP, bare interface, and the structured
	// `next-hop <ip> interface <iface>` form compile exactly as before.
	ctrl := compileSets3870(t, []string{
		"set routing-options static route 192.0.2.0/24 next-hop 10.0.0.1",
		"set routing-options static route 198.51.100.0/24 next-hop eth0",
		"set routing-options static route 203.0.113.0/24 next-hop 10.0.0.1 interface ge-0/0/1.0",
	})
	controls := []struct {
		dest string
		want []NextHopEntry
	}{
		{"192.0.2.0/24", []NextHopEntry{{Address: "10.0.0.1"}}},
		{"198.51.100.0/24", []NextHopEntry{{Interface: "eth0"}}},
		{"203.0.113.0/24", []NextHopEntry{{Address: "10.0.0.1", Interface: "ge-0/0/1.0"}}},
	}
	for _, tc := range controls {
		r := findStaticRoute3871(t, ctrl.RoutingOptions.StaticRoutes, tc.dest)
		if r == nil || !reflect.DeepEqual(r.NextHops, tc.want) {
			t.Errorf("control route %s NextHops = %+v, want %+v", tc.dest, r, tc.want)
		}
	}

	// Direct unit pins for the compiler helper.
	if got := staticNextHopEntry("10.0.0.1@eth0", ""); got != (NextHopEntry{Address: "10.0.0.1", Interface: "eth0"}) {
		t.Errorf("staticNextHopEntry(ip@iface) = %+v", got)
	}
	if got := staticNextHopEntry("@eth0", ""); got != (NextHopEntry{Interface: "eth0"}) {
		t.Errorf("staticNextHopEntry(@iface) = %+v", got)
	}
	// An explicit structured interface stays authoritative and untouched.
	if got := staticNextHopEntry("10.0.0.1", "ge-0/0/1.0"); got != (NextHopEntry{Address: "10.0.0.1", Interface: "ge-0/0/1.0"}) {
		t.Errorf("staticNextHopEntry(structured) = %+v", got)
	}
}
