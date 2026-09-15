package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9821 cell 11 (#15v3 + D7): declared-aware static-route device render.
//
// generateStaticRoute probes DeclaredNetdevs before the legacy `.0` strip:
// an authored declaration renders its kernel device, everything else keeps
// legacy behavior. The map is DEVICE-valued (both spellings → linux device),
// nil → legacy throughout.

// declaredNetdevs9821 builds the DeclaredNetdevs map the way the daemon's
// assembleFRRConfig does: EVERY declaration in BOTH spellings (authored +
// linux) → linux device. Unit refs are NOT keys — only declared names.
func declaredNetdevs9821(names ...string) map[string]string {
	out := make(map[string]string, 2*len(names))
	for _, n := range names {
		dev := config.LinuxIfName(n)
		out[n] = dev
		out[dev] = dev
	}
	return out
}

func staticRoute9821Iface(iface string) *config.StaticRoute {
	return &config.StaticRoute{
		Destination: "10.99.0.0/16",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1", Interface: iface}},
	}
}

func TestGenerateStaticRoute_DeclaredDotted_9821(t *testing.T) {
	m := New()
	declared := declaredNetdevs9821("ge-0/0/5.0", "ge-0/0/1", "wan0", "reth0")
	cases := []struct {
		name  string
		iface string
		want  string
	}{
		// Authored dotted declaration renders its kernel device (the issue
		// probe: legacy mis-stripped this to slash-broken `ge-0/0/5`).
		{"authored slash-spelled dotted", "ge-0/0/5.0", "ip route 10.99.0.0/16 10.0.0.1 ge-0-0-5.0\n"},
		// Both spellings are keyed.
		{"authored dash-spelled dotted", "ge-0-0-5.0", "ip route 10.99.0.0/16 10.0.0.1 ge-0-0-5.0\n"},
		// D7: authored slash-spelled UNDOTTED operands newly render kernel
		// names instead of FRR-choking verbatim slashes (intended repair).
		{"D7 undotted slash repair", "ge-0/0/1", "ip route 10.99.0.0/16 10.0.0.1 ge-0-0-1\n"},
		{"undotted dash", "ge-0-0-1", "ip route 10.99.0.0/16 10.0.0.1 ge-0-0-1\n"},
		// Unit refs are NOT declarations: legacy strip, unchanged.
		{"unit-zero strip", "wan0.0", "ip route 10.99.0.0/16 10.0.0.1 wan0\n"},
		// VLAN suffixes are real kernel names: verbatim, unchanged.
		{"vlan suffix verbatim", "wan0.50", "ip route 10.99.0.0/16 10.0.0.1 wan0.50\n"},
		// Inferred/undeclared operands miss the map: verbatim, unchanged.
		{"inferred verbatim", "ge-0-0-9.50", "ip route 10.99.0.0/16 10.0.0.1 ge-0-0-9.50\n"},
		// Junos UNIT refs keep the legacy strip (still slash-broken —
		// pre-existing, follow-up, NOT fixed here). Characterization pin.
		{"junos unit ref legacy strip", "ge-0/0/1.0", "ip route 10.99.0.0/16 10.0.0.1 ge-0/0/1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.generateStaticRoute(staticRoute9821Iface(tc.iface), "", nil, nil, declared); got != tc.want {
				t.Fatalf("render(%q) = %q, want %q", tc.iface, got, tc.want)
			}
		})
	}
}

func TestGenerateStaticRoute_DeclaredNilMapLegacy_9821(t *testing.T) {
	m := New()
	// nil map → legacy: the dotted declaration mis-strips (documents the
	// pre-#9821 behavior the map exists to fix), everything else identical.
	cases := []struct {
		iface string
		want  string
	}{
		{"ge-0/0/5.0", "ip route 10.99.0.0/16 10.0.0.1 ge-0/0/5\n"},
		{"ge-0/0/1", "ip route 10.99.0.0/16 10.0.0.1 ge-0/0/1\n"},
		{"wan0.0", "ip route 10.99.0.0/16 10.0.0.1 wan0\n"},
		{"wan0.50", "ip route 10.99.0.0/16 10.0.0.1 wan0.50\n"},
	}
	for _, tc := range cases {
		if got := m.generateStaticRoute(staticRoute9821Iface(tc.iface), "", nil, nil, nil); got != tc.want {
			t.Errorf("nil-map render(%q) = %q, want %q", tc.iface, got, tc.want)
		}
	}
}

func TestGenerateStaticRoute_DeclaredRethUnchanged_9821(t *testing.T) {
	m := New()
	declared := declaredNetdevs9821("ge-0/0/5.0", "ge-0/0/1", "wan0", "reth0")
	rethMap := map[string]string{"reth0": "ge-0/0/2"}
	// Reth operands miss the declared map (unit-qualified) or map to
	// themselves (bare `reth0` → `reth0`); the reth translation below the
	// probe then behaves exactly as before.
	if got, want := m.generateStaticRoute(staticRoute9821Iface("reth0.50"), "", rethMap, nil, declared),
		"ip route 10.99.0.0/16 10.0.0.1 ge-0-0-2.50\n"; got != want {
		t.Errorf("reth vlan = %q, want %q", got, want)
	}
	if got, want := m.generateStaticRoute(staticRoute9821Iface("reth0"), "", rethMap, nil, declared),
		"ip route 10.99.0.0/16 10.0.0.1 ge-0-0-2\n"; got != want {
		t.Errorf("reth bare = %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_DeclaredInferredV6Unchanged_9821(t *testing.T) {
	m := New()
	declared := declaredNetdevs9821("ge-0/0/5.0", "ge-0/0/1", "wan0")
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1"}},
	}
	nhIfaces := map[string]map[string]string{"": {"fe80::1": "ge-0-0-3.50"}}
	// The inferred operand is undeclared: misses the map, renders verbatim.
	if got, want := m.generateStaticRoute(sr, "", nil, nhIfaces, declared),
		"ipv6 route ::/0 fe80::1 ge-0-0-3.50\n"; got != want {
		t.Fatalf("inferred v6 = %q, want %q", got, want)
	}
}

func TestBuildManagedSection_DeclaredNetdevsThreaded_9821(t *testing.T) {
	m := New()
	declared := declaredNetdevs9821("ge-0/0/5.0", "ge-0/0/1", "wan0")
	fc := &FullConfig{
		DeclaredNetdevs: declared,
		StaticRoutes:    []*config.StaticRoute{staticRoute9821Iface("ge-0/0/5.0")},
		Inet6StaticRoutes: []*config.StaticRoute{{
			Destination: "2001:db8::/32",
			NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0/0/1"}},
		}},
		Instances: []InstanceConfig{{
			Name:    "BLUE",
			VRFName: "vrf-BLUE",
			StaticRoutes: []*config.StaticRoute{{
				Destination: "10.98.0.0/16",
				NextHops:    []config.NextHopEntry{{Address: "10.0.0.2", Interface: "ge-0/0/5.0"}},
			}},
			Inet6StaticRoutes: []*config.StaticRoute{{
				Destination: "2001:db8:1::/48",
				NextHops:    []config.NextHopEntry{{Address: "fe80::2", Interface: "wan0.0"}},
			}},
		}},
	}
	got := m.buildManagedSection(fc)
	for _, want := range []string{
		"ip route 10.99.0.0/16 10.0.0.1 ge-0-0-5.0\n",
		"ipv6 route 2001:db8::/32 fe80::1 ge-0-0-1\n",
		"ip route 10.98.0.0/16 10.0.0.2 ge-0-0-5.0 vrf vrf-BLUE\n",
		"ipv6 route 2001:db8:1::/48 fe80::2 wan0 vrf vrf-BLUE\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("managed section missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ge-0/0/") {
		t.Errorf("managed section still carries a slash-spelled operand:\n%s", got)
	}
}

// TestGenerateStaticRoute_OperandsPassTheBelt_9821 is the 13b FRR
// render-operand re-validation (belt-level): every operand the render emits
// for declared (incl. dotted) nexthops re-passes the belt — gateways are
// valid next-hop addresses and interface operands are slash-free kernel
// devices drawn from the declared set. It closes the loop cell 11 opens:
// the render is not just pinned, it is belt-clean input.
func TestGenerateStaticRoute_OperandsPassTheBelt_9821(t *testing.T) {
	m := New()
	declared := declaredNetdevs9821("ge-0/0/5.0", "ge-0/0/1")
	devices := map[string]bool{}
	for _, dev := range declared {
		devices[dev] = true
	}
	sr := &config.StaticRoute{
		Destination: "10.99.0.0/16",
		NextHops: []config.NextHopEntry{
			{Address: "10.0.0.1", Interface: "ge-0/0/5.0"},
			{Address: "10.0.0.2", Interface: "ge-0-0-5.0"},
			{Address: "10.0.0.3", Interface: "ge-0/0/1"},
		},
	}
	got := m.generateStaticRoute(sr, "", nil, nil, declared)
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Fatalf("rendered %d lines, want 3 (one per next-hop):\n%s", len(lines), got)
	}
	for _, line := range lines {
		// `ip route <dst> <gw> <iface>`
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "ip" || fields[1] != "route" {
			t.Fatalf("unparseable render line %q — the belt cannot validate what it cannot parse", line)
		}
		if !validFRRNextHopAddress(fields[3]) {
			t.Errorf("line %q: gateway %q fails the next-hop belt", line, fields[3])
		}
		iface := fields[4]
		if strings.Contains(iface, "/") {
			t.Errorf("line %q: interface operand %q carries a slash — FRR chokes on Junos spellings", line, iface)
		}
		if !devices[iface] {
			t.Errorf("line %q: interface operand %q is not a declared device", line, iface)
		}
	}
}
