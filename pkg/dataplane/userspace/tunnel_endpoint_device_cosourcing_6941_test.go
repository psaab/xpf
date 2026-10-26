package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestTunnelEndpointDeviceIsCoSourced6941 binds the invariant that a tunnel
// endpoint's LinuxName and Ifindex come from ONE interface row.
//
// WHY THIS NEEDS A GUARD (#6941). For an interface-level `tunnel mode
// wireguard` whose LOWEST configured unit carries its own `tunnel` stanza, the
// emitted endpoint is keyed by that unit ref (#1910) while carrying the
// INTERFACE-level tunnel object. So routing materialises `wg0` from
// `ifc.Tunnel` (pkg/daemon/daemon_run_routehelpers.go -> pkg/routing/tunnel.go)
// while the dataplane binds the endpoint to `wg0u3`, the unit's device. The
// obvious repair is to make one side "agree" with the other. BOTH obvious
// repairs are outages, and neither is otherwise detectable:
//
//   - Setting the endpoint's LinuxName from the tunnel object while leaving
//     Ifindex alone breaks co-sourcing. userspace-dp compares
//     `endpoint.linux_name` against `ifindex_to_name[logical_ifindex]` in three
//     coherence gates (afxdp/coordinator/tunnel_supervision.rs
//     `wg_tombstone_respawn_coherent` :969-975, its GRE twin :502-507, and the
//     deferred prune :397-402). Today both read `wg0u3` and the gate passes;
//     after that edit they read `wg0` and `wg0u3`, so a tombstoned WireGuard
//     control thread NEVER RESPAWNS — a silent permanent outage after any
//     thread death.
//   - Repointing Ifindex at the parent row is worse: `logical_ifindex` becomes
//     `egress_ifindex` (afxdp/forwarding/tunnel.rs:74) and therefore the to-zone
//     every policy matches on, it keys `tunnel_endpoint_by_ifindex` (so a route
//     `next-hop @wg0.3` would stamp tunnel_endpoint_id 0 and never encapsulate),
//     and every live session stores the old value, so three re-ownership gates
//     turn those sessions drop-only.
//
// This test does NOT assert which device is correct — that is the open design
// question in #6941, and the answer is not "make these two strings match".
// It asserts only that whatever row the builder picks, it takes BOTH fields
// from that one row, so any future repair that desynchronises them fails here
// instead of in a tunnel that stops respawning in the field.
//
// THE DIVERGENT SHAPE IS IN THE FIXTURE ON PURPOSE. In every other tunnel shape
// the endpoint's tunnel object and its unit row already resolve to the same
// device name, so a mutation that swapped the source of LinuxName would be
// invisible: the two candidate values are equal. Only the divergent shape makes
// them differ, which is what gives this guard its teeth.
func TestTunnelEndpointDeviceIsCoSourced6941(t *testing.T) {
	const (
		priv  = "00bedd4ed26623ab2f765d16af2dcba4f6dbe17c284a66c6494b48b823f4c654"
		peerX = "04d9dab116416940a490d8bab5d0dd921094f0a278dee3db867df8fbd2db6e16"
	)
	wgBase := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + priv,
		"set interfaces wg0 tunnel wireguard peer " + peerX + " allowed-ips 10.0.0.0/24",
	}
	join := func(extra ...string) []string {
		return append(append([]string{}, wgBase...), extra...)
	}

	cases := []struct {
		name string
		cmds []string
		// wantDivergent records whether this shape is one where the endpoint's
		// own tunnel object names a DIFFERENT device than the row the builder
		// binds it to. It is asserted so the fixture cannot silently stop
		// covering the divergence that makes this guard mutation-sensitive.
		wantDivergent bool
	}{
		{
			name: "interface-level WG, lowest unit carries its own tunnel (#6941)",
			cmds: join(
				"set interfaces wg0 unit 3 family inet address 10.66.3.1/24",
				"set interfaces wg0 unit 3 tunnel mode gre",
				"set interfaces wg0 unit 3 tunnel source 10.1.1.1",
				"set interfaces wg0 unit 3 tunnel destination 10.1.1.2"),
			wantDivergent: true,
		},
		{
			name: "interface-level WG, plain unit",
			cmds: join("set interfaces wg0 unit 0 family inet address 10.66.0.1/24"),
		},
		{
			name: "interface-level WG, lower plain unit shadows the tunnel unit",
			cmds: join(
				"set interfaces wg0 unit 1 family inet address 10.66.1.1/24",
				"set interfaces wg0 unit 3 family inet address 10.66.3.1/24",
				"set interfaces wg0 unit 3 tunnel mode gre",
				"set interfaces wg0 unit 3 tunnel source 10.1.1.1",
				"set interfaces wg0 unit 3 tunnel destination 10.1.1.2"),
		},
		{
			name: "GRE per-unit tunnels",
			cmds: []string{
				"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 unit 2 tunnel source 10.0.0.3",
				"set interfaces gr-0/0/0 unit 2 tunnel destination 10.0.0.4",
			},
		},
		{
			name: "GRE interface-level plus a unit tunnel",
			cmds: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 unit 2 tunnel source 10.0.0.3",
				"set interfaces gr-0/0/0 unit 2 tunnel destination 10.0.0.4",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, c := range tc.cmds {
				p, err := config.ParseSetCommand(c)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", c, err)
				}
				if err := tree.SetPath(p); err != nil {
					t.Fatalf("SetPath(%q): %v", c, err)
				}
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}

			ifaces := buildInterfaceSnapshots(cfg)
			// buildTunnelEndpointSnapshots skips rows with Ifindex <= 0, and a
			// test host has none of these netdevs — without this the endpoint
			// list is EMPTY and every assertion below passes vacuously.
			for i := range ifaces {
				ifaces[i].Ifindex = 100 + i
			}
			byIfindex := make(map[int]InterfaceSnapshot, len(ifaces))
			for _, iface := range ifaces {
				byIfindex[iface.Ifindex] = iface
			}

			eps := buildTunnelEndpointSnapshots(cfg, ifaces)
			if len(eps) == 0 {
				t.Fatalf("no tunnel endpoints built — the fixture stopped exercising the builder")
			}

			sawDivergent := false
			for _, ep := range eps {
				row, ok := byIfindex[ep.Ifindex]
				if !ok {
					t.Fatalf("endpoint %q has Ifindex %d, which matches no interface row; "+
						"LinuxName and Ifindex must come from ONE row (#6941)",
						ep.Interface, ep.Ifindex)
				}
				if row.LinuxName != ep.LinuxName {
					t.Errorf("endpoint %q: LinuxName %q but the row at its Ifindex %d "+
						"(%q) has LinuxName %q. The two fields are no longer co-sourced, so "+
						"userspace-dp's endpoint.linux_name == ifindex_to_name[logical_ifindex] "+
						"coherence gates will not pass and a tombstoned tunnel control thread "+
						"will never respawn (#6941)",
						ep.Interface, ep.LinuxName, ep.Ifindex, row.Name, row.LinuxName)
				}
				if tunnelDeviceNameFor(cfg, ep.Interface) != "" && tunnelDeviceNameFor(cfg, ep.Interface) != ep.LinuxName {
					sawDivergent = true
				}
			}
			if sawDivergent != tc.wantDivergent {
				t.Errorf("divergence coverage changed: endpoint-tunnel-device != bound-device "+
					"was %v, fixture expects %v. This guard is only mutation-sensitive on a "+
					"shape where the two candidate device names DIFFER; if the divergent shape "+
					"stopped diverging, re-establish coverage rather than relaxing this",
					sawDivergent, tc.wantDivergent)
			}
		})
	}
}

// tunnelDeviceNameFor returns the device name the endpoint's OWN tunnel object
// carries, which is what routing keys its desired set by (TunnelConfig.Name,
// pkg/routing/tunnel.go). It is deliberately not used to assert correctness —
// only to prove the fixture still contains a shape where it disagrees with the
// device the builder binds.
func tunnelDeviceNameFor(cfg *config.Config, ifName string) string {
	for _, ep := range config.EmitTunnelEndpointNames(cfg) {
		if ep.Name == ifName && ep.Tunnel != nil {
			return ep.Tunnel.Name
		}
	}
	return ""
}
