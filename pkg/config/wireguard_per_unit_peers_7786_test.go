package config

import (
	"strings"
	"testing"
)

const (
	wg7786Priv  = "3de6404700006875ca73c26dfc1f4a50fa627601e24664d40310b975b40514c2"
	wg7786Priv2 = "5a9303297e0c6babb14de8cfcc2a84491da7f760ec8bd9729494f71d17829980"
	// PeerX sorts AFTER the unit peers on purpose. The merge appends the
	// interface-level peers first, so a fixture whose pubkeys ascend in that
	// same order is already sorted by coincidence and CANNOT detect the sort
	// being removed. Measured: with X="1111..." deleting the sort left every
	// assertion green.
	wg7786PeerX = "7359c9b96d8163cea105619230a228503e6ae19b4997f0e440c1f04cc46627a0"
	wg7786PeerA = "6e2cc0919a4d6127938b531ab7cd6e69a908a780fd2b73083b31cba690abc177"
	wg7786PeerB = "892f9db59473d45dad1b10a68e562115cc633c972e1664b1660990309792c228"
)

func wg7786Base() []string {
	return []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wg7786Priv,
		"set interfaces wg0 tunnel wireguard peer " + wg7786PeerX + " allowed-ips 10.100.0.0/24",
	}
}

func wg7786Compile(t *testing.T, cmds []string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	return CompileConfig(tree)
}

func wg7786EmittedPeers(t *testing.T, cfg *Config) []string {
	t.Helper()
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 {
		t.Fatalf("interface-level WireGuard emits exactly one endpoint (#1910); got %d", len(eps))
	}
	out := make([]string, 0, len(eps[0].Tunnel.WgPeers))
	for _, p := range eps[0].Tunnel.WgPeers {
		out = append(out, p.PublicKeyHex)
	}
	return out
}

// TestPerUnitWireguardPeersReachTheEndpoint7786 is the fail-on-revert gate for
// the merge. A peer authored under a unit must appear in the ONE endpoint an
// interface-level WireGuard interface emits, because that endpoint's
// TunnelConfig is the only path config peers have to the dataplane
// (pkg/dataplane/userspace/tunnels.go builds WgPeers from it).
func TestPerUnitWireguardPeersReachTheEndpoint7786(t *testing.T) {
	cfg, err := wg7786Compile(t, append(wg7786Base(),
		"set interfaces wg0 unit 1 tunnel wireguard peer "+wg7786PeerA+" allowed-ips 10.200.1.0/24",
		"set interfaces wg0 unit 2 tunnel wireguard peer "+wg7786PeerB+" allowed-ips 10.200.2.0/24"))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// The endpoint's REF is unchanged by the merge, which is what keeps
	// StableTunnelEndpointID (derived from this string) identical for every
	// existing config: only the peer set grows.
	eps := EmitTunnelEndpointNames(cfg)
	if eps[0].Name != "wg0.1" {
		t.Errorf("emitted ref = %q, want %q — the merge must not move the ref, or "+
			"StableTunnelEndpointID renumbers every existing WireGuard endpoint",
			eps[0].Name, "wg0.1")
	}
	if eps[0].Tunnel.Name != "wg0" {
		t.Errorf("emitted tunnel device = %q, want %q — the merge must not move the device "+
			"either (#6941 is the open question about which device this binds to; this "+
			"change must not perturb it)", eps[0].Tunnel.Name, "wg0")
	}

	got := wg7786EmittedPeers(t, cfg)
	want := []string{wg7786PeerX, wg7786PeerA, wg7786PeerB}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("peer %s missing from the emitted endpoint %v — a per-unit peer that is "+
				"compiled, deep-copied and validated but never emitted can never handshake, "+
				"and nothing else reports it", w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("emitted endpoint carries %d peers %v, want exactly %d", len(got), got, len(want))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("emitted peers must be sorted by pubkey so every consumer of this "+
				"emitter sees one order (#1434 5.4): %v", got)
			break
		}
	}
}

// TestPerUnitWireguardPeerDedup7786 pins that a peer inherited by a unit is not
// installed twice. Each unit's compiled tunnel carries the inherited peers as
// well as its own, so a merge that simply concatenated would offer the
// interface-level peer once per unit.
func TestPerUnitWireguardPeerDedup7786(t *testing.T) {
	cfg, err := wg7786Compile(t, append(wg7786Base(),
		"set interfaces wg0 unit 1 tunnel wireguard peer "+wg7786PeerA+" allowed-ips 10.200.1.0/24",
		"set interfaces wg0 unit 2 tunnel wireguard peer "+wg7786PeerB+" allowed-ips 10.200.2.0/24"))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// Precondition, asserted rather than assumed: each unit really does carry
	// the inherited peer, so concatenation really would duplicate it. Without
	// this the dedup assertion below could pass because there was nothing to
	// dedup.
	ifc := cfg.Interfaces.Interfaces["wg0"]
	for _, n := range []int{1, 2} {
		unit := ifc.Units[n]
		if unit == nil || unit.Tunnel == nil {
			t.Fatalf("unit %d has no tunnel; fixture no longer exercises the merge", n)
		}
		inherited := false
		for _, p := range unit.Tunnel.WgPeers {
			if p.PublicKeyHex == wg7786PeerX {
				inherited = true
			}
		}
		if !inherited {
			t.Fatalf("unit %d does not carry the inherited peer, so this fixture cannot "+
				"detect a duplicate", n)
		}
	}

	counts := map[string]int{}
	for _, p := range wg7786EmittedPeers(t, cfg) {
		counts[p]++
	}
	for pub, n := range counts {
		if n != 1 {
			t.Errorf("peer %s appears %d times in the emitted endpoint; each pubkey must be "+
				"installed once", pub, n)
		}
	}
}

// TestInterfaceLevelWireguardUnchangedWithoutUnitPeers7786 pins that a config
// with no per-unit peers is untouched by the merge — the emitter returns the
// interface-level object itself, so no existing endpoint's bytes move.
func TestInterfaceLevelWireguardUnchangedWithoutUnitPeers7786(t *testing.T) {
	cfg, err := wg7786Compile(t, append(wg7786Base(),
		"set interfaces wg0 unit 0 family inet address 10.66.0.1/24"))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 {
		t.Fatalf("want one endpoint, got %d", len(eps))
	}
	if eps[0].Tunnel != cfg.Interfaces.Interfaces["wg0"].Tunnel {
		t.Error("a WireGuard interface with no per-unit peers must emit the interface-level " +
			"TunnelConfig itself, not a copy — copying it for every config would risk moving " +
			"existing endpoints' serialized bytes for no reason")
	}
	if got := wg7786EmittedPeers(t, cfg); len(got) != 1 || got[0] != wg7786PeerX {
		t.Errorf("emitted peers = %v, want just the interface-level peer", got)
	}
}

// TestUnitWireguardIdentityOverrideRejected7786 pins the commit-time refusal of
// a unit that changes the local WireGuard identity.
//
// The shape is refused rather than merged because merging would offer a
// DIFFERENT identity's peers the parent's key, and rather than emitted because
// the model is one UDP socket and one identity per WireGuard interface. It is
// not academic: routing materialises the unit's TUN and WireGuardListenPorts()
// already collects the unit's port, so before this the host-inbound filter
// opened a port nothing listened on.
func TestUnitWireguardIdentityOverrideRejected7786(t *testing.T) {
	cases := []struct {
		name    string
		extra   []string
		wantSub string
	}{
		{
			name: "listen-port override",
			extra: []string{
				"set interfaces wg0 unit 1 tunnel wireguard listen-port 51999",
				"set interfaces wg0 unit 1 tunnel wireguard peer " + wg7786PeerA + " allowed-ips 10.200.1.0/24",
			},
			wantSub: "listen-port",
		},
		{
			name: "private-key override",
			extra: []string{
				"set interfaces wg0 unit 1 tunnel wireguard private-key " + wg7786Priv2,
				"set interfaces wg0 unit 1 tunnel wireguard peer " + wg7786PeerA + " allowed-ips 10.200.1.0/24",
			},
			wantSub: "private-key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wg7786Compile(t, append(wg7786Base(), tc.extra...))
			if err == nil {
				t.Fatalf("a unit overriding the WireGuard %s of an interface-level tunnel must "+
					"be refused at commit: the model is ONE UDP socket and ONE local identity "+
					"per WireGuard interface, and this shape half-wires a device and an open "+
					"port with no endpoint behind it", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("rejection message does not name %q, so an operator cannot tell which "+
					"leaf to remove: %v", tc.wantSub, err)
			}
		})
	}
}

// TestUnitLevelWireguardWithoutInterfaceTunnelStillAccepted7786 is the
// over-rejection guard. `interfaces wgN unit 0 tunnel mode wireguard` with NO
// interface-level stanza is the canonical per-unit spelling; it emits its own
// endpoint through the per-unit branch and must be untouched by the refusal
// above, which is scoped to units UNDER an interface-level WireGuard tunnel.
func TestUnitLevelWireguardWithoutInterfaceTunnelStillAccepted7786(t *testing.T) {
	cfg, err := wg7786Compile(t, []string{
		"set interfaces wg0 unit 0 tunnel mode wireguard",
		"set interfaces wg0 unit 0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 unit 0 tunnel wireguard private-key " + wg7786Priv,
		"set interfaces wg0 unit 0 tunnel wireguard peer " + wg7786PeerA + " allowed-ips 10.200.1.0/24",
		"set interfaces wg1 unit 0 tunnel mode wireguard",
		"set interfaces wg1 unit 0 tunnel wireguard listen-port 51999",
		"set interfaces wg1 unit 0 tunnel wireguard private-key " + wg7786Priv2,
		"set interfaces wg1 unit 0 tunnel wireguard peer " + wg7786PeerB + " allowed-ips 10.200.2.0/24",
	})
	if err != nil {
		t.Fatalf("the canonical per-unit WireGuard spelling must still compile; the #7786 "+
			"refusal is scoped to units under an INTERFACE-level WireGuard tunnel: %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 2 {
		t.Errorf("two per-unit WireGuard interfaces must emit two endpoints; got %d", got)
	}
}
