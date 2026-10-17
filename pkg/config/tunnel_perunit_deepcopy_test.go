package config

import (
	"strings"
	"testing"
)

// buildTree (ParseSetCommand + SetPath, NOT NewParser) is defined in
// compiler_equal_flow_worker_cap_test.go and reused here.

func addrList(unitTunnel *TunnelConfig) []string {
	if unitTunnel == nil {
		return nil
	}
	return unitTunnel.Addresses
}

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestPerUnitTunnelAddressesIndependent is the #3898 RED-on-revert gate for
// the Addresses aliasing. Two per-unit tunnels on gr-0/0/0 each set their own
// distinct address. Before the fix the per-unit inherit did a shallow
// `*tc = *ifc.Tunnel`, which copied only the Addresses slice HEADER, so both
// units aliased the interface-level tunnel's backing array. When each unit
// then appended its own address into the shared spare capacity, the
// second-processed unit overwrote the first-processed unit's slot, so unit 1
// ended up carrying unit 2's address (a DUPLICATE IP on two tunnel netdevs).
//
// The three seed units (100/101/102) exist only to grow the interface-level
// tunnel's Addresses slice to len 3 / cap 4 (one-at-a-time appends double the
// capacity: 1 -> 2 -> 4), giving the shared backing array the spare slot the
// aliasing bug writes into. With the deep-copy fix each unit owns an
// independent backing array, so its own address is never clobbered.
func TestPerUnitTunnelAddressesIndependent(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		// Seed units without a per-unit tunnel: their addresses accumulate
		// onto the interface-level tunnel's Addresses slice, building spare
		// capacity in the shared backing array.
		"set interfaces gr-0/0/0 unit 100 family inet address 10.9.0.1/30",
		"set interfaces gr-0/0/0 unit 101 family inet address 10.9.1.1/30",
		"set interfaces gr-0/0/0 unit 102 family inet address 10.9.2.1/30",
		// Two per-unit tunnels, each with its OWN distinct address.
		"set interfaces gr-0/0/0 unit 1 tunnel key 1",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.0.1.1/30",
		"set interfaces gr-0/0/0 unit 2 tunnel key 2",
		"set interfaces gr-0/0/0 unit 2 family inet address 10.0.2.1/30",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	u1, u2 := ifc.Units[1], ifc.Units[2]
	if u1 == nil || u1.Tunnel == nil {
		t.Fatal("unit 1 per-unit tunnel is nil")
	}
	if u2 == nil || u2.Tunnel == nil {
		t.Fatal("unit 2 per-unit tunnel is nil")
	}

	// Distinct devices (aliasing guard also protects Name, but Name is set
	// explicitly by the compiler after the copy so it is never aliased).
	if u1.Tunnel.Name == u2.Tunnel.Name {
		t.Fatalf("units 1 and 2 share tunnel Name %q", u1.Tunnel.Name)
	}

	a1, a2 := addrList(u1.Tunnel), addrList(u2.Tunnel)

	// Each unit must carry its OWN address...
	if !hasStr(a1, "10.0.1.1/30") {
		t.Errorf("unit 1 lost its own address 10.0.1.1/30: got %v", a1)
	}
	if !hasStr(a2, "10.0.2.1/30") {
		t.Errorf("unit 2 lost its own address 10.0.2.1/30: got %v", a2)
	}
	// ...and must NOT carry its sibling's per-unit address. This is the
	// contamination the aliasing bug produces (unit 1 ends up with unit 2's
	// address in the shared slot).
	if hasStr(a1, "10.0.2.1/30") {
		t.Errorf("unit 1 was contaminated with unit 2's address 10.0.2.1/30: got %v", a1)
	}
	if hasStr(a2, "10.0.1.1/30") {
		t.Errorf("unit 2 was contaminated with unit 1's address 10.0.1.1/30: got %v", a2)
	}

	// The two units must not share a backing array at all: mutating one must
	// not be observable in the other. (Independent from the content check
	// above; catches a partial fix that clones one field but keeps aliasing.)
	if len(a1) > 0 && len(a2) > 0 && &a1[0] == &a2[0] {
		t.Error("unit 1 and unit 2 tunnel Addresses share the same backing array")
	}
}

// TestPerUnitTunnelWgPeersIndependent is the #3898 RED-on-revert gate for the
// WgPeers aliasing. The interface-level tunnel is a WireGuard tunnel with three
// peers (X/Y/Z) — enough to grow WgPeers to len 3 / cap 4 (one-at-a-time
// appends double: 1 -> 2 -> 4) and leave a spare slot. Two per-unit tunnels each
// add their OWN distinct peer. Before the fix both units aliased the
// interface-level WgPeers backing array, so the second unit's peer overwrote
// the first unit's peer in the shared spare slot: unit 1 silently carried unit
// 2's peer instead of its own.
func TestPerUnitTunnelWgPeersIndependent(t *testing.T) {
	const (
		priv = "3de6404700006875ca73c26dfc1f4a50fa627601e24664d40310b975b40514c2"
		// X/Y/Z sort AFTER A/B on purpose (#7786). The merge appends the
		// interface-level peers before the per-unit ones, so pubkeys that
		// ascend in that order are already sorted by coincidence and the
		// emitted-order assertion below could not detect the sort being
		// dropped.
		peerX = "5a9303297e0c6babb14de8cfcc2a84491da7f760ec8bd9729494f71d17829980"
		peerY = "9120fd763bf1e7db2ccabc9b92a6b9e2ce66adab27c06fa060dc75ce2cfc971f"
		peerZ = "7359c9b96d8163cea105619230a228503e6ae19b4997f0e440c1f04cc46627a0"
		peerA = "6e2cc0919a4d6127938b531ab7cd6e69a908a780fd2b73083b31cba690abc177"
		peerB = "892f9db59473d45dad1b10a68e562115cc633c972e1664b1660990309792c228"
	)
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel mode wireguard",
		"set interfaces gr-0/0/0 tunnel wireguard listen-port 51820",
		"set interfaces gr-0/0/0 tunnel wireguard private-key " + priv,
		"set interfaces gr-0/0/0 tunnel wireguard peer " + peerX + " allowed-ips 10.100.0.0/24",
		"set interfaces gr-0/0/0 tunnel wireguard peer " + peerY + " allowed-ips 10.100.1.0/24",
		"set interfaces gr-0/0/0 tunnel wireguard peer " + peerZ + " allowed-ips 10.100.2.0/24",
		// Per-unit tunnels, each inheriting mode/listen-port/private-key/X/Y/Z
		// and adding its OWN distinct peer.
		"set interfaces gr-0/0/0 unit 1 tunnel wireguard peer " + peerA + " allowed-ips 10.200.1.0/24",
		"set interfaces gr-0/0/0 unit 2 tunnel wireguard peer " + peerB + " allowed-ips 10.200.2.0/24",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	u1, u2 := ifc.Units[1], ifc.Units[2]
	if u1 == nil || u1.Tunnel == nil || u2 == nil || u2.Tunnel == nil {
		t.Fatal("per-unit wireguard tunnels not found")
	}

	pubkeys := func(tc *TunnelConfig) []string {
		out := make([]string, 0, len(tc.WgPeers))
		for _, p := range tc.WgPeers {
			out = append(out, p.PublicKeyHex)
		}
		return out
	}
	p1, p2 := pubkeys(u1.Tunnel), pubkeys(u2.Tunnel)

	if !hasStr(p1, peerA) {
		t.Errorf("unit 1 lost its own peer %s: got %v", peerA, p1)
	}
	if hasStr(p1, peerB) {
		t.Errorf("unit 1 was contaminated with unit 2's peer %s: got %v", peerB, p1)
	}
	if !hasStr(p2, peerB) {
		t.Errorf("unit 2 lost its own peer %s: got %v", peerB, p2)
	}
	if hasStr(p2, peerA) {
		t.Errorf("unit 2 was contaminated with unit 1's peer %s: got %v", peerA, p2)
	}

	// The inherited X/Y/Z peers must still be present on both units.
	for _, u := range []struct {
		name string
		p    []string
	}{{"unit1", p1}, {"unit2", p2}} {
		for _, want := range []string{peerX, peerY, peerZ} {
			if !hasStr(u.p, want) {
				t.Errorf("%s lost inherited peer %s: got %v", u.name, want, u.p)
			}
		}
	}

	// Backing-array independence: the two units must not share WgPeers.
	if len(u1.Tunnel.WgPeers) > 0 && len(u2.Tunnel.WgPeers) > 0 &&
		&u1.Tunnel.WgPeers[0] == &u2.Tunnel.WgPeers[0] {
		t.Error("unit 1 and unit 2 tunnel WgPeers share the same backing array")
	}

	// #7786: every assertion above is about the COMPILED config, and all of
	// them passed for the entire period in which per-unit peers never reached
	// the dataplane at all. The interface-level WireGuard branch of
	// EmitTunnelEndpointNames discarded every per-unit TunnelConfig, and
	// buildTunnelEndpointSnapshots builds WgPeers from the emitted endpoint's
	// TunnelConfig, which is the only config->dataplane path for them. So this
	// test established the shape as SUPPORTED while nothing consumed it.
	//
	// Deliberately asserted here rather than in a separate file: the property
	// that makes the deep copy worth doing is that each unit's peer is
	// installed, and if that is guarded somewhere else it can be deleted
	// without this test noticing and the shape goes back to being tested at
	// the config layer and dead at the runtime layer.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 {
		t.Fatalf("interface-level WireGuard must emit exactly ONE endpoint (#1910); got %d", len(eps))
	}
	emitted := make([]string, 0, len(eps[0].Tunnel.WgPeers))
	for _, p := range eps[0].Tunnel.WgPeers {
		emitted = append(emitted, p.PublicKeyHex)
	}
	for _, want := range []string{peerX, peerY, peerZ, peerA, peerB} {
		if !hasStr(emitted, want) {
			t.Errorf("peer %s never reaches the dataplane: the emitted endpoint carries %v. "+
				"Per-unit peers are merged into the interface's single endpoint (#7786); "+
				"without that they are compiled, deep-copied and validated and then dropped",
				want, emitted)
		}
	}
	if len(emitted) != 5 {
		t.Errorf("emitted endpoint carries %d peers %v, want the 5 distinct pubkeys "+
			"(X/Y/Z inherited + A from unit 1 + B from unit 2) exactly once each",
			len(emitted), emitted)
	}
	// Sorted by pubkey so every consumer of this emitter sees one order
	// regardless of authoring or unit iteration (#1434 5.4).
	for i := 1; i < len(emitted); i++ {
		if emitted[i-1] >= emitted[i] {
			t.Errorf("emitted peers are not sorted by pubkey: %v", emitted)
			break
		}
	}
}

// TestPerUnitTunnelSingleUnitAndNoOverrideStillInherit guards the non-aliasing
// paths the #3898 fix must not regress: a single per-unit tunnel inherits the
// interface-level source/destination correctly, and a unit WITHOUT its own
// per-unit tunnel shares the interface-level tunnel (addresses collected onto
// it) rather than getting a separate device.
func TestPerUnitTunnelSingleUnitAndNoOverrideStillInherit(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 198.51.100.1",
		"set interfaces gr-0/0/0 tunnel destination 198.51.100.2",
		// unit 0: no per-unit tunnel -> shares the interface-level tunnel;
		// its address is collected onto ifc.Tunnel.
		"set interfaces gr-0/0/0 unit 0 family inet address 10.1.0.1/30",
		// unit 5: per-unit tunnel that overrides only the key, inheriting
		// source/destination from the interface-level tunnel.
		"set interfaces gr-0/0/0 unit 5 tunnel key 42",
		"set interfaces gr-0/0/0 unit 5 family inet address 10.5.0.1/30",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil || ifc.Tunnel == nil {
		t.Fatal("gr-0/0/0 interface tunnel not found")
	}

	// No-override unit shares the interface-level tunnel; its address landed
	// on ifc.Tunnel.Addresses.
	if !hasStr(ifc.Tunnel.Addresses, "10.1.0.1/30") {
		t.Errorf("interface-level tunnel missing no-override unit 0 address: got %v", ifc.Tunnel.Addresses)
	}
	if u0 := ifc.Units[0]; u0 != nil && u0.Tunnel != nil {
		t.Errorf("unit 0 (no per-unit tunnel) unexpectedly got its own tunnel device %q", u0.Tunnel.Name)
	}

	// Single per-unit tunnel inherits source/destination and owns its device.
	u5 := ifc.Units[5]
	if u5 == nil || u5.Tunnel == nil {
		t.Fatal("unit 5 per-unit tunnel is nil")
	}
	if u5.Tunnel.Source != "198.51.100.1" || u5.Tunnel.Destination != "198.51.100.2" {
		t.Errorf("unit 5 did not inherit source/destination: src=%q dst=%q",
			u5.Tunnel.Source, u5.Tunnel.Destination)
	}
	if u5.Tunnel.Key != 42 {
		t.Errorf("unit 5 key override lost: got %d, want 42", u5.Tunnel.Key)
	}
	if !hasStr(u5.Tunnel.Addresses, "10.5.0.1/30") {
		t.Errorf("unit 5 missing its own address 10.5.0.1/30: got %v", u5.Tunnel.Addresses)
	}
	if !strings.HasSuffix(u5.Tunnel.Name, "u5") {
		t.Errorf("unit 5 per-unit tunnel Name %q should end in u5", u5.Tunnel.Name)
	}
}

// TestTunnelConfigCloneForUnitDeepCopy exercises the cloneForUnit helper
// directly, including the nested per-peer AllowedIPs slice that the compile
// paths above do not mutate in place. Mutating the clone's slices (append into
// spare capacity, in-place element overwrite) must leave the original
// completely untouched.
func TestTunnelConfigCloneForUnitDeepCopy(t *testing.T) {
	orig := &TunnelConfig{
		Name:        "gr-0-0-0",
		Mode:        "wireguard",
		Source:      "10.0.0.1",
		Destination: "10.0.0.2",
		// len 2 / cap 4 so an append lands in spare capacity (in-place write
		// on a shared array would corrupt the original).
		Addresses: append(make([]string, 0, 4), "10.1.0.1/30", "10.1.0.2/30"),
		WgPeers: []WgPeerConfig{
			{PublicKeyHex: "aa", AllowedIPs: append(make([]string, 0, 4), "10.2.0.0/24")},
		},
	}
	clone := orig.cloneForUnit("gr-0-0-0u3")

	if clone.Name != "gr-0-0-0u3" {
		t.Errorf("clone Name = %q, want gr-0-0-0u3", clone.Name)
	}
	if orig.Name != "gr-0-0-0" {
		t.Errorf("clone mutated original Name: %q", orig.Name)
	}

	// Mutate the clone's Addresses: append (into spare cap) + in-place set.
	clone.Addresses = append(clone.Addresses, "10.9.9.9/30")
	clone.Addresses[0] = "255.255.255.255/32"
	if hasStr(orig.Addresses, "10.9.9.9/30") {
		t.Errorf("clone Addresses append leaked into original: %v", orig.Addresses)
	}
	if orig.Addresses[0] != "10.1.0.1/30" {
		t.Errorf("clone Addresses in-place write leaked into original: %v", orig.Addresses)
	}

	// Mutate the clone's WgPeers and the nested AllowedIPs.
	clone.WgPeers = append(clone.WgPeers, WgPeerConfig{PublicKeyHex: "bb"})
	clone.WgPeers[0].AllowedIPs = append(clone.WgPeers[0].AllowedIPs, "10.8.8.0/24")
	clone.WgPeers[0].AllowedIPs[0] = "0.0.0.0/0"
	if len(orig.WgPeers) != 1 {
		t.Errorf("clone WgPeers append leaked into original: len=%d", len(orig.WgPeers))
	}
	if hasStr(orig.WgPeers[0].AllowedIPs, "10.8.8.0/24") {
		t.Errorf("clone AllowedIPs append leaked into original: %v", orig.WgPeers[0].AllowedIPs)
	}
	if orig.WgPeers[0].AllowedIPs[0] != "10.2.0.0/24" {
		t.Errorf("clone AllowedIPs in-place write leaked into original: %v", orig.WgPeers[0].AllowedIPs)
	}
}
