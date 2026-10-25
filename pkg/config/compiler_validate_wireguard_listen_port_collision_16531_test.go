package config

import (
	"strings"
	"testing"
)

// hasWGListenPortCollision reports whether err carries the #16531
// duplicate-listen-socket rejection.
func hasWGListenPortCollision(err error) bool {
	return err != nil && strings.Contains(err.Error(), "#16531") &&
		strings.Contains(err.Error(), "listen-port")
}

// wgCollisionLines renders one strict-clean WireGuard tunnel on iface.
// priv/peer must be distinct valid keys per tunnel so no other gate fires.
func wgCollisionLines(iface, port, priv, peer, allowed string) []string {
	return []string{
		"set interfaces " + iface + " tunnel mode wireguard",
		"set interfaces " + iface + " tunnel wireguard listen-port " + port,
		"set interfaces " + iface + " tunnel wireguard private-key " + priv,
		"set interfaces " + iface + " tunnel wireguard peer " + peer + " allowed-ips " + allowed,
	}
}

// Additional distinct valid (non-degenerate) keys for two-tunnel fixtures.
const wgKeyD16531 = "26b8fd16500e6a671c69ef3dfa24e72ae7a463c3cf2a659b2969de785bb9850d"

// TestWireguardListenPortCollision16531 is the #16531 fail-on-revert guard.
// At the defective master, two WireGuard tunnels on one listen-port (same
// instance, or default plus a VRF) commit clean; each then binds its own
// [::]:port socket with no reuse option, the second bind fails EADDRINUSE,
// and that tunnel respawns every 3s without ever handshaking. The gate
// must refuse the colliding shapes at strict commit, keep the working
// shapes (distinct ports; VRF/VRF on one port) clean, and downgrade to a
// warning on the lenient path so an already-committed config still boots.
//
// Fail-on-revert: delete validateWireguardListenPortCollisionStrict's call
// in runTailGates (or its body) and cells (a), (c), (e), (g) go RED — the
// shared-port configs commit clean again.
func TestWireguardListenPortCollision16531(t *testing.T) {
	// (a) Two tunnels, same port, both default instance → strict reject
	// naming BOTH tunnels and the port.
	linesA := append(wgCollisionLines("wg0", "51820", wgKeyA, wgKeyB, "10.1.0.0/24"),
		wgCollisionLines("wg1", "51820", wgKeyC, wgKeyD16531, "10.2.0.0/24")...)
	linesA = append(linesA, "set system dataplane-type userspace")
	if _, err := CompileConfig(buildTree4953(t, linesA)); !hasWGListenPortCollision(err) {
		t.Fatalf("(a) two default-instance tunnels on 51820 must be rejected (#16531), got %v", err)
	} else {
		for _, want := range []string{`"wg0"`, `"wg1"`, "51820"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("(a) rejection must name %s, got %v", want, err)
			}
		}
	}

	// (b) Distinct ports, both default → clean (over-reject guard).
	linesB := append(wgCollisionLines("wg0", "51820", wgKeyA, wgKeyB, "10.1.0.0/24"),
		wgCollisionLines("wg1", "51821", wgKeyC, wgKeyD16531, "10.2.0.0/24")...)
	linesB = append(linesB, "set system dataplane-type userspace")
	if _, err := CompileConfig(buildTree4953(t, linesB)); err != nil {
		t.Fatalf("(b) distinct ports must commit clean, got %v", err)
	}

	// (c) Default plus VRF on the same port → strict reject. The default
	// wildcard socket conflicts with the vrf-blue device bind.
	linesC := append(wgCollisionLines("wg0", "51820", wgKeyA, wgKeyB, "10.1.0.0/24"),
		wgCollisionLines("wg1", "51820", wgKeyC, wgKeyD16531, "10.2.0.0/24")...)
	linesC = append(linesC,
		"set interfaces wg1 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
		"set system dataplane-type userspace")
	if _, err := CompileConfig(buildTree4953(t, linesC)); !hasWGListenPortCollision(err) {
		t.Fatalf("(c) default+VRF on 51820 must be rejected (#16531), got %v", err)
	} else {
		for _, want := range []string{`"wg0"`, `"wg1"`, "51820"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("(c) rejection must name %s, got %v", want, err)
			}
		}
	}

	// (d) Two DIFFERENT VRFs on the same port → clean: each socket binds
	// its own vrf-<instance> device, so the port spaces are disjoint.
	linesD := append(wgCollisionLines("wg0", "51820", wgKeyA, wgKeyB, "10.1.0.0/24"),
		wgCollisionLines("wg1", "51820", wgKeyC, wgKeyD16531, "10.2.0.0/24")...)
	linesD = append(linesD,
		"set interfaces wg0 tunnel routing-instance destination blue",
		"set interfaces wg1 tunnel routing-instance destination red",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances red instance-type virtual-router",
		"set system dataplane-type userspace")
	if _, err := CompileConfig(buildTree4953(t, linesD)); err != nil {
		t.Fatalf("(d) different VRFs on one port must commit clean, got %v", err)
	}

	// (e) Same VRF on the same port (explicit stanza scope) → reject.
	linesE := append(wgCollisionLines("wg0", "51820", wgKeyA, wgKeyB, "10.1.0.0/24"),
		wgCollisionLines("wg1", "51820", wgKeyC, wgKeyD16531, "10.2.0.0/24")...)
	linesE = append(linesE,
		"set interfaces wg0 tunnel routing-instance destination blue",
		"set interfaces wg1 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
		"set system dataplane-type userspace")
	if _, err := CompileConfig(buildTree4953(t, linesE)); !hasWGListenPortCollision(err) {
		t.Fatalf("(e) same VRF on 51820 must be rejected (#16531), got %v", err)
	}

	// (f) Same VRF on the same port via routing-instance interface-list
	// membership (no tunnel routing-instance stanza) → reject. This is
	// the snapshot builder's second scope path (iface.RoutingInstance).
	linesF := append(wgCollisionLines("wg0", "51820", wgKeyA, wgKeyB, "10.1.0.0/24"),
		wgCollisionLines("wg1", "51820", wgKeyC, wgKeyD16531, "10.2.0.0/24")...)
	linesF = append(linesF,
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface wg0",
		"set routing-instances blue interface wg1",
		"set system dataplane-type userspace")
	if _, err := CompileConfig(buildTree4953(t, linesF)); !hasWGListenPortCollision(err) {
		t.Fatalf("(f) same VRF by interface-list membership on 51820 must be rejected (#16531), got %v", err)
	}

	// (g) Lenient path: the (a) shape WARNS instead of rejecting, so an
	// already-committed config still boots (#1960 no-brick).
	cfgG, err := CompileConfigLenient(buildTree4953(t, linesA))
	if err != nil {
		t.Fatalf("(g) lenient compile must not reject a colliding pair, got %v", err)
	}
	found := false
	for _, w := range cfgG.Warnings {
		if strings.Contains(w, "#16531") {
			found = true
			if !strings.Contains(w, "51820") || !strings.Contains(w, "wg0") || !strings.Contains(w, "wg1") {
				t.Fatalf("(g) lenient warning must name both tunnels and the port, got %q", w)
			}
		}
	}
	if !found {
		t.Fatalf("(g) lenient compile must warn on the colliding pair (#16531), warnings=%v", cfgG.Warnings)
	}

	// (h) Direct gate cells: nil config clean; one tunnel clean; a GRE
	// tunnel on a numerically equal "port" is not a WireGuard socket.
	if w, err := validateWireguardListenPortCollisionStrict(nil, false); err != nil || len(w) != 0 {
		t.Fatalf("(h) nil config must be clean, got err=%v warns=%v", err, w)
	}
	one := &Config{}
	one.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"wg0":      {Name: "wg0", Tunnel: &TunnelConfig{Name: "wg0", Mode: TunnelModeWireGuard, WgListenPort: 51820}},
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{Name: "gr-0/0/0", Mode: TunnelModeGRE, Source: "192.0.2.1", Destination: "192.0.2.2"}},
	}
	if w, err := validateWireguardListenPortCollisionStrict(one, false); err != nil || len(w) != 0 {
		t.Fatalf("(h) single WG tunnel + GRE must be clean, got err=%v warns=%v", err, w)
	}

	// (i) Direct gate: distinct-object per-unit tunnels on one interface
	// family. Two per-unit WG tunnels (no interface-level stanza) emit
	// one endpoint each; same port in the default instance collides.
	twoUnits := &Config{}
	twoUnits.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"wg0": {Name: "wg0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Tunnel: &TunnelConfig{Name: "wg0", Mode: TunnelModeWireGuard, WgListenPort: 51820}},
			1: {Number: 1, Tunnel: &TunnelConfig{Name: "wg0u1", Mode: TunnelModeWireGuard, WgListenPort: 51820}},
		}},
	}
	if _, err := validateWireguardListenPortCollisionStrict(twoUnits, false); !hasWGListenPortCollision(err) {
		t.Fatalf("(i) two per-unit WG tunnels on 51820 must be rejected, got %v", err)
	}

	// (j) Determinism: the reported owner is the first-sorting endpoint
	// across repeated runs.
	for i := range 25 {
		_, err := CompileConfig(buildTree4953(t, linesA))
		if !hasWGListenPortCollision(err) || !strings.Contains(err.Error(), `"wg0"`) {
			t.Fatalf("(j) iteration %d: owner report must be stable, got %v", i, err)
		}
	}
}
