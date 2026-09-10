package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func wgConfig9521(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range append(lines, "set system dataplane-type userspace") {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func wgTunnelLines9521(name, port, key, peer, allowed string) []string {
	return []string{
		"set interfaces " + name + " tunnel mode wireguard",
		"set interfaces " + name + " tunnel wireguard listen-port " + port,
		"set interfaces " + name + " tunnel wireguard private-key " + key,
		"set interfaces " + name + " tunnel wireguard peer " + peer + " allowed-ips " + allowed,
	}
}

const (
	wgKeyA9521 = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	wgKeyB9521 = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

// TestSnapshotProgramsTheWarnedWireGuardPort9521 binds the builder wiring:
// buildSnapshot must stamp config.SteeredWireGuardListenPort onto the snapshot,
// and the ctrl-block reader must program that and nothing derived from rows.
//
// The real builder is used deliberately. It builds its interface rows from the
// host, and this host has no wg0/wg1 netdev, so its TunnelEndpoints come out
// EMPTY — the absent-netdev arrangement in which the pre-#9521 reader
// programmed 0 (nothing steered at all) while the warning named 51820. The
// explicit row cases pin the same property independently of the host.
func TestSnapshotProgramsTheWarnedWireGuardPort9521(t *testing.T) {
	two := append(wgTunnelLines9521("wg1", "51900", wgKeyA9521, wgKeyB9521, "10.2.0.0/24"),
		wgTunnelLines9521("wg0", "51820", wgKeyB9521, wgKeyA9521, "10.1.0.0/24")...)
	cfg := wgConfig9521(t, two...)
	wantPort, wantRef := config.SteeredWireGuardListenPort(cfg)
	if wantPort != 51820 || wantRef != "wg0" {
		t.Fatalf("fixture premise: steered should be (51820, wg0), got (%d, %q)", wantPort, wantRef)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if snap.WgSteeredListenPort != wantPort {
		t.Fatalf("buildSnapshot stamped WgSteeredListenPort = %d, want %d", snap.WgSteeredListenPort, wantPort)
	}
	if got := snapshotWgListenPort(snap); got != uint32(wantPort) {
		t.Fatalf("real builder (%d endpoint rows): the dataplane programs %d, the warning names %d",
			len(snap.TunnelEndpoints), got, wantPort)
	}

	// Rows present for the UNSTEERED tunnel only — the exact promotion case.
	onlyWg1 := []InterfaceSnapshot{{Name: "wg1", LinuxName: "wg1", Ifindex: 101}}
	snap.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, onlyWg1)
	if len(snap.TunnelEndpoints) != 1 || snap.TunnelEndpoints[0].WgListenPort != 51900 {
		t.Fatalf("fixture: want exactly wg1's endpoint row, got %+v", snap.TunnelEndpoints)
	}
	if got := snapshotWgListenPort(snap); got != uint32(wantPort) {
		t.Fatalf("with only the unsteered tunnel's netdev present the dataplane programs %d; "+
			"the warning names %d, so this is the #9521 divergence", got, wantPort)
	}

	// POSITIVE CONTROL: one tunnel is steered through the same builder.
	one := wgConfig9521(t, wgTunnelLines9521("wg5", "51855", wgKeyA9521, wgKeyB9521, "10.5.0.0/24")...)
	oneSnap, err := buildSnapshot(one, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(single): %v", err)
	}
	if got := snapshotWgListenPort(oneSnap); got != 51855 {
		t.Fatalf("single-tunnel config programs %d, want 51855", got)
	}

	// CONTROL: no WireGuard tunnel programs nothing, so the WG_RX gate stays off.
	none := wgConfig9521(t)
	noneSnap, err := buildSnapshot(none, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(none): %v", err)
	}
	if got := snapshotWgListenPort(noneSnap); got != 0 {
		t.Fatalf("no WireGuard tunnel, but the dataplane programs %d", got)
	}
}

// TestSnapshotWgSteeredListenPortWireKey9521 pins the JSON key the helper
// decodes. userspace-dp's `wg_steered_listen_port_wire_key_9521` pins the same
// literal from the other side; a misspelling on either side would decode as 0,
// and 0 makes the helper refuse kernel-path transport for every endpoint.
func TestSnapshotWgSteeredListenPortWireKey9521(t *testing.T) {
	raw, err := json.Marshal(&ConfigSnapshot{WgSteeredListenPort: 51820})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"wg_steered_listen_port":51820`) {
		t.Fatalf("snapshot JSON does not carry wg_steered_listen_port=51820: %s", raw)
	}
	raw, err = json.Marshal(&ConfigSnapshot{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "wg_steered_listen_port") {
		t.Fatalf("a snapshot with no WireGuard tunnel should omit the key: %s", raw)
	}
}
