package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"

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

// TestSnapshotProgramsTheWarnedWireGuardSet9587 binds the builder wiring:
// buildSnapshot must stamp the SELECTED steered set onto the snapshot, and
// the ctrl-block programmer must encode that and nothing derived from rows.
//
// The real builder is used deliberately. It builds its interface rows from the
// host, and this host has no wg0/wg1 netdev, so its TunnelEndpoints come out
// EMPTY — the absent-netdev arrangement in which the pre-#9521 reader
// programmed 0 (nothing steered at all) while the warning named ports. The
// explicit row cases pin the same property independently of the host.
func TestSnapshotProgramsTheWarnedWireGuardSet9587(t *testing.T) {
	two := append(wgTunnelLines9521("wg1", "51900", wgKeyA9521, wgKeyB9521, "10.2.0.0/24"),
		wgTunnelLines9521("wg0", "51820", wgKeyB9521, wgKeyA9521, "10.1.0.0/24")...)
	cfg := wgConfig9521(t, two...)
	_, wantSelected, wantOverflow := config.SplitSteeredPorts(config.SteeredWireGuardListenPorts(cfg))
	if !reflect.DeepEqual(wantSelected, []uint16{51820, 51900}) || len(wantOverflow) != 0 {
		t.Fatalf("fixture premise: selected should be [51820 51900] with no overflow, got (%v, %v)",
			wantSelected, wantOverflow)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !reflect.DeepEqual(snap.WgSteeredListenPorts, wantSelected) {
		t.Fatalf("buildSnapshot stamped WgSteeredListenPorts = %v, want %v",
			snap.WgSteeredListenPorts, wantSelected)
	}
	if got := snapshotWgListenPorts(snap); !reflect.DeepEqual(got, wantSelected) {
		t.Fatalf("real builder (%d endpoint rows): the dataplane programs %v, the warning names %v",
			len(snap.TunnelEndpoints), got, wantSelected)
	}
	if count, ports := encodeSteeredPortSet(snapshotWgListenPorts(snap)); count != 2 ||
		ports[0] != 51820 || ports[1] != 51900 {
		t.Fatalf("ctrl encode = (%d, %v), want (2, [51820 51900 ...])", count, ports)
	}

	// Rows present for the UNSTEERED-order tunnel only — the exact promotion
	// case the #9521 reader failed: rows must not move the programmed set.
	onlyWg1 := []InterfaceSnapshot{{Name: "wg1", LinuxName: "wg1", Ifindex: 101}}
	snap.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, onlyWg1)
	if len(snap.TunnelEndpoints) != 1 || snap.TunnelEndpoints[0].WgListenPort != 51900 {
		t.Fatalf("fixture: want exactly wg1's endpoint row, got %+v", snap.TunnelEndpoints)
	}
	if got := snapshotWgListenPorts(snap); !reflect.DeepEqual(got, wantSelected) {
		t.Fatalf("with only one tunnel's netdev present the dataplane programs %v; "+
			"the warning names %v, so this is the #9521 divergence", got, wantSelected)
	}

	// POSITIVE CONTROL: one tunnel is steered through the same builder.
	one := wgConfig9521(t, wgTunnelLines9521("wg5", "51855", wgKeyA9521, wgKeyB9521, "10.5.0.0/24")...)
	oneSnap, err := buildSnapshot(one, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(single): %v", err)
	}
	if got := snapshotWgListenPorts(oneSnap); !reflect.DeepEqual(got, []uint16{51855}) {
		t.Fatalf("single-tunnel config programs %v, want [51855]", got)
	}

	// CONTROL: no WireGuard tunnel programs nothing, so the WG_RX gate stays off.
	none := wgConfig9521(t)
	noneSnap, err := buildSnapshot(none, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(none): %v", err)
	}
	if got := snapshotWgListenPorts(noneSnap); len(got) != 0 {
		t.Fatalf("no WireGuard tunnel, but the dataplane programs %v", got)
	}
}

// TestSnapshotWgSteeredListenPortsWireKey9587 pins the JSON key the helper
// decodes. userspace-dp's `wg_steered_listen_ports_wire_key_9587` pins the same
// literal from the other side; a misspelling on either side would decode as
// empty, and empty makes the helper refuse kernel-path transport for every
// endpoint.
func TestSnapshotWgSteeredListenPortsWireKey9587(t *testing.T) {
	raw, err := json.Marshal(&ConfigSnapshot{WgSteeredListenPorts: []uint16{51820, 51900}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"wg_steered_listen_ports":[51820,51900]`) {
		t.Fatalf("snapshot JSON does not carry wg_steered_listen_ports=[51820,51900]: %s", raw)
	}
	raw, err = json.Marshal(&ConfigSnapshot{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "wg_steered_listen_ports") {
		t.Fatalf("a snapshot with no WireGuard tunnel should omit the key: %s", raw)
	}
}

// TestEncodeSteeredPortSetClamps9587 pins the programmer contract: the only
// producer is SplitSteeredPorts (len <= MAX), and the encoder clamps a longer
// input defensively instead of overflowing the fixed array. The tail stays
// zero-filled so zero never matches on the shim side.
func TestEncodeSteeredPortSetClamps9587(t *testing.T) {
	count, ports := encodeSteeredPortSet([]uint16{51820, 51900})
	if count != 2 || ports[0] != 51820 || ports[1] != 51900 || ports[2] != 0 || ports[7] != 0 {
		t.Fatalf("encode([51820 51900]) = (%d, %v), want (2, [51820 51900 0 ...])", count, ports)
	}
	long := []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	count, ports = encodeSteeredPortSet(long)
	if count != config.MaxSteeredWireGuardPorts {
		t.Fatalf("encode(10 ports) count = %d, want clamped to %d", count, config.MaxSteeredWireGuardPorts)
	}
	for i, want := range []uint16{1, 2, 3, 4, 5, 6, 7, 8} {
		if ports[i] != want {
			t.Fatalf("encode(10 ports) ports[%d] = %d, want %d (first-8 kept)", i, ports[i], want)
		}
	}
	if count, _ := encodeSteeredPortSet(nil); count != 0 {
		t.Fatalf("encode(nil) count = %d, want 0", count)
	}
}

// TestUserspaceCtrlLayoutMatchesShim9587 pins the Go<->Rust ctrl ABI from the
// Go side: total size, every field offset, the exact Rust field order/types
// parsed from userspace-xdp/src/lib.rs (like
// TestSnapshotProtocolVersionLockstepWithRust parses control.rs — a constant
// restated in a comment is a copy that goes stale silently), and the bound
// constant equal across Go, the shim crate and the helper crate.
func TestUserspaceCtrlLayoutMatchesShim9587(t *testing.T) {
	if got := unsafe.Sizeof(userspaceCtrlValue{}); got != 56 {
		t.Fatalf("Sizeof(userspaceCtrlValue) = %d, want 56 (40 + 16 for count+array)", got)
	}
	offsets := map[string]uintptr{
		"Enabled":            0,
		"MetadataVersion":    4,
		"Workers":            8,
		"QueueCount":         12,
		"Flags":              16,
		"WgPortCount":        20,
		"WgPorts":            24,
		"ConfigGeneration":   40,
		"FIBGeneration":      48,
		"HeartbeatTimeoutMS": 52,
	}
	var zero userspaceCtrlValue
	got := map[string]uintptr{
		"Enabled":            unsafe.Offsetof(zero.Enabled),
		"MetadataVersion":    unsafe.Offsetof(zero.MetadataVersion),
		"Workers":            unsafe.Offsetof(zero.Workers),
		"QueueCount":         unsafe.Offsetof(zero.QueueCount),
		"Flags":              unsafe.Offsetof(zero.Flags),
		"WgPortCount":        unsafe.Offsetof(zero.WgPortCount),
		"WgPorts":            unsafe.Offsetof(zero.WgPorts),
		"ConfigGeneration":   unsafe.Offsetof(zero.ConfigGeneration),
		"FIBGeneration":      unsafe.Offsetof(zero.FIBGeneration),
		"HeartbeatTimeoutMS": unsafe.Offsetof(zero.HeartbeatTimeoutMS),
	}
	if !reflect.DeepEqual(got, offsets) {
		t.Fatalf("userspaceCtrlValue offsets = %v, want %v", got, offsets)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "userspace-xdp", "src", "lib.rs"))
	if err != nil {
		t.Fatalf("read shim lib.rs: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, "struct UserspaceCtrl {")
	if start < 0 {
		t.Fatalf("UserspaceCtrl struct not found in userspace-xdp/src/lib.rs")
	}
	block := src[start:]
	end := strings.Index(block, "\n}")
	fields := []string{}
	for _, line := range strings.Split(block[:end], "\n")[1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		name := line
		if i := strings.IndexAny(name, ":"); i >= 0 {
			name = name[:i]
		}
		typ := strings.TrimSpace(strings.TrimSuffix(line[strings.Index(line, ":")+1:], ","))
		fields = append(fields, strings.TrimSpace(name)+" "+typ)
	}
	want := []string{
		"enabled u32", "metadata_version u32", "workers u32", "queue_count u32",
		"flags u32", "wg_port_count u32", "wg_ports [u16; WG_STEERED_PORT_SET_MAX]",
		"config_generation u64", "fib_generation u32", "heartbeat_timeout_ms u32",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("UserspaceCtrl fields = %q, want %q", fields, want)
	}

	// The bound is one number on three sides.
	for _, path := range []string{
		filepath.Join("..", "..", "..", "userspace-xdp", "src", "wg_classify.rs"),
		filepath.Join("..", "..", "..", "userspace-dp", "src", "afxdp", "types", "runtime.rs"),
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		val := -1
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "WG_STEERED_PORT_SET_MAX") || !strings.Contains(line, "=") {
				continue
			}
			after := strings.TrimSpace(line[strings.Index(line, "=")+1:])
			after = strings.TrimRight(after, ";")
			if v, err := strconv.Atoi(strings.Fields(after)[0]); err == nil {
				val = v
			}
		}
		if val != config.MaxSteeredWireGuardPorts {
			t.Fatalf("%s: WG_STEERED_PORT_SET_MAX = %d, want Go MaxSteeredWireGuardPorts = %d",
				path, val, config.MaxSteeredWireGuardPorts)
		}
	}
}
