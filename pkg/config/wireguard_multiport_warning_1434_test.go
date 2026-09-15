package config

import (
	"strings"
	"testing"
)

// wgSteeringWarnings returns the commit warnings that talk about WireGuard
// listen-port STEERING. Selection is by the property the operator cares about
// ("wireguard" + "steered"), not by the exact sentence the current gate emits,
// so a reworded advisory is still found and a REMOVED advisory still reds.
//
// #9251: the #5618 plaintext advisory now names "the steered listen port" too —
// since #9521 its kernel-path residual belongs to that port — and its tunnel
// details say "tunnel mode wireguard", so it carries both words without being a
// steering advisory. It is excluded by its IDENTITY (#5618, which its lead
// always carries), not by rewording it to dodge this selector; for every other
// warning the selection stays exactly as loose as it was.
func wgSteeringWarnings(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "wireguard") && strings.Contains(w, "steered") && !strings.Contains(w, "#5618") {
			out = append(out, w)
		}
	}
	return out
}

// TestWireGuardTwoListenPortsDrawNoAdvisory9587 is the post-#9587 silence
// gate: the steered set holds up to MaxSteeredWireGuardPorts ports, so a
// two-tunnel config on distinct ports is fully served and must draw no
// steering advisory.
//
// Fail-on-revert: reintroduce a single-port scalar (or shrink the bound
// below 2) and this goes RED — the config would commit clean while a tunnel
// silently lost inbound transport, which is the defect.
func TestWireGuardTwoListenPortsDrawNoAdvisory9587(t *testing.T) {
	lines := []string{
		// wg1 on the HIGHER port, authored FIRST. The dataplane snapshot
		// emitter walks interfaces in sorted NAME order, so wg0 leads the
		// steered set regardless of authoring order.
		"set interfaces wg1 tunnel mode wireguard",
		"set interfaces wg1 tunnel wireguard listen-port 51900",
		"set interfaces wg1 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg1 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.2.0.0/24",
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyB,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyA + " allowed-ips 10.1.0.0/24",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("two distinct WG listen-ports must still COMMIT; got error: %v", err)
	}
	if got := wgSteeringWarnings(cfg); len(got) != 0 {
		t.Fatalf("two steered WG listen-ports must draw no steering advisory, got: %v", got)
	}
	// The derivation still covers both ports — silence means "all steered",
	// not "gate removed".
	if got := SteeredWireGuardListenPorts(cfg); len(got) != 2 {
		t.Fatalf("SteeredWireGuardListenPorts = %v, want both ports", got)
	}
}

// TestWireGuardSingleListenPortDoesNotWarn_1434 pins the common case shut: one
// WireGuard tunnel is fully supported today, so it must draw no steering
// advisory. Without this, a gate that fired on "any WireGuard tunnel" would
// pass the multi-port test above while crying wolf on every single-tunnel
// deployment.
func TestWireGuardSingleListenPortDoesNotWarn_1434(t *testing.T) {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyB,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyA + " allowed-ips 10.1.0.0/24",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := wgSteeringWarnings(cfg); len(got) != 0 {
		t.Fatalf("single-tunnel WireGuard config must draw no steering advisory, got: %v", got)
	}
}

// TestWireGuardSameListenPortDoesNotWarn_1434 binds the DISTINCT qualifier. Two
// WireGuard tunnels that share one listen port contribute one set entry —
// that port is programmed and covers both — so this gate must stay quiet. A
// naive "more than one WireGuard tunnel" test would fire here and mislabel a
// different problem (two tunnels on one port collide on the kernel UDP bind;
// bind_wg_socket sets no SO_REUSEPORT) as a steering loss.
func TestWireGuardSameListenPortDoesNotWarn_1434(t *testing.T) {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyB,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyA + " allowed-ips 10.1.0.0/24",
		"set interfaces wg1 tunnel mode wireguard",
		"set interfaces wg1 tunnel wireguard listen-port 51820",
		"set interfaces wg1 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg1 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.2.0.0/24",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := wgSteeringWarnings(cfg); len(got) != 0 {
		t.Fatalf("two WG tunnels sharing ONE listen port must draw no steering advisory, got: %v", got)
	}
}

// TestWireGuardNineListenPortsWarnsOnce9587 covers the overflow case: one
// advisory listing the refused port, not one advisory per refused tunnel
// (which would bury the signal) and not just a count (which would
// under-report what to fix).
//
// Fail-on-revert: delete the validateWireguardSteeredPortSet append in
// runTailGates (or make the gate return nil) and this goes RED — the config
// commits clean again with zero operator signal about the refused port,
// which is the defect.
func TestWireGuardNineListenPortsWarnsOnce9587(t *testing.T) {
	cfg := wgNinePortConfig9587(t, "wg0", 51820)
	got := wgSteeringWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 WireGuard steering advisory for 9 ports, got %d: %v", len(got), got)
	}
	w := got[0]
	if !strings.Contains(w, "9 distinct listen-ports") {
		t.Errorf("advisory does not report the full port count: %s", w)
	}
	// Overflow is wg8's port (ninth in emitter order).
	if !strings.Contains(w, "51009 (wg8)") {
		t.Errorf("advisory omits refused port 51009 (wg8): %s", w)
	}
	// The selected set is named, including the emitter-first port.
	for _, want := range []string{"51820 (wg0)", "51002 (wg1)", "#9587"} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory omits %q: %s", want, w)
		}
	}
}
