package config

import (
	"strings"
	"testing"
)

// wgSteeringWarnings returns the commit warnings that talk about WireGuard
// listen-port STEERING. Selection is by the property the operator cares about
// ("wireguard" + "steered"), not by the exact sentence the current gate emits,
// so a reworded advisory is still found and a REMOVED advisory still reds.
func wgSteeringWarnings(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "wireguard") && strings.Contains(w, "steered") {
			out = append(out, w)
		}
	}
	return out
}

// TestWireGuardDistinctListenPortsWarnsAtCommit_1434 is the #1434 silence gate.
//
// The defect: the AF_XDP shim's WG-RX steering is a SINGLE scalar
// (UserspaceCtrl.wg_listen_port, compared in wg_steer_to_kernel), fed by
// snapshotWgListenPort, which returns the FIRST configured WireGuard endpoint's
// port. A config with two WireGuard tunnels on DISTINCT listen ports commits
// clean, but only the first port is ever programmed. This comment used to add
// that the second tunnel "never receives inbound transport and is permanently,
// silently down". #9016 showed that was false — the port was live and its
// plaintext was forwarded by the kernel — and #9521 made the helper drop that
// transport instead; compiler_validate_wireguard_multiport.go has the mechanism.
//
// This asserts the commit now SAYS so, and says it precisely enough to act on:
// exactly one advisory, naming BOTH ports, BOTH tunnels, which one survives,
// which one does not, and the tracking issue.
//
// Fail-on-revert: delete the validateWireguardSingleSteeredPort append in
// runTailGates (or make the gate return nil) and this goes RED — the config
// commits clean again with zero operator signal, which is the defect.
func TestWireGuardDistinctListenPortsWarnsAtCommit_1434(t *testing.T) {
	lines := []string{
		// wg1 on the HIGHER port, authored FIRST. The dataplane snapshot
		// emitter walks interfaces in sorted NAME order, so wg0 wins the one
		// steering slot regardless of authoring order — the advisory must
		// report the emitter's winner, not the author's first line.
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
		// Explicitly NOT a reject: the config is legal and its first tunnel
		// works. A hard error here would change commit acceptance for a
		// config that commits clean at every released version.
		t.Fatalf("two distinct WG listen-ports must still COMMIT (warning, not reject); got error: %v", err)
	}

	got := wgSteeringWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 WireGuard steering advisory, got %d: %v (all warnings: %v)",
			len(got), got, cfg.Warnings)
	}
	w := got[0]

	// Both ports and both tunnel refs must appear — an advisory that names
	// only the unsteered port leaves the operator guessing which tunnel is the
	// adjudicated one.
	for _, want := range []string{"51820", "51900", "wg0", "wg1", "#1434"} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory does not mention %q: %s", want, w)
		}
	}

	// Direction is the whole point: naming the ports without saying WHICH one
	// survives is no better than silence. Bind the assignment explicitly, so a
	// gate that picks the wrong winner (authoring order, or the max port)
	// cannot pass by merely mentioning both numbers.
	if !strings.Contains(w, "listen-port 51820 (wg0) IS steered") {
		t.Errorf("advisory does not name 51820/wg0 as the port that IS programmed: %s", w)
	}
	if !strings.Contains(w, "listen-port 51900 (wg1) is NOT steered") {
		t.Errorf("advisory does not name 51900/wg1 as the port that is NOT programmed: %s", w)
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
// WireGuard tunnels that share one listen port lose nothing to the single
// steering scalar — that one port is programmed and covers both — so this gate
// must stay quiet. A naive "more than one WireGuard tunnel" test would fire
// here and mislabel a different problem (two tunnels on one port collide on the
// kernel UDP bind; bind_wg_socket sets no SO_REUSEPORT) as a steering loss.
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

// TestWireGuardThreeListenPortsWarnsOnce_1434 covers the >2 case: one advisory
// listing EVERY stranded port, not one advisory per stranded tunnel (which
// would bury the signal) and not just the first stranded one (which would
// under-report the damage).
func TestWireGuardThreeListenPortsWarnsOnce_1434(t *testing.T) {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyB,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyA + " allowed-ips 10.1.0.0/24",
		"set interfaces wg1 tunnel mode wireguard",
		"set interfaces wg1 tunnel wireguard listen-port 51900",
		"set interfaces wg1 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg1 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.2.0.0/24",
		"set interfaces wg2 tunnel mode wireguard",
		"set interfaces wg2 tunnel wireguard listen-port 51999",
		"set interfaces wg2 tunnel wireguard private-key " + wgKeyC1434,
		"set interfaces wg2 tunnel wireguard peer " + wgKeyA + " allowed-ips 10.3.0.0/24",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := wgSteeringWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 WireGuard steering advisory for 3 ports, got %d: %v", len(got), got)
	}
	w := got[0]
	if !strings.Contains(w, "3 distinct listen-ports") {
		t.Errorf("advisory does not report the full port count: %s", w)
	}
	for _, want := range []string{"51900 (wg1)", "51999 (wg2)"} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory omits stranded port %q: %s", want, w)
		}
	}
	if !strings.Contains(w, "listen-port 51820 (wg0) IS steered") {
		t.Errorf("advisory does not name 51820/wg0 as the surviving port: %s", w)
	}
}

const wgKeyC1434 = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
