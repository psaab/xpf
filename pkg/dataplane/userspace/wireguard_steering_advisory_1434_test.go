package userspace

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// steeredPortRe pulls the port the commit advisory tells the operator WILL be
// programmed out of the warning text the operator actually reads.
var steeredPortRe = regexp.MustCompile(`listen-port (\d+) \(([^)]+)\) IS steered`)

// TestWireGuardSteeringAdvisoryNamesTheProgrammedPort_1434 is the cross-package
// parity binding for the #1434 commit advisory.
//
// The advisory (pkg/config, validateWireguardSingleSteeredPort) tells the
// operator WHICH WireGuard listen port survives the dataplane's single steering
// scalar. That claim is only worth anything if it agrees with the code that
// actually fills the scalar — snapshotWgListenPort, whose value the shim
// compares when it decides whether the worker claims a record.
//
// So: compile a two-port config, read the port the ADVISORY names, build the
// dataplane snapshot from the same config, and require snapshotWgListenPort to
// return exactly that port. If they ever diverge the advisory becomes a
// confident lie — worse than the silence it replaced — and this reds.
//
// #9521: this cell used to assemble the snapshot by hand, with a live interface
// row fabricated for EVERY emitted endpoint. That is the one arrangement in
// which the old reader and the advisory could not disagree, and the defect lived
// in the arrangement it did not build: when the warned tunnel's netdev was
// absent the reader promoted the next tunnel's port. It now uses the manager's
// real builder and checks the programmed port with every netdev present, with
// the warned tunnel's netdev absent, and with none present.
func TestWireGuardSteeringAdvisoryNamesTheProgrammedPort_1434(t *testing.T) {
	const (
		keyA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
		keyB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	)
	// wg1 (higher port) authored first, wg0 (lower port) second — so a gate
	// that reported authoring order instead of emitter order would name 51900,
	// and the dataplane would program 51820. That mismatch is what this catches.
	lines := []string{
		"set interfaces wg1 tunnel mode wireguard",
		"set interfaces wg1 tunnel wireguard listen-port 51900",
		"set interfaces wg1 tunnel wireguard private-key " + keyA,
		"set interfaces wg1 tunnel wireguard peer " + keyB + " allowed-ips 10.2.0.0/24",
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + keyB,
		"set interfaces wg0 tunnel wireguard peer " + keyA + " allowed-ips 10.1.0.0/24",
		"set system dataplane-type userspace",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
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

	var advisory string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "wireguard") && strings.Contains(w, "steered") {
			if advisory != "" {
				t.Fatalf("more than one WireGuard steering advisory: %v", cfg.Warnings)
			}
			advisory = w
		}
	}
	if advisory == "" {
		t.Fatalf("no WireGuard steering advisory emitted for two distinct listen-ports; warnings: %v", cfg.Warnings)
	}
	m := steeredPortRe.FindStringSubmatch(advisory)
	if m == nil {
		t.Fatalf("advisory does not name a steered listen-port in the expected form: %s", advisory)
	}
	claimed, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		t.Fatalf("steered port %q is not numeric: %v", m[1], convErr)
	}
	warnedRef := m[2]

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	var allRows, withoutWarned []InterfaceSnapshot
	for i, ep := range config.EmitTunnelEndpointNames(cfg) {
		row := InterfaceSnapshot{Name: ep.Name, LinuxName: ep.Name, Ifindex: 100 + i}
		allRows = append(allRows, row)
		if ep.Name != warnedRef {
			withoutWarned = append(withoutWarned, row)
		}
	}
	if len(allRows) != 2 || len(withoutWarned) != 1 {
		t.Fatalf("fixture: want 2 emitted endpoints and exactly the warned one (%q) dropped, got %d and %d",
			warnedRef, len(allRows), len(withoutWarned))
	}
	for _, tc := range []struct {
		name string
		rows []InterfaceSnapshot
	}{
		{"every tunnel netdev present", allRows},
		{"the warned tunnel's netdev absent", withoutWarned},
		{"no tunnel netdev present", nil},
	} {
		snap.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, tc.rows)
		programmed := snapshotWgListenPort(snap)
		if programmed == 0 {
			t.Fatalf("%s: snapshot programmed no WireGuard port; endpoints: %+v", tc.name, snap.TunnelEndpoints)
		}
		if uint32(claimed) != programmed {
			t.Fatalf("%s: commit advisory claims listen-port %d is steered, but the dataplane programs %d — "+
				"the advisory is wrong: %s", tc.name, claimed, programmed, advisory)
		}
	}
}
