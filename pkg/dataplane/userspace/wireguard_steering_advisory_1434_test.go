package userspace

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// steeredSetRe pulls every "PORT (tunnel)" entry out of the advisory's
// selected-set clause (the text before "ARE steered").
var steeredSetRe = regexp.MustCompile(`(\d+) \(([A-Za-z0-9.]+)\)`)

// TestWireGuardSteeringAdvisoryNamesTheProgrammedSet9587 is the cross-package
// parity binding for the #9587 commit advisory. Successor to the #1434/#9521
// scalar cell of the same intent.
//
// The advisory (pkg/config, validateWireguardSteeredPortSet) tells the
// operator WHICH WireGuard listen ports the dataplane steers. That claim is
// only worth anything if it agrees with the code that actually fills the
// ctrl block — snapshotWgListenPorts + encodeSteeredPortSet, whose values the
// shim compares when it decides whether the worker claims a record.
//
// So: compile a nine-port config, read the SELECTED set the ADVISORY names,
// build the dataplane snapshot from the same config, and require the
// programmed set to equal exactly that set. If they ever diverge the advisory
// becomes a confident lie — worse than the silence it replaced — and this
// reds.
//
// The manager's real builder is used, and the programmed set is checked with
// every netdev present, with one SELECTED tunnel's netdev absent, and with
// none present — the absent-netdev arrangement is where the pre-#9521 reader
// promoted the next tunnel's port.
func TestWireGuardSteeringAdvisoryNamesTheProgrammedSet9587(t *testing.T) {
	const (
		keyA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
		keyB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	)
	// wg0 (lowest port) authored first; the emitter walks name order, so the
	// selected set is wg0..wg7's ports and the overflow is wg8's — a gate
	// that reported anything else would name a different set than the
	// dataplane programs. That mismatch is what this catches.
	var lines []string
	for i := 0; i < 9; i++ {
		name := "wg" + strconv.Itoa(i)
		port := 51820 + i
		key, peer := keyA, keyB
		if i%2 == 1 {
			key, peer = keyB, keyA
		}
		lines = append(lines,
			"set interfaces "+name+" tunnel mode wireguard",
			"set interfaces "+name+" tunnel wireguard listen-port "+strconv.Itoa(port),
			"set interfaces "+name+" tunnel wireguard private-key "+key,
			"set interfaces "+name+" tunnel wireguard peer "+peer+" allowed-ips 10."+strconv.Itoa(i+1)+".0.0/24",
		)
	}
	lines = append(lines, "set system dataplane-type userspace")
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
		// #9251: the #5618 plaintext advisory also names steered ports and
		// says "tunnel mode wireguard". Exclude it by its identity rather
		// than narrowing what counts as a steering advisory.
		if strings.Contains(w, "wireguard") && strings.Contains(w, "steered") && !strings.Contains(w, "#5618") {
			if advisory != "" {
				t.Fatalf("more than one WireGuard steering advisory: %v", cfg.Warnings)
			}
			advisory = w
		}
	}
	if advisory == "" {
		t.Fatalf("no WireGuard steering advisory emitted for nine distinct listen-ports; warnings: %v", cfg.Warnings)
	}
	clause, _, found := strings.Cut(advisory, "ARE steered")
	if !found {
		t.Fatalf("advisory does not name a steered set in the expected form: %s", advisory)
	}
	var claimed []uint16
	for _, m := range steeredSetRe.FindAllStringSubmatch(clause, -1) {
		p, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			t.Fatalf("steered port %q is not numeric: %v", m[1], convErr)
		}
		claimed = append(claimed, uint16(p))
	}
	if len(claimed) != config.MaxSteeredWireGuardPorts {
		t.Fatalf("advisory names %d steered ports, want the selected %d: %s",
			len(claimed), config.MaxSteeredWireGuardPorts, advisory)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	var allRows, withoutSelected []InterfaceSnapshot
	dropped := false
	for i, ep := range config.EmitTunnelEndpointNames(cfg) {
		row := InterfaceSnapshot{Name: ep.Name, LinuxName: ep.Name, Ifindex: 100 + i}
		allRows = append(allRows, row)
		if !dropped && ep.Name == "wg0" {
			dropped = true
			continue
		}
		withoutSelected = append(withoutSelected, row)
	}
	if len(allRows) != 9 || len(withoutSelected) != 8 || !dropped {
		t.Fatalf("fixture: want 9 emitted endpoints and wg0's row dropped, got %d and %d",
			len(allRows), len(withoutSelected))
	}
	for _, tc := range []struct {
		name string
		rows []InterfaceSnapshot
	}{
		{"every tunnel netdev present", allRows},
		{"a selected tunnel's netdev absent", withoutSelected},
		{"no tunnel netdev present", nil},
	} {
		snap.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, tc.rows)
		programmed := snapshotWgListenPorts(snap)
		if len(programmed) == 0 {
			t.Fatalf("%s: snapshot programmed no WireGuard ports; endpoints: %+v", tc.name, snap.TunnelEndpoints)
		}
		if !reflect.DeepEqual(programmed, claimed) {
			t.Fatalf("%s: commit advisory claims steered set %v, but the dataplane programs %v — "+
				"the advisory is wrong: %s", tc.name, claimed, programmed, advisory)
		}
	}
}
