package userspace

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestWireRefusesV20Helper9821 is the D5 mixed-version refusal coverage
// cell: a v20 helper (which parses rows by name shape) is refused by this
// v21 control plane — abort with the sentinel, disarm, nothing published,
// debt survives. Mirrors the 6722 fail-closed shape at the new boundary.
func TestWireRefusesV20Helper9821(t *testing.T) {
	dir, err := os.MkdirTemp("", "x9821")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")

	helper := startRecordingHelper6722(t, sock, 20)

	m := New()
	m.cfg.ControlSocket = sock
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.ConfigSnapshotProtocolVersion = 20
	m.pendingWorkerArm = true
	m.lastSnapshot = &ConfigSnapshot{
		Version:      ProtocolVersion,
		Generation:   7,
		DeferWorkers: true,
		Config:       &config.Config{},
	}

	err = m.retryDeferredWorkerArmLocked()

	if err == nil {
		t.Fatal("the publish path ACCEPTED a v20 helper; a v21 control plane must " +
			"not report a successful commit against a helper that parses rows by " +
			"name shape and would misread every dotted base row as a unit row")
	}
	if !errors.Is(err, ErrEgressZoneProtocolIncompatible) {
		t.Fatalf("error %v does not wrap ErrEgressZoneProtocolIncompatible", err)
	}
	if !helper.sawDisarm() {
		t.Errorf("no disarm reached the helper; requests seen: %v", helper.seen())
	}
	if helper.sawType("apply_snapshot") {
		t.Errorf("apply_snapshot was sent to a v20 helper before the gate aborted; "+
			"requests seen: %v", helper.seen())
	}
	if !m.pendingWorkerArm {
		t.Error("the deferred-worker-arm debt was cleared by a FAILED publish")
	}
}

// TestRowIdentityDottedBaseDedup9821 pins cell-17 Go: the collapse-dedup
// applies to a DOTTED base row (structural IsUnit, not name shape), so the
// live address lands in exactly ONE view carrying the unit-0-authoritative
// set. Mirrors the #5699 shape with dotted names.
func TestRowIdentityDottedBaseDedup9821(t *testing.T) {
	prev := buildLinkSnapshot
	defer func() { buildLinkSnapshot = prev }()
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-5.0" {
			return 2, 1500, "02:00:00:00:00:01", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.1.10/24"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"ge-0/0/5.0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0/0/5.0.0": {SystemServices: []string{"ssh"}},
			},
		},
	}

	views := BuildZoneHostInboundViews(cfg)

	var carrying []ZoneHostInboundView
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == "10.0.1.10" {
				carrying = append(carrying, v)
			}
		}
	}
	if len(carrying) != 1 {
		t.Fatalf("live address 10.0.1.10 appears in %d views, want exactly 1 (structural dedup on the dotted base)", len(carrying))
	}
	got := carrying[0]
	if !containsAll(got.SystemServices, []string{"ssh"}) {
		t.Fatalf("winning view services = %v, want the unit-0 override set [ssh]", got.SystemServices)
	}
	for _, s := range got.SystemServices {
		if s == "ping" {
			t.Fatalf("winning view services = %v: base zone-level ping must not appear", got.SystemServices)
		}
	}
}

// TestRowIdentityDottedBaseClaimsNoNetdev9821 pins cell-17 Go: only unit rows
// claim netdevs, so a dotted base row's netdev is claimed by its units — and
// a trunk-parent device no unit shares is claimed by none.
func TestRowIdentityDottedBaseClaimsNoNetdev9821(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			10: {Number: 10, VlanID: 100},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"ge-0/0/5.0.10"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}

	views := BuildZoneHostInboundViews(cfg)

	claimed := map[string]bool{}
	for _, v := range views {
		for _, n := range v.IngressNetdevs {
			claimed[n] = true
		}
	}
	if !claimed["ge-0-0-5.0.100"] {
		t.Errorf("unit netdev ge-0-0-5.0.100 unclaimed (claimed: %v) — units claim", claimed)
	}
	if claimed["ge-0-0-5.0"] {
		t.Errorf("trunk-parent ge-0-0-5.0 claimed (claimed: %v) — the dotted base row must claim nothing", claimed)
	}
}

// TestRowIdentityCrossesTheWire9821 pins the Go emit half of #22: base rows
// carry explicit false, unit rows true, and the key is ALWAYS on the wire
// (no omitempty — a missing test for rows the v3 audit looked for and did
// not find, re-grepped at implementation).
func TestRowIdentityCrossesTheWire9821(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	rows := buildInterfaceSnapshots(cfg)
	byName := map[string]InterfaceSnapshot{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	base, ok := byName["ge-0/0/5.0"]
	if !ok {
		t.Fatal("no base row for ge-0/0/5.0")
	}
	if base.IsUnit {
		t.Error("base row IsUnit = true — a dotted base name must not emit as a unit")
	}
	unit, ok := byName["ge-0/0/5.0.0"]
	if !ok {
		t.Fatal("no unit row for ge-0/0/5.0.0")
	}
	if !unit.IsUnit {
		t.Error("unit row IsUnit = false — unit-loop rows must emit true")
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal base row: %v", err)
	}
	if !strings.Contains(string(raw), `"is_unit":false`) {
		t.Errorf("base row marshals without explicit false: %s", raw)
	}
	raw, err = json.Marshal(unit)
	if err != nil {
		t.Fatalf("marshal unit row: %v", err)
	}
	if !strings.Contains(string(raw), `"is_unit":true`) {
		t.Errorf("unit row marshals without true: %s", raw)
	}
}
