package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5489: host-inbound must fail closed on a contested interface identity. A
// lenient config can retain two zones both claiming the same reth0.100, but no
// zone owns that ambiguous key at runtime. Neither zone's per-interface
// override may stamp an admission onto the unzoned snapshot row or host-inbound
// view. The single-owner control below proves ordinary overrides still apply.

// hostInboundCfg5489 declares TWO zones both claiming reth0.100. Their distinct
// ping and ssh overrides must both be withheld because the ownership conflict
// leaves the unit unzoned.
func hostInboundCfg5489() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			100: {Number: 100, Addresses: []string{"10.0.100.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"azone-owner": {
			Name:       "azone-owner",
			Interfaces: []string{"reth0.100"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.100": {SystemServices: []string{"ping"}},
			},
		},
		"zzone-loser": {
			Name:       "zzone-loser",
			Interfaces: []string{"reth0.100"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.100": {SystemServices: []string{"ssh"}},
			},
		},
	}
	return cfg
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// Test_5489_OwnerZonePicksFirstSorted guards against restoring first-wins
// ownership: duplicate claims must be omitted from the runtime zone map.
func Test_5489_OwnerZonePicksFirstSorted(t *testing.T) {
	z := buildInterfaceZoneMap(hostInboundCfg5489())
	if got := z["reth0.100"]; got != "" {
		t.Fatalf("buildInterfaceZoneMap contested reth0.100 = %q, want no zone", got)
	}
	if _, quarantined := config.QuarantinedZoneInterfaceKeys(hostInboundCfg5489())["reth0.100"]; !quarantined {
		t.Fatal("contested reth0.100 was not marked for quarantine")
	}
}

// Test_5489_ExactUnitNoCrossZoneLeak asserts that neither conflicting
// per-interface override is published for reth0.100.
func Test_5489_ExactUnitNoCrossZoneLeak(t *testing.T) {
	m := buildInterfaceHostInboundMap(hostInboundCfg5489())
	if ov := m["reth0.100"]; ov != nil {
		t.Errorf("contested reth0.100 has an effective host-inbound override %+v; want no-zone/drop", ov)
	}
}

// Test_5489_SnapshotNoCrossZoneLeak is the end-to-end assertion through the
// InterfaceSnapshot stamping path: the contested reth0.100 is unzoned and must
// carry no host-inbound stamp from either claimant.
func Test_5489_SnapshotNoCrossZoneLeak(t *testing.T) {
	snaps := buildInterfaceSnapshots(hostInboundCfg5489())
	var found bool
	for _, s := range snaps {
		if s.Name != "reth0.100" {
			continue
		}
		found = true
		if s.Zone != "" {
			t.Errorf("contested reth0.100 snapshot Zone = %q, want empty", s.Zone)
		}
		if s.HostInboundConfigured || len(s.HostInboundSystemServices) != 0 ||
			len(s.HostInboundProtocols) != 0 {
			t.Errorf("contested reth0.100 carries host-inbound stamp: configured=%v services=%v protocols=%v",
				s.HostInboundConfigured, s.HostInboundSystemServices, s.HostInboundProtocols)
		}
	}
	if !found {
		t.Fatal("no InterfaceSnapshot emitted for reth0.100")
	}
}

// Test_5489_ViewNoCrossZoneLeak asserts the contested unit's address appears in
// no zone view, so neither claimant's host-inbound services are admitted.
func Test_5489_ViewNoCrossZoneLeak(t *testing.T) {
	views := BuildZoneHostInboundViews(hostInboundCfg5489())
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == "10.0.100.1" {
				t.Errorf("contested reth0.100 address is scoped by zone %q with services %v; want no-zone/drop",
					v.Zone, v.SystemServices)
			}
		}
	}
}

// Test_5489_SingleOwnerUnaffected is the positive control: a single owner's
// override still reaches its map, snapshot, and zone view.
func Test_5489_SingleOwnerUnaffected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			100: {Number: 100, Addresses: []string{"10.0.100.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:       "trust",
			Interfaces: []string{"reth0.100"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.100": {SystemServices: []string{"ssh"}},
			},
		},
	}
	m := buildInterfaceHostInboundMap(cfg)
	if ov := m["reth0.100"]; ov == nil || !eqStr(ov.SystemServices, []string{"ssh"}) {
		t.Errorf("single-owner reth0.100 effective = %v, want [ssh]", ov)
	}
	var foundSnapshot bool
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name != "reth0.100" {
			continue
		}
		foundSnapshot = true
		if snap.Zone != "trust" || !snap.HostInboundConfigured ||
			!containsStr(snap.HostInboundSystemServices, "ssh") {
			t.Errorf("single-owner snapshot = %+v, want trust with ssh stamp", snap)
		}
	}
	if !foundSnapshot {
		t.Fatal("single-owner control emitted no reth0.100 snapshot")
	}
	var foundView bool
	for _, view := range BuildZoneHostInboundViews(cfg) {
		if view.Zone != "trust" {
			continue
		}
		for _, addr := range view.V4Addrs {
			if addr == "10.0.100.1" && containsStr(view.SystemServices, "ssh") {
				foundView = true
			}
		}
	}
	if !foundView {
		t.Fatal("single-owner control did not scope 10.0.100.1 to trust with ssh")
	}
}

// Test_5489_PhysicalBranchGuardStillHolds re-asserts the pre-existing #3720
// physical-expansion quarantine survives alongside the new exact-unit guard: a
// physical override in trust must not leak onto reth0.20 owned by guest, while
// reth0.10 owned by trust still inherits it.
func Test_5489_PhysicalBranchGuardStillHolds(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			10: {Number: 10, Addresses: []string{"10.0.10.1/24"}},
			20: {Number: 20, Addresses: []string{"10.0.20.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:       "trust",
			Interfaces: []string{"reth0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0": {SystemServices: []string{"ping"}},
			},
		},
		"guest": {Name: "guest", Interfaces: []string{"reth0.20"}},
	}
	m := buildInterfaceHostInboundMap(cfg)
	if ov := m["reth0.20"]; ov != nil {
		t.Errorf("reth0.20 (owned by guest) must NOT inherit trust's physical override, got %v", ov.SystemServices)
	}
	if ov := m["reth0.10"]; ov == nil || !eqStr(ov.SystemServices, []string{"ping"}) {
		t.Errorf("reth0.10 (owned by trust) effective = %v, want [ping]", ov)
	}
}
