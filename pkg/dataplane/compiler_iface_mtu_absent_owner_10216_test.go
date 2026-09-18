package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileZoneMaps10216 drives the REAL programZoneMaps -> mapZoneInterface
// path over interfaces that do not resolve and returns the CompileResult, so
// tests can read both the arm-coverage records and the MTU records. It mirrors
// unarmedFromZoneMaps' minimal result construction (armproof_5275_test.go);
// the DataPlane stub panics on any call past the missing-netdev skip, so
// reaching actuation fails loudly instead of passing vacuously.
func compileZoneMaps10216(t *testing.T, cfg *config.Config) *CompileResult {
	t.Helper()
	result := &CompileResult{
		ZoneIDs:             make(map[string]uint16),
		ScreenIDs:           make(map[string]uint16),
		ifCache:             make(map[string]*net.Interface),
		rxVlanOffCache:      make(map[string]bool),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}
	for name := range cfg.Security.Zones {
		result.ZoneIDs[name] = config.StableZoneID(name)
	}
	if _, err := programZoneMaps(armProofZoneDP{}, cfg, result); err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	return result
}

func unusableTunnelCfg10216() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"tunnels": {Name: "tunnels", Interfaces: []string{"ge-0/0/4.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/4": {
				Name: "ge-0/0/4", MTU: 1400,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, MTU: 1300, Tunnel: &config.TunnelConfig{Name: "gr-0-0-4", Mode: "gre", Source: "192.0.2.1"}},
				},
			},
		}},
	}
}

// TestUnusableTunnelAbsentDeviceRecordsPlannedMTU_10216 is the absent-owner
// cell of #10216: #9985 kept the unusable tunnel planner-owned (the routing
// owner never creates it), so the plan carries MTU 1300 for gr-0-0-4 — and
// the actuator then soft-skipped the absent netdev with no MTU diagnostic.
// A planned MTU the device never receives must record lookup-failed instead
// of reconciling-or-rejecting silently.
//
// FAIL-ON-REVERT: drop the not-found-skip record in mapZoneInterface and this
// reds on zero records — while the commit still reports success.
func TestUnusableTunnelAbsentDeviceRecordsPlannedMTU_10216(t *testing.T) {
	const phys = "gr-0-0-4"
	requireAbsentInterface(t, phys)
	cfg := unusableTunnelCfg10216()

	// Premise: the planner still owns this device (no silent deferral).
	pd := planPhysDesired(cfg)[phys]
	if pd == nil || pd.mtu != 1300 {
		t.Fatalf("premise: plan[%s] = %+v, want planner-owned mtu 1300", phys, pd)
	}

	result := compileZoneMaps10216(t, cfg)
	recs := result.sortedMTUUnconverged()
	if len(recs) != 1 {
		t.Fatalf("MTU records = %+v, want exactly one: the planned 1300 for the "+
			"absent tunnel device was reconciled-or-rejected by nobody", recs)
	}
	r := recs[0]
	if r.Name != phys || r.ConfigRef != "ge-0/0/4" {
		t.Errorf("record identity = (%q, %q), want (gr-0-0-4, ge-0/0/4)", r.Name, r.ConfigRef)
	}
	if r.WantMTU != 1300 || r.LiveMTU != mtuUnknown9841 || r.Grade != MTUGradeLookupFailed {
		t.Errorf("record = %+v, want {want 1300, live unknown, lookup-failed}", r)
	}
	if r.Detail == "" || !strings.Contains(r.Detail, "1300") {
		t.Errorf("record detail = %q, want it to name the unrealized 1300", r.Detail)
	}
	line := r.Warning()
	for _, want := range []string{"ge-0/0/4", "gr-0-0-4", "1300", "unknown", "[lookup-failed]", "(#9841)"} {
		if !strings.Contains(line, want) {
			t.Errorf("commit warning %q must name %q", line, want)
		}
	}
	if len(result.unarmedSurfaces) != 1 {
		t.Errorf("unarmed surfaces = %d, want 1: the MTU record must ride "+
			"alongside the arm-coverage record, not replace it", len(result.unarmedSurfaces))
	}
}

// TestAbsentInterfaceRecordUsesMergedPlan_10216 guards the plan/actuator
// boundary with two references to one absent netdev. The planner's lowest-unit
// rule chooses 1300 regardless of zone order; the diagnostic must report that
// merged value rather than whichever unit was soft-skipped last.
func TestAbsentInterfaceRecordUsesMergedPlan_10216(t *testing.T) {
	const phys = "ge-9-0-8"
	requireAbsentInterface(t, phys)
	for _, zones := range []map[string][]string{
		{"a": {phys + ".20"}, "b": {phys + ".10"}},
		{"a": {phys + ".10"}, "b": {phys + ".20"}},
	} {
		cfg := &config.Config{
			Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
				"a": {Name: "a", Interfaces: zones["a"]},
				"b": {Name: "b", Interfaces: zones["b"]},
			}},
			Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
				phys: {
					Name: phys,
					Units: map[int]*config.InterfaceUnit{
						10: {Number: 10, MTU: 1300},
						20: {Number: 20, MTU: 1400},
					},
				},
			}},
		}
		pd := planPhysDesired(cfg)[phys]
		if pd == nil || pd.mtu != 1300 || !pd.mtuExplicit {
			t.Fatalf("plan[%s] = %+v, want merged authored mtu 1300", phys, pd)
		}
		recs := compileZoneMaps10216(t, cfg).sortedMTUUnconverged()
		if len(recs) != 1 {
			t.Fatalf("MTU records = %+v, want one merged diagnostic", recs)
		}
		if got := recs[0].WantMTU; got != pd.mtu {
			t.Fatalf("zones %v: WantMTU = %d, want merged plan %d", zones, got, pd.mtu)
		}
	}
}

// TestAbsentInterfaceWithStatedMTURecordsPlan_10216 pins the general rule
// behind the tunnel cell: any stated MTU whose netdev is absent records,
// because no writer (planner or owner) can realize it.
func TestAbsentInterfaceWithStatedMTURecordsPlan_10216(t *testing.T) {
	const phys = "ge-9-0-6"
	requireAbsentInterface(t, phys)
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{phys + ".0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			phys: {
				Name: phys, MTU: 1400,
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}},
	}
	if pd := planPhysDesired(cfg)[phys]; pd == nil || pd.mtu != 1400 {
		t.Fatalf("premise: plan[%s] = %+v, want mtu 1400", phys, pd)
	}
	recs := compileZoneMaps10216(t, cfg).sortedMTUUnconverged()
	if len(recs) != 1 {
		t.Fatalf("MTU records = %+v, want exactly one for the stated 1400", recs)
	}
	if r := recs[0]; r.WantMTU != 1400 || r.Grade != MTUGradeLookupFailed {
		t.Errorf("record = %+v, want {want 1400, lookup-failed}", r)
	}
}

// TestAbsentInterfaceWithoutStatedMTUStaysSilent_10216 is the tightening
// control: the #9985 materialized default (1500) on an absent netdev must NOT
// warn. A chassis-specific interface legitimately absent here would otherwise
// warn on every commit, and nothing the operator stated went unrealized.
//
// FAIL-ON-REVERT: record for every pd.mtu > 0 without the stated-MTU gate
// and this reds — the default is a plan, not a promise.
func TestAbsentInterfaceWithoutStatedMTUStaysSilent_10216(t *testing.T) {
	const phys = "ge-9-0-7"
	requireAbsentInterface(t, phys)
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{phys + ".0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			phys: {
				Name:  phys,
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}},
	}
	// Premise: the plan EXISTS (materialized default) — the silence below is
	// the stated-MTU gate's doing, not a missing plan.
	if pd := planPhysDesired(cfg)[phys]; pd == nil || pd.mtu != defaultPhysicalMTU9985 {
		t.Fatalf("premise: plan[%s] = %+v, want materialized default %d", phys, pd, defaultPhysicalMTU9985)
	}
	result := compileZoneMaps10216(t, cfg)
	if recs := result.sortedMTUUnconverged(); len(recs) != 0 {
		t.Fatalf("MTU records = %+v, want none: no MTU was stated, so no "+
			"diagnostic is owed for the absent device", recs)
	}
	if len(result.unarmedSurfaces) != 1 {
		t.Fatalf("unarmed surfaces = %d, want 1: the skip must still fire, "+
			"or this control passes vacuously", len(result.unarmedSurfaces))
	}
}

// TestFabricOwnedAbsentMemberStaysSilent_10216 pins the #9927 interplay: a
// fabric-owned netdev carries no plan (pd.mtu == 0), so its absence records
// no dataplane MTU diagnostic — the fabric setup owns that device and its
// own failure signal (a terminal parent error, not a warning).
func TestFabricOwnedAbsentMemberStaysSilent_10216(t *testing.T) {
	const memberLinux = "ge-9-0-5"
	requireAbsentInterface(t, memberLinux)
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"fabric": {Name: "fabric", Interfaces: []string{"fab0.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"fab0": {
				Name: "fab0", MTU: 9000, LocalFabricMember: "ge-9/0/5",
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}},
	}
	// Premise: #9927 ownership still yields (this control must not reopen it).
	if pd := planPhysDesired(cfg)[memberLinux]; pd != nil && pd.mtu != 0 {
		t.Fatalf("premise: plan[%s] = %+v, want no dataplane MTU write on the fabric-owned member", memberLinux, pd)
	}
	result := compileZoneMaps10216(t, cfg)
	if recs := result.sortedMTUUnconverged(); len(recs) != 0 {
		t.Fatalf("MTU records = %+v, want none: the fabric owner (not the "+
			"dataplane) owes the diagnostic for its absent member", recs)
	}
	if len(result.unarmedSurfaces) != 1 {
		t.Fatalf("unarmed surfaces = %d, want 1: the skip must still fire, "+
			"or this control passes vacuously", len(result.unarmedSurfaces))
	}
}
