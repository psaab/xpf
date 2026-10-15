package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13099 (D3-08): a zone poisoned by DroppedEnforcementChild (#11575/#12623,
// "the zone is unbound") must be quarantined in its own right. Before the fix
// buildZoneSnapshots / quarantineCollidingZones / BuildZoneHostInboundViews /
// ClassifyHostInbound never consulted the flag, so the poisoned z174 still
// claimed its StableZoneID, quarantined the healthy colliding peer z214, and
// classified as HostInboundTokenAdmit despite owning no bound interface.
//
// z174/z214 are the verified StableZoneID-colliding pair (frozen fold).

func compileLenient13099(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func poisonedCollisionCfg13099(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide")
	}
	cfg := compileLenient13099(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set security zones security-zone z174 interfaces ge-0/0/0.0",
		"set security zones security-zone z174 host-inbound-traffic system-services ssh",
		"set security zones security-zone z174 unknown-enforcement-knob foo",
		"set security zones security-zone z214 interfaces ge-0/0/1.0",
		"set security zones security-zone z214 host-inbound-traffic system-services ssh",
	})
	if z := cfg.Security.Zones["z174"]; z == nil || !z.DroppedEnforcementChild {
		t.Fatalf("fixture: z174 must be poisoned, got %+v", z)
	}
	if z := cfg.Security.Zones["z214"]; z == nil || z.DroppedEnforcementChild {
		t.Fatalf("fixture: z214 must be healthy, got %+v", z)
	}
	return cfg
}

func TestPoisonedZoneDoesNotQuarantineHealthyCollisionPeer13099(t *testing.T) {
	cfg := poisonedCollisionCfg13099(t)

	// Config-level quarantine verdict: poisoned excluded, healthy survivor not.
	excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
	if _, ok := excluded["z174"]; !ok {
		t.Fatalf("poisoned z174 must be quarantine-excluded, got %v", excluded)
	}
	if _, ok := excluded["z214"]; ok {
		t.Fatalf("healthy z214 must not be quarantine-excluded, got %v", excluded)
	}
	if r := config.ZoneQuarantineExcludedReason("z174", cfg); !strings.Contains(r, "unbound") {
		t.Fatalf("z174 quarantine reason must name the poisoned/unbound cause, got %q", r)
	}
	if r := config.ZoneQuarantineExcludedReason("z214", cfg); r != "" {
		t.Fatalf("healthy z214 must have no quarantine reason, got %q", r)
	}
	if owner := config.StableZoneIDOwnerForConfig(cfg, config.StableZoneID("z174")); owner != "z214" {
		t.Fatalf("collision id owner must be healthy z214, got %q", owner)
	}

	// Interface resolution: healthy unit stays zoned, poisoned unit unzoned.
	zoneByIface := buildInterfaceZoneMap(cfg)
	if got := zoneByIface["ge-0/0/1.0"]; got != "z214" {
		t.Fatalf("ge-0/0/1.0 must resolve to z214, got %q (map %v)", got, zoneByIface)
	}
	if got := zoneByIface["ge-0/0/0.0"]; got != "" {
		t.Fatalf("ge-0/0/0.0 must be unzoned (poisoned z174), got %q", got)
	}

	// Snapshot quarantine: only the healthy zone survives.
	snap := &ConfigSnapshot{
		Config:     cfg,
		Zones:      buildZoneSnapshots(cfg),
		Interfaces: buildInterfaceSnapshots(cfg),
	}
	collisions := quarantineCollidingZones(snap)
	if len(snap.Zones) != 1 || snap.Zones[0].Name != "z214" {
		t.Fatalf("expected only healthy z214 to survive quarantine, got %+v (collisions %v)", snap.Zones, collisions)
	}
	foundPoisonRecord := false
	for _, c := range collisions {
		if c.Quarantined == "z174" {
			foundPoisonRecord = true
		}
		if c.Quarantined == "z214" {
			t.Fatalf("healthy z214 must not be recorded quarantined: %v", collisions)
		}
	}
	if !foundPoisonRecord {
		t.Fatalf("expected a quarantine record for poisoned z174, got %v", collisions)
	}
	for _, ifc := range snap.Interfaces {
		if ifc.Name == "ge-0/0/1.0" && ifc.Zone != "z214" {
			t.Fatalf("healthy z214 interface must stay zoned, got %q", ifc.Zone)
		}
		if ifc.Name == "ge-0/0/0.0" && ifc.Zone != "" {
			t.Fatalf("poisoned z174 interface must be unzoned, got %q", ifc.Zone)
		}
	}

	// Host-inbound views + classifier: poisoned admits nothing, healthy admits ssh.
	views := BuildZoneHostInboundViews(cfg)
	for _, v := range views {
		if v.Zone == "z174" {
			t.Fatalf("poisoned z174 must have no host-inbound view, got %+v", views)
		}
	}
	found214 := false
	for _, v := range views {
		if v.Zone == "z214" {
			found214 = true
		}
	}
	if !found214 {
		t.Fatalf("healthy z214 must keep a host-inbound view, got %+v", views)
	}
	if got := ClassifyHostInbound(cfg, "z174", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status == HostInboundTokenAdmit {
		t.Fatalf("poisoned unbound z174 must not classify as TokenAdmit, got %+v", got)
	}
	if got := ClassifyHostInbound(cfg, "z214", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("healthy z214 ssh must classify as TokenAdmit, got %+v", got)
	}
	if got := ClassifyHostInboundForInterface(cfg, "z174", "ge-0/0/0.0", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status == HostInboundTokenAdmit {
		t.Fatalf("poisoned z174 per-interface classify must not TokenAdmit, got %+v", got)
	}
	if got := ClassifyHostInboundForInterface(cfg, "z214", "ge-0/0/1.0", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("healthy z214 per-interface ssh must TokenAdmit, got %+v", got)
	}
}

func TestPoisonedZoneAloneIsQuarantined13099(t *testing.T) {
	cfg := compileLenient13099(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone poisoned interfaces ge-0/0/0.0",
		"set security zones security-zone poisoned host-inbound-traffic system-services ssh",
		"set security zones security-zone poisoned unknown-enforcement-knob foo",
	})
	if z := cfg.Security.Zones["poisoned"]; z == nil || !z.DroppedEnforcementChild {
		t.Fatalf("fixture: poisoned must be DroppedEnforcementChild, got %+v", z)
	}
	snap := &ConfigSnapshot{
		Config:     cfg,
		Zones:      buildZoneSnapshots(cfg),
		Interfaces: buildInterfaceSnapshots(cfg),
	}
	quarantineCollidingZones(snap)
	if len(snap.Zones) != 0 {
		t.Fatalf("lone poisoned zone must be quarantined from snapshot, got %+v", snap.Zones)
	}
	for _, v := range BuildZoneHostInboundViews(cfg) {
		if v.Zone == "poisoned" {
			t.Fatalf("lone poisoned zone must have no host-inbound view: %+v", v)
		}
	}
	if got := ClassifyHostInbound(cfg, "poisoned", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status == HostInboundTokenAdmit {
		t.Fatalf("lone poisoned zone must not TokenAdmit, got %+v", got)
	}
}

func TestHealthyZonesUnaffectedByPoisonQuarantine13099(t *testing.T) {
	cfg := compileLenient13099(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
	})
	if _, ok := config.ZoneQuarantineExclusionsForConfig(cfg)["trust"]; ok {
		t.Fatalf("healthy trust must not be excluded")
	}
	snap := &ConfigSnapshot{
		Config:     cfg,
		Zones:      buildZoneSnapshots(cfg),
		Interfaces: buildInterfaceSnapshots(cfg),
	}
	if got := quarantineCollidingZones(snap); len(got) != 0 {
		t.Fatalf("healthy config must have no quarantine records, got %v", got)
	}
	if len(snap.Zones) != 1 || snap.Zones[0].Name != "trust" {
		t.Fatalf("healthy trust must survive, got %+v", snap.Zones)
	}
	if got := ClassifyHostInbound(cfg, "trust", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("healthy trust ssh must TokenAdmit, got %+v", got)
	}
}
