package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13099 (D3-08): a zone poisoned by DroppedEnforcementChild (#11575/#12623,
// "the zone is unbound") must be quarantined in its own right. Before the fix
// buildZoneSnapshots / quarantineCollidingZones / BuildZoneHostInboundViews /
// ClassifyHostInbound never consulted the flag, so the poisoned zzq17760 still
// claimed its StableZoneID, quarantined the healthy colliding peer zzq8100, and
// classified as HostInboundTokenAdmit despite owning no bound interface.
//
// zzq17760/zzq8100 are the verified StableZoneID-colliding pair (frozen fold).

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
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	cfg := compileLenient13099(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set security zones security-zone zzq17760 interfaces ge-0/0/0.0",
		"set security zones security-zone zzq17760 host-inbound-traffic system-services ssh",
		"set security zones security-zone zzq17760 unknown-enforcement-knob foo",
		"set security zones security-zone zzq8100 interfaces ge-0/0/1.0",
		"set security zones security-zone zzq8100 host-inbound-traffic system-services ssh",
	})
	if z := cfg.Security.Zones["zzq17760"]; z == nil || !z.DroppedEnforcementChild {
		t.Fatalf("fixture: zzq17760 must be poisoned, got %+v", z)
	}
	if z := cfg.Security.Zones["zzq8100"]; z == nil || z.DroppedEnforcementChild {
		t.Fatalf("fixture: zzq8100 must be healthy, got %+v", z)
	}
	return cfg
}

func TestPoisonedZoneDoesNotQuarantineHealthyCollisionPeer13099(t *testing.T) {
	cfg := poisonedCollisionCfg13099(t)

	// Config-level quarantine verdict: poisoned excluded, healthy survivor not.
	excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
	if _, ok := excluded["zzq17760"]; !ok {
		t.Fatalf("poisoned zzq17760 must be quarantine-excluded, got %v", excluded)
	}
	if _, ok := excluded["zzq8100"]; ok {
		t.Fatalf("healthy zzq8100 must not be quarantine-excluded, got %v", excluded)
	}
	if r := config.ZoneQuarantineExcludedReason("zzq17760", cfg); !strings.Contains(r, "unbound") {
		t.Fatalf("zzq17760 quarantine reason must name the poisoned/unbound cause, got %q", r)
	}
	if r := config.ZoneQuarantineExcludedReason("zzq8100", cfg); r != "" {
		t.Fatalf("healthy zzq8100 must have no quarantine reason, got %q", r)
	}
	if owner := config.StableZoneIDOwnerForConfig(cfg, config.StableZoneID("zzq17760")); owner != "zzq8100" {
		t.Fatalf("collision id owner must be healthy zzq8100, got %q", owner)
	}

	// Interface resolution: healthy unit stays zoned, poisoned unit unzoned.
	zoneByIface := buildInterfaceZoneMap(cfg)
	if got := zoneByIface["ge-0/0/1.0"]; got != "zzq8100" {
		t.Fatalf("ge-0/0/1.0 must resolve to zzq8100, got %q (map %v)", got, zoneByIface)
	}
	if got := zoneByIface["ge-0/0/0.0"]; got != "" {
		t.Fatalf("ge-0/0/0.0 must be unzoned (poisoned zzq17760), got %q", got)
	}

	// Snapshot quarantine: only the healthy zone survives.
	snap := &ConfigSnapshot{
		Config:     cfg,
		Zones:      buildZoneSnapshots(cfg),
		Interfaces: buildInterfaceSnapshots(cfg),
	}
	collisions := quarantineCollidingZones(snap)
	if len(snap.Zones) != 1 || snap.Zones[0].Name != "zzq8100" {
		t.Fatalf("expected only healthy zzq8100 to survive quarantine, got %+v (collisions %v)", snap.Zones, collisions)
	}
	foundPoisonRecord := false
	for _, c := range collisions {
		if c.Quarantined == "zzq17760" {
			foundPoisonRecord = true
		}
		if c.Quarantined == "zzq8100" {
			t.Fatalf("healthy zzq8100 must not be recorded quarantined: %v", collisions)
		}
	}
	if !foundPoisonRecord {
		t.Fatalf("expected a quarantine record for poisoned zzq17760, got %v", collisions)
	}
	for _, ifc := range snap.Interfaces {
		if ifc.Name == "ge-0/0/1.0" && ifc.Zone != "zzq8100" {
			t.Fatalf("healthy zzq8100 interface must stay zoned, got %q", ifc.Zone)
		}
		if ifc.Name == "ge-0/0/0.0" && ifc.Zone != "" {
			t.Fatalf("poisoned zzq17760 interface must be unzoned, got %q", ifc.Zone)
		}
	}

	// Host-inbound views + classifier: poisoned admits nothing, healthy admits ssh.
	views := BuildZoneHostInboundViews(cfg)
	for _, v := range views {
		if v.Zone == "zzq17760" {
			t.Fatalf("poisoned zzq17760 must have no host-inbound view, got %+v", views)
		}
	}
	found214 := false
	for _, v := range views {
		if v.Zone == "zzq8100" {
			found214 = true
		}
	}
	if !found214 {
		t.Fatalf("healthy zzq8100 must keep a host-inbound view, got %+v", views)
	}
	if got := ClassifyHostInbound(cfg, "zzq17760", config.HostInboundProtoTCP, true, 22, true, nil, "ip"); got.Status == HostInboundTokenAdmit {
		t.Fatalf("poisoned unbound zzq17760 must not classify as TokenAdmit, got %+v", got)
	}
	if got := ClassifyHostInbound(cfg, "zzq8100", config.HostInboundProtoTCP, true, 22, true, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("healthy zzq8100 ssh must classify as TokenAdmit, got %+v", got)
	}
	if got := ClassifyHostInboundForInterface(cfg, "zzq17760", "ge-0/0/0.0", config.HostInboundProtoTCP, true, 22, true, nil, "ip"); got.Status == HostInboundTokenAdmit {
		t.Fatalf("poisoned zzq17760 per-interface classify must not TokenAdmit, got %+v", got)
	}
	if got := ClassifyHostInboundForInterface(cfg, "zzq8100", "ge-0/0/1.0", config.HostInboundProtoTCP, true, 22, true, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("healthy zzq8100 per-interface ssh must TokenAdmit, got %+v", got)
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
	if got := ClassifyHostInbound(cfg, "poisoned", config.HostInboundProtoTCP, true, 22, true, nil, "ip"); got.Status == HostInboundTokenAdmit {
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
	if got := ClassifyHostInbound(cfg, "trust", config.HostInboundProtoTCP, true, 22, true, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("healthy trust ssh must TokenAdmit, got %+v", got)
	}
}
