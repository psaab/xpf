package config

import (
	"strings"
	"testing"
)

// #13095: zoneInterfaceMembershipConflicts, ZoneAuthoredBoundSecureTunnelUnitRefs,
// appendUserspaceMgmtZoneAdvisoryLocked, validateHostInboundManagedRoutingMismatch
// and buildZoneInterfaceMapLocal derived their quarantine exclusions from the
// LOCAL zone map only (ZoneQuarantineExclusions(cfg.Security.Zones keys)),
// ignoring the recorded three-view runtime zone-name union
// (cfg.ZoneQuarantineNames, #10248) — and the wrappers stamped that union onto
// cfg only AFTER compileExpanded had already run those gates. A zone
// quarantined cluster-wide because its StableZoneID collides with a PEER-ONLY
// zone name therefore kept contesting interfaces against healthy zones, so
// QuarantinedZoneInterfaceKeys stripped the interface from the healthy zone
// too and the dataplane snapshot blackholed its traffic.

// zzq17760/zzq8100 fold to the same StableZoneID (#16557 residual pair) and
// "zzq17760" sorts first, so a node1-only zzq17760 quarantines the local
// zzq8100 cluster-wide. (Pre-#16557 this used mgmt/a177301.)
// zzq17760/zzq8100 are the #12829 pair, used the same way.

const peerNodeQuarantineFixture13095 = `
groups {
	node0 { }
	node1 {
		security {
			zones {
				security-zone zzq17760;
			}
		}
	}
}
apply-groups "${node}";
interfaces {
	ge-0/0/0 {
		unit 0 {
			family inet;
		}
	}
}
security {
	zones {
		security-zone trust {
			interfaces {
				ge-0/0/0.0;
			}
		}
		security-zone zzq8100 {
			interfaces {
				ge-0/0/0.0;
			}
		}
	}
}
`

// The decisive cell: on CompileConfigForNodeLenient (Store.SyncApply / HA peer
// sync), a peer-node collision that quarantines local zone mgmt must NOT
// cascade QuarantinedZoneInterfaceKeys onto healthy trust's interface.
func TestPeerNodeZoneQuarantineStopsMembershipCascade13095(t *testing.T) {
	if StableZoneID("zzq17760") != StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	tree := parseHierText(t, peerNodeQuarantineFixture13095)
	cfg, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient: %v", err)
	}
	// Premise: the recorded runtime union (main + node0 + node1 views)
	// quarantines local mgmt via the peer-only name, and leaves trust alone.
	excluded := ZoneQuarantineExclusionsForConfig(cfg)
	if _, ok := excluded["zzq8100"]; !ok {
		t.Fatalf("premise: peer-only zzq17760 did not quarantine local zzq8100 (exclusions=%v recorded=%v)",
			excluded, cfg.ZoneQuarantineNames)
	}
	if _, ok := excluded["trust"]; ok {
		t.Fatalf("premise: trust must never be quarantined (exclusions=%v)", excluded)
	}
	// Core #13095 assertion: the healthy zone keeps the contested interface.
	if keys := QuarantinedZoneInterfaceKeys(cfg); len(keys) != 0 {
		t.Fatalf("peer-quarantined zone zzq8100 cascaded interface quarantine onto healthy trust (keys=%v) (#13095)",
			keys)
	}
	// The in-compile membership gate must not draw the false conflict either.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "is assigned to security zones") {
			t.Fatalf("false zone-interface-membership diagnostic for peer-quarantined zzq8100: %q (#13095)", w)
		}
	}
	// Doctrine: strict commit still rejects the colliding config outright.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile accepted a cross-node stable-zone-id collision (#13095)")
	}
}

// Doctrine guard: the union-aware exclusion must NOT relax genuinely LOCAL
// duplicate membership — strict still rejects it, tolerant still quarantines
// the interface keys for both zones (fail closed, #9914).
func TestZoneMembershipConflictStillDetectedWithoutCollision13095(t *testing.T) {
	tree := parseHierText(t, `
interfaces {
	ge-0/0/0 {
		unit 0 {
			family inet;
		}
	}
}
security {
	zones {
		security-zone trust {
			interfaces {
				ge-0/0/0.0;
			}
		}
		security-zone other {
			interfaces {
				ge-0/0/0.0;
			}
		}
	}
}
`)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "is assigned to security zones") {
		t.Fatalf("strict compile must still reject a local two-zone interface claim, got: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	keys := QuarantinedZoneInterfaceKeys(cfg)
	if _, ok := keys["ge-0/0/0.0"]; !ok {
		t.Fatalf("tolerant load must still quarantine a genuinely contested key, got %v", keys)
	}
}

// A cluster-quarantined zone must not be credited with authored bound
// secure-tunnel unit refs (the #hb166 G-6 warning-suppression view).
func TestZoneAuthoredBoundSecureTunnelUnitRefsSkipUnionQuarantined13095(t *testing.T) {
	if StableZoneID("zzq17760") != StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	mk := func() *Config {
		return &Config{
			Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{
					"zzq8100": {Interfaces: []string{"st0.0"}},
				},
				IPsec: IPsecConfig{
					VPNs: map[string]*IPsecVPN{
						"v1": {BindInterface: "st0"},
					},
				},
			},
		}
	}
	cfg := mk()
	if refs := ZoneAuthoredBoundSecureTunnelUnitRefs(cfg); len(refs) != 1 {
		t.Fatalf("premise: unquarantined zone's bound st0.0 not recognized, refs=%v", refs)
	}
	cfg = mk()
	cfg.ZoneQuarantineNames = []string{"zzq17760", "zzq8100"}
	if refs := ZoneAuthoredBoundSecureTunnelUnitRefs(cfg); len(refs) != 0 {
		t.Fatalf("cluster-quarantined zone zzq8100 still credited bound secure-tunnel refs %v (#13095)", refs)
	}
}

// A cluster-quarantined mgmt zone must not draw the #10308 data-NIC advisory
// for interfaces the dataplane dropped together with the zone.
func TestMgmtZoneAdvisorySkipsUnionQuarantined13095(t *testing.T) {
	mk := func() *Config {
		return &Config{
			Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{
					"mgmt": {Interfaces: []string{"ge-0/0/0.0"}},
				},
			},
		}
	}
	cfg := mk()
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "#10308") {
		t.Fatalf("premise: unquarantined mgmt data member drew no advisory, warnings=%v", cfg.Warnings)
	}
	cfg = mk()
	// #16557: no recorded name collides with "mgmt" under the u32 fold in
	// test time; use the poison exclusion (same
	// ZoneQuarantineExclusionsForConfig SSOT the union feeds) for the
	// quarantined arm.
	cfg.Security.Zones["mgmt"].DroppedEnforcementChild = true
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("cluster-quarantined mgmt zone still drew advisory %v (#13095)", cfg.Warnings)
	}
}

// The local resolved interface->zone view (host-inbound advisories,
// duplicate host-local-address checks) must match the dataplane's
// union-derived exclusion set: a cluster-quarantined zone's claim yields to
// the healthy zone instead of poisoning the key for both.
func TestBuildZoneInterfaceMapLocalSkipsUnionQuarantined13095(t *testing.T) {
	mk := func() *Config {
		return &Config{
			Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{
					"zzq8100": {Interfaces: []string{"ge-0/0/0.0"}},
					"trust":   {Interfaces: []string{"ge-0/0/0.0"}},
				},
			},
		}
	}
	cfg := mk()
	if m := buildZoneInterfaceMapLocal(cfg); len(m) != 0 {
		t.Fatalf("premise: genuinely contested key must stay unresolved without a union, got %v", m)
	}
	cfg = mk()
	cfg.ZoneQuarantineNames = []string{"zzq17760", "zzq8100", "trust"}
	m := buildZoneInterfaceMapLocal(cfg)
	if got := m["ge-0/0/0.0"]; got != "trust" {
		t.Fatalf("healthy trust must own ge-0/0/0.0 once cluster-quarantined zzq8100 yields, got %q (map=%v) (#13095)", got, m)
	}
}
