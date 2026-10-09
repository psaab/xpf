// #3719: on the lenient / HA-sync / pre-#3075-persisted path two security zone
// names can fold to the same StableZoneID. Before this fix buildZoneSnapshots
// published BOTH with the same numeric id, and the Rust id-keyed maps merged the
// two zones (one zone's reverse name / host-inbound set / tcp-rst bit / counters
// stood in for the other) — a zone-isolation failure the lenient warning falsely
// claimed was quarantined. quarantineCollidingZones now DROPS the later-sorting
// colliding zone from the wire (and unzones its interfaces / drops its policies
// so no dangling reference bricks the helper preflight), matching the warning.
//
// These tests go RED if the quarantine pass is removed from buildSnapshot (both
// colliding zones publish with the same id) — the H02/M08 regression they guard.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestQuarantineCollidingZonesDropsAndScrubs exercises the pass directly on a
// hand-built snapshot carrying the verified colliding pair z174/z214 plus a
// distinct zone. It must drop the later-sorting zone (z214), keep the survivor
// (z174) and the distinct zone, unzone z214's interface, drop z214's policy, and
// report the collision — leaving no two zones sharing an id.
func TestQuarantineCollidingZonesDropsAndScrubs(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	collideID := config.StableZoneID("z174")
	snap := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "trust", ID: config.StableZoneID("trust")},
			{Name: "z174", ID: config.StableZoneID("z174")},
			{Name: "z214", ID: config.StableZoneID("z214")},
		},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-0.0", Zone: "z174"},
			{Name: "ge-0-0-1.0", Zone: "z214"},
			{Name: "ge-0-0-2.0", Zone: "trust"},
		},
		Policies: []PolicyRuleSnapshot{
			{Name: "p-survivor", FromZone: "z174", ToZone: "trust"},
			{Name: "p-quarantined-from", FromZone: "z214", ToZone: "trust"},
			{Name: "p-quarantined-to", FromZone: "trust", ToZone: "z214"},
			{Name: "p-global", FromZone: "junos-global", ToZone: "junos-global"},
		},
	}

	collisions := quarantineCollidingZones(snap)

	// The colliding zone is dropped; the survivor + distinct zone remain.
	names := map[string]uint16{}
	for _, z := range snap.Zones {
		if prev, dup := names[z.Name]; dup {
			t.Fatalf("zone %q appears twice (%d, %d)", z.Name, prev, z.ID)
		}
		names[z.Name] = z.ID
	}
	if _, ok := names["z214"]; ok {
		t.Fatalf("quarantined zone z214 still published: %v", names)
	}
	if _, ok := names["z174"]; !ok {
		t.Fatalf("survivor zone z174 was dropped: %v", names)
	}
	if _, ok := names["trust"]; !ok {
		t.Fatalf("distinct zone trust was dropped: %v", names)
	}
	// The core invariant: no two published zones share a numeric id.
	seen := map[uint16]string{}
	for n, id := range names {
		if prev, dup := seen[id]; dup {
			t.Fatalf("two zones share id %d after quarantine: %q and %q", id, prev, n)
		}
		seen[id] = n
	}

	// z214's interface is unzoned (fail closed); the others keep their zone.
	byIface := map[string]string{}
	for _, i := range snap.Interfaces {
		byIface[i.Name] = i.Zone
	}
	if z := byIface["ge-0-0-1.0"]; z != "" {
		t.Fatalf("interface in quarantined zone still bound to %q, want unzoned", z)
	}
	if z := byIface["ge-0-0-0.0"]; z != "z174" {
		t.Fatalf("survivor-zone interface lost its binding: %q", z)
	}
	if z := byIface["ge-0-0-2.0"]; z != "trust" {
		t.Fatalf("distinct-zone interface lost its binding: %q", z)
	}

	// Policies referencing z214 (from OR to) are dropped; survivor + global kept.
	polNames := map[string]bool{}
	for _, p := range snap.Policies {
		polNames[p.Name] = true
	}
	if polNames["p-quarantined-from"] || polNames["p-quarantined-to"] {
		t.Fatalf("policy referencing quarantined zone z214 survived: %v", polNames)
	}
	if !polNames["p-survivor"] || !polNames["p-global"] {
		t.Fatalf("non-colliding policy was wrongly dropped: %v", polNames)
	}

	// The collision is reported with the survivor + quarantined names and id.
	if len(collisions) != 1 {
		t.Fatalf("got %d collisions, want 1: %v", len(collisions), collisions)
	}
	c := collisions[0]
	if c.ID != collideID || c.Survivor != "z174" || c.Quarantined != "z214" {
		t.Fatalf("collision record = %+v, want {ID:%d Survivor:z174 Quarantined:z214}", c, collideID)
	}
}

// TestBuildSnapshotQuarantinesCollidingZone drives the REAL publish path
// (buildSnapshot): a config with the colliding pair must yield a snapshot that
// publishes neither zone twice under one id, drops the later-sorting zone, and
// records the collision on the (unexported) diagnostic the manager reads. On a
// revert (buildZoneSnapshots emits both) this fails: two ZoneSnapshots carry id
// 53547.
func TestBuildSnapshotQuarantinesCollidingZone(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	seen := map[uint16]string{}
	var haveZ214 bool
	for _, z := range snap.Zones {
		if z.Name == "z214" {
			haveZ214 = true
		}
		if prev, dup := seen[z.ID]; dup {
			t.Fatalf("two published zones share id %d: %q and %q (#3719 quarantine reverted?)", z.ID, prev, z.Name)
		}
		seen[z.ID] = z.Name
	}
	if haveZ214 {
		t.Fatalf("later-sorting colliding zone z214 was published, want quarantined")
	}
	if len(snap.zoneIDCollisions) != 1 {
		t.Fatalf("snap.zoneIDCollisions = %v, want exactly one collision", snap.zoneIDCollisions)
	}
	c := snap.zoneIDCollisions[0]
	if c.Survivor != "z174" || c.Quarantined != "z214" {
		t.Fatalf("collision = %+v, want survivor z174 / quarantined z214", c)
	}
}

// TestQuarantineDropsScopedGlobalPolicyOnQuarantinedZone (review MAJOR): a
// GLOBAL policy keeps FromZone/ToZone == "junos-global" but carries its concrete
// `match from-zone`/`to-zone` out-of-band in MatchFromZone/MatchToZone (#3148).
// If the match-zone is the quarantined zone, the scrub MUST drop the policy too
// — otherwise a dangling match-zone reaches the Rust build_global_zone_scope,
// which returns UnresolvableZoneReference and rejects the WHOLE snapshot (a
// fresh-boot brick, the exact failure the quarantine prevents). RED-on-revert:
// without the MatchFromZone/MatchToZone check the two global rules survive.
func TestQuarantineDropsScopedGlobalPolicyOnQuarantinedZone(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	snap := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "z174", ID: config.StableZoneID("z174")},
			{Name: "z214", ID: config.StableZoneID("z214")},
		},
		Policies: []PolicyRuleSnapshot{
			{Name: "g-scoped-from-quarantined", FromZone: "junos-global", ToZone: "junos-global", MatchFromZone: "z214"},
			{Name: "g-scoped-to-quarantined", FromZone: "junos-global", ToZone: "junos-global", MatchToZone: "z214"},
			{Name: "g-scoped-survivor", FromZone: "junos-global", ToZone: "junos-global", MatchFromZone: "z174"},
			{Name: "g-unscoped", FromZone: "junos-global", ToZone: "junos-global"},
		},
	}
	quarantineCollidingZones(snap)

	// No published policy may reference the quarantined zone in ANY zone slot —
	// including the out-of-band global match-zone.
	published := map[string]uint16{}
	for _, z := range snap.Zones {
		published[z.Name] = z.ID
	}
	for _, p := range snap.Policies {
		for _, z := range []string{p.MatchFromZone, p.MatchToZone} {
			if z == "" {
				continue
			}
			if _, ok := published[z]; !ok {
				t.Fatalf("policy %q keeps a dangling match-zone %q absent from published zones — Rust build_global_zone_scope would brick the snapshot", p.Name, z)
			}
		}
	}
	kept := map[string]bool{}
	for _, p := range snap.Policies {
		kept[p.Name] = true
	}
	if kept["g-scoped-from-quarantined"] || kept["g-scoped-to-quarantined"] {
		t.Fatalf("a global policy scoped to the quarantined zone survived: %v", kept)
	}
	if !kept["g-scoped-survivor"] || !kept["g-unscoped"] {
		t.Fatalf("a non-colliding global policy was wrongly dropped: %v", kept)
	}
}

// TestBuildSnapshotDropsDanglingGlobalMatchZone drives the REAL publish path: a
// config with a StableZoneID collision AND a scoped global policy whose
// `match from-zone` is the quarantined zone must yield a snapshot with NO policy
// referencing an unpublished zone (so feeding it to the Rust preflight cannot
// brick). RED-on-revert: without the match-zone scrub the built snapshot carries
// a global rule whose MatchFromZone == "z214" (dropped from Zones).
func TestBuildSnapshotDropsDanglingGlobalMatchZone(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174": {Name: "z174"},
		"z214": {Name: "z214"},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name:   "g-scoped-quarantined",
			Match:  config.PolicyMatch{FromZones: []string{"z214"}, Applications: []string{"any"}},
			Action: config.PolicyPermit,
		},
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	published := map[string]bool{}
	for _, z := range snap.Zones {
		published[z.Name] = true
	}
	for _, p := range snap.Policies {
		for _, z := range []string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone} {
			if z == "" || z == "junos-global" {
				continue
			}
			if !published[z] {
				t.Fatalf("published policy %q references unpublished zone %q — the Rust preflight would reject the whole snapshot (brick)", p.Name, z)
			}
		}
	}
}

// TestQuarantinePrunesScopedGlobalMemberNotWholeRule (#5577, fail-open): a scoped
// global DENY whose match-zone SET carries several zones must keep protecting the
// members that did NOT collide. A deny scoped from [z174, z214] where only z214 is
// quarantined must SURVIVE, pruned to [z174] — NOT be dropped wholesale. Dropping
// the whole rule is fail-open: z174 traffic would no longer hit the deny and would
// reach a later/default permit while the snapshot publishes successfully.
//
// RED-on-revert: with the old any-member-drops-whole-rule logic the deny is
// dropped entirely, so the g-deny-scoped assertion (deny survives for z174) fails.
func TestQuarantinePrunesScopedGlobalMemberNotWholeRule(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	snap := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "untrust", ID: config.StableZoneID("untrust")},
			{Name: "z174", ID: config.StableZoneID("z174")},
			{Name: "z214", ID: config.StableZoneID("z214")},
		},
		Policies: []PolicyRuleSnapshot{
			// A multi-zone scoped global deny: from {z174, z214} to {untrust}.
			// Only z214 collides; the deny must survive scoped to {z174}.
			{
				Name: "g-deny-scoped", FromZone: "junos-global", ToZone: "junos-global",
				Action:         "deny",
				MatchFromZones: []string{"z174", "z214"},
				MatchFromZone:  "z174",
				MatchToZones:   []string{"untrust"},
				MatchToZone:    "untrust",
			},
			// A middle-member collision: [untrust, z214, z174] -> [untrust, z174].
			{
				Name: "g-deny-middle", FromZone: "junos-global", ToZone: "junos-global",
				Action:         "deny",
				MatchFromZones: []string{"untrust", "z214", "z174"},
				MatchFromZone:  "untrust",
			},
			// The to-side carries the collision: from {untrust} to {z174, z214}.
			{
				Name: "g-deny-to", FromZone: "junos-global", ToZone: "junos-global",
				Action:         "deny",
				MatchFromZones: []string{"untrust"},
				MatchFromZone:  "untrust",
				MatchToZones:   []string{"z174", "z214"},
				MatchToZone:    "z174",
			},
			// EVERY match member collides -> the scope can no longer be honored;
			// leaving it empty would broaden to all zones (fail-open), so DROP.
			{
				Name: "g-deny-all-quarantined", FromZone: "junos-global", ToZone: "junos-global",
				Action:         "deny",
				MatchFromZones: []string{"z214"},
				MatchFromZone:  "z214",
			},
		},
	}

	quarantineCollidingZones(snap)

	published := map[string]bool{}
	for _, z := range snap.Zones {
		published[z.Name] = true
	}
	byName := map[string]PolicyRuleSnapshot{}
	for _, p := range snap.Policies {
		byName[p.Name] = p
		// No surviving rule may reference the quarantined zone in ANY zone slot —
		// singular or plural — else the Rust preflight bricks the whole snapshot.
		slots := append([]string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone},
			append(append([]string{}, p.MatchFromZones...), p.MatchToZones...)...)
		for _, z := range slots {
			if z == "" || z == "junos-global" {
				continue
			}
			if !published[z] {
				t.Fatalf("policy %q keeps dangling zone %q absent from published zones", p.Name, z)
			}
		}
	}

	// The core fail-open guard: the multi-zone deny SURVIVES, scoped to z174.
	g, ok := byName["g-deny-scoped"]
	if !ok {
		t.Fatalf("multi-zone scoped global deny was dropped — fail-open: z174 traffic no longer hits the deny (#5577)")
	}
	if got := g.effectiveMatchFromZones(); len(got) != 1 || got[0] != "z174" {
		t.Fatalf("g-deny-scoped from-scope = %v, want [z174] (z214 pruned)", got)
	}
	if g.MatchFromZone != "z174" {
		t.Fatalf("g-deny-scoped singular MatchFromZone = %q, want z174 (regenerated from surviving set)", g.MatchFromZone)
	}
	if got := g.effectiveMatchToZones(); len(got) != 1 || got[0] != "untrust" {
		t.Fatalf("g-deny-scoped to-scope = %v, want [untrust] (untouched)", got)
	}

	// Middle-member prune retains order of the survivors.
	m, ok := byName["g-deny-middle"]
	if !ok {
		t.Fatalf("g-deny-middle was dropped, want pruned survivors")
	}
	if got := m.effectiveMatchFromZones(); len(got) != 2 || got[0] != "untrust" || got[1] != "z174" {
		t.Fatalf("g-deny-middle from-scope = %v, want [untrust z174]", got)
	}

	// To-side collision pruned; from-side untouched.
	t2, ok := byName["g-deny-to"]
	if !ok {
		t.Fatalf("g-deny-to was dropped, want to-side pruned to [z174]")
	}
	if got := t2.effectiveMatchToZones(); len(got) != 1 || got[0] != "z174" {
		t.Fatalf("g-deny-to to-scope = %v, want [z174]", got)
	}
	if t2.MatchToZone != "z174" {
		t.Fatalf("g-deny-to singular MatchToZone = %q, want z174", t2.MatchToZone)
	}

	// A rule whose every match member collided is dropped (would else broaden).
	if _, ok := byName["g-deny-all-quarantined"]; ok {
		t.Fatalf("scoped global whose ALL match members collided survived — would broaden to all zones (fail-open)")
	}
}

// TestQuarantineDropsZonePairEndpointStillDrops guards the OTHER direction of the
// #5577 distinction: a NON-scoped zone-pair rule whose singular FromZone/ToZone is
// quarantined is STRUCTURALLY unapplicable and must STILL be dropped (unchanged
// behavior — pruning does not apply to a required singular endpoint).
func TestQuarantineDropsZonePairEndpointStillDrops(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	snap := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "untrust", ID: config.StableZoneID("untrust")},
			{Name: "z174", ID: config.StableZoneID("z174")},
			{Name: "z214", ID: config.StableZoneID("z214")},
		},
		Policies: []PolicyRuleSnapshot{
			{Name: "zp-from-quarantined", FromZone: "z214", ToZone: "untrust", Action: "deny"},
			{Name: "zp-to-quarantined", FromZone: "untrust", ToZone: "z214", Action: "deny"},
			{Name: "zp-survivor", FromZone: "z174", ToZone: "untrust", Action: "deny"},
		},
	}
	quarantineCollidingZones(snap)
	kept := map[string]bool{}
	for _, p := range snap.Policies {
		kept[p.Name] = true
	}
	if kept["zp-from-quarantined"] || kept["zp-to-quarantined"] {
		t.Fatalf("zone-pair rule with a quarantined endpoint survived: %v", kept)
	}
	if !kept["zp-survivor"] {
		t.Fatalf("zone-pair survivor rule was wrongly dropped: %v", kept)
	}
}

// TestBuildSnapshotPrunesScopedGlobalMemberFromRealPath drives the REAL publish
// path (buildSnapshot) end-to-end: a config with a StableZoneID collision AND a
// scoped global DENY whose `match from-zone [z174 z214]` includes both the
// survivor and the quarantined zone must publish a deny that SURVIVES scoped to
// [z174] and references no unpublished zone. RED-on-revert: the old whole-rule
// drop removes the deny entirely, so the "deny present, scoped to z174" assertion
// fails and z174 traffic would fall through to the default permit.
func TestBuildSnapshotPrunesScopedGlobalMemberFromRealPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust"},
		"z174":    {Name: "z174"},
		"z214":    {Name: "z214"},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name: "g-multi-deny",
			Match: config.PolicyMatch{
				FromZones:    []string{"z174", "z214"},
				ToZones:      []string{"untrust"},
				Applications: []string{"any"},
			},
			Action: config.PolicyDeny,
		},
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	published := map[string]bool{}
	for _, z := range snap.Zones {
		published[z.Name] = true
	}
	var deny *PolicyRuleSnapshot
	for i := range snap.Policies {
		p := &snap.Policies[i]
		if p.Name == "g-multi-deny" {
			deny = p
		}
		for _, z := range append([]string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone},
			append(append([]string{}, p.MatchFromZones...), p.MatchToZones...)...) {
			if z == "" || z == "junos-global" {
				continue
			}
			if !published[z] {
				t.Fatalf("published policy %q references unpublished zone %q — Rust preflight would brick", p.Name, z)
			}
		}
	}
	if deny == nil {
		t.Fatalf("multi-zone scoped global deny was dropped from the built snapshot — fail-open (#5577)")
	}
	if got := deny.effectiveMatchFromZones(); len(got) != 1 || got[0] != "z174" {
		t.Fatalf("built deny from-scope = %v, want [z174] (z214 pruned, deny survives for z174)", got)
	}
}

// TestBuildSnapshotNoCollisionPublishesAll: the common case is untouched — an
// ordinary distinct-folding zone set publishes every zone and records no
// collision (no false positive).
func TestBuildSnapshotNoCollisionPublishesAll(t *testing.T) {
	cfg := threeZoneCfg()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Zones) != len(cfg.Security.Zones) {
		t.Fatalf("published %d zones, want %d (quarantine false positive?)", len(snap.Zones), len(cfg.Security.Zones))
	}
	if len(snap.zoneIDCollisions) != 0 {
		t.Fatalf("recorded a collision on a distinct-folding set: %v", snap.zoneIDCollisions)
	}
}

func TestBuildSnapshotQuarantinesReservedZoneNames(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":      {Name: "trust"},
		"junos-host": {Name: "junos-host"},
		"any":        {Name: "any"},
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("reserved zone names must not brick snapshot construction: %v", err)
	}
	published := map[string]bool{}
	for _, zone := range snap.Zones {
		published[zone.Name] = true
	}
	if !published["trust"] || published["junos-host"] || published["any"] {
		t.Fatalf("published zones = %v; want trust only", published)
	}
	if len(snap.zoneIDCollisions) != 2 {
		t.Fatalf("quarantine records = %v, want both reserved names", snap.zoneIDCollisions)
	}
	for _, record := range snap.zoneIDCollisions {
		if record.Survivor != "" {
			t.Fatalf("reserved-name quarantine has a fake collision survivor: %+v", record)
		}
	}
}

func TestReservedZoneQuarantinePoisonsDefinedAnyAndKeepsHostContext(t *testing.T) {
	snap := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "trust", ID: config.StableZoneID("trust")},
			{Name: "junos-host", ID: config.StableZoneID("junos-host")},
			{Name: "any", ID: config.StableZoneID("any")},
		},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-0.0", Zone: "trust"},
			{Name: "ge-0-0-1.0", Zone: "junos-host"},
			{Name: "ge-0-0-2.0", Zone: "any"},
		},
		Policies: []PolicyRuleSnapshot{
			{Name: "host-context", FromZone: "trust", ToZone: "junos-host"},
			{Name: "defined-any", FromZone: "any", ToZone: "trust"},
		},
	}
	collisions := quarantineCollidingZones(snap)
	if len(snap.Zones) != 1 || snap.Zones[0].Name != "trust" {
		t.Fatalf("reserved zones remained installed: %+v", snap.Zones)
	}
	if len(snap.Policies) != 2 {
		t.Fatalf("zone quarantine unexpectedly removed rules: %+v", snap.Policies)
	}
	var definedAny, hostContext *PolicyRuleSnapshot
	for i := range snap.Policies {
		switch snap.Policies[i].Name {
		case "defined-any":
			definedAny = &snap.Policies[i]
		case "host-context":
			hostContext = &snap.Policies[i]
		}
	}
	if definedAny == nil || definedAny.zonePairDefinedAnySide != "from-zone" ||
		len(definedAny.ApplicationTerms) != 1 || definedAny.ApplicationTerms[0].Protocol != unsupportedApplicationSentinel {
		t.Fatalf("defined-any policy was not poisoned before quarantine: %+v", definedAny)
	}
	if hostContext == nil || hostContext.zonePairDefinedAnySide != "" {
		t.Fatalf("valid host-context policy was changed: %+v", hostContext)
	}
	for _, iface := range snap.Interfaces {
		if iface.Name != "ge-0-0-0.0" && iface.Zone != "" {
			t.Fatalf("interface in reserved zone %q remained assigned to %q", iface.Name, iface.Zone)
		}
	}
	if len(collisions) != 2 {
		t.Fatalf("quarantine records = %v, want both reserved names", collisions)
	}
}

func TestConflictingZoneInterfaceMembershipHasNoUserspaceOwner(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"aaa":   {Name: "aaa", Interfaces: []string{"ge-0/0/0.0"}},
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}
	for _, zones := range []map[string]string{
		buildInterfaceZoneMap(cfg),
		authoredZoneRefs(cfg),
	} {
		if got := zones["ge-0/0/0.0"]; got != "" {
			t.Fatalf("conflicting interface resolved to zone %q, want no owner", got)
		}
	}
}
