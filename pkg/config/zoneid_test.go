package config

import (
	"strings"
	"testing"
)

// Hash-freeze pins (#3075): StableZoneID is wire-adjacent — both HA nodes must
// compute identical ids from identical config, so the fold may NEVER change. If
// this test fails you changed the fold; revert. (The values were computed once
// and frozen.)
func TestStableZoneIDHashFreeze(t *testing.T) {
	pins := map[string]uint16{
		"trust":   50675,
		"untrust": 20665,
		"dmz":     56918,
		"alpha":   2748,
		// The verified colliding pair used by the gate tests below: both fold
		// to 53547 under the frozen fold.
		"z174": 53547,
		"z214": 53547,
	}
	for name, want := range pins {
		if got := StableZoneID(name); got != want {
			t.Fatalf("StableZoneID(%q) = %d, want %d — the fold is frozen (#3075)", name, got, want)
		}
	}
}

// id 0 means "unassigned / unknown zone" everywhere, and the top two ids
// (ZoneIDReservedMin, JUNOS_GLOBAL_ZONE_ID) are reserved sentinels — the fold
// must never emit any of them.
func TestStableZoneIDNeverZeroOrReserved(t *testing.T) {
	names := []string{"", "trust", "untrust", "dmz", "a", "zone-with-a-very-long-name", "wan", "lan"}
	for _, name := range names {
		id := StableZoneID(name)
		if id == 0 {
			t.Fatalf("StableZoneID(%q) = 0", name)
		}
		if id >= ZoneIDReservedMin {
			t.Fatalf("StableZoneID(%q) = %d landed in the reserved range [>= %d]", name, id, ZoneIDReservedMin)
		}
	}
}

// The defining property (#3075): StableZoneID is a PURE function of the name,
// so the id of an existing zone is identical whether or not an earlier-sorting
// zone exists. Reverting to the sorted 1..N positional assignment breaks this —
// adding "alpha" (sorts before "untrust") would shift untrust's id. The
// dataplane-compiler / daemon RED-on-revert guard for the assignment loop lives
// in pkg/dataplane and pkg/daemon; this pins the SSOT primitive itself.
func TestStableZoneIDPureFunctionAcrossEarlierZone(t *testing.T) {
	idWithout := StableZoneID("untrust")
	// "alpha" sorts before "untrust"; under the old sorted 1..N scheme adding
	// it would renumber untrust. The pure function cannot depend on the set.
	idWith := StableZoneID("untrust")
	if idWith != idWithout {
		t.Fatalf("StableZoneID(\"untrust\") changed: %d vs %d", idWithout, idWith)
	}
	// Distinct names get distinct ids in the common case.
	if StableZoneID("alpha") == StableZoneID("untrust") {
		t.Fatalf("alpha and untrust unexpectedly collide")
	}
}

// The commit-time collision gate hard-rejects a config whose two zone names
// fold to the same StableZoneID (strict path), with a two-name remediation
// error naming both zones. Removing validateZoneIDCollisionAST (or its dispatch
// in compiler.go) makes this go green on the colliding config — the regression
// it guards.
func TestZoneIDCollisionFailsCommit(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree := buildTree(t, []string{
		"set security zones security-zone z174",
		"set security zones security-zone z214",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a colliding zone pair")
	}
	for _, want := range []string{"z174", "z214", "collision", "rename"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
		}
	}
}

// Lenient (load / peer-sync) downgrades the collision to a warning so an
// already-persisted or peer-synced config still boots (#1960 no-brick),
// mirroring the tunnel-id gate.
func TestZoneIDCollisionLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone z174",
		"set security zones security-zone z214",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a colliding zone pair: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") && strings.Contains(w, "z174") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile carried no zone-id collision warning: %v", cfg.Warnings)
	}
}

// HA symmetry (three-view gate): a collision involving a `groups nodeN`-scoped
// zone must fail commit on BOTH nodes — including the node whose effective
// config never applies the group — or config-sync would split (originator
// accepts, peer rejects). View 1 unions zone names across the main hierarchy
// AND every groups block pre-expansion, so the verdict is node-independent.
func TestZoneIDCollisionAcrossGroupsIsSymmetric(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups node1 security zones security-zone z174",
		"set security zones security-zone z214",
		// No apply-groups: node0's effective config never contains z174 —
		// the union check must still reject on both nodes.
	})
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("node0 compile accepted a collision hidden in groups node1")
	}
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("node1 compile accepted a collision hidden in groups node1")
	}
}

// An ordinary multi-zone config commits cleanly — the gate must not perturb the
// common case (no false positive on distinct-folding names).
func TestZoneIDNoFalsePositiveOnOrdinaryZones(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary 3-zone config: %v", err)
	}
}

// #3719: QuarantinedZoneNames is the runtime SSOT the lenient-path builders use
// to enforce the collision warning's promise. For a colliding pair it must
// quarantine the LATER-sorting zone and keep the earlier one (which owns the
// id), so the dataplane never receives two zones sharing an id. Reverting the
// quarantine (returning nil / empty) makes this RED.
func TestQuarantinedZoneNamesDropsLaterColliding(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	q := QuarantinedZoneNames([]string{"z214", "z174"}) // deliberately unsorted input
	if _, dropped := q["z214"]; !dropped {
		t.Fatalf("QuarantinedZoneNames did not quarantine the later-sorting colliding zone z214: %v", q)
	}
	if _, dropped := q["z174"]; dropped {
		t.Fatalf("QuarantinedZoneNames wrongly quarantined the earlier-sorting survivor z174: %v", q)
	}
	if len(q) != 1 {
		t.Fatalf("QuarantinedZoneNames returned %d entries, want exactly 1 (only z214): %v", len(q), q)
	}
}

// The common case: distinct-folding names yield no quarantine (nil), and a
// single zone can never collide.
func TestQuarantinedZoneNamesNoFalsePositive(t *testing.T) {
	if q := QuarantinedZoneNames([]string{"trust", "untrust", "dmz"}); len(q) != 0 {
		t.Fatalf("QuarantinedZoneNames quarantined an ordinary distinct-folding set: %v", q)
	}
	if q := QuarantinedZoneNames([]string{"trust"}); len(q) != 0 {
		t.Fatalf("QuarantinedZoneNames quarantined a single zone: %v", q)
	}
}

// StableZoneIDOwner resolves a colliding id to the sorted-first (survivor) name
// — the zone the dataplane actually installed — so id->name reverse maps never
// name a quarantined zone.
func TestStableZoneIDOwnerReturnsSurvivor(t *testing.T) {
	id := StableZoneID("z174")
	owner := StableZoneIDOwner([]string{"z214", "z174"}, id)
	if owner != "z174" {
		t.Fatalf("StableZoneIDOwner(%d) = %q, want the sorted-first survivor z174", id, owner)
	}
	if got := StableZoneIDOwner([]string{"z174", "z214"}, 1); got != "" {
		t.Fatalf("StableZoneIDOwner for an unclaimed id = %q, want empty", got)
	}
}
func TestZoneQuarantineHelpersMatchRuntimeVerdict(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	names := []string{"z214", "z174"}
	exclusions := ZoneQuarantineExclusions(names)
	if _, ok := exclusions["z214"]; !ok {
		t.Fatalf("ZoneQuarantineExclusions did not preserve the runtime exclusion: %v", exclusions)
	}
	if _, ok := exclusions["z174"]; ok {
		t.Fatalf("ZoneQuarantineExclusions excluded the surviving zone: %v", exclusions)
	}

	cfg := &Config{Security: SecurityConfig{Zones: map[string]*ZoneConfig{
		"z174": {},
		"z214": {},
	}}}
	reason := ZoneQuarantineExcludedReason("z214", cfg)
	for _, want := range []string{"z214", "z174", "stable ID"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("quarantine reason %q does not mention %q", reason, want)
		}
	}
	if got := ZoneQuarantineExcludedReason("z174", cfg); got != "" {
		t.Fatalf("surviving zone received a quarantine reason: %q", got)
	}
	if got := ZoneQuarantineExcludedReason("ordinary", cfg); got != "" {
		t.Fatalf("ordinary zone received a quarantine reason: %q", got)
	}
	if got := ZoneQuarantineExcludedReason("z214", nil); got != "" {
		t.Fatalf("nil config received a quarantine reason: %q", got)
	}
}

// #3719 (L13): the lenient warning must state that the later-sorting zone is
// QUARANTINED and that isolation is degraded — the wording must not merely say
// "not installed" while the runtime published both (the pre-fix contradiction).
func TestZoneIDCollisionLenientWarningStatesQuarantine(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone z174",
		"set security zones security-zone z214",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a colliding zone pair: %v", err)
	}
	var warn string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") && strings.Contains(w, "z214") {
			warn = w
		}
	}
	if warn == "" {
		t.Fatalf("no zone-id collision warning naming z214: %v", cfg.Warnings)
	}
	for _, want := range []string{"QUARANTINED", "z174", "z214", "DEGRADED"} {
		if !strings.Contains(warn, want) {
			t.Fatalf("lenient warning %q does not mention %q", warn, want)
		}
	}
}
