package config

import (
	"fmt"
	"testing"
)

// #5296/#16142: app_id is a stable, name-derived candidate (NaturalAppIDCandidate)
// resolved to an AssignedAppID by AssignStableAppIDs, replacing the legacy sorted 1..N positional assignment whose
// ids shifted on an ordinary catalog edit and mis-resolved a RETAINED session's
// frozen app_id. These tests pin the stability, HA-symmetry, collision, and
// overflow contracts.

// TestNaturalAppIDCandidateHashFreeze freezes the fold output for a handful of names. The
// fold is semantics-bearing: a stamped app_id only round-trips to the right name
// while the fold is stable, so a change here must be a deliberate, reviewed
// migration — this test makes an accidental change RED.
func TestNaturalAppIDCandidateHashFreeze(t *testing.T) {
	want := map[string]AssignedAppID{
		"junos-http":    61388,
		"junos-https":   38147,
		"trust":         50675,
		"my-custom-app": 31593,
		"svc-bravo":     54084,
	}
	for name, id := range want {
		if got := NaturalAppIDCandidate(name); got != id {
			t.Errorf("NaturalAppIDCandidate(%q) = %d, frozen value is %d (the fold changed — a stamped app_id would no longer round-trip)", name, got, id)
		}
	}
}

// TestNaturalAppIDCandidateNeverZeroOrOverMax proves the fold lands strictly in
// [1, MaxCatalogAppID]: 0 is the reserved unknown sentinel and must never be
// assigned to a real application.
func TestNaturalAppIDCandidateNeverZeroOrOverMax(t *testing.T) {
	names := []string{"", "a", "junos-http", "SVC", "x-y-z", "0", "reserved"}
	for name := range PredefinedApplications {
		names = append(names, name)
	}
	for _, n := range names {
		id := NaturalAppIDCandidate(n)
		if id == 0 || id > MaxCatalogAppID {
			t.Fatalf("NaturalAppIDCandidate(%q) = %d, must be in [1,%d]", n, id, MaxCatalogAppID)
		}
	}
}

// TestPredefinedAppIDsCollisionFree freezes the invariant that the ~89 FIXED
// predefined application names are MUTUALLY collision-free under the fold, so
// they always own their NaturalAppIDCandidate slot and their ids are permanently stable
// (AssignStableAppIDs places them first and never probes them). A future
// predefined application whose name collides with an existing one turns this RED
// at CI time, forcing the collision to be resolved before it can silently
// displace another predefined app's id.
func TestPredefinedAppIDsCollisionFree(t *testing.T) {
	byID := map[AssignedAppID]string{}
	for name := range PredefinedApplications {
		id := NaturalAppIDCandidate(name)
		if other, dup := byID[id]; dup {
			t.Fatalf("predefined app id collision: %q and %q both fold to app_id %d — resolve before merge (a colliding predefined would displace a permanently-stable id)", name, other, id)
		}
		byID[id] = name
	}
}

// TestAssignStableAppIDsStableAcrossInsert is the CORE #5296 fail-on-revert: a
// catalog edit that inserts an EARLIER-sorting application must NOT renumber the
// existing (non-colliding) applications. The three svc-* names and aaa-early
// have distinct, non-colliding NaturalAppIDCandidates, so under the stable scheme aaa-early
// simply takes its own hash slot and the svc-* ids are unchanged.
//
// RED-on-revert: restore the sorted 1..N positional assignment and inserting
// aaa-early (which sorts first) shifts every svc-* id by one, failing the
// "unchanged" assertions.
func TestAssignStableAppIDsStableAcrossInsert(t *testing.T) {
	before, err := AssignStableAppIDs([]string{"svc-alpha", "svc-bravo", "svc-charlie"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := AssignStableAppIDs([]string{"aaa-early", "svc-alpha", "svc-bravo", "svc-charlie"})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"svc-alpha", "svc-bravo", "svc-charlie"} {
		if before[n] != after[n] {
			t.Errorf("inserting an earlier-sorting app renumbered %q: %d -> %d (ids must be stable across catalog edits)", n, before[n], after[n])
		}
		if after[n] != NaturalAppIDCandidate(n) {
			t.Errorf("%q id = %d, want its NaturalAppIDCandidate %d (no probing expected — these names do not collide)", n, after[n], NaturalAppIDCandidate(n))
		}
	}
	if after["aaa-early"] != NaturalAppIDCandidate("aaa-early") {
		t.Errorf("aaa-early id = %d, want its NaturalAppIDCandidate %d", after["aaa-early"], NaturalAppIDCandidate("aaa-early"))
	}
}

// TestAssignStableAppIDsOrderIndependent is the HA-symmetry guard: the id map is
// a pure function of the name SET, independent of the input order, so two nodes
// (and a cold boot) that see the same applications compute identical ids with
// zero synced/persisted state.
func TestAssignStableAppIDsOrderIndependent(t *testing.T) {
	set := []string{"aaa", "zzz", "junos-http", "mmm", "junos-https", "bbb"}
	shuffled := []string{"junos-https", "bbb", "zzz", "junos-http", "mmm", "aaa"}
	a, err := AssignStableAppIDs(set)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AssignStableAppIDs(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("map size differs by input order: %d vs %d", len(a), len(b))
	}
	for n, id := range a {
		if b[n] != id {
			t.Errorf("id for %q depends on input order: %d vs %d (must be a pure function of the name set for HA symmetry)", n, id, b[n])
		}
	}
}

// TestAssignStableAppIDsPredefinedWinsUserProbes proves the collision policy: a
// USER app whose NaturalAppIDCandidate collides with a PREDEFINED app is displaced to a
// different slot while the predefined app keeps its (permanently stable) id.
// collider-1057 folds to the same id as junos-bootpc.
func TestAssignStableAppIDsPredefinedWinsUserProbes(t *testing.T) {
	const userName = "collider-1057"
	const predName = "junos-bootpc"
	if NaturalAppIDCandidate(userName) != NaturalAppIDCandidate(predName) {
		t.Skipf("test fixture stale: %q no longer collides with %q under the fold", userName, predName)
	}
	if _, ok := PredefinedApplications[predName]; !ok {
		t.Skipf("test fixture stale: %q is no longer a predefined application", predName)
	}
	out, err := AssignStableAppIDs([]string{userName, predName})
	if err != nil {
		t.Fatal(err)
	}
	if out[predName] != NaturalAppIDCandidate(predName) {
		t.Errorf("predefined %q id = %d, want its NaturalAppIDCandidate %d (predefined must win its slot)", predName, out[predName], NaturalAppIDCandidate(predName))
	}
	if out[userName] == 0 {
		t.Errorf("displaced user %q got the reserved id 0", userName)
	}
	if out[userName] == out[predName] {
		t.Errorf("displaced user %q shares an id with %q (%d) — collision not resolved", userName, predName, out[userName])
	}
	if out[userName] == NaturalAppIDCandidate(userName) {
		t.Errorf("user %q kept its colliding base id %d instead of being displaced", userName, out[userName])
	}
}

// TestAssignStableAppIDsOverflow is the #3438 H4 fail-closed boundary in the new
// assignment: a catalog with more distinct applications than the u16 space can
// address must be rejected (fail-closed) rather than assigning a duplicate or
// the reserved id 0; exactly MaxCatalogAppID must be accepted with all-distinct
// nonzero ids.
func TestAssignStableAppIDsOverflow(t *testing.T) {
	names := make([]string, 0, int(MaxCatalogAppID)+1)
	for i := 0; i <= int(MaxCatalogAppID); i++ { // 65536 distinct names
		names = append(names, fmt.Sprintf("app-%06d", i))
	}
	if _, err := AssignStableAppIDs(names); err == nil {
		t.Fatal("AssignStableAppIDs(65536 apps) returned no error; the u16 app_id space must be rejected, not overrun")
	}

	names = names[:MaxCatalogAppID] // exactly 65535
	out, err := AssignStableAppIDs(names)
	if err != nil {
		t.Fatalf("AssignStableAppIDs(65535 apps) error = %v; the boundary must be accepted", err)
	}
	if len(out) != int(MaxCatalogAppID) {
		t.Fatalf("assigned %d ids, want %d", len(out), MaxCatalogAppID)
	}
	seen := map[AssignedAppID]bool{}
	for n, id := range out {
		if id == 0 {
			t.Fatalf("app %q assigned the reserved id 0", n)
		}
		if seen[id] {
			t.Fatalf("duplicate id %d assigned (probing failed to keep ids distinct)", id)
		}
		seen[id] = true
	}
}
