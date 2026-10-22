package config

import (
	"encoding/json"
	"testing"
)

// #16142: the App ID space's typed returns. NaturalAppIDCandidate is the
// initial hash candidate; AssignStableAppIDs returns the collision-
// resolved AssignedAppID. The pair must not be conflated: for a colliding
// user pair the displaced name's assigned id differs from its candidate.
//
// RED-on-revert: rename NaturalAppIDCandidate back to a name claiming it
// is the assigned/stable id, or make AssignStableAppIDs return the bare
// candidate for every name, and the displaced-name assertion below fails
// (svc-396 would keep the shared candidate instead of its displaced id).
func TestAssignedAppIDDiffersFromCandidateOnCollision_16142(t *testing.T) {
	const owner = "svc-217"
	const displaced = "svc-396"
	candidate := NaturalAppIDCandidate(owner)
	if NaturalAppIDCandidate(displaced) != candidate {
		t.Skipf("fixture stale: %q and %q no longer collide (candidate %d vs %d)",
			owner, displaced, candidate, NaturalAppIDCandidate(displaced))
	}
	assigned, err := AssignStableAppIDs([]string{owner, displaced})
	if err != nil {
		t.Fatalf("AssignStableAppIDs: %v", err)
	}
	if assigned[owner] != candidate {
		t.Fatalf("sorted-first %q assigned %d, want its candidate %d (owner keeps slot)",
			owner, assigned[owner], candidate)
	}
	if assigned[displaced] == candidate {
		t.Fatalf("displaced %q kept candidate %d; AssignedAppID must be the collision-resolved id, not the NaturalAppIDCandidate",
			displaced, candidate)
	}
	if assigned[displaced] == 0 {
		t.Fatalf("displaced %q assigned reserved id 0", displaced)
	}
}

// TestAssignedAppIDJSONParity_16142 pins numeric parity at the JSON edge:
// an AssignedAppID marshals as the same JSON number as its uint16 value,
// so snapshot app_catalog bytes are unchanged by the typed return.
func TestAssignedAppIDJSONParity_16142(t *testing.T) {
	for _, id := range []AssignedAppID{0, 1, 49397, MaxCatalogAppID} {
		typed, err := json.Marshal(id)
		if err != nil {
			t.Fatalf("marshal AssignedAppID(%d): %v", id, err)
		}
		plain, err := json.Marshal(uint16(id))
		if err != nil {
			t.Fatalf("marshal uint16(%d): %v", id, err)
		}
		if string(typed) != string(plain) {
			t.Fatalf("AssignedAppID(%d) JSON = %s, want numeric parity with uint16 %s", id, typed, plain)
		}
	}
}
