package config

import (
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
)

// AssignedAppID is the assigned application id for one ID space (#16142):
// the collision-resolved value AssignStableAppIDs /
// AssignStableAppIDsQuiet place for a name, carried by catalog entries,
// AppNames (reversed), CompileResult.AppIDs, and the session app_id the
// show paths resolve. Its underlying type is uint16 because app_id is a
// uint16 on the Rust wire (userspace-dp/src/protocol/security.rs) where 0
// is the reserved "unknown" sentinel, so real applications take ids
// 1..65535 (#3438). Explicit conversion to uint16/uint32 is required at
// ABI edges (#[repr(C)]/FFI layouts, sync-codec PutUint32, JSON numeric
// fields that stay plain integers) — this Go type deliberately does not
// cross those edges by implicit widening.
type AssignedAppID uint16

// MaxCatalogAppID is the largest assignable application id.
const MaxCatalogAppID AssignedAppID = 65535

// NaturalAppIDCandidate maps an application NAME to its initial hash
// candidate: FNV-1a/64 xor-folded to 16 bits, mapped into
// [1, MaxCatalogAppID]. It mirrors StableZoneID (#3075) for the
// application namespace (#5296).
//
// It is a CANDIDATE, not the assigned id: AssignStableAppIDs may displace
// a colliding user application to a different AssignedAppID (see its
// collision policy). Callers that need the id a session was actually
// stamped with must use the AssignStableAppIDs result, never this
// candidate alone.
//
// The candidate is a pure function of the application NAME alone — never
// of the rest of the catalog, the compile order, or allocation history —
// so adding, renaming, or removing an application can NEVER change
// another application's candidate. This replaces the legacy sorted 1..N
// positional assignment, whose ids shifted whenever an earlier-sorting
// name was inserted and then mis-resolved a RETAINED session's frozen
// app_id against the rebuilt catalog (#5296). Both HA nodes and a
// cold-booting node compute identical candidates by construction with
// zero synced/persisted state.
//
// THE FOLD IS SEMANTICS-BEARING AND MUST NOT CHANGE lightly: a stamped
// app_id only round-trips to the right name while the fold is stable.
// appid.BuildCatalog and dataplane.compileApplications assign catalog
// ids through AssignStableAppIDs, while the runtime tuple fallback uses
// AssignStableAppIDsQuiet. All three paths share this helper so their
// candidate semantics cannot drift. TestNaturalAppIDCandidateHashFreeze
// freezes output.
//
// 0 is never returned: id 0 means "unassigned / unknown application"
// across the dataplane.
func NaturalAppIDCandidate(name string) AssignedAppID {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
	return AssignedAppID(folded)%MaxCatalogAppID + 1 // [1, 65535]
}

// AssignStableAppIDs assigns a stable, name-derived application id to every name
// in the catalog and returns the name -> id map (#5296). It is the single
// assignment SSOT shared by appid.BuildCatalog and dataplane.compileApplications
// so the two producers cannot drift (the AppNames byte-identity contract,
// appid_catalog_parity_test.go).
//
// Collision policy (the app-namespace refinement over StableZoneID, whose few
// operator-named zones can afford a hard hash-collision reject): the application
// namespace is ~89 fixed predefined names plus arbitrary user names in the u16
// id space, so a bare-hash hard-reject would be too fragile. Instead:
//
//   - PREDEFINED applications (config.PredefinedApplications) are placed FIRST
//     and always own their NaturalAppIDCandidate slot. They are a FIXED, mutually
//     collision-free universe (TestPredefinedAppIDsCollisionFree freezes this),
//     so no predefined ever probes and predefined ids are permanently stable —
//     the common case (predefined apps label the common flows) never renumbers.
//   - USER applications are placed next, in sorted-name order. A user app whose
//     NaturalAppIDCandidate collides with an already-placed id is DISPLACED to the next
//     free slot (deterministic linear fill over ascending free ids). So a rare
//     hash collision degrades to a bounded reshuffle of the colliding user apps
//     only — NOT a whole-catalog renumber like the positional scheme.
//
// The result is a pure function of the name SET (independent of the input
// order): both HA nodes and a cold boot compute identical ids with zero
// synced/persisted state. It returns an error only when the catalog holds more
// than MaxCatalogAppID distinct names (the u16 space cannot give each a distinct
// id) — the same fail-closed boundary the positional scheme enforced (#3438 H4).
//
// HONEST RESIDUAL (#5296): stability is NOT absolute. If a newly added user app
// hash-collides with an existing USER app, the displaced-fill can renumber that
// small colliding set. This is a massive reduction from the positional defect
// (which renumbered on ANY earlier-sorting insert), not a zero-residual
// guarantee. The zero-residual path is Option A (versioning application identity
// in session state — a cross-language conntrack-ABI + HA-wire flag day),
// deliberately out of scope for this bounded, Go-only fix.
//
// AssignStableAppIDs assigns IDs and warns when a collision displaces a name.
func AssignStableAppIDs(names []string) (map[string]AssignedAppID, error) {
	return assignStableAppIDs(names, true)
}

// AssignStableAppIDsQuiet assigns the same IDs without warnings. Runtime
// fallback lookups can repeat assignment for colliding overlaps, so they must
// not emit a catalog-build diagnostic for each rendered session.
func AssignStableAppIDsQuiet(names []string) (map[string]AssignedAppID, error) {
	return assignStableAppIDs(names, false)
}

func assignStableAppIDs(names []string, warnOnDisplacement bool) (map[string]AssignedAppID, error) {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	if len(set) > int(MaxCatalogAppID) {
		return nil, fmt.Errorf("application catalog holds %d distinct applications, but the uint16 app_id space can assign at most %d distinct ids (0 is the reserved unknown sentinel); reduce the number of referenced applications", len(set), MaxCatalogAppID)
	}

	// Split predefined vs user; sort each for a deterministic, order-independent
	// placement. Predefined are placed first so they always own their (frozen,
	// collision-free) NaturalAppIDCandidate slot.
	var predef, user []string
	for n := range set {
		if _, ok := PredefinedApplications[n]; ok {
			predef = append(predef, n)
		} else {
			user = append(user, n)
		}
	}
	sort.Strings(predef)
	sort.Strings(user)

	out := make(map[string]AssignedAppID, len(set))
	taken := make(map[AssignedAppID]bool, len(set))
	var displaced []string
	place := func(names []string) {
		for _, n := range names {
			id := NaturalAppIDCandidate(n)
			if taken[id] {
				// Collision with an already-placed id: defer to the free-slot
				// fill below (a predefined never reaches here — the freeze
				// guarantees predefined are mutually collision-free and they are
				// placed first, so only a user app can be displaced).
				displaced = append(displaced, n)
				continue
			}
			taken[id] = true
			out[n] = id
		}
	}
	place(predef)
	place(user)

	// Fill displaced names into the lowest free ids in deterministic order. The
	// count check above guarantees enough free slots exist.
	if len(displaced) > 0 {
		free := make([]AssignedAppID, 0, len(displaced))
		for id := AssignedAppID(1); id <= MaxCatalogAppID && len(free) < len(displaced); id++ {
			if !taken[id] {
				free = append(free, id)
			}
		}
		for i, n := range displaced {
			out[n] = free[i]
			taken[free[i]] = true
			// A displaced app is the HONEST RESIDUAL (#5296): its stable,
			// name-derived NaturalAppIDCandidate hash-collided with an already-placed id
			// (another user app, or — placed first — a predefined), so it was
			// bumped to the lowest free id. That bumped id is NOT a pure
			// function of the app name alone, so this small colliding set can
			// renumber across catalog edits — the one case the doc says needs
			// operator attention. The warning is for config/catalog assignment;
			// runtime fallback uses the quiet form to avoid logging per session.
			if warnOnDisplacement {
				slog.Warn("application id displaced by stable-id hash collision; its app_id may renumber across catalog edits (rare — see docs/services-application-identification.md)",
					"application", n,
					"natural_app_id", uint16(NaturalAppIDCandidate(n)),
					"assigned_app_id", uint16(free[i]))
			}
		}
	}

	return out, nil
}
