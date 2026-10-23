package config

import (
	"strings"
	"testing"
)

// #8317: a redundancy-group id has TWO ceilings and only one was enforced.
//
//	heartbeat per-group id field is one byte -> 255  (enforced, with a message)
//	rg_active / ha_watchdog array length     -> 16   (NOT enforced)
//
// Both limits were already written down. The 16 existed only as the max_entries
// of the two BPF arrays the id indexes, so nothing connected it to the value an
// operator types, and ids 16..255 committed against arrays whose valid indices
// are 0..15.
//
// WHY IT MATTERS AT RUNTIME, measured rather than inferred: a BPF array with
// max_entries 16 accepts an update at key 15 and returns E2BIG ("key too big
// for map") at 16, 17 and 255. `Manager.UpdateRGActive` returns that error
// BEFORE recording the group or syncing HA state to the helper, so the RG never
// activates and its RETH interfaces never forward, while the reconcile loop
// retries forever (#757). A loud, permanent failure rather than a silent one —
// but a failure the operator was allowed to commit.
func TestRedundancyGroupIDBoundedByDataplaneArray8317(t *testing.T) {
	for _, tc := range []struct {
		id        string
		wantRefus bool
		wantMsg   string
		why       string
	}{
		// THE BOUNDARY, and the row that matters most. An off-by-one here
		// silently breaks a working cluster on upgrade, which is worse than the
		// bug being fixed.
		{"15", false, "", "the highest usable id — MaxRedundancyGroups-1 — must still commit"},
		{"0", false, "", "id 0 indexes rg_active[0], the node-level slot"},
		{"1", false, "", "the ordinary case"},

		// The defect.
		{"16", true, "rg_active", "first index past the array"},
		{"17", true, "rg_active", ""},
		{"200", true, "rg_active", ""},

		// Still refused by the PRE-EXISTING one-byte bound, and it must keep
		// winning for an id that violates both — it names the more surprising
		// consequence (a silent collision with another group). If this row ever
		// reports the array message, the two checks have been reordered.
		{"256", true, "one byte", "the heartbeat-field bound must still own this id"},
		{"9999", true, "one byte", ""},
	} {
		t.Run("rg-"+tc.id, func(t *testing.T) {
			// CompileConfig runs validateChassisClusterStrict, so drive it
			// directly rather than through compileTreeFromSet — that helper
			// t.Fatalf's on a compile error, which would kill every refusal row
			// inside the harness before it reached an assertion here.
			tree := &ConfigTree{}
			for _, line := range []string{
				"set chassis cluster cluster-id 1",
				"set chassis cluster node 0",
				"set chassis cluster authentication-key secret1234567890ab",
				"set chassis cluster redundancy-group " + tc.id + " node 0 priority 200",
				"set chassis cluster redundancy-group " + tc.id + " node 1 priority 100",
			} {
				path, perr := ParseSetCommand(line)
				if perr != nil {
					t.Fatalf("ParseSetCommand(%q): %v", line, perr)
				}
				if serr := tree.SetPath(path); serr != nil {
					t.Fatalf("SetPath(%q): %v", line, serr)
				}
			}
			_, err := CompileConfig(tree)
			if !tc.wantRefus {
				if err != nil {
					t.Fatalf("redundancy-group %s must still COMMIT, got %v.\n%s\n"+
						"Over-rejecting here breaks a working cluster on upgrade.",
						tc.id, err, tc.why)
				}
				return
			}
			if err == nil {
				t.Fatalf("redundancy-group %s must be REFUSED at commit. %s", tc.id, tc.why)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("redundancy-group %s: refusal must name %q as the reason, got %q.\n%s",
					tc.id, tc.wantMsg, err, tc.why)
			}
		})
	}
}

// ASSERT THE AGREEMENT, and note what makes it strong: there is nothing to
// assert equal, because there is only one constant.
//
// `dataplane.MaxRedundancyGroups` is an ALIAS of the value below, so "the
// commit bound equals the array length" is a compile-time identity rather than
// a test that must be remembered. This cell exists to state the invariant where
// someone editing the bound will read it, and to fail loudly if a future change
// re-introduces a second literal here — which is precisely what created the gap.
//
// The cross-package half (the alias, and that the BPF specs are sized from it)
// is asserted in pkg/dataplane, which can import this package; the reverse
// import would be a cycle.
func TestRedundancyGroupBoundIsTheOnlyLiteral8317(t *testing.T) {
	if MaxRedundancyGroups != 16 {
		t.Fatalf("MaxRedundancyGroups = %d; if the dataplane arrays really grew, "+
			"this is the ONE place to change and pkg/dataplane follows by alias — "+
			"but check that rg_active and ha_watchdog actually grew with it",
			MaxRedundancyGroups)
	}
	if MaxRedundancyGroups > MaxHeartbeatRedundancyGroupID+1 {
		t.Fatalf("MaxRedundancyGroups (%d) exceeds the one-byte heartbeat id space "+
			"(0..%d) — the array bound could then never fire, because the wire bound "+
			"would reject first, and the #8317 refusal would be dead code",
			MaxRedundancyGroups, MaxHeartbeatRedundancyGroupID)
	}
}
