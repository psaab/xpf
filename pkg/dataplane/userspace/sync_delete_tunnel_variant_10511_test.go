package userspace

import (
	"testing"
)

// #10511 MIN-10 handoff, helper-request half: a scoped key carrying
// PurgeTunnelVariants must reach the helper SessionSyncRequest intact, v4 and
// v6, while an unflagged key stays exact-match. Deleting either assignment in
// deleteHelperSessionsScopedV4/V6Marked silently narrows the helper to an
// exact delete the GRE0 row never matches, leaking it. Runs through the
// sync-only manager: no BPF, no privilege (peer of the #9364 domain cells).
func TestBatchDeleteCarriesTunnelVariantFlag10511(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	keys := scopedKeys9364(0, 1234, 1235)
	// GRE0-only flag rides a GRE row; the unflagged control stays TCP.
	keys[0].Key.Protocol = 47
	keys[0].PurgeTunnelVariants = true

	if err := m.deleteHelperSessionsScopedV4(keys); err != nil {
		t.Fatalf("deleteHelperSessionsScopedV4: %v", err)
	}
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE FAILED: recorded %d delete requests, want 2", len(got))
	}
	if !got[0].PurgeTunnelVariants {
		t.Error("flagged request lost PurgeTunnelVariants in batching; the helper takes " +
			"the exact-match path and the GRE0 row leaks")
	}
	if got[1].PurgeTunnelVariants {
		t.Error("unflagged request gained PurgeTunnelVariants in batching; a plain delete " +
			"must not widen into a wildcard")
	}
	for i, req := range got {
		if req.Operation != "delete" {
			t.Errorf("request %d operation = %q, want delete", i, req.Operation)
		}
	}
}

// V6 twin: V6 has its own batching function and could drift independently.
func TestBatchDeleteCarriesTunnelVariantFlagV6_10511(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	keys := scopedKeys10513V6(0, 1234, 1235)
	keys[0].Key.Protocol = 47
	keys[0].PurgeTunnelVariants = true

	if err := m.deleteHelperSessionsScopedV6(keys); err != nil {
		t.Fatalf("deleteHelperSessionsScopedV6: %v", err)
	}
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE FAILED: recorded %d delete requests, want 2", len(got))
	}
	if !got[0].PurgeTunnelVariants {
		t.Error("flagged V6 request lost PurgeTunnelVariants in batching")
	}
	if got[1].PurgeTunnelVariants {
		t.Error("unflagged V6 request gained PurgeTunnelVariants in batching")
	}
}
