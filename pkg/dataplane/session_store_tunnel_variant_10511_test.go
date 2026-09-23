package dataplane

import (
	"testing"
)

// #10511 MIN-10 handoff, store half: a SessionEntry carrying PurgeTunnelVariants
// (set only by the policy-invalidation capture for GRE0 rows) must survive
// scoped-key construction onto BOTH the forward key and its reverse companion,
// v4 and v6. An unflagged entry must stay unflagged. Deleting any of the four
// copy sites in DeleteBatchKnownV4/V6 silently downgrades the helper to an
// exact-match delete that cannot address the GRE0 row, leaking it. Runs through
// domainRecorderDP: no BPF, no privilege.
func TestDeleteBatchKnownCarriesTunnelVariantFlag10511(t *testing.T) {
	dp := &domainRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}

	fwd := key9364(1234)
	rev := key9364(4321)
	// The flag is GRE0-only in production: model GRE rows so a future boundary
	// validation cannot invalidate the positive case. The unflagged control
	// stays TCP.
	fwd.Protocol, rev.Protocol = 47, 47
	plain := key9364(1235)
	entries := []SessionEntryV4{
		{
			Key:                 fwd,
			Value:               SessionValue{ReverseKey: rev},
			PurgeTunnelVariants: true,
		},
		{
			Key:                 plain,
			Value:               SessionValue{},
			PurgeTunnelVariants: false,
		},
	}

	if _, err := store.DeleteBatchKnownV4(entries, DeleteReasonPolicyDeleted, false); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	// Forward + reverse companion for the flagged entry; forward only for the
	// plain one (zero ReverseKey, so no companion is derived).
	if len(dp.scopedV4) != 3 {
		t.Fatalf("recorded %d scoped keys, want 3 (flagged forward + reverse, plain forward); got %+v",
			len(dp.scopedV4), dp.scopedV4)
	}
	seen := map[SessionKey]bool{}
	for _, sk := range dp.scopedV4 {
		seen[sk.Key] = sk.PurgeTunnelVariants
	}
	for name, k := range map[string]SessionKey{"forward": fwd, "reverse": rev} {
		got, ok := seen[k]
		if !ok {
			t.Errorf("the flagged %s key never reached the dataplane", name)
			continue
		}
		if !got {
			t.Errorf("the flagged %s key reached the dataplane without PurgeTunnelVariants; "+
				"the helper takes the exact-match path and the GRE0 row leaks", name)
		}
	}
	if got, ok := seen[plain]; !ok || got {
		t.Errorf("plain entry: present=%v flag=%v, want present with flag clear — an "+
			"unflagged delete must not widen into a wildcard", ok, got)
	}
}

// V6 twin: V6 has its own derivation and could drift independently.
func TestDeleteBatchKnownCarriesTunnelVariantFlagV6_10511(t *testing.T) {
	dp := &domainRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}

	fwd := SessionKeyV6{Protocol: 47, SrcPort: 1234, DstPort: 443}
	rev := SessionKeyV6{Protocol: 47, SrcPort: 4321, DstPort: 443}
	plain := SessionKeyV6{Protocol: 6, SrcPort: 1235, DstPort: 443}
	entries := []SessionEntryV6{
		{
			Key:                 fwd,
			Value:               SessionValueV6{ReverseKey: rev},
			PurgeTunnelVariants: true,
		},
		{
			Key:                 plain,
			Value:               SessionValueV6{},
			PurgeTunnelVariants: false,
		},
	}

	if _, err := store.DeleteBatchKnownV6(entries, DeleteReasonPolicyDeleted, false); err != nil {
		t.Fatalf("DeleteBatchKnownV6: %v", err)
	}
	if len(dp.scopedV6) != 3 {
		t.Fatalf("recorded %d scoped V6 keys, want 3; got %+v", len(dp.scopedV6), dp.scopedV6)
	}
	seen := map[SessionKeyV6]bool{}
	for _, sk := range dp.scopedV6 {
		seen[sk.Key] = sk.PurgeTunnelVariants
	}
	for name, k := range map[string]SessionKeyV6{"forward": fwd, "reverse": rev} {
		got, ok := seen[k]
		if !ok {
			t.Errorf("the flagged V6 %s key never reached the dataplane", name)
			continue
		}
		if !got {
			t.Errorf("the flagged V6 %s key reached the dataplane without PurgeTunnelVariants", name)
		}
	}
	if got, ok := seen[plain]; !ok || got {
		t.Errorf("plain V6 entry: present=%v flag=%v, want present with flag clear", ok, got)
	}
}
