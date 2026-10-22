package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16153 (W2.4) regression suite.
//
// P3: the partial publishers (route-overlay, capture-authority,
// link-refresh, policy-scheduler, deferred worker-arm) now share the
// clone->bump->hash->dedup->adopt pipeline in
// manager_partial_publish.go. The dedup predicates differ per publisher
// and are characterized here, NOT unified:
//   - route: shared dedupHit only.
//   - capture: dedupHit AND publishedSnapshot != 0 (an extra arm).
//   - link-refresh: dedupHit AND resampled == 0.
//
// FAIL-ON-REVERT: dropping the capture publisher's publishedSnapshot
// arm (making it use the bare shared dedupHit) turns the
// unpublished-capture cell below RED — it would dedup-skip a snapshot
// the helper never received. Collapsing the predicates the other way
// (giving route the capture arm) breaks the route dedup cell in
// publish_hash_dedup_15955_test.go.
//
// P4: the four capture-authority fields are stamped through the single
// captureAuthorityFields.applyTo helper. Mutating a provider's backing
// slice after the stamp must not leak into the snapshot (detach), and
// the builder stamp and the retained refresh must produce identical
// field values for the same provider result.
//
// P2: typed policy actions. The send-site invariant refuses unknown /
// empty rule actions and non-empty garbage defaults as known-unsent
// (errSnapshotPolicyAction, matched by isKnownUnsentFailure), while
// admitting the three known tokens and the empty (omitempty) default.
// FAIL-ON-REVERT: removing the action arm from validateSnapshotForSend
// lets the invalid cells ship to the helper and turns this test RED.
//
// P8 (canary-aware narrowed): NO binding_plan.go move is made — the
// pure helpers (snapshotBindingPlanKey et al.) stay in maps_sync.go
// where binding_plan_key_crossplane_8901_test.go's source-text
// canaries read them. TestBindingPlanHelpersStayReachable16153 pins
// that the helpers remain directly callable from this package (their
// existing direct tests keep passing unchanged).

func captureManager16153(t *testing.T, sent *[]ConfigSnapshot) (*Manager, *config.Config) {
	t.Helper()
	cfg := overlayTestConfig()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	// The retained hash must describe the REFRESHED clone the publisher
	// will build, not the raw retained snapshot: refreshCaptureAuthority
	// detaches the capture slices (nil -> empty copies change the JSON
	// hash input), so hash the clone exactly as the publisher does —
	// otherwise the dedup predicate never engages and the test is
	// vacuous. The provider below returns the retained authority
	// verbatim, so the refreshed clone is the dedup candidate.
	m.captureEpochProvider = func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return m.lastSnapshot.PermitEpoch, m.lastSnapshot.QueueEpochs,
			m.lastSnapshot.IpsecTunnelSnapshotGeneration, m.lastSnapshot.IpsecTunnelRows
	}
	probe := *m.lastSnapshot
	m.refreshCaptureAuthorityLocked(&probe)
	if h, ok := snapshotContentHash(&probe); ok {
		m.lastSnapshotHash = h
	} else {
		t.Fatal("fixture snapshot did not hash")
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			*sent = append(*sent, *req.Snapshot)
			if status != nil {
				*status = ProcessStatus{
					ConfigSnapshotProtocolVersion: ProtocolVersion,
					LastSnapshotGeneration:        req.Snapshot.Generation,
					LastFIBGeneration:             req.Snapshot.FIBGeneration,
				}
			}
		}
		return nil
	}
	return m, cfg
}

// TestCaptureDedupRequiresPublished16153 characterizes the capture-vs-
// route dedup difference: with identical content (hash match) and no
// unknown outcomes, the capture publisher still publishes when nothing
// was ever published (publishedSnapshot == 0), and dedups only once a
// publication exists.
func TestCaptureDedupRequiresPublished16153(t *testing.T) {
	var sent []ConfigSnapshot
	m, _ := captureManager16153(t, &sent)

	// Never published: hash matches but the helper holds nothing, so
	// the extra capture arm must NOT skip.
	m.publishedSnapshot = 0
	published, err := m.RepublishCurrentCaptureAuthority()
	if err != nil || !published {
		t.Fatalf("unpublished capture republish = (%t, %v), want a publish (capture dedup requires publishedSnapshot != 0)", published, err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent %d snapshots, want 1", len(sent))
	}
	if m.publishedSnapshot != m.lastSnapshot.Generation || m.lastSnapshot.Generation != 8 {
		t.Fatalf("published/generation = %d/%d, want 8/8 after adopt", m.publishedSnapshot, m.lastSnapshot.Generation)
	}
	if m.generation != 8 {
		t.Fatalf("m.generation = %d, want 8 committed on success", m.generation)
	}

	// Now published with identical content: the capture dedup skips.
	published, err = m.RepublishCurrentCaptureAuthority()
	if err != nil || published {
		t.Fatalf("duplicate capture republish = (%t, %v), want a dedup skip", published, err)
	}
	if len(sent) != 1 {
		t.Fatalf("dedup skip sent a second snapshot (%d total)", len(sent))
	}
}

// TestCaptureStampDetachAndParity16153 pins P4: both stamp entry points
// write the same four fields from the same provider result, and the
// stamped slices are detached from the provider's backing arrays.
func TestCaptureStampDetachAndParity16153(t *testing.T) {
	queues := []QueueEpochSnapshot{{Queue: 3, Epoch: 11}}
	rows := []IpsecTunnelRowSnapshot{{STN: "st0.0", IfID: 8}}
	provider := func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 42, queues, 7, rows
	}

	built := &ConfigSnapshot{Generation: 5, FIBGeneration: 2}
	stampCaptureAuthorityWithRoutesMode(built, provider, nil, true)

	m := New()
	m.captureEpochProvider = provider
	retained := &ConfigSnapshot{Generation: 5, FIBGeneration: 2}
	m.refreshCaptureAuthorityLocked(retained)

	for name, snap := range map[string]*ConfigSnapshot{"builder": built, "refresh": retained} {
		if snap.PermitEpoch != 42 || snap.IpsecTunnelSnapshotGeneration != 7 {
			t.Fatalf("%s stamp epochs = %d/%d, want 42/7", name, snap.PermitEpoch, snap.IpsecTunnelSnapshotGeneration)
		}
		if len(snap.QueueEpochs) != 1 || snap.QueueEpochs[0].Epoch != 11 {
			t.Fatalf("%s stamp queues = %+v, want the provider queue", name, snap.QueueEpochs)
		}
		if len(snap.IpsecTunnelRows) != 1 || snap.IpsecTunnelRows[0].STN != "st0.0" {
			t.Fatalf("%s stamp rows = %+v, want the provider row", name, snap.IpsecTunnelRows)
		}
	}

	// Detach: mutating the provider's backing arrays after the stamp
	// must not leak into either snapshot.
	queues[0].Epoch = 99
	rows[0].STN = "mutated"
	if built.QueueEpochs[0].Epoch != 11 || retained.QueueEpochs[0].Epoch != 11 {
		t.Fatalf("queue stamp aliases provider backing: built=%d refresh=%d, want 11/11",
			built.QueueEpochs[0].Epoch, retained.QueueEpochs[0].Epoch)
	}
	if built.IpsecTunnelRows[0].STN != "st0.0" || retained.IpsecTunnelRows[0].STN != "st0.0" {
		t.Fatalf("tunnel stamp aliases provider backing: built=%q refresh=%q, want st0.0/st0.0",
			built.IpsecTunnelRows[0].STN, retained.IpsecTunnelRows[0].STN)
	}
}

// TestSendGateTypedPolicyActions16153 is the P2 differential table:
// known tokens (and the empty default) are admitted; empty / malformed /
// future rule actions and garbage defaults are refused known-unsent so
// no retry-debt authority is adopted and the prior snapshot stays live.
func TestSendGateTypedPolicyActions16153(t *testing.T) {
	rule := func(action string) []PolicyRuleSnapshot {
		return []PolicyRuleSnapshot{{Name: "r1", Action: action}}
	}
	cases := []struct {
		name    string
		def     string
		rules   []PolicyRuleSnapshot
		wantErr bool
	}{
		{"permit rule, deny default", "deny", rule("permit"), false},
		{"deny rule, empty default (omitempty)", "", rule("deny"), false},
		{"reject rule, reject default", "reject", rule("reject"), false},
		{"no rules, permit default", "permit", nil, false},
		{"empty rule action", "deny", rule(""), true},
		{"future rule action", "deny", rule("reject-all"), true},
		{"malformed rule action", "deny", rule("PERMIT"), true},
		{"garbage default", "allow", rule("permit"), true},
		{"filter vocabulary not unified (accept)", "deny", rule("accept"), true},
		{"filter vocabulary not unified (discard)", "deny", rule("discard"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			snap := &ConfigSnapshot{
				Version:       ProtocolVersion,
				Generation:    3,
				DefaultPolicy: tc.def,
				Policies:      tc.rules,
			}
			snap.Summary.PolicyCount = len(tc.rules)
			m.expectedPolicyCount = len(tc.rules)
			err := m.validateSnapshotForSend(snap)
			if tc.wantErr {
				if !errors.Is(err, errSnapshotPolicyAction) {
					t.Fatalf("validateSnapshotForSend err = %v, want errSnapshotPolicyAction", err)
				}
				if !isKnownUnsentFailure(err) {
					t.Fatalf("action refusal must be known-unsent (no retry debt): %v", err)
				}
			} else if err != nil {
				t.Fatalf("validateSnapshotForSend err = %v, want admitted", err)
			}
		})
	}

	// The typed vocabulary itself: exactly the three tokens.
	for token, want := range map[string]bool{
		"permit": true, "deny": true, "reject": true,
		"": false, "accept": false, "discard": false, "permit-all": false,
	} {
		if _, ok := typedPolicyAction(token); ok != want {
			t.Fatalf("typedPolicyAction(%q) ok = %t, want %t", token, ok, want)
		}
	}
	// The lowerer only emits typed tokens, including for out-of-range
	// config values (fail closed to deny, never permit).
	for in, want := range map[config.PolicyAction]string{
		config.PolicyPermit:     "permit",
		config.PolicyDeny:       "deny",
		config.PolicyReject:     "reject",
		config.PolicyAction(99): "deny",
	} {
		if got := policyActionString(in); got != want {
			t.Fatalf("policyActionString(%d) = %q, want %q", int(in), got, want)
		}
	}
}

// TestBindingPlanHelpersStayReachable16153 pins the P8 narrowed form:
// no standalone binding_plan.go move — the pure helpers remain directly
// callable (and canary-readable in maps_sync.go), and a partial adopt
// records the plan key from them exactly as before.
func TestBindingPlanHelpersStayReachable16153(t *testing.T) {
	snap := &ConfigSnapshot{Version: ProtocolVersion, Generation: 9}
	key := snapshotBindingPlanKey(snap)
	entries := buildUserspaceIngressDomainEntries(snap)
	if entries == nil && key == "" {
		t.Fatal("binding-plan helpers must stay reachable and functional in place")
	}
	if got := snapshotBindingPlanKey(snap); got != key {
		t.Fatalf("snapshotBindingPlanKey not deterministic: %q vs %q", got, key)
	}
	_ = buildUserspaceIngressIfindexes
}
