package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestPartialRepublishStripsSingleUseRenameMetadata(t *testing.T) {
	cfg := &config.Config{}
	paths := []struct {
		name    string
		publish func(*Manager, *config.Config) error
		prepare func(*Manager)
	}{
		{
			name: "route overlay",
			publish: func(m *Manager, cfg *config.Config) error {
				_, err := m.PublishRouteOverlaySnapshot(cfg, nil, nil)
				return err
			},
		},
		{
			name: "policy scheduler",
			publish: func(m *Manager, cfg *config.Config) error {
				return m.UpdatePolicyScheduleState(cfg, map[string]bool{})
			},
		},
		{
			name:    "deferred worker arm",
			prepare: func(m *Manager) { m.pendingWorkerArm = true },
			publish: func(m *Manager, _ *config.Config) error {
				m.mu.Lock()
				defer m.mu.Unlock()
				return m.retryDeferredWorkerArmLocked()
			},
		},
		{
			name: "capture authority",
			prepare: func(m *Manager) {
				m.captureEpochProvider = func(uint64, uint32) (
					uint64,
					[]QueueEpochSnapshot,
					uint64,
					[]IpsecTunnelRowSnapshot,
				) {
					return 1, nil, 1, nil
				}
			},
			publish: func(m *Manager, _ *config.Config) error {
				_, err := m.RepublishCurrentCaptureAuthority()
				return err
			},
		},
	}

	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
			reqs := make(chan ControlRequest, 32)
			m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				select {
				case reqs <- req:
				default:
				}
				if status != nil {
					*status = ProcessStatus{PID: 4242}
				}
				return nil
			}
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 5, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			snap.Config = cfg
			snap.PolicyRenameAncestry = []PolicyRenameAncestry{{SourceRuleID: "old", DestinationRuleID: "new"}}
			snap.PolicySessionRebinds = []PolicySessionRebind{{Family: "ipv4", RuleID: "new", PolicyID: 2}}
			if tc.name == "deferred worker arm" {
				snap.DeferWorkers = true
			}
			m.lastSnapshot = snap
			m.generation = 5
			m.publishedSnapshot = 5
			if tc.prepare != nil {
				tc.prepare(m)
			}
			err = tc.publish(m, cfg)
			if err != nil && tc.name != "deferred worker arm" {
				t.Fatalf("partial republish: %v", err)
			}
			var snapshot *ConfigSnapshot
			deadline := time.After(2 * time.Second)
			for snapshot == nil {
				select {
				case req := <-reqs:
					if req.Snapshot != nil {
						snapshot = req.Snapshot
					}
				case <-deadline:
					t.Fatal("partial republish did not reach control socket")
				}
			}
			if len(snapshot.PolicyRenameAncestry) != 0 || len(snapshot.PolicySessionRebinds) != 0 {
				t.Fatalf("partial republish replayed single-use metadata: ancestry=%v rebinds=%v", snapshot.PolicyRenameAncestry, snapshot.PolicySessionRebinds)
			}
		})
	}
}

func TestDeferredReplayRetainsMetadataAfterFirstPublishFailure(t *testing.T) {
	cfg := scheduledPolicyConfig9520()
	ucfg := deriveUserspaceConfig(cfg)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg = ucfg
	m.syncCancel = func() {}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.xskLivenessProven = true
	seed := mustBuildSnapshot(t, cfg, ucfg, 7, 0)
	m.lastSnapshot = seed
	m.generation = 7
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(seed)
	if h, ok := snapshotContentHash(seed); ok {
		m.lastSnapshotHash = h
	}
	m.compileUserspaceShimHook = func(*config.Config) (*dataplane.CompileResult, error) {
		return &dataplane.CompileResult{}, nil
	}
	m.deferWorkers = true
	m.SetPolicyRenameAncestry(
		[]PolicyRenameAncestry{{SourceRuleID: "old", DestinationRuleID: "new"}},
		[]PolicySessionRebind{{Family: "ipv4", RuleID: "new", PolicyID: 2}},
	)
	var sent []*ConfigSnapshot
	failFirst := true
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			sent = append(sent, req.Snapshot)
			if failFirst {
				failFirst = false
				return errors.New("first publish failed")
			}
		}
		if status != nil {
			*status = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
		}
		return nil
	}
	if _, err := m.Compile(cfg); err == nil {
		t.Fatal("first worker-deferred publish unexpectedly succeeded")
	}
	// This is the daemon's post-ApplyConfig cleanup before the mandatory
	// same-commit MAC replay.
	m.deferWorkers = false
	m.RestagePolicyRenameAncestryForReplay()
	if _, err := m.Compile(cfg); err != nil {
		t.Fatalf("second replay publish: %v", err)
	}
	if len(sent) < 2 {
		t.Fatalf("apply_snapshot requests = %d, want failed first plus successful replay", len(sent))
	}
	for i, snap := range sent[:2] {
		if len(snap.PolicyRenameAncestry) != 1 || len(snap.PolicySessionRebinds) != 1 {
			t.Fatalf("publish %d lost exact deferred metadata: ancestry=%v rebinds=%v", i+1, snap.PolicyRenameAncestry, snap.PolicySessionRebinds)
		}
	}
}

func TestRestageRenameMetadataForDeferredReplay(t *testing.T) {
	m := New()
	// A stale retained snapshot must not be treated as replay provenance.
	m.lastSnapshot = &ConfigSnapshot{
		PolicyRenameAncestry: []PolicyRenameAncestry{{SourceRuleID: "stale", DestinationRuleID: "wrong"}},
	}
	m.deferredReplayAncestry = []PolicyRenameAncestry{{SourceRuleID: "old", DestinationRuleID: "new"}}
	m.deferredReplayRebinds = []PolicySessionRebind{{Family: "ipv4", RuleID: "new", PolicyID: 2}}
	m.deferredReplayReady = true
	m.RestagePolicyRenameAncestryForReplay()
	m.mu.Lock()
	ancestry, rebinds := m.takeStagedRenameMetadataLocked()
	m.deferredReplayInFlight = false
	m.mu.Unlock()
	if len(ancestry) != 1 || ancestry[0].SourceRuleID != "old" {
		t.Fatalf("restaged ancestry = %v, want one old->new record", ancestry)
	}
	if len(rebinds) != 1 || rebinds[0].RuleID != "new" {
		t.Fatalf("restaged rebinds = %v, want one new-rule record", rebinds)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.policyRenameAncestry) != 0 || len(m.policySessionRebinds) != 0 {
		t.Fatal("takeStagedRenameMetadataLocked did not clear the staging slot")
	}
}

func TestDeferredFullThenRouteOverlayPreservesRenameMetadata(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)
	f.snap.PolicyRenameAncestry = []PolicyRenameAncestry{
		{SourceRuleID: "old", DestinationRuleID: "new"},
	}
	f.snap.PolicySessionRebinds = []PolicySessionRebind{
		{Family: "ipv4", RuleID: "new", PolicyID: 2},
	}
	f.m.pendingFullSnapshotMetadata = true
	f.m.generation = f.snap.Generation
	var sent *ConfigSnapshot
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sent = req.Snapshot
		}
		if status != nil {
			*status = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
		}
		return nil
	}
	cfg := f.snap.Config
	if cfg == nil {
		cfg = &config.Config{}
		f.snap.Config = cfg
	}
	published, err := f.m.PublishRouteOverlaySnapshot(cfg, nil, nil)
	if err != nil || !published {
		t.Fatalf("deferred-first route overlay publish: published=%v err=%v", published, err)
	}
	if sent == nil {
		t.Fatal("route overlay did not send the first accepted snapshot")
	}
	if len(sent.PolicyRenameAncestry) != 1 || len(sent.PolicySessionRebinds) != 1 {
		t.Fatalf("deferred-first overlay stripped rename metadata: ancestry=%v rebinds=%v",
			sent.PolicyRenameAncestry, sent.PolicySessionRebinds)
	}
	if sent.Generation != f.snap.Generation+1 {
		t.Fatalf("deferred-first overlay generation = %d, want %d", sent.Generation, f.snap.Generation+1)
	}
}

func TestPublishedFullFIBBumpThenRouteOverlayStripsRenameMetadata(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)
	f.snap.PolicyRenameAncestry = []PolicyRenameAncestry{
		{SourceRuleID: "old", DestinationRuleID: "new"},
	}
	f.snap.PolicySessionRebinds = []PolicySessionRebind{
		{Family: "ipv4", RuleID: "new", PolicyID: 2},
	}
	f.m.pendingFullSnapshotMetadata = false
	f.m.generation = f.snap.Generation
	f.m.publishedSnapshot = f.snap.Generation
	var sent *ConfigSnapshot
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sent = req.Snapshot
		}
		if status != nil {
			*status = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
		}
		return nil
	}
	// Model BumpFIBGeneration's snapshot bookkeeping without requiring a BPF
	// map in this unprivileged fixture: it advances the retained generation
	// while leaving publishedSnapshot and the metadata latch untouched.
	f.m.mu.Lock()
	f.m.generation++
	f.m.lastSnapshot.Generation = f.m.generation
	f.m.mu.Unlock()

	cfg := f.snap.Config
	published, err := f.m.PublishRouteOverlaySnapshot(cfg, nil, nil)
	if err != nil || !published {
		t.Fatalf("post-FIB-bump route overlay publish: published=%v err=%v", published, err)
	}
	if sent == nil {
		t.Fatal("route overlay did not send the post-FIB-bump snapshot")
	}
	if len(sent.PolicyRenameAncestry) != 0 || len(sent.PolicySessionRebinds) != 0 {
		t.Fatalf("post-FIB-bump overlay replayed consumed rename metadata: ancestry=%v rebinds=%v",
			sent.PolicyRenameAncestry, sent.PolicySessionRebinds)
	}
}

func TestStatusPartialRepublishStripsConsumedRenameMetadataAfterFIBBump(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)
	f.m.xskLivenessProven = true
	f.m.pendingFullSnapshotMetadata = false
	f.m.publishedSnapshot = f.snap.Generation
	f.m.generation = f.snap.Generation + 1
	f.m.lastSnapshot.Generation = f.m.generation
	f.m.partialOutcomeUnknown = partialFabrics
	f.snap.PolicyRenameAncestry = []PolicyRenameAncestry{
		{SourceRuleID: "old", DestinationRuleID: "new"},
	}
	f.snap.PolicySessionRebinds = []PolicySessionRebind{
		{Family: "ipv4", RuleID: "new", PolicyID: 2},
	}
	var sent *ConfigSnapshot
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sent = req.Snapshot
		}
		if status != nil {
			*status = ProcessStatus{
				ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration:        req.Snapshot.Generation,
				LastFIBGeneration:             req.Snapshot.FIBGeneration,
			}
		}
		return nil
	}
	f.m.mu.Lock()
	err := f.m.syncSnapshotLocked()
	f.m.mu.Unlock()
	if err != nil {
		t.Fatalf("status partial republish: %v", err)
	}
	if sent == nil {
		t.Fatal("status partial republish did not send apply_snapshot")
	}
	if len(sent.PolicyRenameAncestry) != 0 || len(sent.PolicySessionRebinds) != 0 {
		t.Fatalf("status partial republish replayed consumed metadata: ancestry=%v rebinds=%v",
			sent.PolicyRenameAncestry, sent.PolicySessionRebinds)
	}
}

// TestStatusPartialRepublishPreservesRenameMetadataWhenFullPending pins the
// latch-TRUE (preserve) side of the status-path branch in syncSnapshotLocked
// (process_status.go): when a FIB bump advanced lastSnapshot.Generation without
// publishing a full snapshot, a later status tick can be the FIRST accepted
// publication of a deferred or unknown-outcome full snapshot, so its one-shot
// rename metadata must be preserved — the status-path twin of
// TestDeferredFullThenRouteOverlayPreservesRenameMetadata, and the mirror of
// TestStatusPartialRepublishStripsConsumedRenameMetadataAfterFIBBump (latch
// FALSE). RED-on-revert: delete the latch guard so the status path always
// strips, and this cell fails while both twins stay green — the mutant loses
// ancestry+rebinds on the first accepted publication and tears down renamed
// sessions (fail-closed availability regress, #10592 N1).
func TestStatusPartialRepublishPreservesRenameMetadataWhenFullPending(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)
	f.m.xskLivenessProven = true
	f.m.pendingFullSnapshotMetadata = true
	f.m.publishedSnapshot = f.snap.Generation
	f.m.generation = f.snap.Generation + 1
	f.m.lastSnapshot.Generation = f.m.generation
	f.m.partialOutcomeUnknown = partialFabrics
	f.snap.PolicyRenameAncestry = []PolicyRenameAncestry{
		{SourceRuleID: "old", DestinationRuleID: "new"},
	}
	f.snap.PolicySessionRebinds = []PolicySessionRebind{
		{Family: "ipv4", RuleID: "new", PolicyID: 2},
	}
	var sent *ConfigSnapshot
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sent = req.Snapshot
		}
		if status != nil {
			*status = ProcessStatus{
				ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration:        req.Snapshot.Generation,
				LastFIBGeneration:             req.Snapshot.FIBGeneration,
			}
		}
		return nil
	}
	f.m.mu.Lock()
	err := f.m.syncSnapshotLocked()
	f.m.mu.Unlock()
	if err != nil {
		t.Fatalf("status partial republish: %v", err)
	}
	if sent == nil {
		t.Fatal("status partial republish did not send apply_snapshot")
	}
	if len(sent.PolicyRenameAncestry) != 1 || len(sent.PolicySessionRebinds) != 1 {
		t.Fatalf("deferred-first status publish stripped rename metadata: ancestry=%v rebinds=%v",
			sent.PolicyRenameAncestry, sent.PolicySessionRebinds)
	}
	if f.m.pendingFullSnapshotMetadata {
		t.Fatal("successful status-first publication did not clear the full-snapshot metadata latch")
	}
}
