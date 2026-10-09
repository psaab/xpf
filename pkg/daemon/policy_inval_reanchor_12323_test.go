package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type policyListApply12072DP struct {
	*policyListRead12072DP
	generation uint64
	applyErr   error
}

func (d *policyListApply12072DP) ApplyConfig(_ context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	if d.applyErr != nil {
		err := d.applyErr
		d.applyErr = nil
		return nil, err
	}
	d.generation++
	d.policyInvalTestDP.appliedConfig = cfg
	d.activeCfg = cfg
	return &dataplane.ApplyResult{Generation: d.generation}, nil
}

func TestPolicyInvalidationReanchorRetainsPublishedScanFailure12323(t *testing.T) {
	c0 := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	c1 := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	c2 := twoPolicyConfig([]string{"p-first"}, nil)
	c0IDs := dpuserspace.PolicyIDsByStableKey(c0)
	c1IDs := dpuserspace.PolicyIDsByStableKey(c1)
	const webSessionID, sshSessionID = 4001, 4002
	mk := func(policyID uint32, sessionID uint64, srcPort uint16) dpuserspace.SessionPolicyMatch {
		return dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: srcPort, DstPort: 443,
			},
			PolicyID: policyID, ExpectedRTFlowSessionID: sessionID,
		}
	}
	readErr := errors.New("worker-1: transient queue timeout")
	dp := &policyListApply12072DP{policyListRead12072DP: &policyListRead12072DP{
		policyInvalTestDP: &policyInvalTestDP{appliedConfig: c0},
		activeCfg:         c0,
		rows: []dpuserspace.SessionPolicyMatch{
			mk(c0IDs["trust->untrust/p-web"], webSessionID, 4001),
			mk(c0IDs["trust->untrust/p-ssh"], sshSessionID, 4002),
		},
		stableRuleIDsBySession: map[uint64]string{
			webSessionID: "trust->untrust/p-web",
			sshSessionID: "trust->untrust/p-ssh",
		},
		readErr: readErr, readErrOnce: true,
	}}
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
	d.setDataplane(dp)
	if _, err := d.store.SyncApply("system { host-name c0; }", nil); err != nil {
		t.Fatalf("promote C0: %v", err)
	}

	if _, err := d.store.SyncApply("system { host-name c1; }", nil); err != nil {
		t.Fatalf("promote C1: %v", err)
	}
	d.armPolicyInvalidationPlan(c0, c1)
	d.capturePolicyInvalidationLocked(c1)
	if capture := d.policyInvalidationCapture; capture == nil || !errors.Is(capture.readErr, readErr) {
		t.Fatalf("first capture read error = %v, want transient failure", capture)
	}
	if dp.request.ExpectedConfig != c0 {
		t.Fatalf("first helper LIST expected config = %p, want C0 %p", dp.request.ExpectedConfig, c0)
	}
	result, err := dp.ApplyConfig(context.Background(), c1)
	if err != nil {
		t.Fatalf("publish C1: %v", err)
	}
	d.notePolicyInvalidationPublish(c1, result.Generation)
	recordAppliedDigest := func() {
		if debt := d.policyInvalidationDebt; debt != nil {
			debt.appliedDigest = d.store.ActiveDigest()
		}
	}
	recordAppliedDigest()
	if err := d.dischargePolicyInvalidationDebtLocked(c0, c1); !errors.Is(err, readErr) {
		t.Fatalf("C1 discharge error = %v, want transient READ failure", err)
	}
	if d.policyInvalidationDebt == nil || d.policyInvalidationDebt.oldCfg != c0 {
		t.Fatal("failed C0→C1 invalidation must retain its original namespace until a later landed target can re-anchor it")
	}
	if d.store.ActiveApplied() {
		t.Fatal("C1 publication with an incomplete invalidation was marked applied; config-sync shortcut must stay off")
	}

	if _, err := d.store.SyncApply("system { host-name c2; }", nil); err != nil {
		t.Fatalf("promote C2: %v", err)
	}
	d.armPolicyInvalidationPlan(c1, c2)
	if d.policyInvalidationPlan == nil || d.policyInvalidationPlan.oldCfg != c1 {
		t.Fatalf("fresh C2 plan retained stale namespace: %+v", d.policyInvalidationPlan)
	}
	d.capturePolicyInvalidationLocked(c2)
	if capture := d.policyInvalidationCapture; capture == nil || capture.readErr != nil {
		t.Fatalf("complete C1→C2 capture retained the superseded C0→C1 scan gap: %+v", capture)
	}
	if debt := d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil ||
		debt.scanFailure.oldCfg != c0 {
		t.Fatalf("store moved ahead of C1 helper authority but C1 scan debt was lost: %+v", debt)
	}
	if dp.request.ExpectedConfig != c1 {
		t.Fatalf("re-anchored helper LIST expected config = %p, want C1 %p", dp.request.ExpectedConfig, c1)
	}
	publishErr := errors.New("C2 publication failed before landing")
	dp.applyErr = publishErr
	if _, err := dp.ApplyConfig(context.Background(), c2); !errors.Is(err, publishErr) {
		t.Fatalf("first C2 apply error = %v, want %v", err, publishErr)
	}
	if dp.appliedConfig != c1 {
		t.Fatalf("failed C2 apply advanced helper config to %p, want C1 %p", dp.appliedConfig, c1)
	}

	d.armPolicyInvalidationPlan(c1, c2)
	if d.policyInvalidationPlan == nil || d.policyInvalidationPlan.oldCfg != c1 {
		t.Fatalf("same-pair C2 retry changed its applied namespace: %+v", d.policyInvalidationPlan)
	}
	d.capturePolicyInvalidationLocked(c2)
	if capture := d.policyInvalidationCapture; capture == nil || capture.readErr != nil {
		t.Fatalf("complete C1→C2 retry capture retained the superseded C0→C1 scan gap: %+v", capture)
	}
	result, err = dp.ApplyConfig(context.Background(), c2)
	if err != nil {
		t.Fatalf("publish C2 after same-pair retry: %v", err)
	}
	d.notePolicyInvalidationPublish(c2, result.Generation)
	recordAppliedDigest()
	if err := d.dischargePolicyInvalidationDebtLocked(c1, c2); err != nil {
		t.Fatalf("C2 debt discharge repeated the originating scan error: %v", err)
	}
	if debt := d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil ||
		debt.scanFailure.oldCfg != c0 || debt.oldCfg != c1 {
		t.Fatalf("complete C1→C2 scan incorrectly certified the earlier C0→C1 gap: %+v", debt)
	}
	if len(dp.deletedPolicy) != 1 || dp.deletedPolicy[0].ExpectedRTFlowSessionID != sshSessionID {
		t.Fatalf("C2 deleted rows = %+v, want only independent p-ssh session %d", dp.deletedPolicy, sshSessionID)
	}
	if d.store.ActiveApplied() {
		t.Fatal("the unresolved C0→C1 scan gap was marked ActiveApplied")
	}
	if len(dp.rows) != 1 || dp.rows[0].ExpectedRTFlowSessionID != webSessionID {
		t.Fatalf("remaining helper rows = %+v, want unresolved p-web session %d", dp.rows, webSessionID)
	}
	if got := dp.readCalls; got != 3 {
		t.Fatalf("helper READ calls = %d, want failed C0→C1 plus initial and retried C1→C2 reads", got)
	}
	if got := dp.request.PolicyIDs; len(got) != 1 || got[0] != c1IDs["trust->untrust/p-ssh"] {
		t.Fatalf("C2 helper LIST IDs = %v, want C1 p-ssh id %d", got, c1IDs["trust->untrust/p-ssh"])
	}
}

func TestPolicyInvalidationDebtResolvesReadErrorOnSamePairRetry12323(t *testing.T) {
	c0 := twoPolicyConfig([]string{"p-first", "p-web"}, nil)
	c1 := twoPolicyConfig([]string{"p-first"}, nil)
	webID := dpuserspace.PolicyIDsByStableKey(c0)["trust->untrust/p-web"]
	const sessionID = 4101
	row := dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 4101, DstPort: 443,
		},
		PolicyID: webID, ExpectedRTFlowSessionID: sessionID,
	}
	readErr := errors.New("worker-1: transient queue timeout")
	dp := &policyListApply12072DP{policyListRead12072DP: &policyListRead12072DP{
		policyInvalTestDP: &policyInvalTestDP{appliedConfig: c0},
		activeCfg:         c0,
		rows:              []dpuserspace.SessionPolicyMatch{row},
		stableRuleIDsBySession: map[uint64]string{
			sessionID: "trust->untrust/p-web",
		},
		readErr: readErr, readErrOnce: true,
	}}
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
	d.setDataplane(dp)
	if _, err := d.store.SyncApply("system { host-name c0; }", nil); err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	if _, err := d.store.SyncApply("system { host-name c1; }", nil); err != nil {
		t.Fatalf("promote C1: %v", err)
	}

	d.armPolicyInvalidationPlan(c0, c1)
	d.capturePolicyInvalidationLocked(c1)
	if capture := d.policyInvalidationCapture; capture == nil || !errors.Is(capture.readErr, readErr) {
		t.Fatalf("initial capture read error = %v, want transient failure", capture)
	}
	if dp.appliedConfig != c0 {
		t.Fatalf("initial failed READ changed helper config to %p, want C0 %p", dp.appliedConfig, c0)
	}

	d.armPolicyInvalidationPlan(c0, c1)
	d.capturePolicyInvalidationLocked(c1)
	if capture := d.policyInvalidationCapture; capture == nil || capture.readErr != nil ||
		len(capture.deleted.policy) != 1 {
		t.Fatalf("same-pair complete retry did not resolve the failed scan: %+v", capture)
	}
	result, err := dp.ApplyConfig(context.Background(), c1)
	if err != nil {
		t.Fatalf("publish C1 after complete retry: %v", err)
	}
	d.notePolicyInvalidationPublish(c1, result.Generation)
	if debt := d.policyInvalidationDebt; debt != nil {
		debt.appliedDigest = d.store.ActiveDigest()
	}
	if err := d.dischargePolicyInvalidationDebtLocked(c0, c1); err != nil {
		t.Fatalf("same-pair retry discharge: %v", err)
	}
	if d.policyInvalidationDebt != nil || len(dp.rows) != 0 ||
		len(dp.deletedPolicy) != 1 || dp.deletedPolicy[0].ExpectedRTFlowSessionID != sessionID {
		t.Fatalf("successful retry did not clear exact debt row: debt=%+v rows=%+v deleted=%+v",
			d.policyInvalidationDebt, dp.rows, dp.deletedPolicy)
	}
	if !d.store.ActiveApplied() {
		t.Fatal("complete same-pair retry did not restore ActiveApplied convergence")
	}
	if got := dp.readCalls; got != 2 {
		t.Fatalf("helper READ calls = %d, want failed attempt plus complete retry", got)
	}
}

func TestPolicyInvalidationDebtReanchorsAndPreservesDeleteIdentity12323(t *testing.T) {
	c0 := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	c1 := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	c2 := twoPolicyConfig([]string{"p-first"}, nil)
	c0IDs := dpuserspace.PolicyIDsByStableKey(c0)
	c1IDs := dpuserspace.PolicyIDsByStableKey(c1)
	const webSessionID, sshSessionID = 4201, 4202
	mk := func(policyID uint32, sessionID uint64, srcPort uint16) dpuserspace.SessionPolicyMatch {
		return dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: srcPort, DstPort: 443,
			},
			PolicyID: policyID, ExpectedRTFlowSessionID: sessionID,
		}
	}
	webRow := mk(c0IDs["trust->untrust/p-web"], webSessionID, 4201)
	sshRow := mk(c0IDs["trust->untrust/p-ssh"], sshSessionID, 4202)
	deleteErr := errors.New("temporary conditional delete failure")
	dp := &policyListApply12072DP{policyListRead12072DP: &policyListRead12072DP{
		policyInvalTestDP: &policyInvalTestDP{appliedConfig: c0},
		activeCfg:         c0,
		rows:              []dpuserspace.SessionPolicyMatch{webRow, sshRow},
		stableRuleIDsBySession: map[uint64]string{
			webSessionID: "trust->untrust/p-web",
			sshSessionID: "trust->untrust/p-ssh",
		},
	}}
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
	d.setDataplane(dp)
	if _, err := d.store.SyncApply("system { host-name c0; }", nil); err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	if _, err := d.store.SyncApply("system { host-name c1; }", nil); err != nil {
		t.Fatalf("promote C1: %v", err)
	}

	d.armPolicyInvalidationPlan(c0, c1)
	d.capturePolicyInvalidationLocked(c1)
	if capture := d.policyInvalidationCapture; capture == nil || capture.readErr != nil ||
		len(capture.deleted.policy) != 1 ||
		capture.deleted.policy[0].ExpectedRTFlowSessionID != webSessionID {
		t.Fatalf("C0→C1 capture did not retain only the deleted p-web identity: %+v", capture)
	}
	result, err := dp.ApplyConfig(context.Background(), c1)
	if err != nil {
		t.Fatalf("publish C1: %v", err)
	}
	d.notePolicyInvalidationPublish(c1, result.Generation)
	if debt := d.policyInvalidationDebt; debt != nil {
		debt.appliedDigest = d.store.ActiveDigest()
	}
	dp.deleteErr = deleteErr
	if err := d.dischargePolicyInvalidationDebtLocked(c0, c1); !errors.Is(err, deleteErr) {
		t.Fatalf("C1 discharge error = %v, want conditional delete failure", err)
	}
	if d.policyInvalidationDebt == nil || d.policyInvalidationDebt.capture == nil ||
		len(d.policyInvalidationDebt.capture.deleted.policy) != 1 {
		t.Fatalf("failed C1 delete dropped the retained row identity: %+v", d.policyInvalidationDebt)
	}
	if d.store.ActiveApplied() {
		t.Fatal("C1 with an outstanding identity-specific delete was marked applied")
	}

	dp.deleteErr = nil
	if _, err := d.store.SyncApply("system { host-name c2; }", nil); err != nil {
		t.Fatalf("promote C2: %v", err)
	}
	d.armPolicyInvalidationPlan(c1, c2)
	if d.policyInvalidationPlan == nil || d.policyInvalidationPlan.oldCfg != c1 {
		t.Fatalf("fresh C2 plan did not re-anchor to landed C1: %+v", d.policyInvalidationPlan)
	}
	d.capturePolicyInvalidationLocked(c2)
	if capture := d.policyInvalidationCapture; capture == nil || capture.readErr != nil ||
		len(capture.deleted.policy) != 2 {
		t.Fatalf("C1→C2 capture did not merge fresh and retained identities: %+v", capture)
	}
	if dp.request.ExpectedConfig != c1 {
		t.Fatalf("re-anchored helper LIST expected config = %p, want C1 %p", dp.request.ExpectedConfig, c1)
	}
	if got := dp.request.PolicyIDs; len(got) != 1 || got[0] != c1IDs["trust->untrust/p-ssh"] {
		t.Fatalf("C2 helper LIST IDs = %v, want C1 p-ssh id %d", got, c1IDs["trust->untrust/p-ssh"])
	}
	result, err = dp.ApplyConfig(context.Background(), c2)
	if err != nil {
		t.Fatalf("publish C2: %v", err)
	}
	d.notePolicyInvalidationPublish(c2, result.Generation)
	if debt := d.policyInvalidationDebt; debt != nil {
		debt.appliedDigest = d.store.ActiveDigest()
	}
	if err := d.dischargePolicyInvalidationDebtLocked(c1, c2); err != nil {
		t.Fatalf("C2 debt discharge: %v", err)
	}
	deleted := make(map[uint64]bool, len(dp.deletedPolicy))
	for _, match := range dp.deletedPolicy {
		deleted[match.ExpectedRTFlowSessionID] = true
	}
	if d.policyInvalidationDebt != nil || len(dp.rows) != 0 ||
		len(deleted) != 2 || !deleted[webSessionID] || !deleted[sshSessionID] {
		t.Fatalf("C2 discharge lost a retained identity: debt=%+v rows=%+v deleted=%v",
			d.policyInvalidationDebt, dp.rows, deleted)
	}
	if !d.store.ActiveApplied() {
		t.Fatal("successful re-anchored discharge did not restore ActiveApplied convergence")
	}
	if got := dp.readCalls; got != 2 {
		t.Fatalf("helper READ calls = %d, want C0→C1 and fresh C1→C2 scans", got)
	}
}

func TestPolicyInvalidationDoesNotRestoreDebtFromDifferentAuthority12323(t *testing.T) {
	r, _ := newLandedRollbackRun12072(t)
	store := r.h.d.store
	c1, err := store.SyncApply(policySetConfigText12072(
		"authority-c1", []string{"p-first", "b", "web"}), nil)
	if err != nil {
		t.Fatalf("promote C1: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c1, c1
	ids := dpuserspace.PolicyIDsByStableKey(c1)
	var permitted dpuserspace.SessionPolicyMatch
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
		if row.ExpectedRTFlowSessionID == 2 {
			permitted = *row
		}
	}
	if permitted.ExpectedRTFlowSessionID != 2 {
		t.Fatal("C1 permitted-session fixture is missing")
	}
	store.MarkActiveApplied()

	c2 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	c3 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	staleLanded := &policyInvalidationDebt{
		oldCfg: c1,
		newCfg: c2,
		capture: &policyInvalidationCapture{
			deleted: capturedSessions{policy: []dpuserspace.SessionPolicyMatch{permitted}},
		},
	}
	r.h.d.policyInvalidationDebt = &policyInvalidationDebt{
		oldCfg: c2, newCfg: c3, landed: staleLanded,
	}
	r.h.d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: c1, newCfg: c1}
	r.h.d.capturePolicyInvalidationLocked(c1)

	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.capture == nil ||
		len(debt.capture.deleted.policy) != 0 {
		t.Fatalf("stale C2 candidate entered the C1 capture: %+v", debt)
	}
	result, err := r.dp.ApplyConfig(context.Background(), c1)
	if err != nil {
		t.Fatalf("apply C1: %v", err)
	}
	r.h.d.notePolicyInvalidationPublish(c1, result.Generation)
	if debt := r.h.d.policyInvalidationDebt; debt != nil {
		debt.appliedDigest = store.ActiveDigest()
	}
	if err := r.h.d.dischargePolicyInvalidationDebtLocked(c1, c1); err != nil {
		t.Fatalf("discharge C1: %v", err)
	}
	if r.hasDeletedSession(2) || !r.hasLiveSession(2) {
		t.Fatalf("C1 rollback used a stale C2 candidate: deleted-b=%v live-b=%v",
			r.hasDeletedSession(2), r.hasLiveSession(2))
	}
}

func TestPolicyInvalidationStoreMovePreservesUnpublishedCandidates12323(t *testing.T) {
	r, c1 := newLandedRollbackRun12072(t)
	publishErr := errors.New("C2 publication failed before landing")
	r.dp.invalDebtTestDP12073.script = make([]invalDebtOutcome12073, r.dp.invalDebtTestDP12073.applyCalls+1)
	r.dp.invalDebtTestDP12073.script[r.dp.invalDebtTestDP12073.applyCalls] =
		invalDebtOutcome12073{err: publishErr}
	c2, err := publishLandedRollbackConfig12072(
		t, r, c1, "authority-c2", []string{"p-first", "a", "web"})
	if !errors.Is(err, publishErr) {
		t.Fatalf("C1->C2 definite publish failure = %v, want %v", err, publishErr)
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.newCfg != c2 || debt.landed != nil ||
		debt.capture == nil || len(debt.capture.deleted.policy) != 1 {
		t.Fatalf("C2 did not retain its unlanded candidate debt: %+v", debt)
	}

	r.dp.incompleteNext = 1
	c3, err := publishLandedRollbackConfig12072(
		t, r, c1, "authority-c3", []string{"p-first", "a", "web"})
	if c3 == nil {
		t.Fatalf("promote C3: %v", err)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil {
		t.Fatalf("published incomplete C3 did not retain scan-failure debt: %+v", debt)
	}
	if !r.hasDeletedSession(2) || r.hasLiveSession(2) {
		t.Fatalf("store move lost the identified candidate: deleted-b=%v live-b=%v",
			r.hasDeletedSession(2), r.hasLiveSession(2))
	}
}
