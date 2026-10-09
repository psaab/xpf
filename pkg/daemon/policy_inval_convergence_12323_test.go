package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type convergenceHelper12072 struct {
	*invalDebtTestDP12073
	applied               *config.Config
	helperCfg             *config.Config
	unknown               bool
	lostAckNext           bool
	incompleteNext        int
	incompletePartialNext int
	readErr               error
	deleteErrOnce         bool
	rows                  []dpuserspace.SessionPolicyMatch
	ruleBySession         map[uint64]string
	lastExpectedConfig    *config.Config
	applyAttempts         int
	reads                 int
	refused               int
	deleteRowsSent        int
	deleted               []dpuserspace.SessionPolicyMatch
}

func (d *convergenceHelper12072) AppliedConfig() *config.Config { return d.applied }

func (d *convergenceHelper12072) PolicyReadConfig() *config.Config {
	if d.unknown {
		return nil
	}
	return d.applied
}

func (d *convergenceHelper12072) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	d.applyAttempts++
	if d.lostAckNext {
		d.lostAckNext = false
		d.helperCfg = cfg
		d.unknown = true
		return nil, errors.New("apply_snapshot response lost (outcome unknown)")
	}
	result, err := d.invalDebtTestDP12073.ApplyConfig(ctx, cfg)
	if err == nil && (result == nil || !result.SnapshotPublishDeferred) {
		d.applied, d.helperCfg, d.unknown = cfg, cfg, false
	}
	return result, err
}

func (d *convergenceHelper12072) ListSessionsByPolicy(req dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error) {
	d.lastExpectedConfig = req.ExpectedConfig
	if req.Mode == "prepublish" && (req.ExpectedConfig == nil || d.PolicyReadConfig() != req.ExpectedConfig) {
		d.refused++
		return dpuserspace.ControlResponse{}, errors.New("policy session READ refused: authority changed")
	}
	d.reads++
	if d.readErr != nil {
		return dpuserspace.ControlResponse{}, d.readErr
	}
	if d.incompleteNext > 0 {
		d.incompleteNext--
		return dpuserspace.ControlResponse{}, errors.New("policy session READ incomplete without continuation")
	}
	incomplete := d.incompletePartialNext > 0
	if incomplete {
		d.incompletePartialNext--
	}
	wanted := make(map[uint32]struct{}, len(req.PolicyIDs))
	for _, id := range req.PolicyIDs {
		wanted[id] = struct{}{}
	}
	ids := dpuserspace.PolicyIDsByStableKey(d.helperCfg)
	var matches []dpuserspace.SessionPolicyMatch
	for _, row := range d.rows {
		id, ok := ids[d.ruleBySession[row.ExpectedRTFlowSessionID]]
		if !ok {
			id = dataplane.DefaultPolicySentinelID
		}
		row.PolicyID = id
		if _, ok := wanted[id]; ok {
			matches = append(matches, row)
		}
	}
	return dpuserspace.ControlResponse{
		OK: true, SessionPolicyComplete: !incomplete, SessionPolicyMatches: matches,
	}, nil
}

func (d *convergenceHelper12072) DeletePolicySessions(matches []dpuserspace.SessionPolicyMatch) (dpuserspace.PolicyDeleteResult, error) {
	d.deleteRowsSent += len(matches)
	if d.deleteErrOnce {
		d.deleteErrOnce = false
		return dpuserspace.PolicyDeleteResult{}, errors.New("policy session delete: deadline exceeded")
	}
	var result dpuserspace.PolicyDeleteResult
	for _, match := range matches {
		found := false
		for i, row := range d.rows {
			if row.ExpectedRTFlowSessionID == match.ExpectedRTFlowSessionID {
				d.rows = append(d.rows[:i], d.rows[i+1:]...)
				found = true
				break
			}
		}
		if found {
			result.Applied++
			d.deleted = append(d.deleted, match)
		} else {
			result.Stale++
		}
	}
	return result, nil
}

type convergenceRun12072 struct {
	t  *testing.T
	h  *invalDebtHarness12073
	dp *convergenceHelper12072
}

func newConvergenceRun12072(t *testing.T, policies []string) (*convergenceRun12072, *config.Config) {
	t.Helper()
	h := newInvalDebtHarness12073(t, nil)
	c0 := twoPolicyConfig(policies, nil)
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	dp := &convergenceHelper12072{
		invalDebtTestDP12073: h.dp,
		applied:              c0,
		helperCfg:            c0,
		ruleBySession:        make(map[uint64]string),
	}
	for i, name := range policies {
		if name == "p-first" {
			continue
		}
		sid := uint64(i)
		dp.rows = append(dp.rows, dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: uint16(1000 + i), DstPort: 80,
			},
			PolicyID: ids["trust->untrust/"+name], ExpectedRTFlowSessionID: sid,
		})
		dp.ruleBySession[sid] = "trust->untrust/" + name
	}
	h.d.setDataplane(dp)
	if _, err := h.d.store.SyncApply("system { host-name c0; }", nil); err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	h.d.store.MarkActiveApplied()
	return &convergenceRun12072{t: t, h: h, dp: dp}, c0
}

func (r *convergenceRun12072) commit(name string, old, next *config.Config) error {
	return r.commitWithPeer(name, old, next, peerSyncNever)
}

func (r *convergenceRun12072) commitWithPeer(
	name string, old, next *config.Config, peerSync peerSyncPolicy,
) error {
	r.t.Helper()
	if _, err := r.h.d.store.SyncApply(fmt.Sprintf("system { host-name %s; }", name), nil); err != nil {
		r.t.Fatalf("promote %s: %v", name, err)
	}
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		return err
	}
	_, err := r.h.d.applyAndSyncCommitted(old, next, peerSync)
	r.h.d.applySem.Release(1)
	_, _ = r.h.sender.ApplyQueuedMessagesForTesting(r.h.receiver)
	return err
}

func (r *convergenceRun12072) hasDeletedSession(id uint64) bool {
	for _, match := range r.dp.deleted {
		if match.ExpectedRTFlowSessionID == id {
			return true
		}
	}
	return false
}

func (r *convergenceRun12072) hasLiveSession(id uint64) bool {
	for _, match := range r.dp.rows {
		if match.ExpectedRTFlowSessionID == id {
			return true
		}
	}
	return false
}

func TestPolicyInvalidationKnownAuthorityReanchorsBeforeRead12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first"}, nil)
	readsBefore, attemptsBefore := r.dp.reads, r.dp.applyAttempts
	if err := r.commitWithPeer("c2", c1, c2, peerSyncNever); err != nil {
		t.Fatalf("commit with stale store predecessor and known C0 authority: %v", err)
	}
	if r.dp.lastExpectedConfig != c0 || r.dp.reads != readsBefore+1 || r.dp.refused != 0 {
		t.Fatalf("capture authority/read/refusal = %p/%d/%d, want C0/%d/0",
			r.dp.lastExpectedConfig, r.dp.reads-readsBefore, r.dp.refused, readsBefore+1)
	}
	if r.dp.applyAttempts != attemptsBefore+1 ||
		!r.hasDeletedSession(1) || !r.hasDeletedSession(2) {
		t.Fatalf("known-authority re-anchor did not apply and revoke C0 targets: attempts=%d deleted=%v",
			r.dp.applyAttempts-attemptsBefore, r.dp.deleted)
	}
}

func TestPolicyInvalidationUnknownAuthorityNeverPushesUnappliedConfig12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.lostAckNext = true
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("lost apply ACK was not surfaced")
	}
	attemptsBefore := r.dp.applyAttempts
	pushes := 0
	r.h.d.syncPeerForTest = func() { pushes++ }
	err := r.commitWithPeer("c2", c1, c2, peerSyncAlways)
	if !errors.Is(err, dpuserspace.ErrPolicyReadAuthority) {
		t.Fatalf("unknown-authority commit error = %v, want policy READ authority refusal", err)
	}
	if r.dp.applyAttempts != attemptsBefore || pushes != 0 {
		t.Fatalf("unknown-authority commit attempted local apply/pushed peer: applyAttempts+%d peerPushes+%d",
			r.dp.applyAttempts-attemptsBefore, pushes)
	}
	if !r.dp.unknown || r.dp.helperCfg != c1 {
		t.Fatalf("unknown helper state changed unexpectedly: unknown=%v helper=%p", r.dp.unknown, r.dp.helperCfg)
	}
}

func TestPolicyInvalidationSupersedingCompleteReadClearsUnpublishedScanFailure12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.incompleteNext = 1
	r.h.dp.script = []invalDebtOutcome12073{{
		err: errors.New("helper control socket: connection refused"),
	}}
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("incomplete READ plus failed C0→C1 publication was not surfaced")
	}
	if r.dp.applied != c0 {
		t.Fatalf("failed C1 publication changed helper authority: got %p, want C0 %p", r.dp.applied, c0)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil {
		t.Fatalf("failed C1 publication did not retain scan debt: %+v", debt)
	}

	readsBefore := r.dp.reads
	if err := r.commit("c2", c1, c2); err != nil {
		t.Fatalf("superseding C1→C2 commit at still-authoritative C0 failed: %v", err)
	}
	if r.dp.lastExpectedConfig != c0 || r.dp.reads != readsBefore+1 || r.dp.refused != 0 {
		t.Fatalf("superseding capture authority/read/refusal = %p/%d/%d, want C0/1/0",
			r.dp.lastExpectedConfig, r.dp.reads-readsBefore, r.dp.refused)
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("complete C0 scan did not retire unpublished C1 debt: debt=%+v activeApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
	if !r.hasDeletedSession(1) || !r.hasDeletedSession(2) ||
		r.hasLiveSession(1) || r.hasLiveSession(2) || !r.hasLiveSession(3) {
		t.Fatalf("superseding scan did not revoke exactly C0's removed a/b rows: deleted=%v rows=%v",
			r.dp.deleted, r.dp.rows)
	}
}

func TestPolicyInvalidationPublishedReadFailureStaysVisibleWithoutWedge12072(t *testing.T) {
	var logs strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(previous)

	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "c", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "c", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first", "c", "web"}, nil)
	c3 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	c4 := twoPolicyConfig([]string{"p-first"}, nil)
	r.dp.incompleteNext = 1
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("originating incomplete READ was not surfaced on its commit")
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil {
		t.Fatalf("published scan failure was not retained as explicit non-convergence: %+v", debt)
	}
	if !r.hasLiveSession(1) || r.h.d.store.ActiveApplied() {
		t.Fatalf("missed a row or prematurely marked the published partial scan applied: live-a=%v activeApplied=%v",
			r.hasLiveSession(1), r.h.d.store.ActiveApplied())
	}
	errorLinesAfterOrigin := strings.Count(logs.String(), "level=ERROR")
	if errorLinesAfterOrigin == 0 {
		t.Fatal("originating incomplete scan did not raise its single ERROR alarm")
	}

	for _, tc := range []struct {
		name string
		old  *config.Config
		next *config.Config
	}{
		{"c2", c1, c2}, {"c3", c2, c3}, {"c4", c3, c4},
	} {
		if err := r.commit(tc.name, tc.old, tc.next); err != nil {
			t.Fatalf("independent %s revocation was blocked by the old scan debt: %v", tc.name, err)
		}
	}
	if !r.hasDeletedSession(2) || !r.hasDeletedSession(3) || !r.hasDeletedSession(4) ||
		!r.hasLiveSession(1) {
		t.Fatalf("later independent revocations did not proceed while the missed a row stayed visible: deleted=%v live-a=%v",
			r.dp.deleted, r.hasLiveSession(1))
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil ||
		r.h.d.store.ActiveApplied() {
		t.Fatalf("later captures falsely certified the old scan gap: debt=%+v activeApplied=%v",
			debt, r.h.d.store.ActiveApplied())
	}
	if got := r.dp.deleteRowsSent; got != 3 {
		t.Fatalf("helper delete rows sent = %d, want only b/c/web once each", got)
	}
	if got := strings.Count(logs.String(), "level=ERROR"); got != errorLinesAfterOrigin {
		t.Fatalf("later commits repeated the original ERROR alarm: %d→%d", errorLinesAfterOrigin, got)
	}
	beforeSent, beforeErrors := r.dp.deleteRowsSent, strings.Count(logs.String(), "level=ERROR")
	for i := 0; i < 3; i++ {
		if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		err := r.h.d.dischargePolicyInvalidationDebtLocked(c3, c4)
		r.h.d.applySem.Release(1)
		if err != nil {
			t.Fatalf("settled debt tick %d repeated a surfaced error: %v", i, err)
		}
	}
	if r.dp.deleteRowsSent != beforeSent || strings.Count(logs.String(), "level=ERROR") != beforeErrors {
		t.Fatalf("settled ticks re-sent deletes or repeated alarms: sends %d→%d errors %d→%d",
			beforeSent, r.dp.deleteRowsSent, beforeErrors, strings.Count(logs.String(), "level=ERROR"))
	}
}

func TestPolicyInvalidationSettledTicksDoNotResendAppliedRows12072(t *testing.T) {
	var logs strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(previous)

	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.incompletePartialNext = 1
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("originating incomplete READ was not surfaced")
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.scanFailure == nil || debt.capture == nil || len(debt.capture.deleted.policy) != 0 {
		t.Fatalf("applied partial-read candidates were not pruned while retaining scan debt: %+v", debt)
	}
	beforeSent, beforeErrors := r.dp.deleteRowsSent, strings.Count(logs.String(), "level=ERROR")
	for i := 0; i < 3; i++ {
		if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		err := r.h.d.dischargePolicyInvalidationDebtLocked(c0, c1)
		r.h.d.applySem.Release(1)
		if err != nil {
			t.Fatalf("settled retry %d repeated a surfaced scan error: %v", i, err)
		}
	}
	if r.dp.deleteRowsSent != beforeSent || strings.Count(logs.String(), "level=ERROR") != beforeErrors {
		t.Fatalf("settled ticks repeated work after successful deletes: sends %d→%d errors %d→%d",
			beforeSent, r.dp.deleteRowsSent, beforeErrors, strings.Count(logs.String(), "level=ERROR"))
	}
	if err := r.commit("c2", c1, c2); err != nil {
		t.Fatalf("independent C1→C2 revocation failed: %v", err)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil ||
		r.h.d.store.ActiveApplied() {
		t.Fatalf("later complete capture certified the earlier incomplete scan: debt=%+v activeApplied=%v",
			debt, r.h.d.store.ActiveApplied())
	}
	if !r.hasDeletedSession(1) || !r.hasDeletedSession(2) || r.hasLiveSession(1) {
		t.Fatalf("settled rows were not revoked exactly once: deleted=%v live-a=%v", r.dp.deleted, r.hasLiveSession(1))
	}
	if got := r.dp.deleteRowsSent; got != 2 {
		t.Fatalf("delete rows sent = %d, want a and b once each", got)
	}
}
func TestPolicyInvalidationLostAckCatchupReanchorsBeforeNextCommit12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.lostAckNext = true
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("lost apply ACK was not surfaced")
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.publishGeneration != 0 {
		t.Fatalf("lost-ACK fixture did not retain unstamped debt: %+v", debt)
	}
	// Model the status loop replaying its exact retained C1 snapshot after the
	// helper reports the prior apply's lost ACK.
	if _, err := r.dp.ApplyConfig(context.Background(), c1); err != nil {
		t.Fatalf("status-loop retry of retained C1 failed: %v", err)
	}
	readsBefore := r.dp.reads
	if err := r.commit("c2", c1, c2); err != nil {
		t.Fatalf("C1→C2 after catch-up failed: %v", err)
	}
	if r.dp.reads != readsBefore+1 || r.dp.refused != 0 {
		t.Fatalf("C1→C2 READ count/refusals = %d/%d, want one complete READ and no refusal", r.dp.reads-readsBefore, r.dp.refused)
	}
	if !r.hasDeletedSession(2) {
		t.Fatalf("lost-ACK re-anchor failed to revoke b's session; deleted=%v", r.dp.deleted)
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("lost-ACK recovery did not converge: debt=%+v activeApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}

func TestPolicyInvalidationUnknownAuthorityHoldsSupersedingPublish12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.lostAckNext = true
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("lost apply ACK was not surfaced")
	}
	if err := r.commit("c2", c1, c2); err == nil || !strings.Contains(err.Error(), "authority refusal") {
		t.Fatalf("superseding publish under unknown authority = %v, want a fail-closed authority refusal", err)
	}
	if r.dp.helperCfg != c1 || !r.dp.unknown || r.h.d.policyInvalidationPlan == nil ||
		r.dp.applyCalls != 0 {
		t.Fatalf("unknown authority changed the helper, attempted publication, or lost its retry plan: helper=%p unknown=%v ApplyConfig calls=%d plan=%+v",
			r.dp.helperCfg, r.dp.unknown, r.dp.applyCalls, r.h.d.policyInvalidationPlan)
	}
	if r.hasDeletedSession(2) {
		t.Fatal("b was deleted before a complete capture under a known authority")
	}
	// The status loop retries the same retained C1 generation; it does not
	// fabricate an authority transition.
	if _, err := r.dp.ApplyConfig(context.Background(), c1); err != nil {
		t.Fatalf("status-loop retry of retained C1 failed: %v", err)
	}
	if err := r.commit("c2-retry", c1, c2); err != nil {
		t.Fatalf("known-authority retry failed: %v", err)
	}
	if !r.hasDeletedSession(2) || r.h.d.policyInvalidationDebt != nil {
		t.Fatalf("retry did not revoke b and converge: deleted=%v debt=%+v", r.dp.deleted, r.h.d.policyInvalidationDebt)
	}
	if !r.containsSessionPort(1003) {
		t.Fatal("retry mis-captured the surviving web session under shifted positional IDs")
	}
}

func TestPolicyInvalidationDeferredPublishRefusesUnknownAuthority12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.h.d.store = nil
	r.h.d.policyInvalidationDebt = &policyInvalidationDebt{
		oldCfg: c0, newCfg: c1, publishGeneration: 7,
	}
	r.dp.unknown = true
	readsBefore := r.dp.reads
	err := r.h.d.capturePolicyInvalidationBeforeDeferredPublish(7)
	if err == nil || !strings.Contains(err.Error(), "authority refusal") {
		t.Fatalf("deferred publish under unknown authority = %v, want refusal", err)
	}
	if r.dp.reads != readsBefore || r.h.d.policyInvalidationPlan == nil {
		t.Fatalf("deferred refusal issued a READ or lost its retry plan: reads+%d plan=%+v",
			r.dp.reads-readsBefore, r.h.d.policyInvalidationPlan)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.authorityRefusal == nil ||
		debt.scanFailure != nil {
		t.Fatalf("deferred authority refusal was misclassified: %+v", debt)
	}
}

func TestPolicyInvalidationAuthorityRaceIsNotScanFailure12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.readErr = fmt.Errorf("%w: helper page authority changed", dpuserspace.ErrPolicyReadAuthority)
	err := r.commit("c1", c0, c1)
	if !errors.Is(err, dpuserspace.ErrPolicyReadAuthority) {
		t.Fatalf("authority race error = %v, want manager authority sentinel", err)
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.authorityRefusal == nil ||
		!errors.Is(debt.authorityRefusal, dpuserspace.ErrPolicyReadAuthority) || debt.scanFailure != nil {
		t.Fatalf("manager authority race was retained as scan failure: %+v", debt)
	}
	if r.dp.reads != 1 || r.dp.applyCalls != 0 || r.h.d.policyInvalidationPlan == nil {
		t.Fatalf("authority race read/apply/plan = %d/%d/%+v; want one refused READ, no publish, retry plan",
			r.dp.reads, r.dp.applyCalls, r.h.d.policyInvalidationPlan)
	}
}

func TestPolicyInvalidationAuthorityRefusalDoesNotDischargePriorCommit12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	c2 := twoPolicyConfig([]string{"p-first"}, nil)
	if err := r.commit("c1", c0, c1); err != nil {
		t.Fatalf("successful C1 commit: %v", err)
	}
	if !r.h.d.policyInvalidationPublishLanded {
		t.Fatal("successful C1 apply did not set the publication marker")
	}
	r.dp.readErr = fmt.Errorf("%w: helper page authority changed", dpuserspace.ErrPolicyReadAuthority)
	err := r.commit("c2", c1, c2)
	if !errors.Is(err, dpuserspace.ErrPolicyReadAuthority) {
		t.Fatalf("C2 authority refusal = %v, want manager authority sentinel", err)
	}
	if r.h.d.policyInvalidationPublishLanded {
		t.Fatal("refused C2 capture retained C1's successful publication marker")
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.authorityRefusal == nil ||
		debt.scanFailure != nil {
		t.Fatalf("refused C2 attempt was discharged using C1's marker: %+v", debt)
	}
	if r.dp.applyCalls != 1 {
		t.Fatalf("refused C2 reached ApplyConfig: calls=%d, want only successful C1", r.dp.applyCalls)
	}
}

func (r *convergenceRun12072) containsSessionPort(port uint16) bool {
	for _, match := range r.dp.rows {
		if match.Tuple.SrcPort == port {
			return true
		}
	}
	return false
}

func TestPolicyInvalidationSamePairRetryClearsUnpublishedScanFailure12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "b", "web"}, nil)
	r.dp.incompleteNext = 1
	r.h.dp.script = []invalDebtOutcome12073{{err: errors.New("helper control socket: connection refused")}}
	applyErr := r.commit("c1", c0, c1)
	if applyErr == nil {
		t.Fatal("failed publish was not surfaced")
	}
	if !strings.Contains(applyErr.Error(), "connection refused") ||
		!strings.Contains(applyErr.Error(), "READ incomplete without continuation") {
		t.Fatalf("originating failed commit omitted its scan gap: %v", applyErr)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil {
		t.Fatalf("unpublished incomplete READ did not leave scan debt: %+v", debt)
	}
	if err := r.commit("c1", c0, c1); err != nil {
		t.Fatalf("complete retry of the original C0→C1 pair failed: %v", err)
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("complete same-pair retry did not converge: debt=%+v activeApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
	if !r.hasDeletedSession(1) || r.hasLiveSession(1) {
		t.Fatalf("same-pair retry did not revoke a: deleted=%v live=%v", r.dp.deleted, r.dp.rows)
	}
	if r.dp.reads != 2 {
		t.Fatalf("helper reads = %d, want incomplete origin plus complete same-pair retry", r.dp.reads)
	}
}

func TestPolicyInvalidationBareRetryReusesLandedCapture12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.lostAckNext = true
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("lost apply ACK was not surfaced")
	}
	// Status retries the retained snapshot and confirms C1 before the bare
	// daemon retry exercises the already captured invalidation.
	if _, err := r.dp.ApplyConfig(context.Background(), c1); err != nil {
		t.Fatalf("status-loop retry of retained C1 failed: %v", err)
	}
	readsBefore := r.dp.reads
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	err := r.h.d.applyConfigLocked(context.Background(), c1)
	r.h.d.applySem.Release(1)
	if err != nil {
		t.Fatalf("bare retry of landed C1: %v", err)
	}
	if r.dp.reads != readsBefore || r.dp.refused != 0 {
		t.Fatalf("bare retry re-captured the landed debt: reads+%d refusals=%d", r.dp.reads-readsBefore, r.dp.refused)
	}
	if r.h.d.policyInvalidationDebt != nil || !r.hasDeletedSession(1) {
		t.Fatalf("bare retry did not reuse and discharge retained identity: debt=%+v deleted=%v",
			r.h.d.policyInvalidationDebt, r.dp.deleted)
	}
}

func TestPolicyInvalidationBackgroundApplyDoesNotCreateFalseScanFailure12072(t *testing.T) {
	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.deleteErrOnce = true
	if err := r.commit("c1", c0, c1); err == nil {
		t.Fatal("transient delete failure was not surfaced")
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure != nil {
		t.Fatalf("delete failure must retain candidate debt without a scan failure: %+v", debt)
	}
	readsBefore, refusedBefore := r.dp.reads, r.dp.refused
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	err := r.h.d.applyConfigLocked(context.Background(), c1)
	r.h.d.applySem.Release(1)
	if err != nil {
		t.Fatalf("background apply did not heal the delete debt: %v", err)
	}
	if r.dp.reads != readsBefore || r.dp.refused != refusedBefore {
		t.Fatalf("background apply performed a false READ: reads+%d refusals+%d",
			r.dp.reads-readsBefore, r.dp.refused-refusedBefore)
	}
	if r.h.d.policyInvalidationDebt != nil || !r.hasDeletedSession(1) {
		t.Fatalf("background retry did not discharge deleted session a: debt=%+v deleted=%v",
			r.h.d.policyInvalidationDebt, r.dp.deleted)
	}
}

func TestPolicyInvalidationRenameKeepsImmediatePairAncestry12072(t *testing.T) {
	c0 := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	c0.Security.Policies[1].Policies = append(c0.Security.Policies[1].Policies,
		&config.Policy{Name: "p-gone", Action: config.PolicyPermit})
	c1 := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	c2 := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	renamed := helperRenameMatch10626(ids["lan->wan/p-old"])
	renamed.Tuple.DstPort = 5201
	renamed.ExpectedRTFlowSessionID = 0xA11CE
	gone := helperRenameMatch10626(ids["lan->wan/p-gone"])
	gone.Tuple.SrcPort = 2222
	gone.ExpectedRTFlowSessionID = 0xB0B
	dp := &policyListApply12072DP{policyListRead12072DP: &policyListRead12072DP{
		policyInvalTestDP: &policyInvalTestDP{appliedConfig: c0},
		activeCfg:         c0,
		rows:              []dpuserspace.SessionPolicyMatch{renamed, gone},
		stableRuleIDsBySession: map[uint64]string{
			0xA11CE: "lan->wan/p-old", 0xB0B: "lan->wan/p-gone",
		},
		readErr: errors.New("worker-1: worker-ack-timeout"), readErrOnce: true,
	}}
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
	d.setDataplane(dp)
	if _, err := d.store.SyncApply("system { host-name c1; }", nil); err != nil {
		t.Fatal(err)
	}
	d.armPolicyInvalidationPlan(c0, c1)
	d.capturePolicyInvalidationLocked(c1)
	result, err := dp.ApplyConfig(context.Background(), c1)
	if err != nil {
		t.Fatal(err)
	}
	d.notePolicyInvalidationPublish(c1, result.Generation)
	if debt := d.policyInvalidationDebt; debt != nil {
		debt.appliedDigest = d.store.ActiveDigest()
	}
	if err := d.dischargePolicyInvalidationDebtLocked(c0, c1); err == nil {
		t.Fatal("originating incomplete READ was not surfaced")
	}

	if _, err := d.store.SyncApply("system { host-name c2; }", nil); err != nil {
		t.Fatal(err)
	}
	d.armPolicyInvalidationPlanWithRename(c1, c2, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	})
	if d.policyInvalidationPlan == nil || d.policyInvalidationPlan.renameApply == nil || d.policyInvalidationPlan.oldCfg != c1 {
		t.Fatalf("immediate-pair re-anchor dropped rename ancestry: %+v", d.policyInvalidationPlan)
	}
	d.capturePolicyInvalidationLocked(c2)
	capture := d.policyInvalidationCapture
	if capture == nil || len(capture.renamed) != 1 ||
		capture.renamed[0].RuleID != "lan->wan/p-new" ||
		capture.renamed[0].DstPort != renamed.Tuple.DstPort {
		t.Fatalf("renamed session was not rebound: capture=%+v", capture)
	}
	for _, match := range capture.deleted.policy {
		if match.ExpectedRTFlowSessionID == 0xA11CE {
			t.Fatal("renamed session entered the delete bucket instead of being rebound")
		}
	}
}
