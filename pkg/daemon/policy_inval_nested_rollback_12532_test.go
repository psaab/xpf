package daemon

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12532 P3: nested commit-confirmed C0->C1->C2, timer rollback to the
// original confirmed C0. C1 removes a (s1 debt), C2 removes b (s2 debt).
// C0 permits both, so neither session may be deleted by the rollback.
func TestPolicyInvalidationNestedConfirmedRollbackToRootDischargesPermitted12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)

	r.dp.deleteErrOnce = true
	c1, _, applyErr := publishConfirmedRollbackTarget12072(
		t, r, c0, "nested12532-c1", []string{"p-first", "b", "web"})
	if applyErr == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	r.dp.deleteErrOnce = true
	_, gen, applyErr := publishConfirmedRollbackTarget12072(
		t, r, c1, "nested12532-c2", []string{"p-first", "web"})
	if applyErr == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.capture == nil ||
		debt.capture.candidateCount() == 0 {
		t.Fatalf("premise: nested debt missing: %+v", debt)
	}
	for _, id := range []uint64{1, 2, 3} {
		if !r.hasLiveSession(id) {
			t.Fatalf("premise: session %d not live before rollback", id)
		}
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION: rollback to C0 deleted permitted session %d: deleted=%v live=%v",
				id, r.hasDeletedSession(id), r.hasLiveSession(id))
		}
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("rollback to C0 did not discharge permitted debt: debt=%+v ActiveApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}

// A candidate whose rule remains explicitly denied by the root policy must
// not be discharged while candidates from the same nested chain are filtered.
func TestPolicyInvalidationNestedRollbackKeepsRootDeniedCandidate12532(t *testing.T) {
	policies := []string{"p-first", "a", "b", "x", "web"}
	r, _ := newConvergenceRun12072(t, policies)
	c0, err := r.h.d.store.SyncApply(policySetConfigText12072("root-denies-x", policies), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	c0.Security.Policies[0].Policies[3].Action = config.PolicyDeny
	r.dp.applied, r.dp.helperCfg = c0, c0
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
		row.IngressZoneID = config.StableZoneID("trust")
		row.EgressZoneID = config.StableZoneID("untrust")
	}
	r.h.d.store.MarkActiveApplied()

	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackTarget12072(
		t, r, c0, "root-denies-x-c1", []string{"p-first", "b", "x", "web"})
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	xID := dpuserspace.PolicyIDsByStableKey(c1)["trust->untrust/x"]
	r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1099, DstPort: 80,
		},
		PolicyID: xID, ExpectedRTFlowSessionID: 99,
		IngressZoneID: config.StableZoneID("trust"),
		EgressZoneID:  config.StableZoneID("untrust"),
	})
	r.dp.ruleBySession[99] = "trust->untrust/x"
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackTarget12072(
		t, r, c1, "root-denies-x-c2", []string{"p-first", "web"})
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	if !r.hasDeletedSession(99) || r.hasLiveSession(99) {
		t.Fatalf("UNDER-DELETION: root-denied x candidate survived nested rollback: deleted=%v live=%v",
			r.hasDeletedSession(99), r.hasLiveSession(99))
	}
	for _, id := range []uint64{1, 2, 4} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION: root-permitted session %d did not survive", id)
		}
	}
}

// #12532 depth-3: C0->C1->C2->C3 each forbidding one more rule, timer
// rollback to C0 must discharge every candidate C0 permits.
func TestPolicyInvalidationTripleNestedRollbackToRoot12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)

	r.dp.deleteErrOnce = true
	c1, _, err1 := publishConfirmedRollbackTarget12072(
		t, r, c0, "nested12532c-c1", []string{"p-first", "b", "web"})
	r.dp.deleteErrOnce = true
	c2, _, err2 := publishConfirmedRollbackTarget12072(
		t, r, c1, "nested12532c-c2", []string{"p-first", "web"})
	r.dp.deleteErrOnce = true
	_, gen, err3 := publishConfirmedRollbackTarget12072(
		t, r, c2, "nested12532c-c3", []string{"p-first"})
	if err1 == nil || err2 == nil || err3 == nil {
		t.Fatalf("premise: failed deletes not surfaced: %v %v %v", err1, err2, err3)
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION at depth 3: session %d deleted by rollback to C0", id)
		}
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("depth-3 rollback did not converge: debt=%+v ActiveApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}

type rule12532 struct {
	name string
	app  string
	deny bool
}

func anyRules12532(names ...string) []rule12532 {
	rules := make([]rule12532, 0, len(names))
	for _, name := range names {
		rules = append(rules, rule12532{name: name, app: "any"})
	}
	return rules
}

// rulesConfigText12532 renders a trust->untrust policy set with per-rule
// applications and actions, plus an optional default-policy action.
func rulesConfigText12532(host, defaultPolicy string, rules []rule12532) string {
	var body strings.Builder
	for _, rule := range rules {
		action := "permit"
		if rule.deny {
			action = "deny"
		}
		fmt.Fprintf(&body, `
            policy %s {
                match { source-address any; destination-address any; application %s; }
                then { %s; }
            }`, rule.name, rule.app, action)
	}
	defaultStanza := ""
	if defaultPolicy != "" {
		defaultStanza = "\n        default-policy { " + defaultPolicy + "; }"
	}
	return fmt.Sprintf(`system { host-name %s; }
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {%s
        }%s
    }
}`, host, body.String(), defaultStanza)
}

// heldCandidates12532 reports the RT_FLOW session IDs a debt's capture owes.
func heldCandidates12532(debt *policyInvalidationDebt) map[uint64]bool {
	held := map[uint64]bool{}
	if debt == nil || debt.capture == nil {
		return held
	}
	for _, bucket := range []capturedSessions{debt.capture.deleted, debt.capture.modified, debt.capture.deflt} {
		for _, match := range bucket.policy {
			held[match.ExpectedRTFlowSessionID] = true
		}
	}
	return held
}

// #12532 F1: re-authorization runs before the rollback capture's authority
// checks. When the helper refuses the rollback READ, the restored C2 debt must
// still own every candidate: C2 stays enforced, so a later commit that still
// forbids a and b must delete sessions 1 and 2.
func TestPolicyInvalidationRefusedNestedRollbackKeepsDebtCandidates12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)
	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackTarget12072(
		t, r, c0, "refused12532-c1", []string{"p-first", "b", "web"})
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	// n keeps the C2->C0 diff non-empty, so the rollback capture must READ.
	r.dp.deleteErrOnce = true
	c2, gen, err := publishConfirmedRollbackTarget12072(
		t, r, c1, "refused12532-c2", []string{"p-first", "web", "n"})
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}
	before := heldCandidates12532(r.h.d.policyInvalidationDebt)
	if r.dp.applied != c2 || !before[1] || !before[2] {
		t.Fatalf("premise: helper=%p want C2 %p; C2 debt holds %v, want sessions 1 and 2",
			r.dp.applied, c2, before)
	}

	r.dp.readErr = fmt.Errorf("%w: helper restarted mid-capture", dpuserspace.ErrPolicyReadAuthority)
	r.h.d.executeConfirmedRollback(gen)
	r.dp.readErr = nil

	if r.dp.applied != c2 || r.h.d.store.ActiveConfig() != c0 {
		t.Fatalf("premise: refused rollback moved authority: helper=%p (C2 %p) store=%p (C0 %p)",
			r.dp.applied, c2, r.h.d.store.ActiveConfig(), c0)
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.newCfg != c2 || debt.authorityRefusal == nil {
		t.Fatalf("authority refusal did not restore the C2 debt: %+v", debt)
	}
	if after := heldCandidates12532(debt); !after[1] || !after[2] {
		t.Fatalf("refused rollback dropped C2 debt candidates: before=%v after=%v", before, after)
	}
	c3, err := publishLandedRollbackConfig12072(
		t, r, c0, "refused12532-c3", []string{"p-first", "web", "n"})
	if r.dp.applied != c3 {
		t.Fatalf("premise: C3 did not land: %v", err)
	}
	for _, id := range []uint64{1, 2} {
		if !r.hasDeletedSession(id) || r.hasLiveSession(id) {
			t.Errorf("UNDER-DELETION: C3 forbids session %d's rule but it survived: deleted=%v live=%v",
				id, r.hasDeletedSession(id), r.hasLiveSession(id))
		}
	}
	if r.hasDeletedSession(3) || !r.hasLiveSession(3) {
		t.Error("OVER-DELETION: C3 permits web session 3 but it was deleted")
	}
}

// #12532 F2: candidates the restored root permits stop being owed only once
// the rollback lands. The helper definitively rejects the rollback publish and
// keeps enforcing C2; an operator commit C3 that still forbids a and b then
// supersedes the rollback, so C3 must delete sessions 1 and 2.
func TestPolicyInvalidationRejectedNestedRollbackReowesCandidates12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)
	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackTarget12072(
		t, r, c0, "rejected12532-c1", []string{"p-first", "b", "web"})
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	r.dp.deleteErrOnce = true
	c2, gen, err := publishConfirmedRollbackTarget12072(
		t, r, c1, "rejected12532-c2", []string{"p-first", "web"})
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}
	r.dp.script = make([]invalDebtOutcome12073, r.dp.applyCalls+1)
	r.dp.script[r.dp.applyCalls] = invalDebtOutcome12073{
		err: errors.New("apply_snapshot rejected by helper (definite)"),
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.dp.applied != c2 || r.h.d.store.ActiveConfig() != c0 {
		t.Fatalf("premise: rejected rollback moved the helper: helper=%p (C2 %p) store=%p (C0 %p)",
			r.dp.applied, c2, r.h.d.store.ActiveConfig(), c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("premise: the unpublished rollback deleted session %d", id)
		}
	}
	c3, err := publishLandedRollbackConfig12072(
		t, r, c0, "rejected12532-c3", []string{"p-first", "web"})
	if r.dp.applied != c3 {
		t.Fatalf("premise: C3 did not land: %v", err)
	}
	for _, id := range []uint64{1, 2} {
		if !r.hasDeletedSession(id) || r.hasLiveSession(id) {
			t.Errorf("UNDER-DELETION: the unlanded rollback discharged session %d; C3 forbids its rule but it survived: deleted=%v live=%v",
				id, r.hasDeletedSession(id), r.hasLiveSession(id))
		}
	}
	if r.hasDeletedSession(3) || !r.hasLiveSession(3) {
		t.Error("OVER-DELETION: C3 permits web session 3 but it was deleted")
	}
}

// #12532 F4: re-authorization must evaluate the restored rule's match, not
// only its existence and action. Root rule a admits only junos-ssh; C1 widened
// a to any and admitted sessions 7 (tcp/80) and 8 (tcp/22) under it. After C2
// deletes a, the nested rollback must delete session 7, which the root does
// not permit, and keep session 8, which root a still permits.
func TestPolicyInvalidationNestedRollbackChecksRestoredRuleMatch12532(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first"})
	c0, err := r.h.d.store.SyncApply(rulesConfigText12532("match12532-c0", "", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "a", app: "junos-ssh"}, {name: "web", app: "junos-https"},
	}), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	r.h.d.store.MarkActiveApplied()
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0, rulesConfigText12532("match12532-c1", "", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "a", app: "any"}, {name: "web", app: "junos-https"},
	}))
	if err != nil {
		t.Fatalf("premise: C0->C1 widen a: %v", err)
	}
	aID := dpuserspace.PolicyIDsByStableKey(c1)["trust->untrust/a"]
	for _, session := range []struct {
		id   uint64
		port uint16
	}{{7, 80}, {8, 22}} {
		r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: uint16(2000 + session.id), DstPort: session.port,
			},
			PolicyID: aID, ExpectedRTFlowSessionID: session.id,
			IngressZoneID: config.StableZoneID("trust"),
			EgressZoneID:  config.StableZoneID("untrust"),
		})
		r.dp.ruleBySession[session.id] = "trust->untrust/a"
	}
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackText12072(t, r, c1, rulesConfigText12532("match12532-c2", "", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "web", app: "junos-https"},
	}))
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	if !r.hasDeletedSession(7) || r.hasLiveSession(7) {
		t.Errorf("UNDER-DELETION: root a admits only junos-ssh, but tcp/80 session 7 survived: deleted=%v live=%v",
			r.hasDeletedSession(7), r.hasLiveSession(7))
	}
	if r.hasDeletedSession(8) || !r.hasLiveSession(8) {
		t.Errorf("OVER-DELETION: root a permits tcp/22 session 8, but it was deleted")
	}
}

// #12532 F4: a candidate captured again under a different rule key keeps the
// key recorded first. Session 9 was admitted by x in C1; C2 deletes x (records
// x), and C3's default-policy change captures the orphan again under
// default-policy. Root C0 has no x, so the nested rollback must delete session
// 9; letting the newer key win would let C0's p-first permit it.
func TestPolicyInvalidationNestedRollbackKeepsOlderRecordedRule12532(t *testing.T) {
	policies := []string{"p-first", "a", "b", "web"}
	r, _ := newConvergenceRun12072(t, policies)
	c0, err := r.h.d.store.SyncApply(
		rulesConfigText12532("order12532-c0", "deny-all", anyRules12532(policies...)), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
		row.IngressZoneID = config.StableZoneID("trust")
		row.EgressZoneID = config.StableZoneID("untrust")
	}
	r.h.d.store.MarkActiveApplied()

	c1, _, err := publishConfirmedRollbackText12072(t, r, c0, rulesConfigText12532(
		"order12532-c1", "permit-all", anyRules12532("p-first", "a", "b", "web", "x")))
	if err != nil {
		t.Fatalf("premise: C0->C1 add x: %v", err)
	}
	session9 := dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1009, DstPort: 80,
		},
		PolicyID: dpuserspace.PolicyIDsByStableKey(c1)["trust->untrust/x"], ExpectedRTFlowSessionID: 9,
		IngressZoneID: config.StableZoneID("trust"),
		EgressZoneID:  config.StableZoneID("untrust"),
	}
	r.dp.rows = append(r.dp.rows, session9)
	r.dp.ruleBySession[9] = "trust->untrust/x"
	r.dp.deleteErrOnce = true
	c2, _, err := publishConfirmedRollbackText12072(t, r, c1, rulesConfigText12532(
		"order12532-c2", "permit-all", anyRules12532(policies...)))
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackText12072(t, r, c2, rulesConfigText12532(
		"order12532-c3", "deny-all", anyRules12532(policies...)))
	if err == nil {
		t.Fatal("C2->C3 failed candidate delete was not surfaced")
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.capture == nil || len(debt.capture.deflt.policy) != 1 ||
		debt.capture.deflt.policy[0].ExpectedRTFlowSessionID != 9 {
		t.Fatalf("premise: C3 did not recapture session 9 as a default-policy orphan: %+v", debt)
	}
	if got := debt.capture.candidateRuleIDs[policyInvalidationMatchID(session9)]; got != "trust->untrust/x" {
		t.Fatalf("merged provenance for session 9 = %q, want the older trust->untrust/x", got)
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	if !r.hasDeletedSession(9) || r.hasLiveSession(9) {
		t.Errorf("UNDER-DELETION: root has no rule x, but session 9 survived the nested rollback: deleted=%v live=%v",
			r.hasDeletedSession(9), r.hasLiveSession(9))
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Errorf("OVER-DELETION: root permits session %d, but it was deleted", id)
		}
	}
}

// #12532 F1/F6: re-authorization judges a copy and leaves its input whole,
// and when two restored zone names fold to one StableZoneID every candidate's
// zone is ambiguous, so it must keep all of them instead of picking a name by
// map iteration order.
func TestPolicyInvalidationReauthorizationRefusesZoneIDCollision12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)
	trustID := config.StableZoneID("trust")
	capture := &policyInvalidationCapture{candidateRuleIDs: map[policyInvalidationMatchIdentity]string{}}
	const candidates = 32
	for i := range candidates {
		match := dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: uint16(3000 + i), DstPort: 80,
			},
			ExpectedRTFlowSessionID: uint64(3000 + i),
			IngressZoneID:           trustID,
			EgressZoneID:            config.StableZoneID("untrust"),
		}
		capture.deleted.policy = append(capture.deleted.policy, match)
		capture.candidateRuleIDs[policyInvalidationMatchID(match)] = "trust->untrust/a"
	}
	kept, permitted := r.h.d.reauthorizePolicyCandidates(capture, c0)
	if kept.candidateCount() != 0 || permitted.candidateCount() != candidates {
		t.Fatalf("premise: root C0 permits every candidate: kept=%d permitted=%d",
			kept.candidateCount(), permitted.candidateCount())
	}
	if len(capture.deleted.policy) != candidates || len(capture.candidateRuleIDs) != candidates {
		t.Fatalf("re-authorization mutated its input: rows=%d provenance=%d, want %d each",
			len(capture.deleted.policy), len(capture.candidateRuleIDs), candidates)
	}

	collider := ""
	for i := 0; collider == "" && i < 1<<22; i++ {
		if name := fmt.Sprintf("trust-collider-%d", i); config.StableZoneID(name) == trustID {
			collider = name
		}
	}
	if collider == "" {
		t.Fatal("no StableZoneID collision with trust in the brute-force window")
	}
	restored := *c0
	restored.Security.Zones = maps.Clone(c0.Security.Zones)
	restored.Security.Zones[collider] = &config.ZoneConfig{Name: collider}
	kept, permitted = r.h.d.reauthorizePolicyCandidates(capture, &restored)
	if permitted != nil || kept.candidateCount() != candidates {
		t.Fatalf("zones trust/%s share id %d, yet re-authorization permitted %d of %d candidates",
			collider, trustID, permitted.candidateCount(), candidates)
	}
}

// provenanceCostConfig12532 builds total permit-any policies in 200-rule zone
// pairs (MaxRulesPerPolicy is 256). The victim rule, when requested, follows
// p-first: runtime policy ID 0 is never swept, so it must not be the victim.
func provenanceCostConfig12532(total int, withVictim bool) *config.Config {
	permitAny := func(name string) *config.Policy {
		return &config.Policy{
			Name: name,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}
	}
	cfg := &config.Config{}
	for set, made := 0, 0; made < total; set++ {
		zpp := &config.ZonePairPolicies{FromZone: fmt.Sprintf("z%d", set), ToZone: "untrust"}
		if set == 0 {
			zpp.FromZone = "trust"
			zpp.Policies = append(zpp.Policies, permitAny("p-first"))
			if withVictim {
				zpp.Policies = append(zpp.Policies, permitAny("victim"))
			}
		}
		for i := 0; i < 200 && made < total; i++ {
			zpp.Policies = append(zpp.Policies, permitAny(fmt.Sprintf("p%d", i)))
			made++
		}
		cfg.Security.Policies = append(cfg.Security.Policies, zpp)
	}
	return cfg
}

// #12532 F3: recording provenance must not make every commit's capture cost
// sessions x policies. Rebuilding the stable-key map per candidate took about
// 15s for this shape; the per-capture index takes tens of milliseconds. The
// budget clears the fix by well over an order of magnitude so wall-clock noise
// cannot flake the gate.
func TestPolicyInvalidationCaptureProvenanceCostIsLinear12532(t *testing.T) {
	const policies, sessions = 1000, 20000
	oldCfg := provenanceCostConfig12532(policies, true)
	newCfg := provenanceCostConfig12532(policies, false)
	victimID, ok := dpuserspace.PolicyIDsByStableKey(oldCfg)["trust->untrust/victim"]
	if !ok {
		t.Fatal("premise: victim policy has no runtime ID")
	}
	dp := &convergenceHelper12072{
		invalDebtTestDP12073: &invalDebtTestDP12073{},
		applied:              oldCfg,
		helperCfg:            oldCfg,
		ruleBySession:        make(map[uint64]string, sessions),
	}
	for i := range sessions {
		sid := uint64(i + 1)
		dp.rows = append(dp.rows, dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6,
				SrcIP:   fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
				DstIP:   "10.255.0.2",
				SrcPort: uint16(1024 + i%60000), DstPort: 80,
			},
			PolicyID: victimID, ExpectedRTFlowSessionID: sid,
		})
		dp.ruleBySession[sid] = "trust->untrust/victim"
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.armPolicyInvalidationPlan(oldCfg, newCfg)

	start := time.Now()
	d.capturePolicyInvalidationLocked(newCfg)
	elapsed := time.Since(start)

	capture := d.policyInvalidationCapture
	if capture == nil || len(capture.deleted.policy) != sessions {
		t.Fatalf("premise: capture holds %d of %d victim candidates", capture.candidateCount(), sessions)
	}
	for _, match := range capture.deleted.policy {
		if got := capture.candidateRuleIDs[policyInvalidationMatchID(match)]; got != "trust->untrust/victim" {
			t.Fatalf("candidate %d recorded rule %q, want trust->untrust/victim", match.ExpectedRTFlowSessionID, got)
		}
	}
	const budget = 3 * time.Second
	if elapsed > budget {
		t.Fatalf("capture of %d candidates under %d policies took %v > %v: provenance is no longer O(1) per candidate",
			sessions, policies, elapsed, budget)
	}
	t.Logf("policies=%d candidates=%d pre-publication capture=%v", policies, sessions, elapsed)
}
