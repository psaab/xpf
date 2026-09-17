package eventengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Regression tests for #5063 (committed-with-apply-debt classification).
//
// The daemon's commit callback (commitAndApply -> applyAndSyncCommitted,
// daemon_apply.go) returns TRI-STATE (compiled, err): on a NON-FATAL
// best-effort subsystem apply error (networkd write / Kea restart /
// host-inbound nft) the config is committed, active, and the dataplane is
// ARMED, so it returns a NON-nil compiled config ALONGSIDE the error. The
// generation is live.
//
// Pre-fix, applyOnce discarded compiled and returned errBatch for ANY err,
// and runAction counted it rejected without arming the cooldown. A live
// autonomous change was miscounted rejected, no cooldown was armed, and the
// same event could immediately re-commit — false telemetry plus control-plane
// churn during an incident. The fix reads the returned *config.Config, not the
// error, as the authority on promotion: a non-nil compiled with an error is
// committed-with-debt (count committed + a distinct debt counter, arm the
// cooldown, no retry); only a nil compiled is a genuine rejection.

// debtCommitFn promotes the candidate (real s.Commit) and then returns the
// promoted config alongside a non-fatal subsystem error — modelling the daemon
// leaving a best-effort subsystem in debt while the dataplane is armed.
func armWaitForCooldown(t *testing.T, e *Engine, policy string) {
	t.Helper()
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime[policy]
		return rt != nil && !rt.lastTrigger.IsZero()
	})
}

// #5063 CORE (RED-on-revert): a commit that promoted+armed the generation but
// left a best-effort subsystem in debt (non-nil compiled + non-nil err) MUST be
// counted committed (with a distinct debt counter) and MUST arm the cooldown —
// never rejected.
//
// FAIL-ON-REVERT: reverting applyOnce to discard compiled and return errBatch on
// any err makes runAction count this rejected. Committed stays 0, so the
// waitFor(Committed>=1) times out and the test goes RED.
func TestCommitDebt_ActiveWithNonfatalError_CountsCommitted_5063(t *testing.T) {
	s := newStore(t)
	pol := redefinePolicy("p", "ping_test_failed", "set system host-name remediated")

	debtErr := errors.New("networkd write failed: best-effort subsystem in debt")
	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		cfg, err := s.Commit()
		if err != nil {
			return nil, err
		}
		// Committed + active + dataplane armed, but a best-effort subsystem
		// remains in debt (the daemon's non-fatal apply tail, #4034).
		return cfg, debtErr
	}
	e := New(s, commitFn)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "committed-with-debt counted", func() bool { return e.Stats().Committed >= 1 })

	st := e.Stats()
	if st.Committed != 1 {
		t.Errorf("Committed=%d; a dataplane-armed commit with apply debt must count committed (#5063)", st.Committed)
	}
	if st.CommittedWithDebt != 1 {
		t.Errorf("CommittedWithDebt=%d; the debt subset must be counted distinctly (#5063)", st.CommittedWithDebt)
	}
	if st.Rejected != 0 {
		t.Errorf("Rejected=%d; a live committed generation must NOT be counted rejected (#5063)", st.Rejected)
	}
	// The cooldown MUST arm so the same event cannot immediately re-commit.
	armWaitForCooldown(t, e, "p")
	// The generation is genuinely live: the remediation landed in the active config.
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Errorf("host-name=%q; the committed-with-debt generation must be active", got)
	}
}

// #5063 (genuine rejection preserved): a commit that did NOT promote (nil
// compiled) is still a permanent rejection — counted rejected, cooldown NOT
// armed, active config unchanged. Guards that the debt carve-out did not swallow
// real failures.
func TestCommitDebt_GenuineRejection_CountsRejected_5063(t *testing.T) {
	s := newStore(t)
	pol := redefinePolicy("p", "ping_test_failed", "set system host-name remediated")

	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		// Required-protocol gate / disarmed dataplane: the commit did not
		// promote. Nil compiled is the ONLY genuine rejection.
		return nil, errors.New("required-protocol gate: dataplane disarmed")
	}
	e := New(s, commitFn)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "rejection counted", func() bool { return e.Stats().Rejected >= 1 })

	st := e.Stats()
	if st.Rejected != 1 {
		t.Errorf("Rejected=%d; a commit that did not promote (nil compiled) must count rejected", st.Rejected)
	}
	if st.Committed != 0 || st.CommittedWithDebt != 0 {
		t.Errorf("Committed=%d CommittedWithDebt=%d; a genuine rejection must not count committed",
			st.Committed, st.CommittedWithDebt)
	}
	// Cooldown must NOT arm on a rejection (a re-fire may legitimately retry).
	time.Sleep(50 * time.Millisecond)
	e.mu.Lock()
	rt := e.runtime["p"]
	armed := rt != nil && !rt.lastTrigger.IsZero()
	e.mu.Unlock()
	if armed {
		t.Error("cooldown armed on a genuine rejection; only a committed generation arms the cooldown")
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Errorf("host-name=%q; a rejected commit must not mutate the active config", got)
	}
}

// #5063 (clean-commit control): a commit that promoted with NO error counts
// committed with ZERO debt — the debt carve-out must not inflate the debt
// counter on the common path.
func TestCommitDebt_CleanCommit_NoDebtCounted_5063(t *testing.T) {
	s := newStore(t)
	pol := redefinePolicy("p", "ping_test_failed", "set system host-name remediated")

	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		return s.Commit()
	}
	e := New(s, commitFn)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "clean commit counted", func() bool { return e.Stats().Committed >= 1 })

	st := e.Stats()
	if st.Committed != 1 {
		t.Errorf("Committed=%d; a clean commit must count committed", st.Committed)
	}
	if st.CommittedWithDebt != 0 {
		t.Errorf("CommittedWithDebt=%d; a clean commit carries no apply debt", st.CommittedWithDebt)
	}
	if st.Rejected != 0 {
		t.Errorf("Rejected=%d; a clean commit is not a rejection", st.Rejected)
	}
	armWaitForCooldown(t, e, "p")
}

// #5063 (stale case, matrix completeness): an action whose policy is no longer
// live (no semRev entry) is dropped stale at the pre-commit revalidation gate —
// never reaching commitFn — and counts droppedStale, NOT committed/rejected.
// Driven directly through runAction for determinism (the worker path is racy).
func TestCommitDebt_StaleActionDropped_5063(t *testing.T) {
	s := newStore(t)
	// No policies applied: e.semRev has no entry, so staleReason returns
	// "policy removed" before any commitFn runs.
	e := New(s, func(ctx context.Context, comment string) (*config.Config, error) {
		t.Fatal("commitFn must not run for a stale action")
		return nil, nil
	})
	defer e.Close()

	e.runAction(plannedAction{
		policyName: "ghost",
		semRev:     "rev-x",
		ops:        []plannedOp{{setInput: "system host-name x", raw: "set system host-name x"}},
	})

	st := e.Stats()
	if st.DroppedStale != 1 {
		t.Errorf("DroppedStale=%d; an action for a removed policy must be dropped stale", st.DroppedStale)
	}
	if st.Committed != 0 || st.CommittedWithDebt != 0 || st.Rejected != 0 {
		t.Errorf("Committed=%d CommittedWithDebt=%d Rejected=%d; a stale action is neither committed nor rejected",
			st.Committed, st.CommittedWithDebt, st.Rejected)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Errorf("host-name=%q; a stale action must not mutate the active config", got)
	}
}
