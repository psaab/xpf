package eventengine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Regression tests for #5311 (revision-aware cooldown arm). The arm-on-commit
// cooldown stamp used to be revision-BLIND: runAction called armCooldown(name)
// after a successful commit and armCooldown stamped e.runtime[name].lastTrigger
// with no identity check. When a remediation's OWN commit redefined its
// triggering policy (R1 -> R2), the daemon's commit callback reconciled the new
// config and Apply installed a FRESH re-armed runtime for the successor R2 (zero
// lastTrigger, because the semantic revision changed). The revision-blind stamp
// then wrote R1's completion time onto that freshly re-armed R2 — a name-based
// ABA that suppressed R2 for the whole ~30s cooldown, undoing the very re-arm the
// reconcile just performed and contradicting the documented "a redefined policy
// re-arms" contract.
//
// The fix passes the authorizing semantic revision (plannedAction.semRev) to
// armCooldown, which stamps ONLY when e.semRev[name] still equals it — i.e. only
// when the live runtime is still the same generation that authorized the action.
// The check and the stamp run together under e.mu so a concurrent Apply cannot
// swap the runtime between them (no TOCTOU).

// redefinePolicy builds a policy with the given self-remediation command. Two
// instances with different commands hash to different semantic revisions, so
// Apply treats the second as a redefinition of the first (same name) and installs
// a fresh re-armed runtime.
func redefinePolicy(name, event, cmd string) *config.EventPolicy {
	return &config.EventPolicy{
		Name:         name,
		Events:       []string{event},
		ThenCommands: []string{cmd},
	}
}

// #5311 (unit, deterministic RED-on-revert): armCooldown must NOT stamp a
// successor generation. Model the reconcile directly — Apply R1, capture its
// authorizing revision, then Apply a redefined R2 (fresh runtime) as the commit
// callback would, then call armCooldown with R1's revision. The freshly re-armed
// R2 must keep its zero lastTrigger.
//
// FAIL-ON-REVERT: reverting armCooldown to the name-only stamp
// (rt.lastTrigger = e.now() unconditionally) stamps the successor R2, so
// lastTrigger is non-zero and this test goes RED.
func TestArmCooldown_SkipsSuccessorGeneration_5311(t *testing.T) {
	e := New(nil, nil)

	r1 := redefinePolicy("p", "ping_test_failed", "set system host-name gen2")
	applyPolicies9984(e, []*config.EventPolicy{r1})

	e.mu.Lock()
	authRev := e.semRev["p"] // the revision the action carries (evaluate time)
	r1rt := e.runtime["p"]
	e.mu.Unlock()

	// The daemon's commit callback reconciles a redefined policy: same name, new
	// semantic revision -> Apply installs a FRESH re-armed runtime.
	r2 := redefinePolicy("p", "ping_test_failed", "set system host-name gen3")
	applyPolicies9984(e, []*config.EventPolicy{r2})

	e.mu.Lock()
	succRev := e.semRev["p"]
	r2rt := e.runtime["p"]
	e.mu.Unlock()

	// Prove the ABA setup is real: a genuinely fresh successor runtime.
	if succRev == authRev {
		t.Fatalf("redefinition did not change the semantic revision (%q); the ABA "+
			"setup is invalid", authRev)
	}
	if r2rt == r1rt {
		t.Fatal("Apply carried the runtime forward instead of installing a fresh " +
			"successor; the ABA setup is invalid")
	}
	if !r2rt.lastTrigger.IsZero() {
		t.Fatal("the freshly reconciled successor runtime is not zero-armed; the " +
			"ABA setup is invalid")
	}

	// The worker arms the cooldown with the AUTHORIZING revision (R1's), after the
	// successor R2 has already been installed by the in-commit reconcile.
	e.armCooldown("p", authRev)

	e.mu.Lock()
	lt := e.runtime["p"].lastTrigger
	e.mu.Unlock()
	if !lt.IsZero() {
		t.Fatalf("successor R2 lastTrigger=%v; the revision-blind arm stamped the "+
			"freshly re-armed successor with the predecessor's completion time "+
			"(name-based ABA, #5311) — R2 would be suppressed for the whole cooldown", lt)
	}
}

// #5311 (unit, normal-case guard): armCooldown MUST still stamp the cooldown when
// the policy did not redefine itself — the guard passes because the authorizing
// revision matches the carried-forward runtime. Protects the common path from a
// guard that is too aggressive.
func TestArmCooldown_StampsSameGeneration_5311(t *testing.T) {
	e := New(nil, nil)
	fixed := time.Unix(1_700_000_000, 0)
	e.nowFn = func() time.Time { return fixed }

	pol := redefinePolicy("p", "ping_test_failed", "set system host-name r")
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.mu.Lock()
	rev := e.semRev["p"]
	e.mu.Unlock()

	// Same generation authorized and still live: the cooldown must arm.
	e.armCooldown("p", rev)

	e.mu.Lock()
	lt := e.runtime["p"].lastTrigger
	e.mu.Unlock()
	if lt.IsZero() {
		t.Fatal("same-generation armCooldown did not stamp lastTrigger; the #5311 " +
			"revision guard must not break the normal (non-self-modifying) cooldown")
	}
	if !lt.Equal(fixed) {
		t.Fatalf("lastTrigger=%v; want the injected clock %v", lt, fixed)
	}
}

// #5311 (end-to-end through the worker): a policy whose action redefines itself
// (R1 -> R2) must leave the successor R2 re-armed, so an IMMEDIATELY following
// event fires R2 instead of being throttled by R1's cooldown. Drives the real
// runAction/armCooldown path; the commit callback models the daemon reconcile by
// calling Apply with the redefined policy on the first commit (exactly as the
// daemon's commitAndApply would after the config changed).
//
// FAIL-ON-REVERT: with the name-only stamp, the first commit re-arms R2 (fresh
// runtime) and then armCooldown re-stamps it with R1's time; the second event is
// suppressed (at evaluate, or dropped as "cooldown active" at commit), so
// Committed stays 1 and the wait for the second commit times out -> RED.
func TestCooldown_SelfRedefinedSuccessorFires_5311(t *testing.T) {
	s := newStore(t)

	r1 := redefinePolicy("p", "ping_test_failed", "set system host-name gen2")
	// r2 is the successor the reconcile installs: same name/event, different
	// command -> different semantic revision -> fresh re-armed runtime.
	r2 := redefinePolicy("p", "ping_test_failed", "set system host-name gen3")

	var e *Engine
	var applied int32
	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		cfg, err := s.Commit()
		if err != nil {
			return nil, err
		}
		// Model the daemon's post-commit reconcile: the just-committed config
		// redefined policy p, so event-options Apply installs the successor R2's
		// fresh runtime. Only on the FIRST commit (R1's) — R2 does not redefine
		// itself again.
		if atomic.AddInt32(&applied, 1) == 1 {
			applyPolicies9984(e, []*config.EventPolicy{r2})
		}
		return cfg, nil
	}
	e = New(s, commitFn)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{r1})

	// R1 fires: commits gen2 AND (via the reconcile) installs the fresh R2.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "R1 commit + reconcile", func() bool { return e.Stats().Committed >= 1 })

	// The successor R2 is re-armed; an immediate event must fire it (not be
	// throttled by R1's completion time).
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "successor R2 commit", func() bool { return e.Stats().Committed >= 2 })

	if got := e.Stats().DroppedStale; got != 0 {
		t.Errorf("DroppedStale=%d; the re-armed successor R2 must not be dropped as "+
			"cooldown-active (name-based ABA, #5311)", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "gen3" {
		t.Errorf("host-name=%q; the re-armed successor R2 must have committed 'gen3'", got)
	}
}

// #5311 (regression guard, end-to-end): a NORMAL policy (does not redefine
// itself) must keep its cooldown — a rapid re-fire within the window is
// suppressed. Confirms the revision guard does not weaken the common-case
// cooldown. The commit callback does NOT reconcile a new policy, so the
// authorizing revision still matches at arm time and the stamp lands.
func TestCooldown_NormalPolicyRapidRefireSuppressed_5311(t *testing.T) {
	s := newStore(t)
	pol := redefinePolicy("p", "ping_test_failed", "set system host-name remediated")

	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		return s.Commit()
	}
	e := New(s, commitFn)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// First trigger commits and arms the cooldown.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })
	// Wait until the cooldown is observably ARMED (armCooldown runs on the worker
	// just after the committed counter bumps) so the within-window re-fire below
	// cannot race an unarmed window.
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime["p"]
		return rt != nil && !rt.lastTrigger.IsZero()
	})

	// A rapid re-fire within the cooldown must be suppressed (never re-committed).
	e.HandleEvent(eventFor("ping_test_failed"))
	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Errorf("Committed=%d; the ~30s cooldown must suppress a rapid re-fire of a "+
			"policy that did not redefine itself (want exactly 1)", got)
	}
}
