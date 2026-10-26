package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #17848: PR #17462 reintroduced the old-policy/new-revision pairing that
// #16645 closed on the evaluation side. Engine.apply published
// e.runtime/e.semRev, then released e.mu for the #16650 pending purge, and
// only rebuilt e.eventIndex after relocking. An evaluation landing in that
// window read the PREDECESSOR policy out of the old index
// (evaluate.go eventIndex loop) and stamped it with the SUCCESSOR revision
// (e.semRev[pol.Name]); staleReason compares revisions only, so the
// retracted batch passed the "policy redefined" gate and could commit once
// under the new definition.
//
// Fix: apply builds the successor eventIndex/policyOrder/regexCache from
// the policy list BEFORE publishing anything, then assigns policies,
// runtime, semRev, eventIndex, policyOrder and regexCache together under
// the one e.mu hold; the pending purge still runs after, in its
// unlock/relock window, against the fully-published generation.
//
// This test parks Apply deterministically inside the old window: the test
// holds pendingMu, so a pre-fix Apply blocks in the purge AFTER publishing
// the new revision but BEFORE rebuilding the index. The poll below waits
// until the new revision is observable under e.mu; pre-fix the index at
// that instant provably still holds the old policy pointer (Apply cannot
// advance past pendingMu), post-fix the index is already the successor's.
func TestApplyPublishesIndexAndRevisionAtomically17848(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()

	pOld := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name old"}}
	pNew := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name new"}}
	oldRev := policySemanticRevision(pOld)
	newRev := policySemanticRevision(pNew)
	if oldRev == newRev {
		t.Fatal("test policies must have distinct semantic revisions")
	}

	applyPolicies9984(e, []*config.EventPolicy{pOld})

	// Hold pendingMu so the redefining Apply parks in its purge window.
	e.pendingMu.Lock()
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		applyPolicies9984(e, []*config.EventPolicy{pNew})
	}()

	// Wait until the successor revision is published. Pre-fix that is
	// observable while eventIndex still lists pOld; post-fix the whole
	// generation (index included) is already swapped.
	deadline := time.Now().Add(10 * time.Second)
	for {
		e.mu.Lock()
		published := e.semRev["p"] == newRev
		e.mu.Unlock()
		if published {
			break
		}
		if time.Now().After(deadline) {
			e.pendingMu.Unlock()
			t.Fatal("redefining Apply never published the new revision")
		}
		time.Sleep(time.Millisecond)
	}

	// Evaluate while Apply is parked in (pre-fix) / already past
	// (post-fix) the publication window. e.mu is free in both cases:
	// pre-fix Apply released it for the purge; post-fix Apply released
	// it only after publishing the complete generation, and is blocked
	// on pendingMu.
	triggered := e.evaluateEvent(eventFor("ping_test_failed"))
	e.pendingMu.Unlock()
	select {
	case <-applyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("redefining Apply did not complete")
	}

	for _, tp := range triggered {
		if tp.pol == pOld && tp.semRev != oldRev {
			t.Fatalf("old policy paired with new revision: pol=%p semRev=%q, want old rev %q "+
				"(staleReason would accept this retracted batch under the new definition)",
				tp.pol, tp.semRev, oldRev)
		}
		if tp.pol == pOld {
			t.Fatalf("evaluation during Apply returned the predecessor policy %p; "+
				"the published generation must be observed whole", tp.pol)
		}
		if tp.pol.Name == "p" && tp.semRev != newRev {
			t.Fatalf("successor policy stamped with non-live revision %q, want %q", tp.semRev, newRev)
		}
	}

	// After Apply settles, the successor is the live generation.
	triggered = e.evaluateEvent(eventFor("ping_test_failed"))
	found := false
	for _, tp := range triggered {
		if tp.pol == pNew && tp.semRev == newRev {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-Apply evaluation did not trigger the successor policy, got %+v", triggered)
	}
}

// Control: with no concurrent redefinition, an evaluation triggers the
// applied policy stamped with that policy's own revision (#16645/#3750
// pairing invariant on the quiet path).
func TestApplyPublishControlNoRedefinition17848(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()

	p := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name only"}}
	applyPolicies9984(e, []*config.EventPolicy{p})

	triggered := e.evaluateEvent(eventFor("ping_test_failed"))
	if len(triggered) != 1 {
		t.Fatalf("evaluate triggered %d policies, want 1: %+v", len(triggered), triggered)
	}
	if triggered[0].pol != p {
		t.Fatalf("triggered policy %p, want applied policy %p", triggered[0].pol, p)
	}
	if want := policySemanticRevision(p); triggered[0].semRev != want {
		t.Fatalf("triggered semRev %q, want the policy's own revision %q", triggered[0].semRev, want)
	}
}
