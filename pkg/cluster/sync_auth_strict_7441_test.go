package cluster

import (
	"testing"
	"time"
)

// #7441 introduced the operator-declared eviction posture; #10717 makes
// eviction of a keyed node's never-authenticated session-sync connection the
// default after a bounded in-place-upgrade grace.
//
// The fixtures below reuse the #6628 harness: newUpgEnd installs an
// ESTABLISHED, unauthenticated authConn on a SessionSync, which is exactly the
// "admitted while unkeyed" state.

// strictEnd builds a keyed node holding one established, never-authenticated
// connection, with the eviction grace already elapsed.
//
// elapsed is expressed by back-dating the anchor rather than by sleeping: the
// grace is anchored in MONOTONIC time, so a test that slept would have to sleep
// the real grace, and one that shrank the grace to microseconds would no longer
// be exercising the same arithmetic.
func strictEnd(t *testing.T, key string, posture bool, graceElapsed bool) *upgEnd {
	t.Helper()
	e := newUpgEnd(t, key, 0)
	e.s.SetStrictSessionAuth(posture)
	if graceElapsed {
		e.s.writeMu.Lock()
		e.ac.strictGraceStart = MonotonicNanos() - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
		e.s.writeMu.Unlock()
	}
	return e
}

func connStillInstalled(e *upgEnd) bool {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	return e.s.conn0 != nil
}

// TestStrictSessionAuthEvictsAnUnauthenticatedStream7441 covers the keyed,
// never-authenticated connection once its grace has elapsed.
func TestStrictSessionAuthEvictsAnUnauthenticatedStream7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, true)

	if !connStillInstalled(e) || len(e.ac.authPSK) != 0 {
		t.Fatal("fixture must install an established, never-authenticated connection")
	}
	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d connections, want 1", n)
	}
	if connStillInstalled(e) {
		t.Fatal("the connection slot was not cleared; the stream survives the eviction")
	}
	if got := e.s.stats.PreKeyAuthEvictions.Load(); got != 1 {
		t.Errorf("PreKeyAuthEvictions = %d, want 1", got)
	}
}

// FAIL-ON-REVERT: keyed pre-key connections expire after the same grace even
// with the default (strict-session-auth unset) configuration. Restoring the
// old strict-session-auth gate leaves this connection installed and fails.
func TestDefaultEvictsAnUnauthenticatedStreamAfterGrace10717(t *testing.T) {
	e := strictEnd(t, "control-link-psk", false, true)
	if e.s.StrictSessionAuth() {
		t.Fatal("fixture must exercise the default, posture-off configuration")
	}
	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("default keyed-node enforcement evicted %d connections, want 1", n)
	}
	if connStillInstalled(e) {
		t.Fatal("the pre-key connection survived beyond its grace with strict-session-auth unset")
	}
}

// An unkeyed node has no authentication to demand; evicting there would drop
// session sync on a cluster that never asked for authentication.
func TestUnkeyedNodeEvictsNothing7441(t *testing.T) {
	e := strictEnd(t, "", true, true)
	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections on an unkeyed node, want none", n)
	}
}

// Within the bounded grace, the #6628 in-place upgrade may still complete;
// this protection applies by default, not only when the legacy leaf is set.
func TestGraceHoldsInsideTheWindow7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", false, false)
	e.s.writeMu.Lock()
	e.ac.strictGraceStart = MonotonicNanos()
	e.s.writeMu.Unlock()

	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections inside the grace, want none", n)
	}
	if !connStillInstalled(e) {
		t.Fatal("the connection was closed inside the in-place-upgrade grace")
	}
}


// TestUnanchoredConnectionIsNotEvicted7441: a connection no reconcile has
// reached yet has no anchor, and must not be evicted on a zero timestamp.
//
// Without this, `now - 0 > grace` is true for every connection from process
// start, so the rule would fire on a connection the upgrade had never been
// attempted on — evicting a legitimate peer before it was ever asked.
func TestUnanchoredConnectionIsNotEvicted7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, false)
	e.s.writeMu.Lock()
	anchor := e.ac.strictGraceStart
	e.s.writeMu.Unlock()
	if anchor != 0 {
		t.Fatalf("fixture anchor = %d, want 0 — this cell tests the unanchored case", anchor)
	}
	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections that no reconcile had reached; a zero anchor "+
			"must not read as an infinitely-elapsed grace", n)
	}
}

// TestAuthenticatedConnectionIsNeverEvicted7441: the negative control. A
// connection that completed the exchange proves its peer holds the PSK, and
// evicting it would be a self-inflicted outage on a correctly-keyed cluster.
func TestAuthenticatedConnectionIsNeverEvicted7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, true)
	e.s.writeMu.Lock()
	e.ac.authPSK = []byte("control-link-psk")
	e.s.writeMu.Unlock()

	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d AUTHENTICATED connections", n)
	}
	if !connStillInstalled(e) {
		t.Fatal("an authenticated connection was closed")
	}
}

// TestGraceAnchorIsSetOnceAndNotReArmed7441 binds a security property, not an
// optimisation.
//
// The anchor is set by ReconcileConnectionAuth, which runs on EVERY commit. If
// each reconcile re-anchored, a peer able to induce commits — and an admitted
// peer can, through the config-sync push this rule exists to distrust — would
// push its own deadline forward indefinitely and never be evicted. That is
// #5078's re-arming constraint in its original costume.
func TestGraceAnchorIsSetOnceAndNotReArmed7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, false)

	e.s.ReconcileConnectionAuth("first")
	e.s.writeMu.Lock()
	first := e.ac.strictGraceStart
	e.s.writeMu.Unlock()
	if first == 0 {
		t.Fatal("the first reconcile did not anchor the grace; the rule can never fire")
	}

	// Back-date so a re-anchor would be unmistakable, then reconcile again the
	// way a second commit would.
	e.s.writeMu.Lock()
	e.ac.strictGraceStart = first - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
	backdated := e.ac.strictGraceStart
	e.s.writeMu.Unlock()

	for i := 0; i < 5; i++ {
		e.s.ReconcileConnectionAuth("later-commit")
	}
	e.s.writeMu.Lock()
	after := e.ac.strictGraceStart
	e.s.writeMu.Unlock()

	if after != backdated {
		t.Fatalf("the anchor moved from %d to %d across repeated reconciles. A peer that "+
			"can induce commits then holds its own eviction window open forever, which "+
			"is exactly the re-arming #5078 could not solve", backdated, after)
	}
}

// TestReconcileEvictsWhenTheGraceHasAlreadyElapsed7441 is the WIRING cell for
// the commit path.
//
// enforceStrictSessionAuth is called from two places: the periodic tick and
// ReconcileConnectionAuth. The tick is what normally fires, so a test that only
// called the enforcement directly would stay green with the reconcile call
// deleted — and a commit landing after the grace had already elapsed would then
// wait up to a full tick while the hostile stream kept injecting.
func TestReconcileEvictsWhenTheGraceHasAlreadyElapsed7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, true)
	e.s.ReconcileConnectionAuth("commit-after-grace")
	if connStillInstalled(e) {
		t.Fatal("ReconcileConnectionAuth did not evict a connection whose grace had " +
			"already elapsed; the commit path does not enforce the posture and the " +
			"stream survives until the next tick")
	}
}

// TestEvictionActsOnAnEstablishedConnectionNotAnAdmission7441 states, as an
// executable claim, the constraint #5078 named first: the window must bound a
// connection's LIFETIME, not its admission.
//
// The fixture never runs an accept path. It builds an ESTABLISHED,
// unauthenticated connection before enforcement; the key arrives afterwards,
// and eviction still reaches it. An admission-time check cannot: by the time
// the key exists there is no admission left to gate.
func TestEvictionActsOnAnEstablishedConnectionNotAnAdmission7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, true) // key committed afterwards
	if !connStillInstalled(e) {
		t.Fatal("fixture did not install an established connection")
	}
	if len(e.ac.authPSK) != 0 {
		t.Fatal("fixture connection is already authenticated; it is not the population #7441 evicts")
	}
	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d, want 1: the rule did not reach a connection that was already "+
			"established when the key was committed, which is the only population #7441 "+
			"is about", n)
	}
}
