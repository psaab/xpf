package cluster

import (
	"testing"
	"time"
)

// #7441 — the strict session-auth posture, which closes the #6628 security
// residual: a hostile session-sync stream admitted BEFORE the control-link key
// was committed keeps injecting frames, because the in-place upgrade only ever
// PROMOTES a connection whose peer answers and a hostile peer declines by
// staying silent.
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

// TestStrictSessionAuthEvictsAnUnauthenticatedStream7441 is the security half
// of the issue's gate: a stream admitted while unkeyed, which then declines the
// upgrade by staying silent, is evicted.
func TestStrictSessionAuthEvictsAnUnauthenticatedStream7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, true)

	// Ground truth: the connection really is in the population under test —
	// installed, and never authenticated. Without this pin a fixture that
	// stopped installing a connection would make the assertion below pass over
	// an empty set.
	if !connStillInstalled(e) {
		t.Fatal("fixture did not install a connection")
	}
	if len(e.ac.authPSK) != 0 {
		t.Fatal("fixture connection is already authenticated; it is not the population this rule is about")
	}

	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d connections, want 1 — a stream admitted before the key "+
			"was committed is still injecting frames after it, which is the whole "+
			"of #7441", n)
	}
	if connStillInstalled(e) {
		t.Fatal("the connection slot was not cleared; the stream survives the eviction")
	}
	if got := e.s.stats.StrictAuthEvictions.Load(); got != 1 {
		t.Errorf("StrictAuthEvictions = %d, want 1 — an eviction the operator cannot see "+
			"is indistinguishable from a peer that went away on its own", got)
	}
}

// TestPostureOffLeavesARollingUpgradePeerAlone7441 is the OTHER half of the
// gate, and it is the half that makes this shippable.
//
// A legitimate peer that is keyed but running an older, pre-#6628 build cannot
// answer the upgrade either — it is indistinguishable on the wire from the
// hostile decliner above. Nothing in this package can separate them, so the
// separation is the OPERATOR's declaration. With the posture undeclared (the
// default) the identical connection must survive indefinitely, or every
// rolling upgrade becomes an outage.
//
// This is the cell that fails if anyone "simplifies" the design by inferring
// the posture from HeartbeatPeerAuthSeen() or from the peer's #6650 capability
// advertisement.
func TestPostureOffLeavesARollingUpgradePeerAlone7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", false, true)

	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections with the posture UNDECLARED. A keyed peer on "+
			"an older build cannot answer the in-place upgrade, so dropping it by "+
			"default turns every rolling upgrade into a session-sync outage", n)
	}
	if !connStillInstalled(e) {
		t.Fatal("the connection was closed with the posture undeclared")
	}
}

// TestUnkeyedNodeEvictsNothing7441: the posture is inert without a key. The
// runtime rule is "declared AND this node holds a key"; an unkeyed node has no
// authentication to demand, and evicting there would drop session sync on a
// cluster that never asked for it.
func TestUnkeyedNodeEvictsNothing7441(t *testing.T) {
	e := strictEnd(t, "", true, true)
	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections on an UNKEYED node; the posture is inert "+
			"without a key and a strict commit rejects the combination", n)
	}
}

// TestGraceHoldsInsideTheWindow7441 is the middle row.
//
// A rule that only ever evicts, and one that only ever evicts after the grace,
// both satisfy the eviction cell above. This is the one that separates them:
// inside the window the connection must survive, because the in-place upgrade
// takes a round trip and dropping inside it would kill a connection that was
// about to succeed.
func TestGraceHoldsInsideTheWindow7441(t *testing.T) {
	e := strictEnd(t, "control-link-psk", true, false)
	e.s.writeMu.Lock()
	e.ac.strictGraceStart = MonotonicNanos() // anchored now: grace has not elapsed
	e.s.writeMu.Unlock()

	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections INSIDE the grace; the in-place upgrade takes a "+
			"round trip and this drops a connection that was about to authenticate", n)
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
// The fixture never runs an accept path. The connection is already established
// and was admitted while this node was unkeyed — syncAuthDecision let it in
// because keyConfigured was false at the time. The key arrives afterwards, and
// the eviction still reaches it. An admission-time check cannot: by the time
// the key exists there is no admission left to gate.
func TestEvictionActsOnAnEstablishedConnectionNotAnAdmission7441(t *testing.T) {
	// Admitted while unkeyed: this is what syncAuthDecision does with no key.
	if _, accept, _ := syncAuthDecision(false, false, false, false); !accept {
		t.Fatal("syncAuthDecision no longer admits an unkeyed peer on an unkeyed node; " +
			"the premise of this fixture — a stream admitted BEFORE the key — is gone")
	}
	e := strictEnd(t, "control-link-psk", true, true) // key committed afterwards
	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d, want 1: the rule did not reach a connection that was already "+
			"established when the key was committed, which is the only population #7441 "+
			"is about", n)
	}
}
