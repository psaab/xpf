package cluster

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #9717: a session-sync connection established BEFORE the control-link key was committed, whose peer
// never answered the #6628 in-place upgrade, stays unauthenticated for its lifetime unless the
// opt-in strict-session-auth (#7441) evicts it. Its frames are accepted without HMAC.
//
// The status line said "engaged (peer authenticated; unauthenticated frames rejected)" from heartbeat
// evidence alone, and nothing warned. These cells reuse the #6628/#7441 fixtures:
//   - newUpgEnd installs an ESTABLISHED, never-authenticated authConn on a keyed SessionSync;
//   - strictEnd additionally sets the posture and back-dates the grace anchor.

const key9717 = "control-link-psk"

const engagedLine9717 = "engaged (peer authenticated; unauthenticated frames rejected)"

// keyedManagerWithAuthenticatedHeartbeat9717 builds the Manager side of the acceptance: keyed, with a
// heartbeat peer that has proven the key, and wired to s as its session-sync provider.
func keyedManagerWithAuthenticatedHeartbeat9717(t *testing.T, s *SessionSync) *Manager {
	t.Helper()
	m := &Manager{controlAuthKey: []byte(key9717)}
	r := &heartbeatReceiver{mgr: m, auth: m.heartbeatAuthState()}
	m.hbReceiver = r
	r.auth.peerAuthSeen.Store(true)
	m.SetSyncStats(s)
	return m
}

// THE DEFECT, as the acceptance states it: the status must not claim rejection, and must name the
// unauthenticated connection.
func TestAuthStatusNamesAnUnauthenticatedSessionSyncConnection_9717(t *testing.T) {
	e := newUpgEnd(t, key9717, 0)
	if len(e.ac.authPSK) != 0 {
		t.Fatal("FIXTURE: the connection is already authenticated; it is not the population this cell is about")
	}
	m := keyedManagerWithAuthenticatedHeartbeat9717(t, e.s)

	got := m.controlLinkAuthStatus()
	if strings.Contains(got, "rejected") {
		t.Errorf("status = %q: it claims unauthenticated frames are rejected while an established "+
			"session-sync connection that never authenticated is still accepted without HMAC (#9717)", got)
	}
	remote := connRemoteAddrString(e.ac)
	if remote == "" || !strings.Contains(got, remote) {
		t.Errorf("status = %q: it must name the unauthenticated session-sync connection %q (#9717)", got, remote)
	}
	if strings.Contains(got, key9717) {
		t.Errorf("the status leaked the control-link key: %q", got)
	}
}

// With strict-session-auth set, the connection is evicted after the grace, and the status stops naming
// it.
func TestAuthStatusStopsNamingAnEvictedConnection_9717(t *testing.T) {
	e := strictEnd(t, key9717, true, true)
	m := keyedManagerWithAuthenticatedHeartbeat9717(t, e.s)
	if got := m.controlLinkAuthStatus(); got == engagedLine9717 {
		t.Fatalf("FIXTURE: before the eviction the status must name the unauthenticated connection, got %q", got)
	}

	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("FIXTURE: strict-session-auth must evict the connection after the grace, evicted %d", n)
	}
	if got := m.controlLinkAuthStatus(); got != engagedLine9717 {
		t.Errorf("after the eviction no unauthenticated session-sync connection remains, so the status must "+
			"be the engaged line again, got %q", got)
	}
}

// Controls: nothing is listed on an unkeyed node or for an authenticated connection, and then the
// engaged line is accurate and unchanged.
func TestNoConnectionIsListedWhenUnkeyedOrAuthenticated_9717(t *testing.T) {
	if got := newUpgEnd(t, "", 0).s.UnauthenticatedSessionConns(); got != nil {
		t.Errorf("an unkeyed node authenticates nothing by the operator's choice; it must list nothing, got %v", got)
	}

	e := newUpgEnd(t, key9717, 0)
	e.s.writeMu.Lock()
	e.ac.authPSK = []byte(key9717)
	e.s.writeMu.Unlock()
	if got := e.s.UnauthenticatedSessionConns(); got != nil {
		t.Errorf("an authenticated connection must not be listed, got %v", got)
	}
	m := keyedManagerWithAuthenticatedHeartbeat9717(t, e.s)
	if got := m.controlLinkAuthStatus(); got != engagedLine9717 {
		t.Errorf("with every connection authenticated the engaged line is accurate and must be unchanged, got %q", got)
	}
}

// With the posture off, the residual is warned about once per connection after the grace.
func TestResidualWarningFiresOnceAfterTheGraceWithThePostureOff_9717(t *testing.T) {
	e := strictEnd(t, key9717, false, true)

	if n := e.s.warnUnauthenticatedResidual(); n != 1 {
		t.Fatalf("keyed, posture off, never authenticated, grace elapsed: the residual must be warned about, "+
			"warned %d (#9717)", n)
	}
	if n := e.s.warnUnauthenticatedResidual(); n != 0 {
		t.Errorf("the next tick warned again (%d): the notice must be ONE line per connection", n)
	}
	if got := e.s.stats.StrictAuthResidualWarnings.Load(); got != 1 {
		t.Errorf("StrictAuthResidualWarnings = %d, want 1", got)
	}
}

// It stays quiet inside the grace, where a legitimate peer's upgrade may still be in flight, and when
// the posture is on, where the eviction handles the connection.
func TestResidualWarningStaysQuietInsideTheGraceAndWithThePostureOn_9717(t *testing.T) {
	inGrace := newUpgEnd(t, key9717, 0)
	inGrace.s.writeMu.Lock()
	inGrace.ac.strictGraceStart = MonotonicNanos()
	inGrace.s.writeMu.Unlock()
	if n := inGrace.s.warnUnauthenticatedResidual(); n != 0 {
		t.Errorf("inside the grace a legitimate peer's in-place upgrade may still be in flight; warned %d", n)
	}

	strict := strictEnd(t, key9717, true, true)
	if n := strict.s.warnUnauthenticatedResidual(); n != 0 {
		t.Errorf("with strict-session-auth set the eviction handles the connection; warned %d", n)
	}
}

// The periodic strict-auth loop is what delivers the warning; nothing else calls it. Bound the call
// site, not just the method.
func TestTheStrictAuthLoopDeliversTheResidualWarning_9717(t *testing.T) {
	e := strictEnd(t, key9717, false, true)
	prev := strictSessionAuthTick
	strictSessionAuthTick = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.s.strictSessionAuthLoop(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for e.s.stats.StrictAuthResidualWarnings.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	strictSessionAuthTick = prev

	if got := e.s.stats.StrictAuthResidualWarnings.Load(); got != 1 {
		t.Errorf("the periodic strict-auth loop did not deliver the residual warning exactly once (count %d); "+
			"nothing else calls it (#9717)", got)
	}
}
