package cluster

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #9717 status coverage: a keyed session-sync connection that has not yet
// authenticated is named during its bounded upgrade grace, then disappears
// from the status after default #10717 enforcement evicts it.
// These cells reuse the #6628/#7441 fixtures:
//   - newUpgEnd installs an ESTABLISHED, never-authenticated authConn on a keyed SessionSync;
//   - strictEnd can back-date the grace anchor without sleeping.

const key9717 = "control-link-psk"

const engagedLine9717 = "engaged (local key configured; unauthenticated heartbeat frames rejected)"

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

// An unkeyed node has no authentication posture to report, and authenticated
// connections do not appear in the unauthenticated session-sync list.
func TestNoConnectionIsListedWhenUnkeyedOrAuthenticated_9717(t *testing.T) {
	if got := newUpgEnd(t, "", 0).s.UnauthenticatedSessionConns(); got != nil {
		t.Errorf("an unkeyed node must list nothing, got %v", got)
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
		t.Errorf("with every connection authenticated, status must be the engaged line, got %q", got)
	}
}

// With the default posture off, the periodic enforcement loop closes a
// never-authenticated connection after its grace.
func TestPreKeyConnectionEvictedByPeriodicLoop10717(t *testing.T) {
	e := strictEnd(t, key9717, false, true)
	m := keyedManagerWithAuthenticatedHeartbeat9717(t, e.s)
	if e.s.StrictSessionAuth() {
		t.Fatal("fixture must leave the legacy strict-session-auth setting unset")
	}
	previousTick := strictSessionAuthTick
	strictSessionAuthTick = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.s.strictSessionAuthLoop(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for connStillInstalled(e) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	strictSessionAuthTick = previousTick

	if connStillInstalled(e) {
		t.Fatal("periodic enforcement left the pre-key connection installed past its grace")
	}
	if got := e.s.stats.PreKeyAuthEvictions.Load(); got != 1 {
		t.Fatalf("PreKeyAuthEvictions = %d, want 1", got)
	}
	if got := m.controlLinkAuthStatus(); got != engagedLine9717 {
		t.Fatalf("after default eviction, the status must stop naming the pre-key connection, got %q", got)
	}
}
