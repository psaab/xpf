// Pre-key session-sync connections are bounded by the #10717 default policy.
// Once this node has a control-link key, a connection that has never
// authenticated gets one grace period to complete the #6628 in-place upgrade.
// If it does not, enforcement closes it whether or not the legacy
// strict-session-auth config leaf is set. This retains compatibility with
// #6628 rolling upgrades while preventing an unresponsive pre-key stream from
// remaining a pass-through connection for the lifetime of the process.
//
// The grace is anchored when ReconcileConnectionAuth first observes the key,
// not at connection setup: this bounds a connection's lifetime after keying
// and gives a live upgrade one round trip. It is set once, so commits cannot
// re-arm it, and uses monotonic time so wall-clock steps cannot extend it.
//
// #16857 extends the same population to a connection whose authPSK has left
// the accepted set (authAcceptedKeys). Finalize ("the retired key stops
// authenticating", README rotation step 5) previously left such a connection
// untouched: both this eviction and the #9717 listing keyed only on
// len(authPSK)==0, so a holder of the retired key kept verifying frames under
// retired-key-derived connection keys for as long as it declined the #6628
// rekey. It now anchors a set-once monotonic grace at the reconcile where its
// key leaves the accepted set, is listed by UnauthenticatedSessionConns during
// that grace, and is evicted at expiry. A round already in flight at retirement
// may complete under the stale key; that authenticated completion starts a
// fresh grace for the immediately-triggered current-key rekey. A cooperating
// peer that rekeys (or whose key is re-accepted) within grace is never evicted,
// and failed/incomplete rounds never move the deadline.
//
// HISTORY (#7441 -> #10717): eviction was operator-declared because no live
// signal distinguishes a hostile silent peer from a legitimate keyed peer on
// a pre-#6628 build that cannot answer the upgrade (dropping on inference
// breaks that rolling upgrade; see the pre-#10717 header in git history for
// the full analysis). #10717 flips the default per the residual finding: a
// pre-#6628 peer that cannot complete the upgrade is now evicted after grace.
// The #6628 rolling-upgrade cells are the binding constraint — they must stay
// green — and the strict-session-auth leaf is retained (compat) but no longer
// gates enforcement.
package cluster

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// strictSessionAuthGrace bounds the #6628 in-place-upgrade round trip for a
// pre-key connection on a keyed node. After 10s without authentication, the
// connection is closed by default.
//
// A var, not a const, so tests can shrink it. Lengthening it costs only a
// longer window in which a hostile stream survives after keying; shortening it
// below one round trip risks a reconnect loop against a legitimate slow peer.
var strictSessionAuthGrace = 10 * time.Second

// strictSessionAuthTick is how often established connections are re-evaluated.
// The commit-driven reconciler also enforces immediately when it observes an
// already-expired grace period.
var strictSessionAuthTick = 1 * time.Second

// SetStrictSessionAuth publishes the legacy #7441 node-local config leaf.
//
// The setting is retained for configuration compatibility; #10717 made
// eviction default whenever this node is keyed, so this value no longer gates
// enforcement. The value remains available through StrictSessionAuth for
// callers that report the configured posture.
func (s *SessionSync) SetStrictSessionAuth(on bool) {
	prev := s.strictSessionAuth.Swap(on)
	if prev != on {
		slog.Info("cluster sync: strict session-auth config changed (#7441)",
			"enabled", on)
	}
}

// StrictSessionAuth reports the legacy configured posture. It does not gate
// the default pre-key connection eviction.
func (s *SessionSync) StrictSessionAuth() bool { return s.strictSessionAuth.Load() }

// noteStrictAuthGraceStart anchors the eviction grace for conn, once.
//
// Called from ReconcileConnectionAuth for every established connection at the
// first reconcile where this node is keyed and the connection is not
// authenticated — which is the moment the upgrade attempt begins for BOTH
// roles (the initiator emits a Hello, the responder emits a Request). Anchoring
// there rather than at connection setup is what makes the rule bound a
// connection's LIFETIME: a connection established long before the key was
// committed starts its grace when the key arrives, not when it was accepted.
//
// SET ONCE. A later reconcile must not push the anchor forward, or a peer able
// to induce commits could hold its own window open indefinitely.
//
// Caller must hold s.writeMu.
func (s *SessionSync) noteStrictAuthGraceStartLocked(ac *authConn) {
	if ac == nil || ac.strictGraceStart != 0 {
		return
	}
	ac.strictGraceStart = MonotonicNanos()
	ac.strictGraceRetired = false
}

// noteRetiredKeyGraceStartLocked anchors the #16857 eviction grace for a
// connection authenticated under a key that has left the accepted set. The
// reconcile path is set-once so later commits cannot extend a stale
// connection's lifetime; recordAuthUpgradeCompleteLocked separately handles a
// round that was already in flight at retirement.
//
// Caller must hold s.writeMu.
func (s *SessionSync) noteRetiredKeyGraceStartLocked(ac *authConn) {
	if ac == nil || ac.strictGraceStart != 0 {
		return
	}
	ac.strictGraceStart = MonotonicNanos()
	ac.strictGraceRetired = true
}

// clearStrictAuthGraceLocked clears the eviction grace when the connection is
// authenticated under an accepted key: either it completed a rekey to the new
// key, or its key was re-accepted (e.g. re-added as the additional key). A
// later retirement then anchors a fresh grace.
//
// Caller must hold s.writeMu.
func (s *SessionSync) clearStrictAuthGraceLocked(ac *authConn) {
	if ac == nil {
		return
	}
	ac.strictGraceStart = 0
	ac.strictGraceRetired = false
}

// recordAuthUpgradeCompleteLocked stamps the key proved by a completed
// in-place upgrade and updates its eviction grace under the same lock. A
// completion under an accepted key ends the prior stale episode. If a round
// that was already in flight completes under a key now outside the accepted
// set, the peer has completed the old round and the completion path may prompt
// for the current-key rekey; give that continuation one grace window from this
// completion rather than inheriting an expired pre-key/retirement deadline.
// Failed or incomplete rounds never call this, so they cannot re-arm grace.
//
// Caller must hold s.writeMu.
func (s *SessionSync) recordAuthUpgradeCompleteLocked(ac *authConn, psk []byte, accepted [][]byte) {
	if ac == nil {
		return
	}
	ac.authPSK = append([]byte(nil), psk...)
	if authPSKAccepted(psk, accepted) {
		s.clearStrictAuthGraceLocked(ac)
		return
	}
	ac.strictGraceStart = MonotonicNanos()
	ac.strictGraceRetired = true
}

// authPSKAccepted reports whether psk is in the accepted set. An empty psk
// (never authenticated) is never accepted.
func authPSKAccepted(psk []byte, accepted [][]byte) bool {
	if len(psk) == 0 {
		return false
	}
	for _, k := range accepted {
		if bytes.Equal(psk, k) {
			return true
		}
	}
	return false
}

// connAuthStaleLocked reports whether ac belongs to the eviction/listing
// population: never authenticated, or authenticated under a key outside the
// accepted set (#16857). Caller must hold s.writeMu (authPSK is read).
func connAuthStaleLocked(ac *authConn, accepted [][]byte) bool {
	if ac == nil {
		return false
	}
	if len(ac.authPSK) == 0 {
		return true
	}
	return !authPSKAccepted(ac.authPSK, accepted)
}

// enforceStrictSessionAuth closes every established session-sync connection
// that must not survive on a keyed node, and returns how many it closed.
//
// #10717 made eviction the DEFAULT when a key is configured: the predicate is
// this node holds a control-link key AND the connection is in the stale
// population AND its grace anchor is set and has elapsed. The stale
// population is (a) never authenticated, or (b) #16857: authenticated under
// a key that has left the accepted set. The #7441 operator posture
// (`chassis cluster strict-session-auth`) is retained for compatibility but no
// longer gates enforcement; a stream that declines the in-place upgrade or
// rekey is evicted whether or not the leaf is set.
//
// The accepted set is re-read live on every pass, so a connection whose key
// is re-accepted (or which rekeys to an accepted key) before expiry has its
// anchor cleared here and is never evicted — enforcement must not close a
// connection that is no longer stale merely because an anchor exists.
//
// authPSK and strictGraceStart are both written under s.writeMu (authPSK and
// completion-time grace updates by the upgrade exchange, reconcile-time grace
// updates by the reconciler), so they are read here under the same lock.
// readKey is deliberately NOT consulted even though authed() would be the more
// natural-sounding predicate: readKey is owned by the per-connection
// receiveLoop goroutine with no lock, so reading it from this loop would be a
// data race. authPSK carries the same fact — it is set only by a completed
// exchange, which requires the PSK — and is race-safe.
func (s *SessionSync) enforceStrictSessionAuth() int {
	if len(s.authKey()) == 0 {
		// Unkeyed: the rule is inert by design. Evicting here would drop
		// session sync on a cluster that never asked for authentication.
		return 0
	}
	now := MonotonicNanos()
	s.mu.Lock()
	conns := []net.Conn{s.conn0, s.conn1}
	s.mu.Unlock()

	var doomed []net.Conn
	var doomedRetired []bool
	s.writeMu.Lock()
	// #18016: snapshot accepted keys only after acquiring writeMu. A
	// snapshot taken before the lock can go stale while this pass waits:
	// a concurrent retirement reconcile anchors a fresh grace under the
	// new accepted set, and a stale-set pass could then clear that new
	// anchor (authPSK accepted under the stale set), leaving the anchor
	// zero so every later pass skips the connection and eviction never
	// fires. authAcceptedKeys only reads the atomic provider and, for
	// *Manager, takes m.mu.RLock; production does not call back into
	// SessionSync while that manager lock is held.
	accepted := s.authAcceptedKeys()
	for _, c := range conns {
		ac, ok := c.(*authConn)
		if !ok || ac == nil {
			continue
		}
		if !connAuthStaleLocked(ac, accepted) {
			// Authentication under an accepted key ends either stale
			// episode, so a later retirement starts a fresh grace.
			s.clearStrictAuthGraceLocked(ac)
			continue
		}
		if ac.strictGraceStart == 0 {
			continue // no reconcile has attempted an upgrade/rekey yet
		}
		if now-ac.strictGraceStart < strictSessionAuthGrace.Nanoseconds() {
			continue // still inside the in-place-upgrade grace
		}
		doomed = append(doomed, c)
		doomedRetired = append(doomedRetired, ac.strictGraceRetired)
	}
	s.writeMu.Unlock()

	for i, c := range doomed {
		if doomedRetired[i] {
			slog.Warn("cluster sync: closing a session-sync connection authenticated "+
				"under a retired control-link key that did not rekey within the grace "+
				"(#16857); a keyed peer reconnects and authenticates at connection setup",
				"remote", connRemoteAddrString(c), "grace", strictSessionAuthGrace)
		} else {
			slog.Warn("cluster sync: closing a pre-key session-sync connection that never authenticated "+
				"within the upgrade grace (#10717); a keyed peer reconnects and authenticates "+
				"at connection setup",
				"remote", connRemoteAddrString(c), "grace", strictSessionAuthGrace)
		}
		s.stats.PreKeyAuthEvictions.Add(1)
		s.handleDisconnect(c)
	}
	return len(doomed)
}

// UnauthenticatedSessionConns returns the remote address of every installed
// session-sync connection in the stale population — never authenticated, or
// authenticated under a key that has left the accepted set (#16857) — when
// this node holds a control-link key (#9717).
//
// It returns nil when the node is unkeyed. An unkeyed cluster authenticates
// nothing by the operator's choice, and listing every connection there would
// read as an alarm about a posture nobody asked for.
//
// Same population and locking as enforceStrictSessionAuth: the connections are
// read under s.mu, and authPSK under s.writeMu, which the upgrade exchange writes
// it under. readKey is not consulted, for the race reason given there.
func (s *SessionSync) UnauthenticatedSessionConns() []string {
	if len(s.authKey()) == 0 {
		return nil
	}
	accepted := s.authAcceptedKeys()
	s.mu.Lock()
	conns := []net.Conn{s.conn0, s.conn1}
	s.mu.Unlock()

	var out []string
	s.writeMu.Lock()
	for _, c := range conns {
		ac, ok := c.(*authConn)
		if !ok || ac == nil {
			continue
		}
		if !connAuthStaleLocked(ac, accepted) {
			continue
		}
		out = append(out, connRemoteAddrString(c))
	}
	s.writeMu.Unlock()
	return out
}

// RetiredKeySessionConns returns the remote address of every installed
// session-sync connection authenticated under a key that has left the
// accepted set (#16857), when this node holds a control-link key. It is the
// retired-key subset of UnauthenticatedSessionConns, split out so the
// operator status can distinguish "never authenticated, frames accepted
// without HMAC" from "authenticated under a retired key, frames still
// verify under retired-key-derived keys".
//
// It returns nil when the node is unkeyed. Same locking as
// UnauthenticatedSessionConns.
func (s *SessionSync) RetiredKeySessionConns() []string {
	if len(s.authKey()) == 0 {
		return nil
	}
	accepted := s.authAcceptedKeys()
	s.mu.Lock()
	conns := []net.Conn{s.conn0, s.conn1}
	s.mu.Unlock()

	var out []string
	s.writeMu.Lock()
	for _, c := range conns {
		ac, ok := c.(*authConn)
		if !ok || ac == nil || len(ac.authPSK) == 0 {
			continue
		}
		if authPSKAccepted(ac.authPSK, accepted) {
			continue
		}
		out = append(out, connRemoteAddrString(c))
	}
	s.writeMu.Unlock()
	return out
}

// strictSessionAuthLoop periodically re-evaluates established connections.
//
// The grace elapses strictly AFTER the commit that armed it, so a commit-time
// evaluation alone cannot enforce it. ReconcileConnectionAuth also enforces
// directly when a commit arrives after the grace has already elapsed.
func (s *SessionSync) strictSessionAuthLoop(ctx context.Context) {
	ticker := time.NewTicker(strictSessionAuthTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.enforceStrictSessionAuth()
		}
	}
}

// strictSessionAuthState records the legacy configured posture, retained for
// compatibility. Zero value false no longer disables keyed-node eviction.
type strictSessionAuthState = atomic.Bool
