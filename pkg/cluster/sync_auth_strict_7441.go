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
// Only connections that have NEVER authenticated (len(authPSK) == 0) are
// eligible. A connection authenticated under a retired key during rotation
// has already proved it holds a key and is re-derived in place by the
// reconciler.
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
}

// enforceStrictSessionAuth closes every established session-sync connection
// that must not survive on a keyed node, and returns how many it closed.
//
// #10717 made eviction the DEFAULT when a key is configured: the predicate is
// this node holds a control-link key AND the connection has never authenticated
// AND its grace anchor is set and has elapsed. The #7441 operator posture
// (`chassis cluster strict-session-auth`) is retained for compatibility but no
// longer gates enforcement; a pre-key stream that declines the in-place upgrade
// is evicted whether or not the leaf is set.
//
// authPSK and strictGraceStart are both written under s.writeMu (authPSK by
// the upgrade exchange, the anchor by the reconciler), so they are read here
// under the same lock. readKey is deliberately NOT consulted even though
// authed() would be the more natural-sounding predicate: readKey is owned by
// the per-connection receiveLoop goroutine with no lock, so reading it from
// this loop would be a data race. authPSK carries the same fact — it is set
// only by a completed exchange, which requires the PSK — and is race-safe.
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
	s.writeMu.Lock()
	for _, c := range conns {
		ac, ok := c.(*authConn)
		if !ok || ac == nil {
			continue
		}
		if len(ac.authPSK) > 0 {
			continue // authenticated on this connection; not our population
		}
		if ac.strictGraceStart == 0 {
			continue // no reconcile has attempted an upgrade yet
		}
		if now-ac.strictGraceStart < strictSessionAuthGrace.Nanoseconds() {
			continue // still inside the in-place-upgrade grace
		}
		doomed = append(doomed, c)
	}
	s.writeMu.Unlock()

	for _, c := range doomed {
		slog.Warn("cluster sync: closing a pre-key session-sync connection that never authenticated "+
			"within the upgrade grace (#10717); a keyed peer reconnects and authenticates "+
			"at connection setup",
			"remote", connRemoteAddrString(c), "grace", strictSessionAuthGrace)
		s.stats.PreKeyAuthEvictions.Add(1)
		s.handleDisconnect(c)
	}
	return len(doomed)
}

// UnauthenticatedSessionConns returns the remote address of every installed
// session-sync connection that has never authenticated, when this node holds a
// control-link key (#9717).
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
	s.mu.Lock()
	conns := []net.Conn{s.conn0, s.conn1}
	s.mu.Unlock()

	var out []string
	s.writeMu.Lock()
	for _, c := range conns {
		ac, ok := c.(*authConn)
		if !ok || ac == nil || len(ac.authPSK) > 0 {
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
