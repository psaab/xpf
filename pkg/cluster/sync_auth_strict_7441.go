// Strict session-auth posture: evicting a session-sync connection that was
// admitted before the control-link key was committed and never authenticated
// (#7441, the security residual of #6628).
//
// THE DEFECT. #6628 promotes an established unkeyed connection to
// authenticated in place, without a reconnect. But it only ever PROMOTES a
// connection whose peer ANSWERS, and a hostile peer declines by staying
// silent. So a stream admitted while this node was unkeyed keeps injecting
// frames after the key is committed, and restarting xpfd was the only thing
// that evicted it.
//
// THE PROBLEM IS AN INDISTINGUISHABILITY, NOT A MISSING TIMER. A peer that
// does not answer an AuthUpgradeHello is indistinguishable, on the wire, from
// a legitimate peer that is not keyed yet — which is exactly the rolling
// upgrade this must not break. Three signals look like the discriminator and
// each fails:
//
//   - Manager.HeartbeatPeerAuthSeen() proves the LEGITIMATE peer holds the key
//     on a channel that reads it live. Necessary, but NOT sufficient: a keyed
//     legitimate peer on an OLDER, pre-#6628 build also cannot answer the
//     upgrade, so dropping on this signal alone breaks a rolling upgrade.
//   - The peer's syncMsgPeerCapabilities advertisement (#6650) would say
//     whether the peer is new enough to answer — except a hostile peer simply
//     WITHHOLDS it, and withholding then buys immunity. Using a peer-supplied
//     value as the arming input hands the attacker the switch, which is
//     #5078's "re-arming" constraint wearing a different costume.
//   - Time alone is what #5078 shipped and removed; see below.
//
// What is left is the operator, who knows the one thing neither node can
// observe: whether the cluster is homogeneous. Hence a DECLARED posture
// (`chassis cluster strict-session-auth`) rather than an inference.
//
// WHY THIS IS NOT #5078'S WINDOW COMING BACK. #5078 shipped a bounded
// dual-accept window and removed it for three reasons, and all three bite on a
// TIMER. None bites on a static, operator-declared posture:
//
//  1. "It had to bound a connection's LIFETIME rather than just its
//     admission." Satisfied by construction: the rule below is evaluated on
//     ESTABLISHED connections, on every commit and on a periodic tick, not at
//     admission.
//  2. "It had to stop an admitted peer re-arming it through config-sync."
//     This is the sharp edge and it decides where the posture lives. An
//     unauthenticated stream's frames DO reach handleConfigPayload —
//     readAuthed() (sync_conn_read.go) gates trailer VERIFICATION only, so an
//     unauthenticated connection is a pass-through — and handleConfigSync
//     (pkg/daemon/daemon_ha_sync.go) refuses a push only on the RG0 primary,
//     so a STANDBY accepts. A posture flag in ordinary synced config would
//     therefore be clearable by the connection it exists to evict. It is
//     node-local and pinned across every peer-sync apply by
//     preserveNodeLocalChassis (pkg/daemon), sharing the chassisPreserve hook
//     with #6629's eventual node-local posture.
//  3. "It could not survive a crash loop without persisting its deadline."
//     #5078's window FAILED OPEN on lapse: a lost deadline left the connection
//     admitted, so the deadline had to be durable — a security deadline in the
//     config DB, with its own rollback and clock questions. Inverting the
//     failure direction dissolves the constraint. Nothing here is persisted,
//     because there is no deadline to persist: the decision is recomputed from
//     committed config on every evaluation. A crash loop re-applies the same
//     static rule, and after a restart the hostile peer faces
//     performSyncHandshake, where syncAuthDecision already refuses an unkeyed
//     peer outright.
//
// THE GRACE IS NOT A SECURITY DEADLINE. The in-place upgrade takes a round
// trip, and dropping inside it would kill a connection that was about to
// succeed. Losing the grace costs one avoidable reconnect — never an
// admission — which is the whole difference from #5078. It is anchored in
// MONOTONIC time so a wall-clock step cannot extend it, and it is SET ONCE per
// connection: re-anchoring on each reconcile would let a peer that can induce
// commits keep pushing its own deadline forward, which is constraint (2) again.
//
// SCOPE. Eviction is for a connection that has NEVER authenticated
// (len(authPSK) == 0) — the "admitted while unkeyed" population this issue is
// about. A connection authenticated under a RETIRED key during a #6630
// rotation has proven it holds a key and is deliberately left alone; the
// reconciler re-derives its frame key in place.
package cluster

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// strictSessionAuthGrace is how long an established, keyed-node connection may
// remain unauthenticated before it is closed.
//
// It bounds ONE in-place upgrade round trip on the fabric link, which is a
// directly-attached control segment (sub-millisecond RTT), plus the reconcile
// tick that starts it. 10s is far above any healthy exchange and well below
// the point at which an operator would be waiting on it.
//
// A var, not a const, so tests can shrink it. Lengthening it costs only a
// longer window in which a hostile stream survives AFTER the operator declared
// the posture; shortening it below one round trip costs a reconnect loop
// against a legitimate slow peer.
var strictSessionAuthGrace = 10 * time.Second

// strictSessionAuthTick is how often established connections are re-evaluated.
//
// The check is a couple of atomic loads per connection when the posture is off,
// which it is by default, so this is cheap. It logs nothing per tick — an
// eviction is a rare state transition and warns once, per the project rule
// against Info/Warn inside a periodic loop.
var strictSessionAuthTick = 1 * time.Second

// SetStrictSessionAuth publishes the operator-declared posture (#7441).
//
// Called from the config-apply path with the COMPILED, node-local value. It is
// deliberately a push from the daemon rather than a read of config here: this
// package has no view of the config store, and the value must be the one that
// survived preserveNodeLocalChassis rather than whatever a peer last pushed.
func (s *SessionSync) SetStrictSessionAuth(on bool) {
	prev := s.strictSessionAuth.Swap(on)
	if prev != on {
		slog.Info("cluster sync: strict session-auth posture changed (#7441)",
			"enabled", on)
	}
}

// StrictSessionAuth reports the currently published posture.
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
// that the declared posture says must not survive, and returns how many it
// closed.
//
// The predicate, in full: the posture is declared AND this node holds a
// control-link key AND the connection has never authenticated AND its grace
// anchor is set and has elapsed. Any one of those false leaves the connection
// alone.
//
// authPSK and strictGraceStart are both written under s.writeMu (authPSK by
// the upgrade exchange, the anchor by the reconciler), so they are read here
// under the same lock. readKey is deliberately NOT consulted even though
// authed() would be the more natural-sounding predicate: readKey is owned by
// the per-connection receiveLoop goroutine with no lock, so reading it from
// this loop would be a data race. authPSK carries the same fact — it is set
// only by a completed exchange, which requires the PSK — and is race-safe.
func (s *SessionSync) enforceStrictSessionAuth() int {
	if !s.strictSessionAuth.Load() {
		return 0
	}
	if len(s.authKey()) == 0 {
		// Posture declared but this node is unkeyed: the rule is inert by
		// design, and a strict commit rejects the combination
		// (validateStrictSessionAuthNeedsKeyStrict). Evicting here would drop
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
		slog.Warn("cluster sync: closing a session-sync connection that never authenticated "+
			"while this node is keyed and strict-session-auth is set (#7441) — it was "+
			"admitted before the control-link key was committed and declined the in-place "+
			"upgrade; a legitimate keyed peer reconnects and authenticates immediately",
			"remote", connRemoteAddrString(c), "grace", strictSessionAuthGrace)
		s.stats.StrictAuthEvictions.Add(1)
		s.handleDisconnect(c)
	}
	return len(doomed)
}

// strictSessionAuthLoop re-evaluates the posture on established connections.
//
// A periodic tick is required, not merely convenient: the grace elapses
// strictly AFTER the commit that armed the posture, so a commit-time
// evaluation alone can never fire. ReconcileConnectionAuth also calls the
// enforcement directly so a commit that arrives after the grace has already
// elapsed acts immediately instead of waiting for the next tick.
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

// strictSessionAuthState is the published posture. Zero value (false) is the
// pre-#7441 behaviour exactly: nothing is ever evicted.
type strictSessionAuthState = atomic.Bool
