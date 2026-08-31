package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

func shouldInitiateFabricDial(localAddr, peerAddr string) bool {
	local, err := netip.ParseAddrPort(localAddr)
	if err != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(peerAddr)
	if err != nil {
		return true
	}
	if cmp := local.Addr().Compare(peer.Addr()); cmp != 0 {
		return cmp < 0
	}
	return local.Port() < peer.Port()
}

// preferredFabricLocked returns the fabric index whose connection should carry
// outbound sync traffic, or -1 when nothing is installed. The caller must hold
// s.mu.
//
// #5718 fold r4 BLOCKER 1: a CURRENT-incarnation connection wins over a stale
// one, and only then does the historical fab0-before-fab1 preference apply.
// Slot preference alone is wrong once a slot can hold a connection to a peer
// process that no longer exists: when the peer reboots and its replacement
// dials FABRIC 1, conn0 still holds the dead incarnation's socket (no FIN/RST
// on a hard reboot) while conn1 holds the live one. Picking conn0 because it
// is non-nil hands every sender — bulk sync, config sync, failover requests and
// acks, session writes; 18 call sites through getActiveConn — a socket
// connected to nothing. doBulkSync pins it once and streams the entire session
// table into it.
//
// The r2 stamp made "installed" and "current" different things for the ack
// path; this is the same distinction on the SEND path, which was left behind.
//
// When no installed connection is current the old slot preference still applies
// rather than returning nil: writing to a stale socket fails and drives
// handleDisconnect, which cleans it up. That is the pre-existing
// self-correcting behaviour, and this change does not alter it.
//
// #5718 fold r4b: since installConn now EVICTS a retired incarnation's
// connections at the moment the incarnation advances, a slot can no longer hold
// a stale-stamped connection, so the generation test above is a fail-closed
// belt rather than the load-bearing gate — it keeps an install path added later
// that forgets to evict from silently handing the senders a dead socket. The
// belt is deliberately not sufficient on its own: it governs SELECTION only,
// and the readers that made eviction necessary (handleDisconnect's connectivity
// test, fabricConnectLoop's redial gate, d.wasDisconnected) all read raw slot
// occupancy and never come through here.
func (s *SessionSync) preferredFabricLocked() int {
	if s.conn0 != nil && s.conn0Gen == s.peerIncarnation {
		return 0
	}
	if s.conn1 != nil && s.conn1Gen == s.peerIncarnation {
		return 1
	}
	if s.conn0 != nil {
		return 0
	}
	if s.conn1 != nil {
		return 1
	}
	return -1
}

// activeConnLocked returns the preferred active connection: a
// current-incarnation connection first, fab0 before fab1. The caller must hold
// s.mu.
func (s *SessionSync) activeConnLocked() net.Conn {
	switch s.preferredFabricLocked() {
	case 0:
		return s.conn0
	case 1:
		return s.conn1
	}
	return nil
}

// getActiveConn returns the active connection while taking s.mu.
func (s *SessionSync) getActiveConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeConnLocked()
}

// noteHeartbeatAck latches the peer heartbeat-ack capability for the CURRENT
// peer incarnation (#5718 C01a fold F1).
//
// The membership test and the store both run under s.mu, so they are atomic
// with installConn's supersession clear and handleDisconnect's full-disconnect
// clear. That ordering is the point: an ack frame already read off a
// connection that is being superseded would otherwise re-arm the latch for the
// incoming incarnation between the clear and the store, re-creating the stale
// capability the clear just removed.
//
// A conn that is not (or is no longer) installed in a fabric slot cannot speak
// for the current incarnation, so its ack is ignored. That also covers the
// pre-install handshake-pending frame in handleNewConnection: an ack can never
// legitimately be a peer's FIRST frame (we only send syncMsgHeartbeat after a
// read deadline elapses on an established connection), so an unsolicited ack
// arriving before the connection is wired in must not arm an enforcement path.
//
// #5718 fold F1b: being installed is NOT sufficient — the slot's incarnation
// stamp must also be current. `s.conn0 == conn || s.conn1 == conn` asks only
// whether the connection sits in EITHER slot, and with two fabric links the
// rebooted peer's other connection is still sitting in the other one: a hard
// reboot sends no FIN/RST, so both of its sockets stay ESTABLISHED while its
// new process supersedes just the slot it dialled. A membership-only test
// accepts an in-flight ack off that survivor and re-arms the capability the
// supersession cleared — the previous incarnation enforced against the current
// one, the exact defect C01a exists to prevent, one level up. Comparing the
// slot's stamp to peerIncarnation binds the ack to the incarnation that owns
// the connection rather than to slot membership.
func (s *SessionSync) noteHeartbeatAck(conn net.Conn) {
	if conn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connIsCurrentIncarnationLocked(conn) {
		return
	}
	if hook := noteHeartbeatAckMidpointHook.Load(); hook != nil {
		(*hook)()
	}
	s.peerHeartbeatAckEver.Store(true)
}

// noteHeartbeatAckMidpointHook is a test seam invoked between the incarnation
// check and the capability store in noteHeartbeatAck, WHILE s.mu is held. It is
// nil in production.
//
// It exists because the atomicity above is otherwise only a claim: a test that
// calls installConn and handleMessage in sequence never opens the window the
// lock is there to close, so "check and store are atomic" would hold no matter
// how the function was written. Widening the observation point is the only way
// to distinguish this implementation from one that checks under the lock,
// releases it, and then stores — which lets a supersession land in between and
// resurrect a capability that was just cleared.
//
// A test installs a hook that starts a competing installConn and waits for it:
// under this implementation the competitor BLOCKS on s.mu until noteHeartbeatAck
// returns, so it can never interleave; under the released-early shape it
// completes inside the window and the stale ack overwrites its clear.
var noteHeartbeatAckMidpointHook atomic.Pointer[func()]

// connIsCurrentIncarnationLocked reports whether conn is installed in a fabric
// slot AND that slot was stamped by the incarnation currently in force. The
// caller must hold s.mu.
//
// #5718 fold r4b: with installConn evicting stale-stamped slots, membership now
// IMPLIES a current stamp, so the comparison below is a fail-closed belt rather
// than the sole gate. It is kept deliberately — an install path added later
// that forgets to evict would otherwise silently re-admit a retired
// incarnation's acks — and pinned directly by
// TestConnIsCurrentIncarnationRejectsAStaleStamp_5718, which builds that state
// by hand because the production path can no longer reach it.
func (s *SessionSync) connIsCurrentIncarnationLocked(conn net.Conn) bool {
	switch {
	case conn == nil:
		return false
	case s.conn0 == conn:
		return s.conn0Gen == s.peerIncarnation
	case s.conn1 == conn:
		return s.conn1Gen == s.peerIncarnation
	default:
		return false
	}
}

// evictStaleIncarnationConnsLocked closes and clears every fabric slot other
// than keepIdx whose incarnation stamp is no longer current, and reports whether
// it evicted anything. The caller must hold s.mu and must have already advanced
// peerIncarnation; keepIdx is the slot holding the connection that caused the
// advance, which has not been stamped yet.
//
// #5718 fold r4b. preferredFabricLocked fixed which connection outbound traffic
// SELECTS. It did not change what is installed, and three other paths read raw
// slot occupancy — so the retired incarnation's socket, ESTABLISHED forever
// because a hard reboot sends no FIN/RST, keeps speaking for a dead process:
//
//   - handleDisconnect computes `connected := s.conn0 != nil || s.conn1 != nil`.
//     When the one LIVE connection later drops it therefore takes the "still
//     connected" branch: stats.Connected stays true (so PeerHealthy reports a
//     healthy peer with zero live connections, since the incarnation advance
//     already cleared the capability latch that gates its silence check),
//     barrier and failover waiters are never released with
//     failoverAckDisconnected and block until their own timeouts,
//     OnPeerDisconnected never fires, and the in-progress bulk receive is never
//     reset.
//   - fabricConnectLoop skips a fabric whose slot is non-nil, so the link to
//     the new peer process is never redialled there and the cluster silently
//     runs on one fabric.
//   - installConn's d.wasDisconnected needs BOTH slots nil, so the
//     full-disconnect cold-prime edge cannot be reached while the corpse sits
//     in a slot.
//
// Nothing else removes it either: receiveLoop's missed-heartbeat teardown is
// gated on peerHeartbeatAckEver, which the incarnation advance just cleared, so
// identifying the connection as retired is precisely what disarmed its only
// eviction path. Evicting here restores the invariant all three readers already
// assume — installed means "belongs to the peer incarnation in force" — in one
// place, instead of teaching each reader separately to consult a generation.
//
// The evicted connection's receiveLoop wakes on the closed socket and calls
// handleDisconnect, which finds the slot already cleared and returns down its
// stale-disconnect branch, so the eviction is not double-counted.
//
// Cost of a false positive: a supersession that is really the same peer process
// re-dialling a half-open socket also drops the other fabric, which
// fabricConnectLoop redials within a second, plus one redundant authoritative
// bulk. That is the same "correctness over the optimization" trade #5480 already
// took, and it CONVERGES — the pre-eviction shape did not, because the retired
// socket stayed installed and un-evictable until TCP finally gave up
// retransmitting, which is minutes.
//
// KNOWN-INCOMPLETE (#6910, blocked on #6669): this only fires when installConn
// classifies a SUPERSESSION, and occupancy-based classification cannot see a
// reboot whose replacement enters through an EMPTY alternate slot — the target
// slot is empty, so supersededCurrent is false, nothing is evicted and no
// cold-prime is armed. That shape is observationally identical to the routine
// case (the same process bringing up its second fabric), so it is not fixable
// here: it needs the peer-supplied boot epoch #6669 signs into the heartbeat.
// See pkg/cluster/README.md for the full sequence and which half self-heals.
// applyPeerIncarnationSwitchLocked retires the previous peer incarnation when
// the peer's own BOOT ID proves it rebooted (#6910, on #5084's signal).
//
// WHY THIS EXISTS SEPARATELY FROM installConn's supersededCurrent. That
// classification is LOCAL: it infers a reboot from slot occupancy, and it is
// blind whenever the replacement lands in the empty alternate slot beside a
// corpse. This one is not an inference — `notePeerBootIncarnation` reports that
// the boot id on the wire CHANGED, which only a genuinely new peer boot can
// produce. So where the local classification must not guess, this may act.
//
// WHAT IT DOES NOT CLOSE, stated so the two are not confused: a replacement
// connection that never PRIMES carries no boot id at all (connBootIncarnation
// returns zero for it, deliberately fail-open), so this path never runs for it.
// The empty-slot case in installConn's LIMIT comment is therefore still open and
// still needs the heartbeat epoch — see #7762. This closes the reboot-that-primes
// half only.
//
// The remedy mirrors the supersession path exactly rather than inventing one:
// advance the incarnation, drop the previous incarnation's ack capability, evict
// the connections still stamped with it, then re-stamp the priming connection so
// it belongs to the incarnation it actually established. Keeping the two paths
// identical is deliberate — a second, subtly different notion of "retire the old
// peer" is how the readers listed on evictStaleIncarnationConnsLocked come to
// disagree about which process is live.
//
// keepIdx names the priming connection's slot; it is re-stamped and never
// evicted. Returns whether anything was evicted, for the caller's log.
func (s *SessionSync) applyPeerIncarnationSwitchLocked(keepIdx int) bool {
	s.peerIncarnation++
	s.peerHeartbeatAckEver.Store(false)
	evicted := s.evictStaleIncarnationConnsLocked(keepIdx)
	// Stamp AFTER the advance, exactly as installConn does, so the priming
	// connection belongs to the incarnation it established rather than to the
	// one just retired.
	switch keepIdx {
	case 0:
		s.conn0Gen = s.peerIncarnation
	case 1:
		s.conn1Gen = s.peerIncarnation
	}
	return evicted
}

// fabricIdxForConnLocked reports which slot holds conn, or -1.
func (s *SessionSync) fabricIdxForConnLocked(conn net.Conn) int {
	switch {
	case conn != nil && s.conn0 == conn:
		return 0
	case conn != nil && s.conn1 == conn:
		return 1
	default:
		return -1
	}
}

func (s *SessionSync) evictStaleIncarnationConnsLocked(keepIdx int) bool {
	// #5718 fold r6: "this can never empty the registry" is the ENTIRE
	// justification for exempting this function from
	// TestOnlyHandleDisconnectEmptiesTheRegistry_5718, so it has to be a
	// property of this function and not of the one caller that happens to
	// satisfy it today. installConn installs before it evicts, so keepIdx
	// currently always names an occupied slot — but that is a call-site
	// accident. A future caller passing an out-of-range keepIdx, or naming a
	// slot it has not filled yet, could evict every OTHER slot and leave the
	// registry empty. Neither guard would fire: the AST guard allowlists this
	// function by NAME, and TestInstallConnNeverLeavesTheRegistryEmpty_5718
	// drives the existing call site, so a new one is invisible to both.
	//
	// Make the precondition intrinsic instead. Refuse to evict unless the keep
	// slot actually holds a connection; then whatever else is evicted, that
	// connection is still installed on return, and the registry is non-empty by
	// construction for EVERY caller.
	//
	// The exact property is "cannot cause the nonempty-to-empty TRANSITION",
	// not "always returns a nonempty registry": an already-empty registry stays
	// empty, which is fine, because installConn's proof only reads the
	// transition. And an empty keep slot does not by itself mean eviction WOULD
	// empty the registry — with an empty conn0 and a CURRENT conn1 nothing is
	// stale, so nothing would be evicted anyway. The refusal is not a
	// prediction about this particular call; it is a refusal to proceed when
	// the postcondition cannot be established.
	var keep net.Conn
	switch keepIdx {
	case 0:
		keep = s.conn0
	case 1:
		keep = s.conn1
	}
	if keep == nil {
		slog.Error("cluster sync: refusing to evict retired-incarnation connections — "+
			"the keep slot holds nothing, so this call cannot guarantee it leaves a "+
			"connection installed (this is a caller bug: install before evicting)",
			"keep_idx", keepIdx, "peer_incarnation", s.peerIncarnation)
		return false
	}
	evicted := false
	if keepIdx != 0 && s.conn0 != nil && s.conn0Gen != s.peerIncarnation {
		slog.Warn("cluster sync: evicting fabric 0 connection from a retired peer incarnation",
			"remote", connRemoteAddrString(s.conn0), "conn_incarnation", s.conn0Gen, "peer_incarnation", s.peerIncarnation)
		s.conn0.Close()
		s.conn0 = nil
		s.conn0Gen = 0
		evicted = true
	}
	if keepIdx != 1 && s.conn1 != nil && s.conn1Gen != s.peerIncarnation {
		slog.Warn("cluster sync: evicting fabric 1 connection from a retired peer incarnation",
			"remote", connRemoteAddrString(s.conn1), "conn_incarnation", s.conn1Gen, "peer_incarnation", s.peerIncarnation)
		s.conn1.Close()
		s.conn1 = nil
		s.conn1Gen = 0
		evicted = true
	}
	return evicted
}

func connRemoteAddrString(conn net.Conn) (remote string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			remote = "<unavailable>"
		}
	}()
	addr := conn.RemoteAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
func connLocalAddrString(conn net.Conn) (local string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			local = "<unavailable>"
		}
	}()
	addr := conn.LocalAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
func configureSessionSyncConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		slog.Warn("cluster sync: failed to enable TCP_NODELAY", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
	}
	if err := tcpConn.SetWriteBuffer(256 * 1024); err != nil {
		slog.Warn("cluster sync: failed to set write buffer", "local", connLocalAddrString(conn), "err", err)
	}
	if err := tcpConn.SetReadBuffer(256 * 1024); err != nil {
		slog.Warn("cluster sync: failed to set read buffer", "local", connLocalAddrString(conn), "err", err)
	}
}

// initiator is the #7163 role input, and it comes from the TRANSPORT: the side
// that dialed is the Noise initiator, the side that accepted is the responder.
// That is the only role source the peer cannot assert — a role carried on the
// wire would be an attacker-chosen input to our own key derivation, which is
// the mistake the pre-#7163 proof made with its nonce.
func (s *SessionSync) handleNewConnection(ctx context.Context, fabricIdx int, conn net.Conn, initiator bool) {
	// #5303: the caller (acceptLoop / fabricConnectLoop) already admitted this
	// connection into its pre-auth setup window via beginSetup. NOTE: the large
	// 256 KiB socket buffers are NOT sized here — configureConnFn is deferred
	// until AFTER the handshake succeeds so a connection flood cannot pin socket
	// memory before proving possession of the PSK.

	// #4107 F23: authenticate the stream at connection setup before any session
	// frame flows. A dropped handshake (bad PSK proof / downgrade attempt / I/O)
	// closes the connection; the accept/connect loops retry, so this never
	// bricks a keyed↔keyed reconnect during failover (both nodes are up and
	// keyed → the handshake completes in milliseconds).
	mode, keys, err := s.performSyncHandshake(conn, initiator, fabricIdx)
	// #5303: release the pre-auth admission slot (and the setup-tracking entry)
	// the moment the handshake resolves — an admitted slot must cover only the
	// brief pre-auth window, never the subsequent bulk sync. Post-auth the
	// connection is tracked for shutdown by conn0/conn1 instead.
	s.finishSetup(conn)
	if err != nil {
		slog.Warn("cluster sync: auth handshake failed, dropping connection",
			"fabric", fabricIdx, "remote", connRemoteAddrString(conn), "err", err)
		conn.Close()
		return
	}
	// #5303: only NOW, after auth succeeds, size the large (256 KiB) socket
	// buffers on the raw TCP connection (before it is wrapped in *authConn, which
	// would defeat the *net.TCPConn type assertion inside configureConnFn).
	configureConnFn(conn)
	// Wrap so writeFull seals and receiveLoop verifies per-frame auth when the
	// connection authenticated; an unauthenticated wrapper is a pass-through.
	conn = s.wrapSyncConn(fabricIdx, conn, mode, keys)
	// #4962: install the connection and DECIDE cold-prime atomically under
	// s.mu. Computing the decision after unlock (the pre-#4962 shape) let a
	// racing same-fabric accept supersede this connection between the unlock and
	// the decision's use, so the surviving connection could DROP cold-prime (see
	// installConn / the needColdPrime doc in sync.go).
	d := s.installConn(fabricIdx, conn)
	slog.Info("cluster sync: handling new connection", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "was_disconnected", d.wasDisconnected, "active_before", d.activeBefore, "active_after", d.activeAfter, "became_active", d.becameActive, "should_cold_prime", d.shouldColdPrime, "had_conn0", d.hadConn0, "had_conn1", d.hadConn1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.receiveLoop(ctx, conn)
	}()
	s.sendClockSync(conn)
	// #6650: advertise our config-snapshot protocol version on every installed
	// connection, so the peer's commit path can refuse to push a config this
	// node cannot represent. Beside the clock sync because it has the same
	// lifetime: per-incarnation, cleared on full disconnect.
	s.sendCapabilities(conn)
	// #6629: advertise this connection's ephemeral public key so the peer can
	// encrypt the config payload to us. Beside sendCapabilities because it has
	// the same lifetime (per installed connection) and the same failure
	// posture: advisory, never escalated to a disconnect. Sent BEFORE the
	// OnPeerConnected dispatch below, which is what drives the first config
	// push, so the common case never reaches awaitConfigKey's timeout.
	s.sendConfigKeyExchange(conn)
	coldStart := !s.bulkEverCompleted.Load()
	if d.shouldColdPrime {
		slog.Info("cluster sync: driving authoritative cold-prime bulk on active connection", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "cold_start", coldStart, "was_disconnected", d.wasDisconnected)
		s.flushDeleteJournal()
		if s.OnPeerConnected != nil {
			slog.Info("cluster sync: scheduling OnPeerConnected callback", "fabric", fabricIdx)
			go s.OnPeerConnected()
		}
		// Re-read the resync arm AFTER flushDeleteJournal: a rejournalTail
		// eviction during that flush (or a journalDelete drop while we were
		// disconnected) arms forceResync, and dropped deletes are only
		// recoverable via a full authoritative bulk snapshot (#5450).
		// Consume the resync arm with CAS (symmetric with syncSweep) BEFORE the
		// bulk, so a NEW overflow that arms forceResync DURING this bulk survives
		// to trigger the next resync instead of being cleared by an unconditional
		// Store(false) (#5450 MINOR 1); a consumed arm is re-armed on bulk
		// failure so a later sweep/reconnect retries.
		forcedConsumed := s.forceResync.CompareAndSwap(true, false)
		// #5480: ALWAYS re-push our authoritative session table on a fresh
		// connection after a full (both-fabric) disconnect — not only on a
		// first-ever cold start (bulkEverCompleted false) or a #5450
		// delete-journal-overflow forced resync. bulkEverCompleted is a sticky,
		// process-local flag: once the survivor completes one bulk it stays true
		// forever, so the old `coldStart || forcedConsumed` reconnect gate wrongly
		// SKIPPED the re-push when the PEER rebooted and lost its session table
		// (the peer's own flag reset to false, but ours stayed true). The rebooted
		// peer then sends only its own empty bulk and OnPeerConnected re-pushes
		// non-session state, so the standby ends up with NO synced sessions — and
		// blackholes every established flow on the next failover to it.
		//
		// The survivor cannot locally tell a rebooted peer (empty table, needs
		// priming) from a pure fabric flap (peer kept its table): the sync
		// handshake carries no peer-cold / boot-incarnation / table-count signal,
		// and an unkeyed dual-accept peer sends no HELLO at all. So it re-primes
		// unconditionally. Re-priming is safe and idempotent — the receiver
		// upserts every session and reconcileStaleSessions on the peer prunes what
		// we no longer own — and a both-fabric disconnect means incremental deltas
		// may have been missed during the outage, so the "already primed"
		// assumption no longer holds even for a peer that never rebooted.
		//
		// Cost: one redundant full bulk on a genuine both-fabric flap. It is
		// bounded — this arm fires ONLY on a both-fabric down->up transition, never
		// on a routine single-fabric flip (those hit the becameActive/else branches
		// below and still do NOT re-bulk). The blackhole it prevents is far worse
		// than the redundant transfer (correctness over the optimization). A more
		// surgical fix that keeps the #466 flap-suppression optimization needs a
		// peer boot-incarnation field in the sync handshake — a wire change tracked
		// on #5480 and deferred here.
		switch {
		case forcedConsumed && !coldStart:
			slog.Warn("cluster sync: forcing full bulk resync on reconnect after delete-journal overflow (standby may retain stale sessions)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		case coldStart:
			slog.Info("cluster sync: starting bulk sync on cold start", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		default:
			slog.Info("cluster sync: re-priming bulk sync on reconnect (peer may have rebooted and lost its session table, #5480)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		}
		if err := s.doBulkSync(); err != nil {
			slog.Warn("cluster sync: bulk sync failed", "err", err, "fabric", fabricIdx)
			if forcedConsumed {
				s.forceResync.Store(true)
			}
		} else {
			// #4962: the authoritative cold-prime landed on the (surviving)
			// active connection, discharging the outstanding obligation. Consume
			// the needColdPrime latch so routine single-fabric flips do NOT
			// re-bulk; a later full-disconnect epoch re-arms it via installConn.
			// On FAILURE the latch stays armed, so the next accept that becomes
			// active re-drives the bulk instead of dropping it.
			s.needColdPrime.Store(false)
		}
	} else if d.becameActive {
		slog.Info("cluster sync: active fabric changed, resuming incremental sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "active_before", d.activeBefore, "active_after", d.activeAfter)
	} else {
		slog.Info("cluster sync: connection added without bulk sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
	}
}

// connColdPrimeDecision is the atomically-computed outcome of installing a sync
// connection into a fabric slot (#4962): which fabric was active before/after,
// whether this connection became the active fabric, and whether it must drive
// the authoritative cold-prime bulk. All fields are derived under s.mu together
// with the conn0/conn1 install so the decision is consistent with the registry
// state it was computed from — a racing supersession cannot invalidate it.
type connColdPrimeDecision struct {
	wasDisconnected bool
	becameActive    bool
	shouldColdPrime bool
	activeBefore    int
	activeAfter     int
	hadConn0        bool
	hadConn1        bool
}

// installConn wires conn into the fabric slot (superseding and closing any
// existing same-fabric connection) and returns the cold-prime decision computed
// ATOMICALLY with that install under s.mu (#4962).
//
// The needColdPrime latch is armed here on a full disconnect -> connect edge
// (both slots were empty) and consumed by handleNewConnection only when a
// cold-prime bulk SUCCEEDS. shouldColdPrime is therefore true whenever THIS
// connection is the active fabric AND a cold-prime is still owed for the current
// connected epoch — so a second same-fabric accept that supersedes an in-flight
// cold-prime INHERITS the obligation rather than dropping it. Computing the
// decision under the same lock that installs the connection is the fix's core:
// the pre-#4962 code read wasDisconnected under the lock but USED it after
// unlock, where a concurrent accept could already have changed the registry.
func (s *SessionSync) installConn(fabricIdx int, conn net.Conn) connColdPrimeDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := connColdPrimeDecision{activeBefore: -1, activeAfter: -1}
	d.wasDisconnected = s.conn0 == nil && s.conn1 == nil
	d.activeBefore = s.preferredFabricLocked()
	d.hadConn0 = s.conn0 != nil
	d.hadConn1 = s.conn1 != nil
	// #5718 C01a (fold F1): a SUPERSESSION is the incarnation edge
	// handleDisconnect structurally cannot see. Classify it here, where the
	// slot still holds the outgoing connection AND its incarnation stamp.
	//
	// supersededCurrent means the replaced connection belonged to the CURRENT
	// incarnation — evidence that a new peer process took over. Replacing an
	// ALREADY-STALE connection is the new incarnation reclaiming its second
	// slot, not a further incarnation change (fold F1b): treating it as one
	// would strand the connection that legitimately proved the capability at a
	// stale stamp, so it could never re-arm.
	//
	// LIMIT OF THIS CLASSIFICATION (#6910). wasDisconnected and
	// supersededCurrent between them detect a reboot only when it lands on an
	// OCCUPIED slot or an empty registry. A reboot whose replacement dials the
	// EMPTY alternate slot, while the dead process's socket sits ESTABLISHED in
	// the other one, satisfies NEITHER — so it advances no incarnation, evicts
	// nothing, clears no capability and arms no cold prime, and the replacement
	// is stamped current alongside the corpse (which then wins fab0 preference
	// if it holds slot 0). Nothing observable LOCALLY separates that from the
	// same peer bringing up its second fabric after a link flap, so do NOT add
	// a heuristic here. Full sequence in pkg/cluster/README.md under
	// "ACCEPTED RESIDUAL".
	//
	// THIS COMMENT USED TO SAY "blocked on #6669". THAT WAS WRONG IN A WAY THAT
	// SENDS THE NEXT READER AT THE WRONG SIGNAL, so it is corrected here rather
	// than deleted. #6669 MERGED (2026-08-12). Two distinct peer-boot signals
	// now exist and they are NOT interchangeable:
	//
	//   - bootIncarnation (#5084) — an opaque /proc boot_id compared for
	//     EQUALITY ONLY ("Never order two boot ids", sync_boot_incarnation.go),
	//     carried in the syncMsgBulkStart PAYLOAD;
	//   - the heartbeat boot epoch (#6669) — an ORDERED uint64 floor, latched
	//     on Manager.hbAuth from the independent UDP heartbeat.
	//
	// NEITHER is reachable here, and the root fact is one line: SessionSync's
	// whole view of the outside world is `clusterRuntime`, which exposes
	// Sessions() and Telemetry() and nothing else — there is no Manager handle,
	// so the heartbeat epoch cannot be consulted at all. And the config-sync
	// incarnation arrives only on BulkStart, i.e. strictly AFTER this install.
	//
	// Nor can it simply be applied later for THIS case: connBootIncarnation
	// documents that a connection which never received an incarnated prime —
	// "including the second fabric, which may carry config without having
	// primed" — keeps the ZERO value, and zero is deliberately the never-dropped
	// fail-open class. The empty-slot connection this limit is about is exactly
	// such a connection, so #5084's incarnation is structurally unable to
	// classify it. Closing this needs the heartbeat epoch plumbed through
	// clusterRuntime, which is a contract change plus a latch race (see #7762).
	//
	// What IS now actionable is the case where the replacement DOES prime:
	// notePeerBootIncarnation's `switched` return is positive peer-supplied
	// evidence of a reboot, and applyPeerIncarnationSwitchLocked below acts on
	// it.
	supersededCurrent := false
	switch fabricIdx {
	case 0:
		if s.conn0 != nil {
			supersededCurrent = s.conn0Gen == s.peerIncarnation
			s.conn0.Close()
		}
		s.conn0 = conn
		// #6629: a FRESH ephemeral keypair per install. Replacing (never
		// reusing) the slot's state is what gives the config payload forward
		// secrecy across reconnects — the superseded connection's key is
		// dropped here with its connection.
		s.configCrypto0 = newConfigCryptoState()
	case 1:
		if s.conn1 != nil {
			supersededCurrent = s.conn1Gen == s.peerIncarnation
			s.conn1.Close()
		}
		s.conn1 = conn
		s.configCrypto1 = newConfigCryptoState()
	}
	s.stats.Connected.Store(true)
	s.lastPeerRxMono.Store(MonotonicNanos())
	// #5718 C01a (fold F1): end the previous peer INCARNATION's heartbeat-ack
	// capability at the one edge handleDisconnect structurally cannot see.
	// When a peer reboots hard its TCP connection stays ESTABLISHED on our side
	// (no FIN/RST), our fabricConnectLoop will not redial while it believes the
	// slot is connected, and the peer's NEW process dials in and lands here. We
	// close the old connection above, so its receiveLoop wakes and calls
	// handleDisconnect — which finds the slot already holding the NEW conn and
	// returns down the "ignoring stale disconnect" default branch WITHOUT
	// clearing anything. The latch earned by the previous incarnation would
	// otherwise be enforced against this one, which is exactly the peer
	// DOWNGRADE failure C01a exists to prevent (see handleDisconnect).
	//
	// Scoped to SUPERSESSION only, deliberately:
	//   - a full-disconnect -> connect edge (d.wasDisconnected) needs nothing
	//     here; going to zero connections ran handleDisconnect's clear already,
	//     and re-clearing would discard a capability nothing could have set.
	//     Observing an EMPTY registry proves that clear already ran (or that no
	//     connection ever existed), so the redundancy is structural, not
	//     incidental. Note the proof is NOT "only handleDisconnect nils a slot"
	//     — since fold r4b, evictStaleIncarnationConnsLocked nils slots too.
	//     It is that eviction cannot leave the registry EMPTY: it never touches
	//     the keep slot, and it refuses to run at all unless that slot is
	//     occupied. So an empty registry still implicates handleDisconnect
	//     alone. TestOnlyHandleDisconnectEmptiesTheRegistry_5718 pins that any
	//     THIRD slot-nilling site re-opens this, and the refusal above keeps
	//     the eviction exemption true for callers that do not exist yet.
	//   - a fabric link coming up into an EMPTY slot beside a surviving one is
	//     not a supersession and must NOT clear: same peer process, the mirror
	//     of the partial-disconnect scope control in handleDisconnect.
	// Only a connection REPLACING a live one in its own slot ends an
	// incarnation without a disconnect to observe.
	//
	// #5718 fold F1b: advancing peerIncarnation is what actually retires the
	// old incarnation, because clearing the flag alone is not enough with TWO
	// fabric slots. The rebooted peer's OTHER connection is still installed and
	// still ESTABLISHED; an in-flight ack off it would re-arm the capability
	// microseconds after this clear if acceptance were decided by slot
	// membership. Stamping the incoming connection with the NEW incarnation
	// leaves the survivor at the OLD one, so noteHeartbeatAck rejects it.
	//
	// #5718 fold r4b: refusing its acks and out-ranking it in
	// preferredFabricLocked still leaves it INSTALLED, and slot occupancy is
	// what several other paths read. Evict it — see
	// evictStaleIncarnationConnsLocked for the three readers that otherwise
	// keep believing in a process that no longer exists.
	if supersededCurrent {
		s.peerIncarnation++
		s.peerHeartbeatAckEver.Store(false)
		s.evictStaleIncarnationConnsLocked(fabricIdx)
	}
	// Stamp the slot AFTER any advance, so this connection belongs to the
	// incarnation it actually established.
	switch fabricIdx {
	case 0:
		s.conn0Gen = s.peerIncarnation
	case 1:
		s.conn1Gen = s.peerIncarnation
	}
	// #5718 fold r4 BLOCKER 1: compute the post-install preference AFTER the
	// advance and the stamp, so it agrees with what getActiveConn will hand the
	// senders. Computing it from raw slot occupancy made the cold-prime
	// decision disagree with where the data would actually go: on a fabric-1
	// supersession the stale conn0 kept activeAfter at 0, becameActive went
	// false, and the bulk was skipped for a peer that had just replaced itself.
	d.activeAfter = s.preferredFabricLocked()
	// #4962: arm the cold-prime obligation on a full-disconnect -> connect edge.
	// The latch outlives this goroutine so a superseding same-fabric accept
	// still sees the obligation even though it observes a non-empty registry.
	//
	// #5718 fold r4 BLOCKER 1: a supersession of a CURRENT connection arms it
	// too. That edge is positive evidence of a new peer process — the thing
	// #5480 says the survivor cannot otherwise detect ("the sync handshake
	// carries no peer-cold / boot-incarnation / table-count signal"), which is
	// why it re-primes unconditionally on the full-disconnect edge. A rebooted
	// peer has an EMPTY session table, so without re-arming here the standby
	// ends up with no synced sessions and blackholes every established flow on
	// the next failover to it — the #5480 blackhole, reached through the
	// supersession edge instead of the disconnect edge. Re-priming is
	// idempotent (the receiver upserts and prunes), so the cost of being wrong
	// is one redundant bulk.
	if d.wasDisconnected || supersededCurrent {
		s.needColdPrime.Store(true)
	}
	d.becameActive = d.activeAfter == fabricIdx
	// #4962: commit the decision under the lock. becameActive means this
	// connection is now the active fabric; needColdPrime means the cold-prime
	// for this connected epoch has not yet succeeded. Both are read here, atomic
	// with the install above.
	d.shouldColdPrime = d.becameActive && s.needColdPrime.Load()
	return d
}

func (s *SessionSync) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)
	lc := vrfListenConfig(s.vrfDevice)
	ln, err := lc.Listen(ctx, "tcp", s.localAddr)
	if err != nil {
		return fmt.Errorf("sync listen: %w", err)
	}
	s.listener = ln
	slog.Info("cluster sync: listening", "addr", s.localAddr)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln, 0)
	}()
	if s.localAddr1 != "" {
		lc1 := vrfListenConfig(s.vrfDevice)
		ln1, err := lc1.Listen(ctx, "tcp", s.localAddr1)
		if err != nil {
			slog.Warn("cluster sync: secondary fabric listen failed, using primary only", "addr", s.localAddr1, "err", err)
		} else {
			s.listener1 = ln1
			slog.Info("cluster sync: listening on secondary fabric", "addr", s.localAddr1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(ctx, ln1, 1)
			}()
		}
	}
	if shouldInitiateFabricDial(s.localAddr, s.peerAddr) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 0, s.peerAddr)
		}()
	}
	if s.peerAddr1 != "" && shouldInitiateFabricDial(s.localAddr1, s.peerAddr1) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 1, s.peerAddr1)
		}()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sendLoop(ctx)
	}()
	// #3931: single ordered consumer for config-sync apply. Started once here
	// so it lives for the whole sync lifetime; it drains configApplyCh in
	// receive order and enforces the monotonic config-generation guard.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.configApplyLoop(ctx)
	}()
	// #7441: re-evaluate the strict session-auth posture on established
	// connections. A tick is required rather than convenient — the eviction
	// grace elapses strictly AFTER the commit that armed the posture, so a
	// commit-time evaluation alone could never fire.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.strictSessionAuthLoop(ctx)
	}()
	return nil
}

func (s *SessionSync) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	// #6387: stop the config-apply grace-expiry timer and invalidate any
	// in-flight callback so no timer survives this SessionSync's teardown (a
	// comms transport change tears down this instance and creates a fresh one).
	s.stopConfigApplyGraceTimer()
	if s.listener != nil {
		s.listener.Close()
	}
	if s.listener1 != nil {
		s.listener1.Close()
	}
	s.mu.Lock()
	if s.conn0 != nil {
		s.conn0.Close()
	}
	if s.conn1 != nil {
		s.conn1.Close()
	}
	s.mu.Unlock()
	// #5303: close every connection still in its pre-auth setup window so a
	// stalled handshake read unblocks and its setup goroutine exits — otherwise a
	// flooder's abandoned pre-auth connections would hold setup goroutines until
	// their handshake deadlines and make Stop wait out the full 5s budget.
	s.closeSetupConns()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("cluster sync: Stop timed out waiting for goroutines, proceeding with shutdown")
	}
}

func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener, fabricIdx int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("cluster sync: accept error", "err", err)
				time.Sleep(time.Second)
				continue
			}
		}
		slog.Info("cluster sync: peer connected", "remote", conn.RemoteAddr(), "fabric", fabricIdx)
		// #5303: admit the connection into the bounded pre-auth setup pool BEFORE
		// spawning a setup goroutine, so a connection flood that stalls before
		// authentication cannot exhaust FDs/goroutines/socket-memory. Excess
		// connections (pool saturated) are closed immediately without allocating
		// the large socket buffers; a reserved tail keeps the legitimate peer
		// able to reconnect (see beginSetup). This does NOT revert #4370 — an
		// admitted connection still runs its handshake in its own goroutine.
		if !s.beginSetup(conn, true) {
			s.notePreAuthRejected(conn)
			conn.Close()
			continue
		}
		// #4370: run connection setup (the auth handshake + wire-up + cold-start
		// bulk sync inside handleNewConnection) in a per-connection goroutine so
		// a slow or hung handshake on ONE connection cannot stall accepting the
		// NEXT for up to syncHandshakeTimeout. An active control-link attacker
		// could otherwise open connections that each serially block the accept
		// loop for the full handshake bound. The auth gate is preserved because
		// the connection is not wired into conn0/conn1 (and no session frame is
		// read from it) until performSyncHandshake succeeds INSIDE the goroutine;
		// a failed handshake closes the connection and returns. The goroutine is
		// tracked by s.wg (this loop already holds a wg token, so Add is safe)
		// so Stop() waits for in-flight setup. The outbound fabricConnectLoop
		// stays synchronous — it is a dedicated per-fabric dialer that must not
		// redial while a connection is being handled.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			// Accepted: this node is the Noise RESPONDER.
			s.handleNewConnection(ctx, fabricIdx, conn, false)
		}()
	}
}

func (s *SessionSync) fabricConnectLoop(ctx context.Context, fabricIdx int, peerAddr string) {
	for first := true; ; // fabricConnectLoop retries outbound connection on a single fabric link.
	// Each fabric gets its own loop so fab0 reconnects independently of fab1.
	first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
		s.mu.Lock()
		var connected bool
		if fabricIdx == 0 {
			connected = s.conn0 != nil
		} else {
			connected = s.conn1 != nil
		}
		s.mu.Unlock()
		if connected {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}
		dialer := net.Dialer{Timeout: 3 * time.Second}
		if s.vrfDevice != "" {
			dialer.Control = vrfListenConfig(s.vrfDevice).Control
		}
		conn, err := dialer.DialContext(ctx, "tcp", peerAddr)
		if err != nil {
			continue
		}
		slog.Info("cluster sync: connected to peer", "addr", peerAddr, "fabric", fabricIdx)
		// #5303: register our own outbound dial for shutdown cleanup (so Stop()
		// closes it if it stalls in the handshake). Outbound dials are bounded to
		// one per fabric and initiated by us, so they are NOT subject to the
		// inbound admission cap — beginSetup(inbound=false) never rejects and does
		// not consume a counted slot.
		s.beginSetup(conn, false)
		// Dialed: this node is the Noise INITIATOR.
		s.handleNewConnection(ctx, fabricIdx, conn, true)
	}
}
func (s *SessionSync) handleDisconnect(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.conn0 != nil && s.conn0 == conn:
		s.conn0.Close()
		s.conn0 = nil
		// #6629: drop the connection's ephemeral config key with the
		// connection. Nothing may seal or open a payload with a key that
		// outlived the exchange that produced it.
		s.configCrypto0 = nil
		// #5718 fold F1b: retire the slot's incarnation stamp with the
		// connection it described. The nil slot already makes
		// connIsCurrentIncarnationLocked reject, so this is hygiene — it keeps
		// a stale generation from being resurrected by a future edit that
		// reuses the field before re-stamping it.
		s.conn0Gen = 0
		slog.Info("cluster sync: fabric 0 disconnected")
	case s.conn1 != nil && s.conn1 == conn:
		s.conn1.Close()
		s.conn1 = nil
		s.configCrypto1 = nil
		s.conn1Gen = 0
		slog.Info("cluster sync: fabric 1 disconnected")
	default:
		slog.Debug("cluster sync: ignoring stale disconnect", "stale", fmt.Sprintf("%p", conn))
		return
	}
	connected := s.conn0 != nil || s.conn1 != nil
	s.stats.Connected.Store(connected)
	// #7147: release fence-ack waiters on ANY fabric drop, not only a full
	// disconnect. The peer answers a fence on the connection it RECEIVED it
	// on (sendFenceAck is handed the receive loop's conn), so once that
	// connection is gone the ack can never arrive — the surviving fabric will
	// not carry it. Leaving the waiter registered would make the takeover burn
	// the whole FenceConfirmTimeout for an answer that is already impossible.
	// Fail-open is preserved either way; this is what makes it immediate.
	s.abortFenceAckWaiters()
	if !connected {
		pendingBarriers := s.barrierSeq.Load()
		ackedBarriers := s.barrierAckSeq.Load()
		s.barrierWaitMu.Lock()
		clearedWaiters := len(s.barrierWaiters)
		staleWaiters := s.barrierWaiters
		s.barrierWaiters = nil
		s.barrierWaitMu.Unlock()
		for _, ch := range staleWaiters {
			close(ch)
		}
		s.failoverWaitMu.Lock()
		failoverWaiters := s.failoverWaiters
		failoverCommitWaiters := s.failoverCommitWaiters
		failoverBatchWaiters := s.failoverBatchWaiters
		failoverBatchCommitWaiters := s.failoverBatchCommitWaiters
		clearedFailoverWaiters := len(failoverWaiters)
		clearedFailoverCommitWaiters := len(failoverCommitWaiters)
		clearedFailoverBatchWaiters := len(failoverBatchWaiters)
		clearedFailoverBatchCommitWaiters := len(failoverBatchCommitWaiters)
		s.failoverWaiters = make(map[int]failoverWaiter)
		s.failoverCommitWaiters = make(map[int]failoverWaiter)
		s.failoverBatchWaiters = make(map[string]failoverWaiter)
		s.failoverBatchCommitWaiters = make(map[string]failoverWaiter)
		s.failoverWaitMu.Unlock()
		for _, waiter := range failoverWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverCommitWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverBatchWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverBatchCommitWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		s.clockSynced.Store(false)
		// #6650: the peer's snapshot-protocol capability is scoped to the peer
		// INCARNATION that advertised it, exactly like clockSynced. A full
		// disconnect ends that incarnation and the peer that reconnects may be
		// an OLDER process (that is the rolling-upgrade case this gate exists
		// for), so a retained capability would authorise a push the new
		// incarnation cannot represent.
		s.peerSnapshotProtocol.Store(0)
		// #7147: the capability flags are scoped to the same peer incarnation
		// for the same reason, and a retained fence-ack bit is worse than a
		// retained version: it would make every confirmed-fence takeover wait
		// out its full timeout against a downgraded peer that cannot answer.
		s.peerCapabilityFlags.Store(0)
		// #7990: same incarnation scoping. A retained sync-wire version is the
		// worst of the three to keep: it would let the LANE-1 drain gate certify
		// compatibility against a version the reconnected (possibly downgraded)
		// peer no longer speaks.
		s.peerSessionSyncWire.Store(0)
		// #5718 C01a: peerHeartbeatAckEver is a capability probe of the peer
		// PROCESS, not of this node, so it must be scoped to the peer
		// incarnation exactly like clockSynced above. Full disconnect ends
		// that incarnation: the peer that reconnects may be a DIFFERENT
		// build. Leaving the flag latched across a peer downgrade (new peer
		// acks -> latch true -> peer rolls back to a build that never sends
		// syncMsgHeartbeatAck) makes both readers treat a healthy old peer as
		// failing: receiveLoop counts missedHeartbeats and tears the
		// connection down every 2 read deadlines (sync_conn_read.go), and
		// PeerHealthy() demands recent inbound traffic the old peer never
		// sends (sync.go), which blocks manual-failover readiness with
		// "session sync disconnected". Clearing here restores the intended
		// probe-then-enforce order for each new peer: assume healthy until
		// the CURRENT peer proves it acks.
		s.peerHeartbeatAckEver.Store(false)
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.bulkMu.Lock()
		hadBulkInProgress := s.bulkInProgress
		s.bulkInProgress = false
		s.bulkRecvEpoch = 0
		s.bulkRecvV4 = nil
		s.bulkRecvV6 = nil
		s.bulkZoneSnapshot = nil
		s.bulkMu.Unlock()
		if hadBulkInProgress {
			slog.Info("cluster sync: reset in-progress bulk receive on disconnect")
		}
		slog.Info("cluster sync: peer disconnected (all fabrics down)")
		if pendingBarriers != 0 || ackedBarriers != 0 || clearedWaiters != 0 || clearedFailoverWaiters != 0 || clearedFailoverCommitWaiters != 0 || clearedFailoverBatchWaiters != 0 || clearedFailoverBatchCommitWaiters != 0 {
			slog.Info("cluster sync: reset barrier state after disconnect", "pending_seq", pendingBarriers, "acked_seq", ackedBarriers, "cleared_waiters", clearedWaiters, "cleared_failover_waiters", clearedFailoverWaiters, "cleared_failover_commit_waiters", clearedFailoverCommitWaiters, "cleared_failover_batch_waiters", clearedFailoverBatchWaiters, "cleared_failover_batch_commit_waiters", clearedFailoverBatchCommitWaiters)
		}
		if s.OnPeerDisconnected != nil {
			go s.OnPeerDisconnected()
		}
	} else if !s.outboundBulkAcked.Load() || s.needColdPrime.Load() {
		// #4090: a survivor fabric is still up but the cold-start bulk
		// never completed. The bulk streams over a SINGLE connection
		// (BulkSync pins s.getActiveConn once); if that
		// connection dropped mid-stream the bulk is stranded — it is not
		// retried on the survivor and handleNewConnection will not
		// re-trigger it (its wasDisconnected gate needs BOTH fabrics to
		// have dropped). Re-drive doBulkSync over the survivor.
		//
		// #4360: this gates on outboundBulkAcked, NOT bulkEverCompleted.
		// The re-drive's job is to get OUR outbound bulk to the peer; a
		// small INBOUND bulk (peer->us) completing first sets
		// bulkEverCompleted but says nothing about whether the peer
		// received our table, so keying on the shared flag would wrongly
		// suppress the re-drive of a stranded outbound bulk.
		//
		// #5718 fold r7 BLOCKER 2: `|| needColdPrime`, because an obligation
		// whose firing edge is an event that has ALREADY PASSED is not
		// deferred — it is lost. `needColdPrime` had exactly one consumer,
		// `shouldColdPrime` in installConn, so its only edge was a connection
		// INSTALL that becomes active. Reach the state where the obligation is
		// armed and every connection that could fire it is already installed
		// and there is nothing left to trigger it, ever.
		//
		// `outboundBulkAcked` is what removes the edge, because it is sticky
		// for the life of the PROCESS: written true once (sync_conn_read.go)
		// and cleared nowhere — not on a full disconnect, not on a
		// supersession. So an ack earned by a PRIOR peer incarnation suppresses
		// this re-drive for the CURRENT one. Concretely: a new incarnation
		// supersedes fabric 0, which arms needColdPrime and starts a bulk;
		// fabric 1 of the same new peer joins passively while that bulk runs;
		// fabric 0's write then fails and BulkSync disconnects it. The
		// obligation stays armed, the survivor is already installed, the old
		// incarnation's ack suppresses this branch — and the incremental sweep
		// only ships sessions newer than its watermark, so established flows
		// are never repaired. Failover to that peer blackholes them.
		//
		// Keying on the OBLIGATION rather than on the staleness is deliberate.
		// Clearing `outboundBulkAcked` on supersession would also close this
		// path, but only this path: an owed cold-prime armed by the
		// full-disconnect edge and then failed, with a survivor installed, is
		// the same lost-edge shape with no supersession anywhere in it.
		//
		// This MUST be a goroutine, not inline: handleDisconnect holds
		// s.mu, and doBulkSync -> BulkSync -> getActiveConn
		// re-locks s.mu (self-deadlock if run inline). The CAS guard bounds
		// re-drives to one in-flight at a time so a survivor that also flaps
		// (its own write failure re-entering handleDisconnect) cannot spawn a
		// storm; the flag is reset when the re-drive goroutine returns.
		if s.bulkRedriveInFlight.CompareAndSwap(false, true) {
			slog.Info("cluster sync: scheduling cold-start bulk re-drive on survivor fabric",
				"had_conn0", s.conn0 != nil, "had_conn1", s.conn1 != nil)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.bulkRedriveInFlight.Store(false)
				// A concurrent reconnect (both-fabric drop then reconnect)
				// may have already re-primed via handleNewConnection.
				// #4360: re-check the SAME outbound-only flag the gate above
				// used — bulkEverCompleted may be true from an inbound bulk
				// while our outbound bulk is still un-acked, and bailing on
				// it here would make the fix inert.
				// #5718 fold r7 BLOCKER 2: mirror the widened gate. Bailing on
				// outboundBulkAcked alone would make the `|| needColdPrime`
				// above inert for exactly the case it was added for — the
				// prior incarnation's sticky ack is true in both places.
				if s.outboundBulkAcked.Load() && !s.needColdPrime.Load() {
					return
				}
				// Reset the stranded pending-ack epoch so the re-run's fresh
				// epoch supersedes it (a latched phantom pending epoch would
				// block manual failover, #3912).
				s.pendingBulkAckEpoch.Store(0)
				s.pendingBulkAckSince.Store(0)
				if err := s.doBulkSync(); err != nil {
					slog.Warn("cluster sync: cold-start bulk re-drive failed", "err", err)
				} else {
					// #5718 fold r7 BLOCKER 2: DISCHARGE the obligation here
					// too. Without this the latch that now triggers the
					// re-drive would stay armed after the re-drive satisfied
					// it, so every later survivor disconnect would re-bulk a
					// peer that is already primed — trading a lost obligation
					// for one that can never be paid off. Same discharge, same
					// success-only condition, as the installConn path.
					s.needColdPrime.Store(false)
				}
			}()
		}
	}
}
