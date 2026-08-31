package cluster

// In-place authentication upgrade for an established session-sync connection
// (#6628), carried over Noise_NNpsk0 since #7163.
//
// THE DEFECT #6628 CLOSES. `performSyncHandshake` selects authentication ONCE,
// when the TCP connection is created, and `wrapSyncConn` fixes that
// connection's posture for its whole lifetime. Committing a key updates the
// manager's key but does NOT tear the connection down: the restart decision
// compares `clusterTransportKey`, which excludes the auth key — an exclusion
// that is deliberate and pinned (TestAuthKeyChangeDoesNotRestartClusterComms_5078),
// because the established connection is what carries the key to a READ-ONLY
// secondary (`EnterConfigureSession` returns ErrClusterReadOnly there, so
// config-sync is that node's only writer).
//
// So an unkeyed session-sync stream stays unkeyed INDEFINITELY after the key is
// committed. Legitimate traffic stays unsigned until an incidental disconnect
// or a daemon restart, and a rotation never rekeys an existing connection.
//
// WHY THIS FILE IS PART OF #7163. It called the same two primitives the connect
// handshake did — `syncAuthProof` (an HMAC with no role, no identity and no
// transcript) and `syncDeriveFrameKey` (which sorted its two nonces, so both
// directions got one key). Converting only the connect handshake would have
// left a SECOND admission path carrying the identical two-connection oracle,
// and it would have become the one an attacker picks, because it is the one
// that still accepts. There is no partial version of this fix.
//
// WHAT THIS CLOSES, AND WHAT IT DOES NOT.
//
// Closed — the two properties about the LEGITIMATE peer:
//
//   - an established unkeyed stream becomes authenticated once both ends hold
//     the same key, with no restart and no disconnect;
//   - a key rotation rekeys the live connection instead of leaving it on a
//     frame key derived from the retired PSK.
//
// NOT closed — a HOSTILE stream admitted before the commit keeps injecting
// frames. A hostile peer declines the upgrade by never answering, and a peer
// that declines is INDISTINGUISHABLE from a legitimate peer that is not keyed
// yet, which is the rolling-upgrade case this must not break. The
// indistinguishability is the problem; a timer is not the missing piece.
// Closing it needs a bounded window after which an un-upgraded connection is
// dropped, and #5078 shipped and then REMOVED exactly such a window for three
// reasons any future attempt must answer: it had to bound a connection's
// LIFETIME rather than just its admission, it had to stop an admitted peer
// re-arming it through config-sync, and it could not survive a crash loop
// without persisting its deadline. Tracked separately; not attempted here.
//
// NEVER DROPS. Every failure path — no key, wrong key, malformed frame, a
// forged confirmation, a replayed Hello, a peer that does not answer — leaves
// the connection exactly as it was. That is the property that makes this a
// strict improvement rather than a trade, and it is what constrains every
// ordering decision below.
//
// It is a property about FAILURE MODES and legitimate-peer behaviour, and the
// boundary is worth stating rather than leaving to be discovered. One narrow
// case survives: an on-path attacker that can inject frames into a
// not-yet-sealed stream can forge a Request, and a Request that arrives while a
// round for a DIFFERENT key is outstanding does start a fresh round, which can
// strand a msg2 in flight. Closing it needs per-round state pinning, and it
// buys nothing: the precondition is frame injection on an unauthenticated
// session-sync stream, where the same attacker can already send syncMsgFence
// and disable every redundancy group the victim owns. That is the residual
// #6628 already names — a hostile stream admitted before the commit — not a new
// one. On an authenticated stream (a rotation) every frame is sealed and none
// of this is reachable.
//
// THIS IS A MID-STREAM KEY SWITCH, not merely an "upgrade". There is a live
// frame stream in both directions and the switch point has to be exact.
// `authConn` used ONE key field with a single `authed()` gating both
// receiveLoop's "read and verify a trailer" and writeMsg's "seal", so flipping
// it promotes both directions on one end at the same instant: that end starts
// requiring a trailer while the peer is still sending unsealed frames,
// consumes syncAuthFrameTrailerSize bytes of the NEXT frame as a trailer, fails
// the MAC, and DROPS the connection. The key is therefore split per direction
// (authConn.readKey / writeKey) and each side switches at the boundary the
// peer switched at. TCP preserves order within a direction, so a frame is an
// unambiguous boundary.
//
// #7163 makes that harder, not easier, and the PR says so: `Split()` returns
// TWO keys where the old derivation returned one, so there are two install
// points per direction rather than one shared value. The invariant is
// unchanged — each side installs at the boundary the peer installed at — but it
// now has to hold for two independent values, which is why every install below
// names the frame it is anchored to.
//
// THE EXCHANGE. Three frames, where #6628 needed four.
//
//	I (node 0)                              R (node 1)
//	-- Hello{ver, noise msg1} ------->
//	                                        R reads msg1. Under psk0 the FIRST
//	                                        message is already AEAD-tagged over
//	                                        the transcript, so a peer holding a
//	                                        different PSK — or disagreeing about
//	                                        cluster/node identity, phase or
//	                                        fabric — fails HERE. Reading msg1
//	                                        therefore PROVES key equality before
//	                                        R answers.
//	                                        R switches NOTHING on read yet: I is
//	                                        still writing unsealed frames.
//	                                        <-- Proof{ver, noise msg2} --
//	                                        R installs writeKey AFTER that write
//	I reads msg2 -> installs readKey
//	(that frame IS the boundary)
//	-- Confirm{ver, MAC} ------------>
//	I installs writeKey AFTER that write
//	                                        R verifies the MAC under its
//	                                        candidate readKey and installs it
//	                                        (that frame IS the boundary)
//
// WHY THE FOURTH FRAME IS GONE, and why that is a property claim rather than a
// simplification. #6628's Ack existed for one reason, stated in its own header:
// the responder "has proven NOTHING when it switches", so it had to wait for
// the initiator's proof or a key mismatch would desync the stream. Under
// Noise_NNpsk0 that premise is false. msg1 is 48 bytes — a 32-byte ephemeral
// public key and a 16-byte Poly1305 tag over an empty payload — because psk0
// mixes the PSK into the chaining key BEFORE the first message is encrypted.
// R has authenticated I by the time it decides to answer, so R may switch its
// write direction immediately after msg2 and I's read boundary is that same
// frame. This is MEASURED, not assumed: TestUpgradeMsg1IsAuthenticated7163
// asserts a responder rejects a msg1 built under a different PSK, and if that
// ever stopped holding the three-frame shape would be unsafe.
//
// WHY THE CONFIRM STILL CARRIES A MAC when R has already authenticated I. It is
// not a proof of possession — msg1 was that — it is an UNFORGEABLE BOUNDARY
// MARKER. Without a MAC, anyone able to inject a frame into a not-yet-sealed
// stream could send a Confirm early: R would start requiring a trailer while
// the real I is still writing unsealed frames, and the connection would drop —
// the one outcome this mechanism promises never happens. The MAC is over the
// handshake hash (Noise's channel binding) under the initiator→responder frame
// key, so only a holder of that key can move R's read boundary.
//
// ROLE COMES FROM NODE ID, not from the wire. #6628 decided it by comparing the
// two nonces ("the SMALLER nonce initiates"), which made role a function of a
// PEER-SUPPLIED value feeding our own key derivation — the same mistake vector
// B exploited. Node ids are local knowledge on both sides of a two-node
// cluster, so the lower id is the initiator and neither end can assert
// otherwise. A frame arriving in the wrong direction for the sender's role is
// ignored, not accommodated.
//
// SIMULTANEOUS AND ONE-SIDED TRIGGERS. Both nodes reconcile on their own config
// apply, and either may be keyed first. The initiator-role node starts the
// exchange directly. The responder-role node cannot — it has no initiator half
// — so it emits a Request, which is a prompt and nothing else: it carries no
// key material, moves no boundary, and its only effect is to make the
// initiator-role node emit a Hello. That converges without a timer and cannot
// ping-pong, because the answer to a Request is a Hello and the answer to a
// Hello is a Proof.
//
// A ROUND IS NOT REPLACEABLE WHILE THE PEER MAY HAVE COMMITTED TO IT. This is
// the subtlest rule in the file and the one that keeps NEVER DROPS true, so it
// is stated as a whole rather than left to the three guards that implement it.
//
// A msg1 is 48 bytes of CLEARTEXT on a not-yet-sealed stream — the only stream
// an in-place upgrade ever starts on — and its AEAD tag covers the prologue and
// the initiator's ephemeral, neither of which changes on a replay. So a
// captured Hello RE-VERIFIES. If the responder answered it, it would mint a
// second round on top of a commitment it had already made: the initiator
// installed its read key at the FIRST msg2 and will install its write key the
// instant it emits the Confirm, and only the first round's keys and binding can
// verify that Confirm. The result is a desync in BOTH directions and a dropped
// connection. #6628 was immune to this because its round state was set-once
// nonce state a second Hello could not clobber; Noise handshake state is not,
// so the refusal is explicit.
//
// The rule and the three guards that implement it:
//
//   - the RESPONDER refuses a msg1 while answeredAwaitingConfirm() — it has
//     answered and switched its write direction, and the Confirm it is waiting
//     for can only be verified with the state it holds now;
//   - the INITIATOR never supersedes an incomplete round, not even for a
//     rotation, because the responder may already have answered and only this
//     round's handshake state can read that msg2;
//   - the RESPONDER stays silent — no Request — while awaiting a Confirm, which
//     is what makes a Request, on arrival at the initiator, a PROOF that no
//     msg2 is in flight. TCP orders the responder's stream, so anything it sent
//     before that Request was read before it.
//
// Without an escape the second guard would strand a rotation forever against a
// peer that never answers, so there are two, and they are exactly the two cases
// in which superseding is safe: a Request from the peer (the proof above), and
// a round that COMPLETES under a retired key, which re-triggers itself at the
// end of handleAuthUpgradeProof. Neither is a timer.
//
// The four-frame variant does NOT avoid this, and that was checked before
// reaching for it. Moving the responder's commitment to an Ack only moves the
// exposure: the initiator's write install at the Confirm is still unilateral,
// and the responder still needs un-clobbered round state to honour it. Someone
// commits first either way, so the fix is that the state a commitment depends
// on cannot be taken away.
//
// CONCURRENCY. writeKey and the exchange state are written under
// SessionSync.writeMu — already the invariant serialising every write to a
// connection — inside the same critical section as the frame that precedes the
// install, so no frame can slip out between them and no concurrent seal can
// race the install. readKey is likewise installed under writeMu, and is
// otherwise touched only by the single receiveLoop goroutine that owns the
// connection.
//
// MIXED VERSION. There is none to preserve. #7163 is a flag day —
// SessionSyncWireVersion is 2 and a pre-#7163 peer cannot complete the connect
// handshake at all — so the additive-message-type argument #6628 made no longer
// has to be made here.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"

	"github.com/flynn/noise"
)

// syncAuthUpgradeVersion is the in-place upgrade wire version. Bumped to 2 by
// #7163: the frames carry Noise messages now, and a peer that answered version
// 1 would be answering with a challenge-response proof this node no longer
// knows how to read.
const syncAuthUpgradeVersion = 2

// syncAuthUpgradeConfirmLen is the confirmation MAC length (HMAC-SHA256).
const syncAuthUpgradeConfirmLen = sha256.Size

// errUpgradeNotApplicable means there is nothing to upgrade on this connection
// — not an authConn, an exchange already in flight, or already authenticated
// under the current key. Never surfaced to the operator.
var errUpgradeNotApplicable = errors.New("cluster sync: auth upgrade not applicable")

// authUpgradeState is one in-flight in-place upgrade exchange on one
// connection. Created when the exchange starts and replaced wholesale when a
// new one starts, so a half-finished round can never contribute state to the
// next one.
//
// Read and written under SessionSync.writeMu.
type authUpgradeState struct {
	// hs is live only on the INITIATOR, and only between writing msg1 and
	// reading msg2. The responder completes its handshake inside a single
	// frame handler and keeps only the binding.
	hs *noise.HandshakeState

	// initiator records the role this exchange was started in, so a frame that
	// belongs to the other role is rejected rather than half-processed.
	initiator bool

	// hello is the exact Hello payload this INITIATOR round put on the wire.
	// Cached so a peer Request can RE-SEND it rather than mint a fresh round:
	// re-sending preserves the handshake state a msg2 already in flight needs,
	// where minting would discard it. See handleAuthUpgradeRequest.
	hello []byte

	// binding is the Noise handshake hash once the handshake has completed on
	// this side. It is what the confirmation MAC is computed over, and both
	// ends reach the same value only if they ran the same transcript.
	binding []byte

	// keys are the directional frame keys this exchange derived. They are
	// CANDIDATES until each direction's boundary frame moves it: writeDone and
	// readDone record which of the two has been installed on authConn.
	keys      syncNoiseKeys
	haveKeys  bool
	writeDone bool
	readDone  bool

	// forPSK is the control-link key this exchange belongs to. A rotation over
	// an already-authenticated connection must be able to start a fresh
	// exchange, and the state of the PREVIOUS one would otherwise refuse it
	// forever. Comparing this to the live key distinguishes "an exchange is
	// already running for this key" from "the state belongs to a key we have
	// since rotated away from".
	forPSK []byte
}

// complete reports whether both directions of this round have been installed.
func (st *authUpgradeState) complete() bool {
	return st != nil && st.readDone && st.writeDone
}

// answeredAwaitingConfirm reports whether this is a RESPONDER round that has
// emitted its msg2 — and so has already switched its write direction — but has
// not yet verified the initiator's Confirm.
//
// This is the window in which this node's round state is LOAD-BEARING FOR THE
// PEER. The initiator installed its read key at that msg2 and will install its
// write key the instant it emits the Confirm; only this round's keys and
// binding can verify that Confirm. Replacing the state here is not a failed
// upgrade, it is a DROPPED CONNECTION in both directions: the responder cannot
// verify the Confirm, so it never installs its read key while the initiator is
// already sealing, and the responder is meanwhile sealing under a key derived
// from an ephemeral the initiator never saw.
//
// That is reachable by REPLAY, not only by a race. A msg1 is 48 bytes of
// cleartext on a not-yet-sealed stream; anyone who can inject a frame can
// capture one and send it again. It re-verifies — its tag covers the prologue
// and the initiator's ephemeral, neither of which changes — so without this
// predicate a replayed Hello would make the responder mint a second round on
// top of a commitment it had already made.
func (st *authUpgradeState) answeredAwaitingConfirm() bool {
	return st != nil && !st.initiator && st.haveKeys && !st.readDone
}

// upgradeConfirmMAC computes the confirmation MAC: HMAC-SHA256 over the Noise
// handshake hash, keyed by the initiator→responder frame key.
//
// Both inputs matter. The key proves the sender completed the handshake; the
// binding ties the confirmation to THIS exchange, so a confirmation captured
// from one round cannot move a boundary in another.
func upgradeConfirmMAC(i2rKey, binding []byte) []byte {
	mac := hmac.New(sha256.New, i2rKey)
	mac.Write(syncAuthUpgradeConfirmTag)
	mac.Write(binding)
	return mac.Sum(nil)
}

// upgradeRoleIsInitiator reports whether THIS node drives the in-place upgrade
// exchange. The LOWER node id initiates.
//
// Derived from local identity on both sides, never from the wire — see the role
// paragraph in the file header.
func (s *SessionSync) upgradeRoleIsInitiator() (bool, error) {
	_, localNode, err := s.syncNoiseIdentity()
	if err != nil {
		return false, err
	}
	return localNode < 1-localNode, nil
}

// fabricIndexOf resolves which fabric slot conn is installed in, because that
// index is bound into the handshake prologue and both ends must agree on it.
//
// Fails closed. A connection that is not installed has no index to bind, and
// guessing 0 would produce a prologue that is well-formed and binds the WRONG
// fabric — which, if the peer guessed the same way, would succeed and silently
// drop the binding.
func (s *SessionSync) fabricIndexOf(conn net.Conn) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.conn0 != nil && s.conn0 == conn:
		return 0, true
	case s.conn1 != nil && s.conn1 == conn:
		return 1, true
	}
	return 0, false
}

// ReconcileConnectionAuth re-evaluates the authentication posture of every
// installed session-sync connection against the CURRENT control-link key and
// starts an in-place upgrade on any whose posture is stale (#6628).
//
// Level-triggered: it re-reads the live key and the live connections on every
// call, so a call with nothing to do is a cheap no-op (two pointer reads and a
// bytes.Equal) and a missed trigger heals on the next one. The daemon calls it
// after a config apply.
//
// It never closes a connection.
func (s *SessionSync) ReconcileConnectionAuth(reason string) {
	key := s.authKey()
	if len(key) == 0 {
		// The key was cleared, or none was ever set. An already-authenticated
		// connection is deliberately left sealing: tearing its authentication
		// down because of a config edit would be a DOWNGRADE, and the peer
		// would reject the unsealed frames anyway. Clearing takes effect on
		// the next connection.
		return
	}
	s.mu.Lock()
	conns := []net.Conn{s.conn0, s.conn1}
	s.mu.Unlock()
	for idx, c := range conns {
		if c == nil {
			continue
		}
		// #7441: anchor the eviction grace BEFORE attempting the upgrade, and
		// for BOTH roles — the initiator emits a Hello here, the responder a
		// Request, and a hostile peer answers neither. Anchoring here rather
		// than at connection setup is what makes the rule bound a connection's
		// LIFETIME: a stream established long before the key was committed
		// starts its grace when the key arrives. noteStrictAuthGraceStartLocked
		// is set-once, so a later reconcile cannot push the deadline forward.
		if ac, ok := c.(*authConn); ok && len(ac.authPSK) == 0 {
			s.writeMu.Lock()
			s.noteStrictAuthGraceStartLocked(ac)
			s.writeMu.Unlock()
		}
		err := s.beginAuthUpgrade(c, idx, key, reason)
		if err != nil && !errors.Is(err, errUpgradeNotApplicable) {
			slog.Warn("cluster sync: could not start the in-place auth upgrade; the connection "+
				"stays exactly as it is (#6628)", "reason", reason, "err", err,
				"remote", connRemoteAddrString(c))
		}
	}
	// #7441: evaluate the posture on this pass too. The periodic tick is what
	// normally fires (the grace elapses after the commit that armed it), but a
	// commit arriving when the grace has ALREADY elapsed — a second commit, or
	// the posture being declared on a long-established unauthenticated stream —
	// must act now instead of waiting up to a tick.
	s.enforceStrictSessionAuth()
}

// beginAuthUpgrade starts, or prompts for, an exchange on conn when its posture
// is stale.
//
// The two roles do different things here and that asymmetry is the point: only
// the initiator-role node can emit a Hello, so the responder-role node emits a
// Request instead. Both are triggered by the same level-triggered reconcile, so
// whichever node is keyed first gets the exchange moving.
func (s *SessionSync) beginAuthUpgrade(conn net.Conn, fabricIdx int, key []byte, reason string) error {
	ac, ok := conn.(*authConn)
	if !ok {
		return errUpgradeNotApplicable
	}
	initiator, err := s.upgradeRoleIsInitiator()
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if bytes.Equal(ac.authPSK, key) {
		// Already authenticated under exactly this key. This is the check that
		// makes the reconciler safe to call on every commit: without it an
		// unrelated config change would restart the exchange on a healthy
		// authenticated connection.
		return errUpgradeNotApplicable
	}
	if !initiator {
		// Responder role: prompt, and touch NOTHING else.
		//
		// NOT while awaiting a Confirm, and this is load-bearing rather than
		// tidy. A Request makes the initiator SUPERSEDE its current round (see
		// handleAuthUpgradeRequest), and superseding while this node is
		// awaiting a Confirm strands the msg2 it has already committed to.
		// Staying silent here is what makes a Request a PROOF, on arrival at
		// the initiator, that no msg2 is in flight.
		if ac.upgrade.answeredAwaitingConfirm() {
			return errUpgradeNotApplicable
		}
		if err := writeMsg(ac, syncMsgAuthUpgradeRequest, []byte{syncAuthUpgradeVersion}); err != nil {
			return err
		}
		slog.Info("cluster sync: asking the peer to start the in-place authentication upgrade "+
			"(this node is the responder by node id) (#6628)", "reason", reason,
			"remote", connRemoteAddrString(conn))
		return nil
	}
	if ac.upgrade != nil && !ac.upgrade.complete() {
		// An INCOMPLETE round is never superseded, not even by a rotation, and
		// the reason is stronger than idempotence: the responder may already
		// have answered our Hello and switched its write direction, and only
		// this round's handshake state can read that msg2. Discarding it
		// strands the peer sealing under a key this node can no longer derive
		// — the same drop answeredAwaitingConfirm() prevents, seen from the
		// other end.
		//
		// This does NOT strand a rotation, and the two escapes are what make
		// the rule affordable:
		//
		//   - a round that COMPLETES under a retired key re-triggers itself at
		//     the end of handleAuthUpgradeProof, where superseding is safe;
		//   - a peer that simply was not keyed yet — the round nobody will ever
		//     answer — says so with a Request, which is the one signal that
		//     proves no msg2 is in flight.
		//
		// A COMPLETE round is safe to supersede: the responder installed its
		// read key while processing our Confirm, and TCP puts that Confirm
		// ahead of the Hello below.
		return errUpgradeNotApplicable
	}
	if err := s.emitUpgradeHelloLocked(ac, fabricIdx, key); err != nil {
		return err
	}
	slog.Info("cluster sync: starting the in-place authentication upgrade on an established "+
		"connection (#6628)", "reason", reason, "remote", connRemoteAddrString(conn))
	return nil
}

// emitUpgradeHelloLocked builds a fresh initiator handshake, writes msg1, and
// records the exchange. It installs NO key: the initiator has authenticated
// nothing until it reads msg2.
//
// Caller holds s.writeMu.
func (s *SessionSync) emitUpgradeHelloLocked(ac *authConn, fabricIdx int, key []byte) error {
	hs, err := s.newSyncNoiseState(key, true, syncNoisePhaseUpgrade, fabricIdx)
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	payload := make([]byte, 0, 1+len(msg1))
	payload = append(payload, syncAuthUpgradeVersion)
	payload = append(payload, msg1...)
	// Written through ac, not ac.Conn: on a re-upgrade (a rotation over an
	// already-authenticated connection) the connection is still sealing under
	// the OLD key and the peer's read side is still on that key. Writing to the
	// raw conn would emit an unsealed frame into a stream the peer expects to
	// be sealed — a desync, on the one path where the connection was healthy to
	// begin with.
	if err := writeMsg(ac, syncMsgAuthUpgradeHello, payload); err != nil {
		// Leave no exchange recorded: nothing reached the peer, so a retry on
		// the next reconcile is the correct outcome.
		return err
	}
	ac.upgrade = &authUpgradeState{
		hs:        hs,
		initiator: true,
		hello:     payload,
		forPSK:    append([]byte(nil), key...),
	}
	return nil
}

// handleAuthUpgradeRequest answers the responder-role peer's prompt by starting
// the exchange. It carries no key material and moves no boundary.
//
// It (re)starts even when an exchange is already in flight: the prompt means
// the peer has only just become keyed, so an exchange started before that is
// one the peer never answered and never will.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeRequest(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 1 || payload[0] != syncAuthUpgradeVersion {
		slog.Warn("cluster sync: malformed or unsupported auth-upgrade request; leaving the "+
			"connection as it is (#6628)", "len", len(payload))
		return
	}
	key := s.authKey()
	if len(key) == 0 {
		// Not keyed here yet — the rolling-upgrade case. Silence is the right
		// answer: the peer keeps its connection, unauthenticated, exactly as
		// today, and a later commit on this node starts our own Hello.
		return
	}
	initiator, err := s.upgradeRoleIsInitiator()
	if err != nil || !initiator {
		// A Request from a peer that should itself be answering ours. Role is
		// local knowledge on both sides, so this is a misconfiguration or an
		// injection, never a state we should accommodate.
		slog.Warn("cluster sync: ignoring an auth-upgrade request that arrived at the "+
			"responder-role node (#6628/#7163)", "err", err)
		return
	}
	fabricIdx, ok := s.fabricIndexOf(conn)
	if !ok {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if bytes.Equal(ac.authPSK, key) {
		return
	}
	// A Request is the only thing that may disturb an outstanding round, and
	// even then it RE-SENDS rather than replaces whenever it can.
	//
	// Re-sending is what makes a FORGED Request harmless. A Request carries no
	// MAC — on a not-yet-sealed stream there is nothing to key one with that a
	// replay would not also carry — so an on-path attacker can inject one. If
	// that made this node mint a fresh round, it would discard the handshake
	// state a msg2 already in flight needs, and the responder would be left
	// sealing under a key this node can no longer derive. Re-emitting the SAME
	// Hello keeps the round intact: a responder awaiting a Confirm refuses the
	// duplicate, and a responder that never answered gets exactly the message
	// it missed, which is the whole reason the Request exists.
	//
	// A round for a DIFFERENT key cannot be re-sent — the peer would refuse its
	// msg1 — so a rotation still starts a fresh one. That narrow case is the
	// residual named under NEVER DROPS in the file header.
	if st := ac.upgrade; st != nil && st.initiator && !st.complete() &&
		len(st.hello) > 0 && bytes.Equal(st.forPSK, key) {
		if err := writeMsg(ac, syncMsgAuthUpgradeHello, st.hello); err != nil {
			slog.Warn("cluster sync: could not re-send the auth-upgrade hello the peer "+
				"asked for; the connection stays as it is (#6628)", "err", err)
		}
		return
	}
	if err := s.emitUpgradeHelloLocked(ac, fabricIdx, key); err != nil {
		slog.Warn("cluster sync: could not answer the peer's auth-upgrade request; the "+
			"connection stays as it is (#6628)", "err", err)
	}
}

// handleAuthUpgradeHello reads the initiator's Noise msg1, answers with msg2,
// and installs ONLY the write direction.
//
// Reading msg1 is the load-bearing step: under psk0 it is AEAD-tagged over the
// prologue and the transcript, so it verifies only for a peer that holds the
// same PSK and agrees about cluster id, node ids, phase and fabric index. That
// is what licenses switching the write direction immediately after msg2 — see
// the four-frames-to-three argument in the file header.
//
// The read direction waits for the Confirm: the initiator is still writing
// unsealed frames until it has sent one.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeHello(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 2 || payload[0] != syncAuthUpgradeVersion {
		slog.Warn("cluster sync: malformed or unsupported auth-upgrade hello; leaving the "+
			"connection as it is (#6628)", "len", len(payload))
		return
	}
	key := s.authKey()
	if len(key) == 0 {
		// Not keyed here yet — the rolling-upgrade case. Silence, as above.
		return
	}
	initiator, err := s.upgradeRoleIsInitiator()
	if err != nil {
		slog.Warn("cluster sync: cannot resolve the in-place upgrade role; leaving the "+
			"connection as it is (#6628/#7163)", "err", err)
		return
	}
	if initiator {
		// A Hello from the peer while WE are the initiator by node id. Only one
		// side may drive, and a peer cannot promote itself by sending a msg1.
		slog.Warn("cluster sync: ignoring an auth-upgrade hello that arrived at the " +
			"initiator-role node; role comes from node id, not from the wire (#7163)")
		return
	}
	fabricIdx, ok := s.fabricIndexOf(conn)
	if !ok {
		return
	}

	// writeMu is held across the WHOLE responder step, the Noise arithmetic
	// included. That is deliberate: whether this msg1 may be accepted depends
	// on the round state, and the msg2 write plus the writeKey install have to
	// sit in the same critical section as that decision — splitting them
	// reopens the window the guard below exists to close. The cost is one
	// X25519 keygen and one AEAD open, on a path that runs at config-commit
	// rate, not per packet.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// A round this node has ALREADY ANSWERED may not be replaced. See
	// answeredAwaitingConfirm for what breaks if it is: the initiator has
	// committed to that msg2 and only this state can verify the Confirm that
	// is coming. A REPLAYED Hello is exactly how an attacker gets one replaced
	// — msg1 is 48 cleartext bytes on a not-yet-sealed stream and re-verifies,
	// because its tag covers the prologue and the initiator's ephemeral,
	// neither of which changes on a replay.
	if ac.upgrade.answeredAwaitingConfirm() {
		slog.Warn("cluster sync: refusing an auth-upgrade hello while awaiting the "+
			"initiator's confirm — the round already in flight is what verifies it, and "+
			"replacing it would strand a msg2 this node has committed to (#6628/#7163)",
			"remote", connRemoteAddrString(conn))
		return
	}

	// Nothing else touches ac until the whole step has succeeded: a msg1 that
	// fails its tag — an injection, or a peer on a different key — must leave
	// the existing round intact.
	hs, err := s.newSyncNoiseState(key, false, syncNoisePhaseUpgrade, fabricIdx)
	if err != nil {
		slog.Warn("cluster sync: auth-upgrade responder setup failed; the connection stays "+
			"as it is (#6628)", "err", err)
		return
	}
	if _, _, _, err := hs.ReadMessage(nil, payload[1:]); err != nil {
		// This is where a peer holding a different control-link key is
		// refused, and it is refused by the construction rather than by a
		// comparison we remembered to write. Nothing has switched on either
		// side, so leaving the connection alone costs nothing and loses
		// nothing.
		slog.Warn("cluster sync: auth-upgrade hello did not authenticate — the peer holds a "+
			"different control-link key, or disagrees about cluster/node identity; the "+
			"connection stays in its current posture (#6628/#7163)",
			"err", err, "remote", connRemoteAddrString(conn))
		return
	}
	msg2, csI2R, csR2I, err := hs.WriteMessage(nil, nil)
	if err != nil || csI2R == nil || csR2I == nil {
		slog.Warn("cluster sync: auth-upgrade responder could not complete the handshake; "+
			"the connection stays as it is (#6628)", "err", err)
		return
	}
	keys := syncNoiseSplitKeys(false, csI2R, csR2I)
	binding := append([]byte(nil), hs.ChannelBinding()...)

	payloadOut := make([]byte, 0, 1+len(msg2))
	payloadOut = append(payloadOut, syncAuthUpgradeVersion)
	payloadOut = append(payloadOut, msg2...)

	// Through ac, not ac.Conn — see emitUpgradeHelloLocked for why.
	if err := writeMsg(ac, syncMsgAuthUpgradeProof, payloadOut); err != nil {
		// The msg2 did not go out, so the initiator will not switch its read
		// direction. Install nothing: a half-switched posture is the one state
		// that could desync a survivor.
		slog.Warn("cluster sync: auth-upgrade proof send failed; the connection stays as it "+
			"is (#6628)", "err", err)
		return
	}
	st := &authUpgradeState{
		initiator: false,
		binding:   binding,
		keys:      keys,
		haveKeys:  true,
		forPSK:    append([]byte(nil), key...),
	}
	ac.upgrade = st
	// The write direction switches HERE, immediately after the frame that is
	// the initiator's read boundary and inside the same writeMu section, so no
	// frame can slip out between the two.
	ac.writeKey = keys.writeKey
	st.writeDone = true
	slog.Info("cluster sync: in-place auth upgrade — outbound frames are now authenticated (#6628)",
		"role", "responder", "remote", connRemoteAddrString(conn))
}

// handleAuthUpgradeProof reads the responder's Noise msg2 at the initiator,
// installs the read direction at that frame, and sends the Confirm that is the
// responder's read boundary.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeProof(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 2 || payload[0] != syncAuthUpgradeVersion {
		slog.Warn("cluster sync: malformed or unsupported auth-upgrade proof; leaving the "+
			"connection as it is (#6628)", "len", len(payload))
		return
	}
	// Resolved before the lock: fabricIndexOf takes s.mu, and s.mu is never
	// acquired under writeMu anywhere in this package.
	fabricIdx, haveFabric := s.fabricIndexOf(conn)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Deliberately NOT gated on the live control-link key. This frame COMPLETES
	// a direction the peer has already switched — the responder installed its
	// write key immediately after emitting it — so a refusal here leaves the
	// responder sealing into a reader that never moved, which is the desync the
	// whole switch-point discipline exists to prevent. A key rotated or cleared
	// between our Hello and this frame must not be able to cause that. The
	// round's own state is self-sufficient: st holds the keys this exchange
	// derived, and st.hs will reject a msg2 that does not belong to it.
	st := ac.upgrade
	if st == nil || !st.initiator || st.hs == nil {
		slog.Warn("cluster sync: auth-upgrade proof with no matching outstanding exchange; " +
			"ignoring rather than deriving a key from state we did not establish (#6628)")
		return
	}
	csI2R, csR2I, err := readUpgradeMsg2(st.hs, payload[1:])
	if err != nil {
		// With matching keys this cannot fail, so a failure here is an
		// injected or corrupted frame. Nothing has switched, and nothing is
		// torn down.
		slog.Warn("cluster sync: auth-upgrade proof did not authenticate; the connection "+
			"stays in its current posture (#6628/#7163)",
			"err", err, "remote", connRemoteAddrString(conn))
		return
	}
	st.keys = syncNoiseSplitKeys(true, csI2R, csR2I)
	st.haveKeys = true
	st.binding = append([]byte(nil), st.hs.ChannelBinding()...)
	st.hs = nil

	// The responder switched its write direction immediately after emitting
	// THIS frame, so everything it sends from here on is sealed: install
	// readKey now, with this frame as the boundary.
	ac.readKey = st.keys.readKey
	st.readDone = true
	slog.Info("cluster sync: in-place auth upgrade — inbound frames are now authenticated (#6628)",
		"remote", connRemoteAddrString(conn))

	confirm := make([]byte, 0, 1+syncAuthUpgradeConfirmLen)
	confirm = append(confirm, syncAuthUpgradeVersion)
	// st.keys.writeKey is the initiator→responder key, which is exactly the key
	// the responder will recompute this MAC under (its readKey).
	confirm = append(confirm, upgradeConfirmMAC(st.keys.writeKey, st.binding)...)
	// Through ac, not ac.Conn — this frame must still be sealed under the OLD
	// key on a rotation, because the responder's read side does not move until
	// it has processed it.
	if err := writeMsg(ac, syncMsgAuthUpgradeConfirm, confirm); err != nil {
		// The Confirm did not go out, so the responder will not switch its
		// read direction — and this node must therefore NOT switch its write.
		// readKey stays installed: the responder has already switched its
		// write, so reverting would desync the direction that IS working.
		slog.Warn("cluster sync: auth-upgrade confirm send failed; the outbound direction "+
			"stays un-upgraded (#6628)", "err", err)
		return
	}
	// The write direction switches HERE, after the frame that is the
	// responder's read boundary.
	ac.writeKey = st.keys.writeKey
	st.writeDone = true
	// Stamped with the key THIS ROUND authenticated under, not the live one. If
	// they differ, the connection really is authenticated under a retired key
	// and the level-triggered reconciler must be able to see that and start a
	// fresh round; stamping the live key here would make it look current.
	ac.authPSK = append([]byte(nil), st.forPSK...)
	slog.Info("cluster sync: in-place auth upgrade complete — this connection is now "+
		"authenticated in both directions (#6628)", "remote", connRemoteAddrString(conn))

	// SELF-RETRIGGER. A rotation that landed while this round was outstanding
	// could not supersede it — an outstanding round is the one thing
	// beginAuthUpgrade refuses to replace, because the responder may already
	// have committed to it. The round is COMPLETE now, so superseding is safe
	// and the deferred rotation is driven here rather than left waiting for an
	// unrelated commit. Level-triggered, exactly like the reconciler: the test
	// is the live key against the key this round authenticated under. The
	// Hello below is written AFTER the Confirm above, which is the order the
	// responder needs to install its read key before reading it.
	if live := s.authKey(); len(live) > 0 && !bytes.Equal(st.forPSK, live) && haveFabric {
		if err := s.emitUpgradeHelloLocked(ac, fabricIdx, live); err != nil {
			slog.Warn("cluster sync: could not start the rotation round deferred while this "+
				"exchange was in flight; the connection stays authenticated under the "+
				"previous key until the next commit (#6628)", "err", err)
		}
	}
}

// handleAuthUpgradeConfirm completes the exchange at the RESPONDER: the
// initiator switched its write direction immediately after emitting this frame,
// so everything it sends from here on is sealed.
//
// The MAC is verified before the boundary moves. That check is what stops a
// frame injected into a not-yet-sealed stream from making this node require a
// trailer the real initiator is not yet writing — which would drop the
// connection.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeConfirm(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 1+syncAuthUpgradeConfirmLen || payload[0] != syncAuthUpgradeVersion {
		slog.Warn("cluster sync: malformed or unsupported auth-upgrade confirm; leaving the "+
			"connection as it is (#6628)", "len", len(payload))
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Not gated on the live key either, and for the mirror-image reason: the
	// initiator installed its write key immediately after emitting this frame,
	// so refusing it would leave the initiator sealing into a reader that never
	// moved. The MAC below is what authorises the install, and it binds the
	// round.
	st := ac.upgrade
	if st == nil || st.initiator || !st.haveKeys {
		return
	}
	if st.readDone {
		return
	}
	// st.keys.readKey is the initiator→responder key on this side.
	want := upgradeConfirmMAC(st.keys.readKey, st.binding)
	if !hmac.Equal(payload[1:1+syncAuthUpgradeConfirmLen], want) {
		slog.Warn("cluster sync: auth-upgrade confirm did not verify; the inbound direction "+
			"stays un-upgraded (#6628/#7163)", "remote", connRemoteAddrString(conn))
		return
	}
	ac.readKey = st.keys.readKey
	st.readDone = true
	if st.writeDone {
		ac.authPSK = append([]byte(nil), st.forPSK...)
	}
	slog.Info("cluster sync: in-place auth upgrade complete — this connection is now "+
		"authenticated in both directions (#6628)", "remote", connRemoteAddrString(conn))

	// SELF-RETRIGGER, the responder's half. A rotation that landed while this
	// round was in flight left this node unable to prompt — beginAuthUpgrade
	// stays silent while awaiting a Confirm, precisely so a prompt cannot make
	// the initiator supersede a round this node has committed to. That is over
	// now, so prompt.
	if live := s.authKey(); len(live) > 0 && !bytes.Equal(ac.authPSK, live) {
		if err := writeMsg(ac, syncMsgAuthUpgradeRequest, []byte{syncAuthUpgradeVersion}); err != nil {
			slog.Warn("cluster sync: could not prompt for the rotation round deferred while "+
				"this exchange was in flight (#6628)", "err", err)
		}
	}
}

// readUpgradeMsg2 reads the responder's msg2 into the initiator's handshake and
// returns the two CipherStates, or an error when the handshake did not
// complete. Split out so the "handshake completed but produced no keys" case
// cannot be mistaken for success by a caller reading only err.
func readUpgradeMsg2(hs *noise.HandshakeState, msg []byte) (csI2R, csR2I *noise.CipherState, err error) {
	_, cs1, cs2, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, err
	}
	if cs1 == nil || cs2 == nil {
		return nil, nil, errors.New("cluster sync: auth-upgrade handshake produced no cipher states")
	}
	return cs1, cs2, nil
}

// SyncMsgAuthUpgradeHelloForTest exposes the upgrade Hello message type to
// pkg/daemon's call-site binding test, which must assert on the frame the
// apply tail actually puts on the wire rather than on a source string.
const SyncMsgAuthUpgradeHelloForTest = syncMsgAuthUpgradeHello

// SyncMsgAuthUpgradeRequestForTest exposes the responder-role prompt to the
// same test. Which of the two the apply tail emits depends on this node's id,
// so a test that pinned only the Hello would silently pass on a node-1 fixture
// by never reaching the assertion it thought it was making.
const SyncMsgAuthUpgradeRequestForTest = syncMsgAuthUpgradeRequest

// InstallUnauthenticatedConnForTest installs conn as fabric 0 wrapped in an
// UNAUTHENTICATED authConn — the posture of a connection handshaked while both
// ends were unkeyed, which is by construction the one #6628 is about.
//
// Test-only seam. Production installs connections through installConn, which
// this deliberately does not call: the cold-prime decision and the incarnation
// stamping it performs are irrelevant here and would drag a whole SessionSync
// lifecycle into a test about one line in the apply tail.
func (s *SessionSync) InstallUnauthenticatedConnForTest(conn net.Conn) {
	s.mu.Lock()
	s.conn0 = &authConn{Conn: conn}
	s.mu.Unlock()
}
