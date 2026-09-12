package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// Peer-fence acknowledgement (#7147).
//
// THE GAP. `peer-fencing disable-rg` is best-effort and unacknowledged.
// SessionSync.SendFence writes syncMsgFence and returns as soon as the bytes
// reach the socket; the receiving node runs OnFenceReceived ->
// fenceAllRedundancyGroups and replies with NOTHING. So a successful SendFence
// means "the write succeeded", not "the peer stopped forwarding", and there was
// no observable a takeover decision could legitimately be gated on. #72's
// proposal item 3 ("optionally gate full active ownership until fence
// acknowledged") was therefore unbuildable, and heartbeat_manager.go carried a
// comment saying exactly that.
//
// WHY GATING ON THE OLD PRIMITIVES WOULD BE WORSE THAN NOTHING. Gating takeover
// on SendFence *returning nil* gates on a socket write. Worse, SendFence fails
// precisely when the sync channel is down, which is the common shape of a
// genuinely dead peer — i.e. exactly the split-brain case fencing exists to
// cover. A gate on send-success would convert a dead peer into a total outage.
// The gate has to be on a REPLY, and the reply has to mean something.
//
// WHAT THE ACK MEANS HERE. Receipt is the weaker of the two candidate
// observables and it is not the one an operator would assume. This
// implementation sends the ack only AFTER the local fence has run, and reports
// how many redundancy groups were actually driven to rg_active=false out of how
// many the receiver's LIVE config contains. A peer in config-only mode (no
// published dataplane) cannot act at all and says so with fenceAckUnavailable
// rather than reporting a vacuous success over an empty RG set.
//
// AND EXACTLY WHAT IT DOES NOT MEAN (#9120). An earlier version of this comment
// read "the peer confirms it relinquished every RG it knows about, which is the
// property a takeover gate should be built on". That is STRICTLY STRONGER than
// what the receiver does, and the difference is the whole span an operator
// would misjudge. fenceAllRedundancyGroups does two things per RG —
// SetRGActive(false) on the dataplane, and InvalidateApplied() on the RG state
// machine — and it does NOT:
//
//   - release the VRRP virtual addresses. The peer keeps every VIP, keeps
//     answering ARP/ND for them, and keeps winning the VRRP election. The
//     upstream L2 domain still points that traffic at the fenced node; the
//     dataplane drops it rather than forwarding it. That is a BLACKHOLE, not a
//     relinquishment, and it is what "relinquished" would have promised.
//   - change cluster state. clusterPri is untouched, so the peer still reports
//     itself primary for those groups in `show chassis cluster status`.
//   - hold. `desired = clusterPri || allVrrpMaster` in pkg/daemon/rg_state.go
//     is computed from those two untouched inputs, so the very next
//     reconcileRGState pass sees desired=true, applied=false (that is what the
//     InvalidateApplied above arranges) and re-drives rg_active=TRUE. The
//     suppression therefore lasts AT MOST ONE RECONCILE INTERVAL unless
//     something else — the peer observing the takeover over the sync channel,
//     an operator, a real crash — changes one of the two inputs first.
//
// So the honest reading of a fenceAckOK is: "at the instant it replied, the
// peer had driven rg_active=false for every RG in its live config." It is a
// point-in-time DATAPLANE SUPPRESSION receipt. It is sound for what the gate
// actually uses it for — ORDERING the local takeover behind the peer's
// suppression, closing the window where both nodes forward — and it is NOT a
// lease, a VIP transfer, or a demotion. Do not build a gate on the stronger
// reading; if a future gate needs one, it needs a fence that changes an input
// to `desired` (and then a bounded self-clearing timer, because a fence that
// clears clusterPri and never expires converts a lost sync channel into a
// no-primary outage). Pinned by TestFenceAckProvesDataplaneSuppressionOnly9120
// in pkg/daemon, which is the counterpart of #6530's
// TestFenceRearmsReconcileRetry, not its inversion.
//
// FAIL-OPEN IS A REQUIREMENT, NOT A COMPROMISE. Every negative path — no
// connection, peer not capable, send error, timeout, partial or unavailable ack
// — proceeds with the takeover. Availability of the surviving node is the
// higher-order property: a fence gate that can withhold ownership indefinitely
// turns every peer failure into an outage. What the gate buys is the ORDERING
// in the case where the peer is reachable (the true split-brain risk: heartbeat
// lost, sync channel alive) — there this node now waits for the peer to confirm
// it went dark before claiming the groups. Each fail-open is recorded to the
// EventFence history with its reason so an operator can never mistake one for a
// confirmed fence; see docs/ha-failover-status.md.
//
// WHY THIS IS ADDITIVE — NO SessionSyncWireVersion / CurrentHAProtocolVersion
// BUMP. Three independent reasons, each verified against this tree:
//
//  1. handleMessage's `switch msgType` (sync_conn_read.go) has NO default arm,
//     and framing is length-prefixed, so a peer that predates syncMsgFenceAck
//     skips the frame without desyncing the stream. This is the same property
//     #2239 (syncMsgDHCPLease*) and #6650 (syncMsgPeerCapabilities) relied on,
//     and both of those deliberately declined to bump for it.
//  2. The seq payload added to syncMsgFence is trailing data on an existing
//     type whose old receiver reads no payload at all, so an old peer is
//     unaffected by its presence. The #2170 trailing-field discipline.
//  3. Bumping would be actively harmful. MinCompatHAProtocolVersion ==
//     CurrentHAProtocolVersion today, so the accepted HA window is a single
//     point; GateMixedBaseSwap refuses when peerHAProtocol is outside
//     [MinCompat, Current]. A bump makes the window [N+1, N+1] and refuses a
//     peer at N — the bump itself would break the rolling upgrade this feature
//     has to survive, converting a narrowing bug into an outage (#6650 records
//     the same reasoning).
//
// A mixed-version pair degrades EXACTLY to pre-#7147 behaviour on both sides:
// the old node ignores the ack request and never replies, the new node sees no
// fence-ack capability advertised and does not wait at all.

const (
	// syncMsgFenceAck carries the receiving node's confirmation that it ran
	// its peer-fence and what that fence achieved (#7147).
	//
	// 35 is the first FREE id. Ids 1..34 are all taken — note in particular
	// that 30 is syncMsgConfigKeyExchange (#6629), so the "= 30" suggested in
	// the #7147 discussion would have collided with the config-encryption
	// handshake. sync_auth.go's syncMsgAuthHello=27 / syncMsgAuthProof=28 are
	// PRE-INSTALL handshake frames and do not constrain this POST-INSTALL one,
	// but the numbering is kept globally unique anyway so a reader never has
	// to reason about which phase a frame belongs to.
	syncMsgFenceAck = 35
)

// Fence acknowledgement status codes, carried in the syncMsgFenceAck payload.
//
// Only FenceAckOK authorises the sender to report a CONFIRMED fence. The other
// two are distinct because they need distinct operator remediation, not because
// the takeover behaviour differs — every one of them fails open.
const (
	// FenceAckOK: at the instant it replied, the peer had driven
	// rg_active=false for every redundancy group in its live config. NOT a
	// VIP release and NOT a demotion — see "AND EXACTLY WHAT IT DOES NOT
	// MEAN" above (#9120).
	FenceAckOK uint8 = 0
	// FenceAckPartial: at least one SetRGActive(false) failed. The peer may
	// still be forwarding for that group.
	FenceAckPartial uint8 = 1
	// FenceAckUnavailable: the peer has no published dataplane (config-only
	// mode), so it could not act on the fence at all. Reported explicitly
	// rather than as a vacuous OK over an empty RG set — "nothing to disable"
	// and "unable to disable anything" are different facts.
	FenceAckUnavailable uint8 = 2
)

// Capability flag bits advertised in the trailing byte of the
// syncMsgPeerCapabilities payload (#7147, on top of #6650's version field).
const (
	// capFlagFenceAck: the sender replies to a sequenced syncMsgFence with a
	// syncMsgFenceAck. Absent => the peer predates #7147 and will never ack,
	// so a confirmed-fence gate must not wait on it.
	capFlagFenceAck uint8 = 1 << 0

	// capFlagPeerDeleteOwnership: the sender's helper understands a peer-MARKED
	// session delete (control protocol v16, #9714) and will REFUSE one that
	// would tear down a live LOCAL session whose owner redundancy group is
	// locally forwarding-active. Absent => the peer applies our deletes
	// unconditionally, so under a dual-primary split a delete this node sends
	// destroys a flow that peer is still forwarding — #9714's defect reached
	// from the other side of the wire.
	capFlagPeerDeleteOwnership uint8 = 1 << 1
)

// localCapabilityFlags is what this build advertises. It is a compile-time
// constant: the capability is a property of the BINARY, not of runtime
// configuration, so it must not be conditioned on anything a deployment can
// turn off. In particular it is deliberately independent of
// localSnapshotProtocol — see sendCapabilities for why that mattered.
const localCapabilityFlags = capFlagFenceAck | capFlagPeerDeleteOwnership

// FenceResult is what the local fence handler reports about what it achieved.
// It is the daemon's answer to "how many RGs did you just drive to
// rg_active=false, out of how many you have", and it is what gets encoded into
// the ack. It is deliberately NOT an answer to "did you relinquish everything"
// — no VIP moves and no cluster-state change is implied (#9120).
type FenceResult struct {
	// RGsFenced is the number of redundancy groups successfully driven to
	// rg_active=false.
	RGsFenced int
	// RGsTotal is the number of redundancy groups in the receiver's LIVE
	// config (#3917 — the live set, not a startup snapshot).
	RGsTotal int
	// DataplaneAvailable is false in config-only mode, where the fence could
	// not be acted on at all.
	DataplaneAvailable bool
}

// Status maps a fence outcome onto the wire status code.
//
// The RGsTotal == 0 case resolves to OK deliberately: a node with a dataplane
// and no redundancy groups configured genuinely owns nothing, so it genuinely
// cannot split-brain. That is a real confirmation, not a vacuous one — which is
// exactly why the config-only case is a SEPARATE code rather than being folded
// in here.
func (r FenceResult) Status() uint8 {
	if !r.DataplaneAvailable {
		return FenceAckUnavailable
	}
	if r.RGsFenced < r.RGsTotal {
		return FenceAckPartial
	}
	return FenceAckOK
}

// FenceAck is a decoded acknowledgement as observed by the fence SENDER.
type FenceAck struct {
	Seq       uint64
	Status    uint8
	RGsFenced int
	RGsTotal  int
}

// Confirmed reports whether this ack authorises the sender to treat the peer's
// DATAPLANE as suppressed, which is what it may order its own takeover behind.
// It does not authorise treating the peer as demoted or as having released its
// VIPs — neither is implied and neither is checked (#9120).
func (a FenceAck) Confirmed() bool { return a.Status == FenceAckOK }

// Reason renders the ack for the operator-facing EventFence history.
func (a FenceAck) Reason() string {
	switch a.Status {
	case FenceAckOK:
		return fmt.Sprintf("peer disabled %d/%d redundancy groups", a.RGsFenced, a.RGsTotal)
	case FenceAckPartial:
		return fmt.Sprintf("peer disabled only %d/%d redundancy groups", a.RGsFenced, a.RGsTotal)
	case FenceAckUnavailable:
		return "peer has no dataplane (config-only mode)"
	default:
		return fmt.Sprintf("unknown fence ack status %d", a.Status)
	}
}

// fenceAckPayloadLen is the encoded size: seq(8) + status(1) + fenced(2) +
// total(2).
const fenceAckPayloadLen = 13

func encodeFenceAckPayload(seq uint64, res FenceResult) []byte {
	buf := make([]byte, fenceAckPayloadLen)
	binary.LittleEndian.PutUint64(buf[0:8], seq)
	buf[8] = res.Status()
	binary.LittleEndian.PutUint16(buf[9:11], clampRGCount(res.RGsFenced))
	binary.LittleEndian.PutUint16(buf[11:13], clampRGCount(res.RGsTotal))
	return buf
}

// clampRGCount saturates an RG count into the uint16 wire field. RG ids are
// 0..255 so a real cluster can never approach this, but the encode must not
// wrap a hostile or corrupted count into a small number that would then read as
// a successful fence.
func clampRGCount(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 0xFFFF {
		return 0xFFFF
	}
	return uint16(n)
}

func decodeFenceAckPayload(payload []byte) (FenceAck, bool) {
	if len(payload) < fenceAckPayloadLen {
		return FenceAck{}, false
	}
	return FenceAck{
		Seq:       binary.LittleEndian.Uint64(payload[0:8]),
		Status:    payload[8],
		RGsFenced: int(binary.LittleEndian.Uint16(payload[9:11])),
		RGsTotal:  int(binary.LittleEndian.Uint16(payload[11:13])),
	}, true
}

// PeerFenceAckCapable reports whether the peer advertised that it will reply to
// a sequenced fence (#7147).
//
// false means "will never ack", not "unknown": the flags are cleared on full
// disconnect and re-learned per peer incarnation, so a false reading is either
// a pre-#7147 peer or a peer whose advertisement has not landed yet. Both must
// be treated as "do not wait" — waiting on a peer that will never answer buys
// nothing and spends the whole timeout on the takeover path.
func (s *SessionSync) PeerFenceAckCapable() bool {
	if s == nil {
		return false
	}
	return uint8(s.peerCapabilityFlags.Load())&capFlagFenceAck != 0
}

// PeerDeleteOwnershipCapable reports whether the peer advertised that its helper
// honours the #9714 peer-delete ownership refusal.
//
// UNLIKE PeerFenceAckCapable, a false reading here must NOT be treated as
// "incapable" on its own, and the asymmetry is the whole point. For fence-ack,
// false means "do not wait", and not waiting is harmless. Here false would gate a
// DESTRUCTIVE choice — whether to withhold a session delete — while
// peerCapabilityFlags reads 0 both for a genuinely old peer AND for the window
// before this incarnation's advertisement lands. Acting on false alone would
// silently discard deletes on every reconnect of a perfectly matched pair, turning
// a mixed-version safeguard into an every-reconnect regression. Callers MUST pair
// this with peerCapabilitiesLearned.
func (s *SessionSync) PeerDeleteOwnershipCapable() bool {
	if s == nil {
		return false
	}
	return uint8(s.peerCapabilityFlags.Load())&capFlagPeerDeleteOwnership != 0
}

// peerCapabilitiesLearned reports whether a syncMsgPeerCapabilities frame has been
// decoded for the CURRENT peer incarnation.
//
// peerSnapshotProtocol is stored from that same frame and cleared alongside the
// flags on full disconnect, and no real peer advertises snapshot protocol 0, so a
// non-zero reading is exactly "this incarnation has told us what it is". That is the
// signal separating "the peer said it cannot" from "the peer has not said yet" — a
// distinction peerCapabilityFlags cannot carry alone, because 0 encodes both and
// only one of them justifies withholding anything.
func (s *SessionSync) peerCapabilitiesLearned() bool {
	if s == nil {
		return false
	}
	return s.peerSnapshotProtocol.Load() != 0
}

// sendFenceAck replies to a sequenced fence with what the local fence achieved.
//
// Written directly under writeMu rather than through sendCh for the same reason
// as sendBarrierAck: the sender is blocking on this reply inside the takeover
// path, so it must not queue behind bulk session traffic.
//
// A write failure is logged and counted but NOT escalated to handleDisconnect.
// The fence itself has already been applied locally by the time this runs, so
// the safety action is done; tearing down the fabric because the confirmation
// did not fit would add a sync outage to a peer-loss event. The sender's
// timeout already covers a lost ack, and it fails open.
func (s *SessionSync) sendFenceAck(conn net.Conn, seq uint64, res FenceResult) {
	if conn == nil {
		return
	}
	payload := encodeFenceAckPayload(seq, res)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFenceAck, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: fence ack write failed", "seq", seq, "err", err)
		return
	}
	s.stats.FenceAcksSent.Add(1)
	slog.Info("cluster sync: fence ack sent",
		"seq", seq,
		"status", res.Status(),
		"rgs_fenced", res.RGsFenced,
		"rgs_total", res.RGsTotal)
}

// completeFenceAckWait hands a received ack to the waiter that requested it.
//
// An ack whose seq matches no live waiter is dropped, which is the point of
// carrying the seq at all: without it a LATE ack from a previous fence would
// satisfy the next fence's gate instantly, and the gate would report a
// confirmation the peer never gave for the fence in question.
func (s *SessionSync) completeFenceAckWait(ack FenceAck) {
	s.fenceAckMu.Lock()
	waiter := s.fenceAckWaiters[ack.Seq]
	delete(s.fenceAckWaiters, ack.Seq)
	s.fenceAckMu.Unlock()
	if waiter == nil {
		slog.Debug("cluster sync: dropping fence ack with no waiter", "seq", ack.Seq)
		return
	}
	// Buffered (cap 1) and removed from the map under the same lock, so
	// exactly one send can ever reach it and this cannot block the read loop.
	waiter <- ack
}

// abortFenceAckWaiters releases every pending fence-ack waiter on disconnect.
//
// Closing the channel (rather than sending) is what distinguishes "peer went
// away" from "peer answered": SendFenceAwait reads a zero-value, not-ok result
// from a closed channel and reports a disconnect, which fails open. Without
// this a fence sent moments before the fabric dropped would hold the takeover
// for the whole timeout even though the answer can no longer arrive.
func (s *SessionSync) abortFenceAckWaiters() {
	s.fenceAckMu.Lock()
	waiters := s.fenceAckWaiters
	s.fenceAckWaiters = nil
	s.fenceAckMu.Unlock()
	for _, waiter := range waiters {
		close(waiter)
	}
}

// SendFenceAwait sends a SEQUENCED fence and waits for the peer to confirm what
// it disabled, bounded by timeout (#7147).
//
// This is the confirmed-fence primitive behind `peer-fencing
// disable-rg-confirmed`. `peer-fencing disable-rg` still uses SendFence and is
// completely unaffected.
//
// Every error return is a FAIL-OPEN signal, and the caller must treat it as
// such — see the file header. The errors are distinguished so the EventFence
// history can name the reason, not so the caller can branch on them:
//
//   - not connected: returns IMMEDIATELY. This is the structural reason the
//     gate cannot delay the common dead-peer takeover — with no socket there is
//     nothing to wait for, so no timeout is ever spent.
//   - peer not fence-ack capable: returns immediately. A pre-#7147 peer will
//     never answer; waiting the full timeout on every peer loss during a rolling
//     upgrade would be a self-inflicted takeover delay.
//   - write failed: returns immediately, and (unlike sendFenceAck) DOES
//     escalate to handleDisconnect, matching SendFence — a fence that could not
//     be written means the fabric is gone.
//   - timeout: the peer is connected at the socket level but did not answer.
//     This is the case a hard peer failure lands in when TCP has not yet
//     noticed, and it is the only path that actually spends the timeout.
func (s *SessionSync) SendFenceAwait(timeout time.Duration) (FenceAck, error) {
	conn := s.getActiveConn()
	if conn == nil {
		return FenceAck{}, fmt.Errorf("peer not connected")
	}
	if !s.PeerFenceAckCapable() {
		return FenceAck{}, fmt.Errorf("peer does not support fence acknowledgement")
	}

	// Sequences start at 1: seq 0 is reserved on the wire to mean "no ack
	// requested", which is what a pre-#7147 SendFence's empty payload decodes
	// to on a #7147 receiver.
	seq := s.fenceSeq.Add(1)
	waiter := make(chan FenceAck, 1)
	s.fenceAckMu.Lock()
	if s.fenceAckWaiters == nil {
		s.fenceAckWaiters = make(map[uint64]chan FenceAck)
	}
	s.fenceAckWaiters[seq] = waiter
	s.fenceAckMu.Unlock()

	unregister := func() {
		s.fenceAckMu.Lock()
		delete(s.fenceAckWaiters, seq)
		s.fenceAckMu.Unlock()
	}

	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFence, payload[:])
	s.writeMu.Unlock()
	if err != nil {
		unregister()
		slog.Warn("cluster sync: fence send error", "seq", seq, "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return FenceAck{}, fmt.Errorf("failed to send fence message: %w", err)
	}
	s.stats.FencesSent.Add(1)
	slog.Info("cluster sync: sequenced fence sent to peer, awaiting confirmation",
		"seq", seq, "timeout", timeout)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ack, ok := <-waiter:
		if !ok {
			// Channel closed by abortFenceAckWaiters: the fabric dropped
			// before the peer answered.
			return FenceAck{}, fmt.Errorf("session sync disconnected during fence ack wait seq=%d", seq)
		}
		s.stats.FenceAcksReceived.Add(1)
		slog.Info("cluster sync: fence ack received",
			"seq", ack.Seq,
			"status", ack.Status,
			"rgs_fenced", ack.RGsFenced,
			"rgs_total", ack.RGsTotal)
		return ack, nil
	case <-timer.C:
		unregister()
		s.stats.FenceAcksTimedOut.Add(1)
		return FenceAck{}, fmt.Errorf("timed out after %s waiting for peer fence ack seq=%d", timeout, seq)
	}
}
