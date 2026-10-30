package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// syncMagic identifies cluster session-sync protocol packets.
var syncMagic = [4]byte{'B', 'P', 'S', 'Y'}

// SessionSyncWireVersion is the schema version of the CROSS-CHASSIS session-sync
// wire protocol (the `syncMagic`/`syncMsg*`/`syncHeader` binary format below —
// NOT the daemon↔helper local control socket `userspace.ProtocolVersion`). It is
// the version the #1930 INC-3 mixed-base image-replace gate must compare across
// a mixed-base cluster: two nodes can only sync sessions if they speak the same
// sync wire schema. Bump this whenever the `syncMsg*` set or `syncHeader`
// changes incompatibly. The header has no on-wire version field today, so a
// changed layout cannot be negotiated per-message — this constant is what makes
// the schema version visible to the gate at all.
//
// #7925: this is now its OWN counter, no longer `uint16(CurrentHAProtocolVersion)`.
// It tracked the HA version because the two had always evolved together, and
// `sync.go` named the exit condition itself: "if the sync wire format ever
// diverges from the HA protocol version, replace this with its own counter."
// Widening the session key (#7160) is that divergence — it changes THIS wire and
// leaves heartbeat/failover semantics alone.
//
// The split matters because the mixed-base gate checks the two DIFFERENTLY
// (upgrade.GateProtocolCompat, executed for LANE-2 by _gate_mixed_base in scripts/deploy/xpf-deploy.py):
// the HA protocol is accepted over a WINDOW [MinCompatHAProtocolVersion,
// CurrentHAProtocolVersion], while the session-sync version must match EXACTLY.
// Welded together, a session-wire-only change was forced to push the HA version
// out from under its own floor as a side effect, failing the window for peers
// that remained fully compatible on everything that had not changed.
//
// So: bump THIS when the `syncMsg*` set or `syncHeader` changes. Bump
// CurrentHAProtocolVersion when heartbeat / failover / RG-handoff semantics
// change. A change to both bumps both. They are equal today (1) and that
// equality is a coincidence of history, NOT an invariant — do not write a test
// that pins them to each other.
// #7163 bumped this from 1 to 2. The session-sync handshake was replaced with
// Noise_NNpsk0 (sync_auth_noise_7163.go), which a pre-#7163 peer cannot speak:
// its HELLO is not a valid Noise msg1 and its proof is not a valid msg2. That
// is a FLAG DAY — both nodes must run the new build and sessions drop on the
// upgrade.
//
// The bump is deliberately on THIS counter and not on
// CurrentHAProtocolVersion. GateProtocolCompat treats them differently:
// session-sync must match EXACTLY, so bumping here is what makes the mixed-base
// swap refuse up front instead of letting an operator discover a fabric that
// will not come up. The HA protocol is accepted over a window
// [MinCompat, Current] that is a single point today, so bumping THAT as well
// would additionally refuse a peer at N over heartbeat/failover semantics this
// change does not touch — a second, unnecessary failure on top of the one this
// change genuinely costs. #7925 split the counters precisely so a session-wire
// change stops dragging the HA protocol out from under its own compat floor.
const SessionSyncWireVersion = uint16(3)

const (
	syncMsgSessionV4         = 1
	syncMsgSessionV6         = 2
	syncMsgDeleteV4          = 3
	syncMsgDeleteV6          = 4
	syncMsgBulkStart         = 5
	syncMsgBulkEnd           = 6
	syncMsgHeartbeat         = 7
	syncMsgConfig            = 8
	syncMsgIPsecSA           = 9
	syncMsgFailover          = 10
	syncMsgFence             = 11
	syncMsgClockSync         = 12
	syncMsgBarrier           = 13
	syncMsgBarrierAck        = 14
	syncMsgBulkAck           = 15
	syncMsgFailoverAck       = 16
	syncMsgFailoverCommit    = 17
	syncMsgFailoverCommitAck = 18
	// Wire value 19 was the unused prepare-activation message. Keep it retired
	// so older peers' frames remain unknown and the value cannot be reused.
	syncMsgPrepareActivation      = 19 // retired; do not reuse
	syncMsgFailoverBatch          = 20
	syncMsgFailoverBatchAck       = 21
	syncMsgFailoverBatchCommit    = 22
	syncMsgFailoverBatchCommitAck = 23
	syncMsgHeartbeatAck           = 24
	// #2239 HA DHCP-server lease sync (PATH C). A full-set push of the
	// active lease records this node serves, per family. These are ADDITIVE
	// and length-gated: a peer that predates the feature hits the default
	// receive case and ignores them, and the records use the #2170
	// trailing-field discipline so the schema can grow. Deliberately NO
	// CurrentHAProtocolVersion / SessionSyncWireVersion bump — the change is
	// additive AND end-to-end gated on the `dhcp-lease-synchronization` config
	// knob, so a mixed-base pair (one side new, one old) is safe and must
	// still be allowed to sync SESSIONS; bumping the wire version would make
	// the #1930 INC-3 mixed-base gate falsely refuse session sync across the
	// pair. If a FUTURE change to these messages becomes incompatible, bump
	// the version then.
	syncMsgDHCPLeaseV4 = 25
	syncMsgDHCPLeaseV6 = 26
	// #7328 config-apply NACK. The RECEIVER sends this after an apply that did
	// NOT take effect, carrying the generation it failed on (u64 LE). It exists
	// because the sender has no other way to learn the outcome: QueueConfig is
	// fire-and-forget, the heartbeat carries no config state, and
	// configSyncFailing never leaves the node it is raised on.
	//
	// Without it, #5863's (epoch x generation) push dedupe silently defeats
	// #4151's re-push contract. #4151 deliberately pins lastAppliedConfigGen on
	// a failed apply so the SAME generation stays eligible for a re-push, and
	// errConfigSyncRejectedPrimary's doc says the dual-active window "must heal
	// via the peer's re-push" — but the reconciler claims its marker BEFORE
	// sending and nothing ever clears it, so no trigger on the live connection
	// ever pushes that generation again. #6387's own comment records the same
	// mechanism from the other side ("the sender pushes a generation at most
	// once per connection, so a stable connection with a persistent apply
	// failure would otherwise never re-enter this edge") and answered it with an
	// alarm rather than convergence.
	//
	// ADDITIVE and length-gated on the #2239 precedent above: a peer predating
	// the feature hits the default receive case and ignores it, and a receiver
	// tolerates a short/absent payload. Deliberately NO CurrentHAProtocolVersion
	// / SessionSyncWireVersion bump — nothing about the existing messages
	// changes, and bumping would make the #1930 INC-3 mixed-base gate falsely
	// refuse session sync across a mixed pair. A mixed pair simply keeps
	// today's behaviour: the old side never nacks, so the marker is never
	// re-armed and convergence still waits for a commit or a reconnect.
	syncMsgConfigApplyNack = 27
	// Positive apply result: the receiver sends the successfully applied
	// generation (u64 LE). A newer send does not clear this gate until ACKed.
	syncMsgConfigApplyAck = 40

	// NOTE for the next author: sync_auth.go also declares syncMsgAuthHello=27
	// and syncMsgAuthProof=28. Those are PRE-INSTALL handshake frames and
	// syncMsgConfigApplyNack=27 above is a POST-INSTALL frame, so the reuse of
	// 27 is phase-separated rather than a live collision -- but the number
	// space is shared, so pick an unused value here rather than assuming the
	// gap is free. TestPeerCapabilitiesMessageTypeIsUnique6650 enumerates every
	// live constant, including the ones declared in sync_auth.go.

	// syncMsgPeerCapabilities advertises the SENDER's config-snapshot protocol
	// version so the receiver can refuse to push a config the peer cannot
	// represent (#6650). Sent once per installed connection, right beside the
	// clock sync.
	//
	// ADDITIVE and version-bump-free, following the #2239 DHCP-lease
	// precedent documented above: the receive switch has no default arm, so a
	// peer that predates this simply ignores the frame. Bumping
	// CurrentHAProtocolVersion / SessionSyncWireVersion instead would make the
	// #1930 INC-3 mixed-base gate falsely refuse SESSION sync across exactly
	// the rolling upgrade this exists to make safe -- converting a narrowing
	// bug into an outage, which is the blunt option #6650 weighed and rejected.
	//
	// Payload: {config_snapshot_protocol_version: u16 LE}, with the #2170
	// trailing-field discipline so the record can grow.
	syncMsgPeerCapabilities = 29

	// syncMsgConfigKeyExchange carries the SENDER's ephemeral X25519 public
	// key for config-payload encryption (#6629). Sent once per installed
	// connection, right beside the capabilities advertisement.
	//
	// Payload: {version: u8, x25519_public_key: [32]byte}, with the #2170
	// trailing-field discipline so the record can grow.
	syncMsgConfigKeyExchange = 30

	// syncMsgConfigEncrypted is a syncMsgConfig payload sealed under the key
	// derived from that exchange (#6629). Its plaintext is byte-identical to
	// the syncMsgConfig payload — the same encodeConfigPayload framing,
	// generation trailer included — so the receive path is shared and cannot
	// drift between the two.
	//
	// Payload: {version: u8, nonce: [12]byte, AES-256-GCM(ciphertext||tag)}.
	//
	// BOTH are ADDITIVE and version-bump-free on the #2239/#6650 precedent
	// above: the receive switch has no default arm, so a peer that predates
	// them ignores the exchange, never derives a key, and is sent cleartext
	// syncMsgConfig exactly as today — with a loud warning naming the
	// exposure. Bumping CurrentHAProtocolVersion / SessionSyncWireVersion
	// would make the #1930 INC-3 mixed-base gate falsely refuse SESSION sync
	// across the very rolling upgrade this must survive.
	syncMsgConfigEncrypted = 31

	// syncMsgAuthUpgradeHello / syncMsgAuthUpgradeProof carry the #6628
	// IN-PLACE authentication upgrade over an ESTABLISHED connection, which
	// #7163 moved onto the same Noise_NNpsk0 exchange as the connect handshake.
	//
	// Distinct from syncMsgAuthHello (27) / syncMsgAuthProof (28), which are
	// PRE-INSTALL handshake frames read by readSyncFrameRaw before the
	// connection is wired up. Those numbers are already reused post-install
	// (27 is syncMsgConfigApplyNack), so the upgrade cannot borrow them: a
	// post-install frame of type 27 means the nack, and a receiver has no way
	// to tell the two apart.
	//
	// Hello payload: {version: u8, noise msg1: [48]byte}  initiator -> responder
	// Proof payload: {version: u8, noise msg2: [48]byte}  responder -> initiator
	//
	// #6628 argued these were ADDITIVE and version-bump-free so a rolling
	// upgrade would leave an old peer un-upgraded rather than broken. #7163
	// removes that constraint rather than violating it: it IS a flag day
	// (SessionSyncWireVersion is 2 and a pre-#7163 peer cannot complete the
	// connect handshake at all), so there is no mixed pair left for the
	// argument to protect.
	syncMsgAuthUpgradeHello = 32
	syncMsgAuthUpgradeProof = 33

	// 34 was syncMsgAuthUpgradeAck, the FOURTH frame of the pre-#7163 exchange.
	// It existed because the responder had proven nothing when it answered, so
	// it could not switch its write direction until the initiator's proof
	// arrived. Under Noise_NNpsk0 the initiator's msg1 is already AEAD-tagged
	// over the transcript, so the responder authenticates the initiator BEFORE
	// it answers and the fourth frame has nothing left to do. The number is
	// left unused rather than recycled: a frame numbered 34 meant something
	// else in every build before this one.

	// syncMsgAuthUpgradeConfirm is the third and last frame of the #7163
	// exchange: the initiator's proof that it completed the handshake, and the
	// frame that is the responder's read boundary.
	//
	// Payload: {version: u8, HMAC-SHA256 over the Noise channel binding: [32]byte}
	syncMsgAuthUpgradeConfirm = 36

	// syncMsgAuthUpgradeRequest is the responder-role node's prompt. Role comes
	// from node id, so the higher-id node cannot start the exchange itself; it
	// asks. Carries no key material and moves no boundary.
	//
	// Payload: {version: u8}
	syncMsgAuthUpgradeRequest = 37
	// syncMsgBulkRequest asks the peer to run its normal authoritative bulk
	// source path (#12160). The payload is opaque; request generations are
	// correlated only on the requester. An old peer ignores this additive
	// message and leaves the request fail-closed.
	syncMsgBulkRequest = 42
	// #15160 (B03-01): chunked DHCP lease full-sets. When a family's lease
	// set encodes over maxSyncPayload, queueDHCPLeaseSnapshot splits it
	// across these additive types instead of writing one over-cap frame
	// the receiveLoop refuses connection-fatally. Each chunk payload is
	// {generation u64, index u32, total u32, totalLeases u32} followed by a
	// standard count-prefixed DHCP lease body for that chunk; the LAST
	// chunk also carries the #10170 authority trailer. A pre-#15160 peer
	// ignores the unknown types (additive, no version bump; the #14607
	// precedent), so lease sync for over-cap sets resumes once both peers
	// upgrade — it never tears the connection down. Small sets keep the
	// legacy syncMsgDHCPLeaseV4/V6 single-frame shape. 44 is
	// syncMsgAuthConfirm (pre/post-install shared space; see the NOTE
	// above), so the chunk types take 45/46.
	syncMsgDHCPLeaseV4Chunk = 45
	syncMsgDHCPLeaseV6Chunk = 46
	// syncMsgFailoverAbort / syncMsgFailoverBatchAbort (#15164) carry the
	// reqID-bound abort of a requested transfer-out: the requester abandoned
	// it, including after ACK failure/timeout (#16592), so the owner restores
	// promptly instead of waiting for its #5079 lease. Payloads
	// mirror the commit frames ({rg u8, reqID u64} / batch encoding).
	// ADDITIVE and version-bump-free on the #2239 precedent: an old peer
	// hits the default receive case and ignores it, and the lease remains
	// the fallback that restores the owner. 47/48: 45/46 are the #15160
	// DHCP lease chunk types above.
	syncMsgFailoverAbort      = 47
	syncMsgFailoverBatchAbort = 48
	// #16758: chunked IPsec SA full-sets. When the name set exceeds the
	// receiver's per-frame element bound (maxIPsecSANames), QueueIPsecSA
	// splits it across additive frames of this type instead of emitting
	// one legacy frame the receiver must refuse whole. Each chunk payload
	// is {generation u64, index u32, total u32, totalNames u32} followed
	// by the newline-joined names for that chunk; every chunk carries its
	// own increasing full-set seq. A pre-#16758 peer ignores the unknown
	// type (additive, no version bump; the #15160 precedent), so over-cap
	// sets resume once both peers upgrade.
	syncMsgIPsecSAChunk = 49
)

// syncHeader is the wire header for each sync message.
type syncHeader struct {
	Magic  [4]byte
	Type   uint8
	Pad    [3]byte
	Length uint32
}

const syncHeaderSize = 12

// maxSyncPayload is the shared session-sync receive cap (#14607). The
// receive loop refuses any frame whose declared length exceeds it, so no
// sender may write a larger payload. Full-set encoders that can exceed it
// (persistent-NAT idle leases) must chunk below it; see
// encodePersistentNatLeaseBatchFrames.
const maxSyncPayload = 16 * 1024 * 1024
const syncWriteDeadline = 2 * time.Second
const failoverAckTimeout = 20 * time.Second
const syncReadDeadline = 10 * time.Second
const syncPeerSilenceTimeout = 30 * time.Second

// SyncStats tracks session synchronization statistics.
type SyncStats struct {
	SessionsSent atomic.Uint64
	// SweepSessionsSent counts the SUBSET of SessionsSent contributed by the
	// periodic mirror sweep (syncSweep), as opposed to the authoritative delta
	// stream. It is a sub-total, NOT a separate population: every sweep send
	// increments both, so `SessionsSent - SweepSessionsSent` is the delta
	// stream's share and the existing total is unchanged for every consumer.
	//
	// #7842 exists because that attribution did not exist. Both producers
	// funnel through `queueMessage(msg, &s.stats.SessionsSent, source)` and the
	// `source` string reaches exactly one place -- the send-queue-overflow
	// warning -- so `SessionsSent` is their SUM and nothing could separate
	// them. The issue asks for the duplication to be settled by measuring
	// "stats.SessionsSent and stats.Errors at a realistic connection rate";
	// that measurement cannot answer it, because a duplicate and an original
	// are indistinguishable in the one counter it names. Measured on the loss
	// cluster before this field existed, the totals were uninterpretable for
	// exactly that reason.
	SweepSessionsSent atomic.Uint64
	SessionsReceived  atomic.Uint64
	// MalformedRecordsDropped counts rejected sync input: session records
	// truncated before policy/zone/NAT blocks, DHCP sets with invalid wire
	// framing, and individual lease rows rejected by semantic validation
	// (#10893). A malformed DHCP frame counts once; semantically invalid lease
	// rows count separately. Before #7175, truncated sessions and cut lease sets
	// decoded as partial state — zero-filled policy fields or a set silently
	// truncated to a prefix.

	// CORRECTION: this doc previously cited #6682 for the claim that zone pair
	// (0,0) is matched by a wildcard permit. #3110 fenced every rule tier against
	// zone 0 and #6682 made an unzoned ingress an explicit deny, so a wildcard
	// never reaches a zero pair. The counter's
	// purpose is unchanged — a silently skipped install is how corruption hides
	// — but it does not rest on that claim. The rejection is now countable because the failure mode it
	// replaces was invisible: nothing distinguished a corrupt frame from a
	// legitimately small one.
	MalformedRecordsDropped atomic.Uint64
	SessionsInstalled       atomic.Uint64
	DeletesSent             atomic.Uint64
	DeletesReceived         atomic.Uint64
	BulkSyncs               atomic.Uint64
	ConfigsSent             atomic.Uint64
	ConfigsReceived         atomic.Uint64
	// ConfigsStaleIgnored counts config-sync messages dropped by the #3931
	// config-generation ordering guard: an incoming config whose monotonic
	// generation was NOT strictly newer than the last-applied one (an
	// out-of-order / reordered older config). A nonzero value means the
	// guard prevented a rapid-commit reorder (C1 applied after C2) from
	// leaving the standby on the older config.
	ConfigsStaleIgnored atomic.Uint64
	// BulkPrimesWithoutIncarnation counts bulk primes received from a peer
	// that sent no boot incarnation (#5084) — the legacy 8-byte BulkStart.
	// A silent fail-open is how a half-upgraded cluster hides, so the fallback
	// is counted rather than merely permitted.
	BulkPrimesWithoutIncarnation atomic.Uint64
	// ConfigsDeadIncarnationDropped counts config payloads dropped because
	// they belonged to a peer boot incarnation that a re-prime has replaced
	// (#5084 rule 3) — the defect this fence exists to close, made countable.
	ConfigsDeadIncarnationDropped atomic.Uint64
	// BulkEndsDeadIncarnationDropped counts BulkEnd frames refused for carrying
	// a boot incarnation other than the one that started the bulk in progress
	// (#9174 V013). Counted because the refusal decides whether the VRRP sync
	// hold is released.
	BulkEndsDeadIncarnationDropped atomic.Uint64
	// ClockSyncsRefused counts ClockSync frames refused for a peer monotonic
	// clock no running peer can read (#9653). The previous offset stays in force.
	ClockSyncsRefused atomic.Uint64
	// RebaseSaturations counts session installs whose peer Created/LastSeen
	// fell outside int64 range and were clamped to the far future by the
	// saturating rebase (#9915 F-118). Honest clocks never approach 2^63,
	// so nonzero means corrupt input, counted rather than silently installed.
	RebaseSaturations atomic.Uint64
	// BulkEndsForeignConnDropped counts BulkEnd frames refused because they
	// arrived on a connection other than the one that carried the accepted
	// BulkStart (#9716). BulkSync pins one connection per bulk, so such a frame
	// is a marker from a dead peer process's still-established socket, stopped
	// from completing a live transfer.
	BulkEndsForeignConnDropped atomic.Uint64
	// BulkEndsEpochOnlyMatched counts bulk completions the boot-incarnation check
	// could not judge, because the BulkStart or the BulkEnd carried no
	// incarnation (#9716). They are matched on epoch and connection alone, and
	// counted so a half-upgraded pair is visible rather than silent.
	BulkEndsEpochOnlyMatched atomic.Uint64
	// BulkRecvCapped (#16039) counts distinct session records refused
	// admission to the bulk receive accumulators because the window
	// already held bulkRecvCap() live keys across both families, plus
	// distinct keys dropped on an already-invalid window. The cap is on
	// live occupancy: a delete during the window frees its key's slot,
	// so delete+reinstall churn does not consume it. A nonzero value
	// means the peer's bulk window exceeded the table capacity this
	// node is provisioned for: the window is aborted rather than
	// reconciled.
	BulkRecvCapped atomic.Uint64
	// BulkRecvAborted (#16039) counts accepted bulk windows aborted by
	// the receiver: accumulator overflow past the table cap, deadline
	// expiry observed on receive, or a BulkEnd arriving after the
	// window deadline. An aborted window never reconciles, never acks,
	// and never releases the failover hold; it latches bulkIncomplete
	// readiness debt until a later bulk reconciles successfully. At
	// most one abort is counted per window.
	BulkRecvAborted atomic.Uint64
	// ConfigsApplyFailed counts config-sync messages that were admitted by the
	// #3931 ordering guard but whose apply did NOT take effect on this node —
	// a compile/promote failure (a mixed-build ISSU syntax error, a store
	// rejection) or a transient RG0-primary rejection. On such a failure the
	// config high-water mark (lastAppliedConfigGen) is deliberately NOT
	// advanced, so the primary's re-push of the SAME generation is re-admitted
	// and the standby re-converges instead of being silently stranded on the
	// prior config (M-2/#4151). A persistently-nonzero value means a standby is
	// repeatedly failing to apply the peer's config — investigate divergence.
	ConfigsApplyFailed atomic.Uint64
	// ImportsRefusedByHelper counts synced-session installs the LOCAL userspace
	// helper refused on semantic grounds (#6785) — a stale install generation, the
	// aggregate synced-import ceiling, or a translated-tuple reservation refusal.
	// Before #6785 the helper answered ok=true for all three, so these installs
	// were counted as SessionsInstalled and their BPF mirror rows stayed behind
	// for sessions the helper never took.
	//
	// This is health DEBT, not an error in the sense Errors carries: the helper is
	// working correctly and the local BPF row has been rolled back, but the PEER
	// still believes it synced a session this node does not hold, and only the
	// peer's next full sync closes that gap. It is counted separately from Errors
	// so a persistently oversubscribed standby is legible as such rather than
	// looking like a flaky mirror socket, and it deliberately does NOT feed the
	// takeover-readiness gate — refusing to fail over on a node whose peer is
	// oversubscribing it would turn a capacity problem into an outage.
	ImportsRefusedByHelper atomic.Uint64
	// ImportsRejectedByHelper counts typed deterministic synced-import
	// rejections from the healthy helper. The peer still believes the session
	// was synced, so this peer-session debt is surfaced separately from
	// transport Errors and semantic ImportsRefusedByHelper.
	ImportsRejectedByHelper atomic.Uint64
	// ConfigsQueueFullDropped counts config payloads that never reached the
	// #3931 ordered apply queue because it was full at enqueue (#6778). The
	// non-blocking enqueue discards the INCOMING payload, which is the NEWEST
	// generation the peer has sent, while the queue retains older ones — so the
	// drop leaves this node applying a superseded config. Counted separately
	// from ConfigsApplyFailed because the failure is on the RECEIVE edge (the
	// apply never ran) and from the generic Errors counter because "the standby
	// is behind the primary's committed config" is a distinct operator action.
	// The recovery is the same one an apply failure uses: the received
	// high-water is still raised (so the node reads config-stale and #5563
	// refuses manual-failover promotion), a config-apply nack re-arms the
	// sender's #5863 push marker, and the sender's periodic reconcile re-pushes.
	ConfigsQueueFullDropped atomic.Uint64
	// ConfigsSentCleartext counts config pushes this node SENT in the clear
	// (#11773) — the #6629 fallback, emitted on BOTH arms: a push the peer
	// never negotiated encryption for (a pre-#6629 build, or a #6629-capable
	// peer whose key exchange had not landed when the push ran), and a push
	// whose seal failed. It is a SUB-TOTAL of ConfigsSent, not a separate
	// population: every cleartext send increments both, so
	// `ConfigsSent - ConfigsSentCleartext` is the sealed share.
	//
	// Counted at the same site as ConfigsSent — after a successful write —
	// never on the warning path above it: a guard refusal or a failed write
	// exposed nothing on the segment and must not move this. Monotonic for
	// the life of the process; nothing clears it, so a mixed-version window
	// that has since closed stays visible and a capture taken inside it is
	// still honoured (rotate the PSK afterwards — its frames still verify).
	ConfigsSentCleartext atomic.Uint64
	// ConfigsReceivedCleartext counts config pushes this node RECEIVED in the
	// clear (#11773) — a syncMsgConfig frame from a peer whose push fell back
	// (an older build, a key exchange not yet landed, or a seal failure). A
	// SUB-TOTAL of ConfigsReceived, counted at the same site: every cleartext
	// receive increments both, so `ConfigsReceived - ConfigsReceivedCleartext`
	// is the sealed share. Sticky like the sender half: the receiver-side
	// half of the same exposure, on the node that never chose the fallback.
	ConfigsReceivedCleartext atomic.Uint64
	// CleartextSyncAlarmLatched is the operator-facing alarm state for #11773.
	// It records that config text has crossed the sync link unsealed at least
	// once during this process. It deliberately never clears on reconnect or
	// after a peer upgrades: rotating the PSK is still required because a
	// capture taken during the exposure remains usable.
	CleartextSyncAlarmLatched atomic.Bool
	// ConfigApplyNacksReceived counts #7328 config-apply nacks accepted from the
	// peer — one per generation this node pushed that the peer refused or failed
	// to apply. A nack for a superseded generation is ignored and not counted.
	// A persistently-nonzero, climbing value means the peer is repeatedly
	// failing to apply what this node sends; pair it with the peer's own
	// ConfigsApplyFailed to see why.
	ConfigApplyNacksReceived atomic.Uint64
	// #18521: the positive config-apply ACK, end to end. On the standby,
	// ConfigApplyAcksSent counts ACKs written and ConfigApplyAcksUnsent the
	// ones skipped because the delivering connection was no longer active.
	// On the authority, ConfigApplyAcksCredited counts ACKs accepted against
	// the newest send and ConfigApplyAcksIgnored the ones refused (wrong
	// connection, unsent generation). A stale-config refusal with a sent
	// ACK on one side and no credited ACK on the other names the drop.
	ConfigApplyAcksSent     atomic.Uint64
	ConfigApplyAcksUnsent   atomic.Uint64
	ConfigApplyAcksCredited atomic.Uint64
	ConfigApplyAcksIgnored  atomic.Uint64
	// BulkRerequestsSent counts the #18521 (D) BulkRequests this receiver
	// queued after withholding a BulkAck.
	BulkRerequestsSent atomic.Uint64
	IPsecSASent        atomic.Uint64
	IPsecSAReceived    atomic.Uint64
	// IPsecSAStaleIgnored counts IPsec SA full-sets dropped by the #5706
	// ordering guard: an incoming (incarnation, seq) that was NOT strictly
	// newer than the last-applied pair — a full-set reordered across the
	// redundant fabric streams. A nonzero value means the guard prevented a
	// stale IPsec SA set from regressing the standby's held set.
	IPsecSAStaleIgnored atomic.Uint64
	// IPsecSAMalformedIgnored counts IPsec SA frames refused before commit:
	// a malformed legacy payload (#9061) or a malformed/inconsistent chunk
	// (#16758). The held set is retained and the sequence is not consumed
	// for legacy frames; chunk assemblies are invalidated. A climbing value
	// means the peer is sending sets this node cannot install.
	IPsecSAMalformedIgnored atomic.Uint64
	// IPsecSAOversizeAlarmLatched records that this node, as sender, had to
	// chunk an IPsec SA set over maxIPsecSANames (#16758). Operator-visible
	// in cluster status; it never clears in-process so an extreme selector
	// count is not silent on the primary.
	IPsecSAOversizeAlarmLatched atomic.Bool
	// IPsecSAOverCapSets counts sender pushes whose name count exceeded
	// maxIPsecSANames and were therefore sent chunked (#16758); receiver
	// chunk commits are counted in IPsecSAReceived like legacy pushes.
	IPsecSAOverCapSets atomic.Uint64
	// #2239 HA DHCP-server lease sync counters. Sent/Received count
	// full-set lease push MESSAGES (one per family per push); Seeded counts
	// leases written into a freshly-started Kea on takeover; errors fold
	// into the shared Errors counter (fail-open posture).
	DHCPLeasesSent     atomic.Uint64
	DHCPLeasesReceived atomic.Uint64
	// DHCPLeasesStaleIgnored counts DHCP lease full-sets dropped by the #5706
	// ordering guard (per family), the DHCP analog of IPsecSAStaleIgnored: a
	// reordered older lease set that would otherwise have regressed the
	// standby's held set for a family.
	DHCPLeasesStaleIgnored atomic.Uint64
	DHCPLeasesSeeded       atomic.Uint64
	// DHCPLeasesDroppedNoIdentity counts synced lease records dropped for
	// lacking the minimal identity their message family requires (#9915
	// F-117). Only the violating members drop; a push filtering to zero
	// survivors retains the prior held set (#7175 posture), so this never
	// wipes failover data.
	DHCPLeasesDroppedNoIdentity atomic.Uint64
	FencesSent                  atomic.Uint64
	FencesReceived              atomic.Uint64
	// FenceAcksSent / FenceAcksReceived / FenceAcksTimedOut instrument the
	// #7147 confirmed fence. FenceAcksTimedOut is the one that matters
	// operationally: it counts takeovers that proceeded WITHOUT the
	// confirmation the operator asked for, which is invisible in FencesSent.
	//
	// Directions and exact semantics, because two of these are easy to
	// misread:
	//   - FenceAcksSent counts acks THIS node sent, i.e. times this node was
	//     the one being fenced. The other two are the outbound direction.
	//   - FenceAcksReceived counts acks that reached a LIVE waiter. An ack
	//     that arrives after its wait already timed out is dropped by the seq
	//     match and is NOT counted here — it did not confirm anything the
	//     takeover could act on, and counting it would make
	//     received+timed_out exceed the number of fences sent.
	//   - FenceAcksReceived includes NEGATIVE acks (partial/unavailable): it
	//     counts fences the peer ANSWERED, not fences it satisfied. The
	//     EventFence history distinguishes those.
	FenceAcksSent     atomic.Uint64
	FenceAcksReceived atomic.Uint64
	FenceAcksTimedOut atomic.Uint64
	Errors            atomic.Uint64
	// OversizeFramesRefused counts frames refused by the #16041 per-type
	// payload cap (syncPayloadCap): a header declaring more payload than
	// its type's encoder can ever emit. The connection is dropped, as with
	// the global maxSyncPayload refusal it refines. A nonzero value means
	// a non-conforming or faulty keyed peer; conforming senders chunk
	// full-set types below the global cap and never approach these.
	OversizeFramesRefused atomic.Uint64
	// PreKeyAuthEvictions counts keyed-node session-sync connections closed
	// after they failed to authenticate within the #10717 upgrade grace.
	PreKeyAuthEvictions atomic.Uint64
	DeletesDropped      atomic.Uint64
	// DeletesSuppressedPeerIncapable counts outgoing session deletes WITHHELD
	// because the peer advertised its capabilities and did NOT claim #9714
	// peer-delete ownership (capFlagPeerDeleteOwnership). Such a peer applies a
	// delete unconditionally, so in a dual-primary split our delete would tear
	// down a flow it is still forwarding.
	//
	// A nonzero value is OPERATIONALLY MEANINGFUL, not diagnostic noise: the
	// peer is retaining sessions this node has already closed, and will until
	// they idle out or the upgrade completes on both nodes. It is counted
	// rather than left silent precisely because the suppression trades a
	// visible leak for an invisible teardown.
	DeletesSuppressedPeerIncapable atomic.Uint64
	// DeletesSuppressedPurgeRetirement counts outgoing forward-only session
	// deletes WITHHELD because the peer advertised its capabilities and did
	// NOT claim #9752 forward-only deletes
	// (capFlagPurgeRetirementForwardOnly). Such a peer derives companions
	// for every delete, so our purge-retirement close would destroy
	// sessions the purge deliberately preserved. Same operational meaning
	// as DeletesSuppressedPeerIncapable: counted, visible leak over
	// invisible teardown.
	DeletesSuppressedPurgeRetirement atomic.Uint64
	// DeletesSuppressedScopedPolicy counts outgoing SCOPED session deletes
	// WITHHELD because the peer advertised its capabilities and did NOT
	// claim #10512 scoped policy deletes (capFlagScopedPolicyDelete).
	// Such a peer applies deletes by bare tuple, so our scoped delete
	// would destroy a surviving colliding tenant's session. Same
	// operational meaning as the other delete suppressors: counted,
	// visible leak over invisible teardown.
	DeletesSuppressedScopedPolicy atomic.Uint64
	// InstallsSuppressedNoPeerInstallTable counts outgoing STAMPED session
	// installs WITHHELD because the peer advertised its capabilities and
	// did NOT claim #9752 install-table identity
	// (capFlagInstallTableIdentity). Such a peer installs every session
	// stamp-less, so our stamped install would silently wrong-table after
	// failover. Withholding leaves the session off the peer — a later miss
	// there re-establishes it in the right table — instead of installing a
	// lie. Unstamped installs are never withheld. Same operational meaning
	// as the delete suppressors: counted, visible gap over silent corruption.
	InstallsSuppressedNoPeerInstallTable atomic.Uint64
	// InstallsSuppressedIpsecDiscriminator counts outgoing IPsec
	// (S9.4 class-3 discriminator) session installs WITHHELD because
	// the peer did not advertise capFlagIpsecTunnelDiscriminator or
	// its capabilities are not yet learned (#17113). Such a peer
	// cannot preserve the IPsec if_id discriminator, so sending the
	// install would alias it onto another tunnel's key. Same
	// operational meaning as the other install suppressor: counted,
	// visible gap over silent corruption.
	InstallsSuppressedIpsecDiscriminator atomic.Uint64
	// DeletesStaleIgnored counts deletes refused by the #2170 install-
	// generation guard: a journaled/deferred delete whose generation was
	// strictly older than the currently-installed same-key entry. A nonzero
	// value means the guard prevented a stale delete from killing a live
	// same-5-tuple replacement session.
	DeletesStaleIgnored atomic.Uint64
	// InstallsStaleIgnored counts session installs refused because their
	// generation was strictly older than the currently-stored entry — the
	// delayed-stale-install variant (#2170 SMR C3). Refusing these keeps
	// the per-key stored generation monotonic so a later stale delete can
	// still be matched and refused.
	InstallsStaleIgnored atomic.Uint64
	// SessionsStaleConfigIgnored counts session installs refused by the #5274
	// config-epoch guard: the peer stamped the session with the config-sync
	// generation (#3931) it held at admit time, and that epoch was strictly
	// OLDER than this node's lastAppliedConfigGen — i.e. the peer has since
	// committed (and this node applied) a newer config that may DENY the
	// session. Refusing the install prevents a stale PERMIT from landing after
	// this node's clearSessionsForDeletedPolicies sweep for the newer config
	// (the immediate-policy-invalidation gap across the HA boundary).
	SessionsStaleConfigIgnored atomic.Uint64
	// GenMapOverflow counts how many times a #2170 generation map (sender
	// echo or receiver stored) was at its effective cap and a NEW key therefore
	// could not be recorded (#2198 F1). The key degrades to gen-0 (safe,
	// unconditional) behavior. A nonzero value means a churn workload pushed
	// a generation map to its cap; the map is never cleared, so existing live
	// keys retain their stored generation and the guard stays correct for
	// them.
	GenMapOverflow atomic.Uint64
	// GenTombstonesEvicted counts receiver-side delete tombstones evicted, oldest
	// first, to record a NEW key in a generation map at its effective cap (#9719).
	// A tombstone never frees its entry, so without the eviction a long-lived
	// connection filled the map with tombstones of closed sessions and switched
	// the ordering guards off for every new session until the next bulk. A
	// nonzero value means churn reached the cap between two bulks.
	GenTombstonesEvicted atomic.Uint64
	// GenCapGrown counts generation-guard cap doublings (#9915 F-044): a map
	// full of LIVE entries grew its side cap instead of skip-recording.
	// Nonzero means live demand exceeded the starting default.
	GenCapGrown atomic.Uint64
	// GenCapShrunk counts generation-guard cap clamp-downs (#9915 F-044
	// review): the wired ceiling dropped below a grown side cap and the stored
	// cap was clamped to the ceiling in force. Nonzero means provisioned
	// capacity shrank (fewer helper workers) after demand had grown past it.
	GenCapShrunk atomic.Uint64
	// AuthUpgradeIdentityErrors counts #6628/#7163 upgrade attempts refused
	// because the LOCAL cluster/node identity could not be resolved (#9915
	// F-043 review): every attempt fails the same way until the identity is
	// fixed, so the count names a misconfiguration, not peer behavior. The
	// connection is deliberately left as-is (see the upgrade handlers); the
	// next commit retries and heals on repair.
	AuthUpgradeIdentityErrors atomic.Uint64
	// PreAuthRejected counts inbound sync connections dropped by the #5303
	// pre-auth admission cap: a connection accepted while the pre-auth setup
	// pool was saturated (a flood of connections that stall before
	// authentication). Excess connections are closed immediately and never
	// allocate the large session-sync socket buffers. A nonzero value means the
	// cap absorbed a connection flood on the sync/control network; the reserved
	// tail (preAuthPeerReserve) still admits the legitimate peer's reconnect.
	PreAuthRejected atomic.Uint64
	// PreAuthHandshakeFailed counts connections dropped because the
	// pre-auth handshake failed (#16748): garbage/bad-magic frames,
	// wrong PSK, or a stalled handshake on an admitted connection.
	// Every failure increments it, so the rate-independent observable
	// reflects all rejections even though the WARN is rate-limited.
	PreAuthHandshakeFailed atomic.Uint64
	Connected              atomic.Bool
	BulkSyncStartTime      atomic.Int64
	BulkSyncEndTime        atomic.Int64
	BulkSyncSessions       atomic.Uint64
	LastConfigSyncTime     atomic.Int64
	LastConfigSyncSize     atomic.Uint64
	LastFenceSeq           atomic.Uint64
	LastFenceAckAt         atomic.Int64
}

// SyncStatsSnapshot is a point-in-time copy of SyncStats with plain
// non-atomic fields, safe to copy by value and pass across API boundaries.
type SyncStatsSnapshot struct {
	SessionsSent uint64
	// SweepSessionsSent is the mirror-sweep SUB-TOTAL of SessionsSent (#7842).
	SweepSessionsSent uint64
	SessionsReceived  uint64
	// MalformedRecordsDropped is the #7175/#10724 rejected-record counter:
	// descriptor-driven via syncStatFields (#17107) so it cannot again be
	// counted in SyncStats yet absent from every operator surface.
	MalformedRecordsDropped   uint64
	SessionsInstalled         uint64
	DeletesSent               uint64
	DeletesReceived           uint64
	BulkSyncs                 uint64
	ConfigsSent               uint64
	ConfigsReceived           uint64
	ConfigsSentCleartext      uint64
	ConfigsReceivedCleartext  uint64
	CleartextSyncAlarmLatched bool
	ConfigsStaleIgnored       uint64
	// #5084 observability. A fail-open fence is silent by construction, so
	// both halves are counted: primes that arrived without an incarnation
	// (the peer is old, or half-upgraded and hiding), and payloads dropped
	// because their incarnation was replaced (the fence doing its job).
	BulkPrimesWithoutIncarnation   uint64
	ConfigsDeadIncarnationDropped  uint64
	BulkEndsDeadIncarnationDropped uint64 // #9174 V013
	ClockSyncsRefused              uint64 // #9653
	RebaseSaturations              uint64 // #9915 F-118
	BulkEndsForeignConnDropped     uint64 // #9716
	BulkEndsEpochOnlyMatched       uint64 // #9716
	BulkRecvCapped                 uint64 // #16039
	BulkRecvAborted                uint64 // #16039
	// PeerBootIncarnation renders the boot id of the peer incarnation that
	// most recently primed, or "none". It travels in the snapshot rather than
	// through a new Manager accessor because the Manager holds only the
	// SyncStatsProvider interface, and this is the same transport every other
	// field in the status render already uses.
	PeerBootIncarnation     string
	ConfigsApplyFailed      uint64
	ImportsRefusedByHelper  uint64
	ImportsRejectedByHelper uint64
	// #6778 receive-edge loss, and #7328's nack counter alongside it: the
	// queue-full drop is recovered BY a nack, so a drop that is climbing while
	// nacks are not tells the operator the recovery path itself is broken (a
	// pre-#7328 peer, or a nack that never matched the current config-debt
	// generation). Both are rendered only when nonzero.
	ConfigsQueueFullDropped              uint64
	ConfigApplyNacksReceived             uint64
	ConfigApplyAcksSent                  uint64
	ConfigApplyAcksUnsent                uint64
	ConfigApplyAcksCredited              uint64
	ConfigApplyAcksIgnored               uint64
	BulkRerequestsSent                   uint64
	IPsecSASent                          uint64
	IPsecSAReceived                      uint64
	IPsecSAStaleIgnored                  uint64
	IPsecSAMalformedIgnored              uint64
	IPsecSAOversizeAlarmLatched          bool
	IPsecSAOverCapSets                   uint64
	DHCPLeasesSent                       uint64
	DHCPLeasesReceived                   uint64
	DHCPLeasesStaleIgnored               uint64
	DHCPLeasesSeeded                     uint64
	DHCPLeasesDroppedNoIdentity          uint64 // #9915 F-117
	GenGuardSessionCap                   uint64 // #9915 F-044 wired helper capacity (0 = unwired)
	FencesSent                           uint64
	FencesReceived                       uint64
	FenceAcksSent                        uint64
	FenceAcksReceived                    uint64
	FenceAcksTimedOut                    uint64
	Errors                               uint64
	DeletesDropped                       uint64
	PreKeyAuthEvictions                  uint64
	DeletesSuppressedPeerIncapable       uint64
	DeletesSuppressedPurgeRetirement     uint64
	DeletesSuppressedScopedPolicy        uint64
	InstallsSuppressedNoPeerInstallTable uint64
	InstallsSuppressedIpsecDiscriminator uint64
	DeletesStaleIgnored                  uint64
	InstallsStaleIgnored                 uint64
	SessionsStaleConfigIgnored           uint64
	GenMapOverflow                       uint64
	GenTombstonesEvicted                 uint64 // #9719
	GenCapGrown                          uint64 // #9915 F-044
	GenCapShrunk                         uint64 // #9915 F-044 review
	AuthUpgradeIdentityErrors            uint64 // #9915 F-043 review
	PreAuthRejected                      uint64
	PreAuthHandshakeFailed               uint64 // #16748
	OversizeFramesRefused                uint64 // #16041 per-type payload cap refusals
	Connected                            bool
	ActiveFabric                         int
	BulkSyncStartTime                    int64
	BulkSyncEndTime                      int64
	BulkSyncSessions                     uint64
	LastConfigSyncTime                   int64
	LastConfigSyncSize                   uint64
	LastFenceSeq                         uint64
	LastFenceAckAt                       int64
}

// TransferReadinessSnapshot captures session-sync state that determines whether
// manual failover can proceed without depending on bootstrap timing.
//
// #5563: it also carries the config-sync generations so a planned/manual
// failover refuses to promote a config-stale standby. PeerConfigGen is the
// highest config generation this node has RECEIVED from the peer (the config
// sender's current committed generation as observed by the receiver);
// AppliedConfigGen is the highest generation this node has SUCCESSFULLY
// applied. When PeerConfigGen > AppliedConfigGen the standby is running an
// older policy/zone/application snapshot than the primary committed —
// promoting it fail-opens after a tightening commit and false-denies after a
// loosening commit.
type TransferReadinessSnapshot struct {
	Connected           bool
	PendingBulkAckEpoch uint64
	PendingBulkAckAge   time.Duration
	BulkAckRetryOwed    bool
	// BulkIncomplete is #16039 readiness debt: a bulk window aborted
	// by the cap or deadline. It keeps ReadyForManualFailover false
	// until a later bulk reconciles successfully.
	BulkIncomplete        bool
	BulkReceiveInProgress bool
	BulkReceiveEpoch      uint64
	BulkReceiveSessions   int
	PeerConfigGen         uint64
	AppliedConfigGen      uint64
}

// ConfigStale reports whether this node has received a newer config generation
// from the peer than it has successfully applied — i.e. it is behind the
// primary's committed config. A legacy peer (or a fresh node that has neither
// received nor applied any generation) reports both generations as 0, which is
// NOT stale, so the gate stays scoped to the genuine behind-the-primary case
// and never blanket-blocks (#5563).
func (s TransferReadinessSnapshot) ConfigStale() bool {
	return s.PeerConfigGen > s.AppliedConfigGen
}

// ReadyForManualFailover reports whether the sync path is settled enough to
// use as a manual-failover transport without waiting for bootstrap work.
//
// #5563: a standby that has received a newer config generation than it has
// applied is refused — a planned/manual promotion must not run a stale
// security policy. The unplanned/crash failover path is a separate
// availability-vs-security tradeoff and is NOT gated here.
func (s TransferReadinessSnapshot) ReadyForManualFailover() bool {
	return s.PendingBulkAckEpoch == 0 && !s.BulkAckRetryOwed &&
		!s.BulkReceiveInProgress && !s.BulkIncomplete && !s.ConfigStale()
}

// Reason explains the current transfer-readiness blocker, if any.
func (s TransferReadinessSnapshot) Reason() string {
	switch {
	case s.PendingBulkAckEpoch != 0:
		age := s.PendingBulkAckAge
		if age < 0 {
			age = 0
		}
		return fmt.Sprintf("peer still receiving outbound bulk epoch=%d age=%s", s.PendingBulkAckEpoch, age.Round(100*time.Millisecond))
	case s.BulkAckRetryOwed:
		return "outbound authoritative bulk retry is owed"
	case s.BulkReceiveInProgress:
		return fmt.Sprintf("local bulk receive still in progress epoch=%d sessions=%d", s.BulkReceiveEpoch, s.BulkReceiveSessions)
	case s.BulkIncomplete:
		return fmt.Sprintf("local bulk receive aborted epoch=%d; awaiting successful bulk reconcile", s.BulkReceiveEpoch)
	case s.ConfigStale():
		return fmt.Sprintf("standby config stale: applied gen=%d behind peer committed gen=%d", s.AppliedConfigGen, s.PeerConfigGen)
	default:
		return ""
	}
}

// SessionSync manages TCP-based session state replication between cluster
// peers for stateful failover.
//
// # Lock-order graph (#16159 PR-0 — the gate for the sub-struct extraction)
//
// Every SessionSync mutex, what it guards, and every nesting edge. An edge
// A -> B means a site acquires B while holding A. The graph must stay
// acyclic; a new edge that closes a cycle is a deadlock, not a style issue.
// This comment is pinned by TestSessionSyncLockOrderGraphPinned16159
// (sync_gen_state_16159_test.go), which source-scans the mutex set and the
// documented edges — update this graph in the same commit as any lock or
// nesting change or that test reds.
//
// Mutexes (guard domain in parentheses):
//
//	mu (conn registry, incarnation stamps, configCrypto, peer-incarnation
//	  state, peerSnaps.peerSnapshotProtocolGeneration)
//	writeMu (wire seal+write serialization on a conn)
//	preAuthMu (pre-auth admission: preAuthInFlight, setupConns, peerIPs)
//	queuedFrameMu (queued-frame watermarks)
//	peerSnaps.peerIPsecSAsMu (held IPsec SA set)
//	peerSnaps.peerDHCPLeasesMu (held DHCP lease snapshots)
//	peerSnaps.peerSnapshotProtocolWriteMu (capability-incarnation changes
//	  vs config-send debt sampling and final writes on both config paths)
//	fenceAckMu (fenceAckWaiters)
//	zoneRGMu (zoneRGMap, foldRGMap, zoneRGMapGen; RWMutex)
//	deleteJournalMu (deleteJournal, scopedDeleteJournal)
//	bulkStartMu (table-truth snapshot -> BulkStart boundary)
//	bulkSendMu (bulk send serialization)
//	bulkSnapshotGenMu (authoritative snapshot read vs delete-gen draws)
//	bulkMu (bulk receive window)
//	barrierWaitMu (barrierWaiters)
//	failoverWaitMu (failover waiters)
//	genState.genSentMu (sender generation stamps + sent identity memos)
//	genState.recvGenMu (receiver generations, tombstones + recv memos)
//	applyMu (receive-side session apply serialization, #9715)
//	configEpochRoleMu (config-epoch role/floor)
//	configGenMu (config-generation marks; LEAF — see its field comment)
//	configApplyMu (config-apply health streak)
//	recvSeqMu (full-set sequence guards, recvEpoch)
//	persistentNatLeaseApplyMu (persistent-NAT lease commit order)
//	ipsecApplyMu (IPsec full-set commit order)
//	dhcpApplyMu (DHCP full-set commit + chunk state)
//	configApplyDebtMu (send generation + capability snapshot; leaf)
//
// Nesting edges (holder -> acquired). Pin tokens in [brackets] are the
// exact substrings the pin test searches for in this comment:
//
//	[mu -> peerSnapshotProtocolWriteMu] install/capability paths replace
//	  the advertised protocol under mu, then serialize against config writes;
//	  the gated writer takes this mutex under mu and releases mu while holding
//	  it over write. The ungated writer never acquires mu while holding it.
//	[peerSnapshotProtocolWriteMu -> writeMu] both config writers sample and
//	  publish send debt, then perform the socket write under this lock order.
//	[peerSnapshotProtocolWriteMu -> configApplyDebtMu] both config writers
//	  publish send debt while serializing peer-incarnation capability changes.
//	[writeMu -> configApplyDebtMu] the ungated writer publishes debt while
//	  holding writeMu; the guarded writer does not hold writeMu during publish.
//	[mu -> configApplyDebtMu] the config-apply ACK handler reads the debt
//	  snapshot while holding mu; configApplyDebtMu does not acquire another lock.
//
//	[mu -> fenceAckMu] handleDisconnect/installConn hold mu and take
//	  fenceAckMu to release scoped fence waiters.
//	[bulkSnapshotGenMu -> genSentMu] takeDeleteGen* linearizes a queue-time
//	  delete draw against an authoritative snapshot read.
//	[bulkSnapshotGenMu -> recvGenMu] the same critical sections consult
//	  the receiver guard while holding genSentMu (delete path only).
//	[genSentMu -> recvGenMu] stampInstallGen* nests recvGenMu inside
//	  genSentMu; recvGenMu never nests genSentMu. The install-table memo
//	  restore documents the same direction as a leaf-ward nesting.
//	[applyMu -> recvGenMu] every install/delete apply holds applyMu from
//	  the guard through the dataplane write; nothing takes applyMu while
//	  holding recvGenMu, bulkMu or configGenMu.
//	[dhcpApplyMu -> recvSeqMu] each DHCP arm advances its full-set guard
//	  and stores the held set (peerSnaps.peerDHCPLeasesMu, taken inside
//	  the commit) under dhcpApplyMu; recvSeqMu is never held across the
//	  OnDHCPLeasesReceived callback.
//	[ipsecApplyMu -> recvSeqMu] IPsec commits serialize with the sequence
//	  advance the same way (peerSnaps.peerIPsecSAsMu inside the commit).
//	[persistentNatLeaseApplyMu -> recvSeqMu] persistent-NAT lease commits
//	  follow the identical full-set commit order.
//	[recvSeqMu -> peerDHCPLeasesMu] the DHCP commit advances the guard
//	  and stores the held set in one recvSeqMu section (sync_lease_recv.go).
//	[dhcpApplyMu -> peerDHCPLeasesMu] via the commit above; the lease
//	  store is the innermost lock and never acquires another.
//
// Leaf locks (acquire no other SessionSync mutex while held): preAuthMu,
// queuedFrameMu, zoneRGMu, deleteJournalMu, bulkSendMu,
// barrierWaitMu, failoverWaitMu, configGenMu, configApplyMu,
// configEpochRoleMu, fenceAckMu, configApplyDebtMu,
// peerSnaps.peerIPsecSAsMu,
// peerSnaps.peerDHCPLeasesMu. Atomics (genState.genCounter,
// genState.genGuardSessionCap, and the *SeqCounter / epoch fields) are
// lock-free by design: genGuardSessionCap is atomic precisely so the
// daemon tick never contends the guard mutexes it gates.
//
// Sub-struct boundaries (#16159): genState (sessionGenState) owns
// genSentMu/recvGenMu and every field they guard; peerSnaps
// (peerSnapshotState) owns peerIPsecSAsMu/peerDHCPLeasesMu/
// peerSnapshotProtocolWriteMu and the fields they guard, except
// peerSnapshotProtocolGeneration which stays under mu with the
// incarnation state it binds to. A sub-struct method must never acquire
// a SessionSync lock outside its own domain while holding a domain lock;
// cross-domain work goes through the existing *SessionSync forwarding
// methods, which keep their names and signatures.
type SessionSync struct {
	// strictSessionAuth records the legacy #7441 node-local config leaf. The
	// value is retained for compatibility and reporting, but keyed-node
	// unauthenticated connection eviction no longer depends on it.
	strictSessionAuth strictSessionAuthState

	// configureConn is the PER-INSTANCE seam for the #5303 buffer deferral,
	// replacing a package-level function variable (#8182).
	//
	// The package-level version was a shared global that a test SWAPPED and
	// restored with defer, and the assertion built on it is a NEGATIVE — "this
	// must not have been called". pkg/cluster has 36 t.Parallel() calls and
	// seven test files that reach handleNewConnection, so a parallel sibling
	// completing a successful handshake while the swap was installed satisfied
	// the hook and reddened the assertion. The failure was a FALSE NEGATIVE for
	// the property under test: the deferral was intact.
	//
	// That is worse than an annoyance. A negative assertion over shared global
	// state cannot distinguish "the deferral was reverted" from "a neighbour
	// ran", so a real revert of #5303 would have been indistinguishable from
	// the noise and waved through by the same re-run reflex the noise trains.
	//
	// Nil means the production behaviour: see configureSyncConn. It is written
	// only before the connection goroutines that read it start, so the `go`
	// statement supplies the happens-before edge and no lock is needed — this
	// field is deliberately NOT under mu, which the connection paths already
	// hold when they reach the call site.
	configureConn func(net.Conn)

	localAddr string
	peerAddr  string
	sessions  dataplane.SessionStore
	telemetry dataplane.Telemetry
	stats     SyncStats

	// malformedRecordWarn is the #10724 detector bounding the "dropping
	// malformed session record" warnings (v4/v6 arms in sync_conn_read.go).
	// The receive path runs per record, so an unguarded Warn lets a corrupt
	// or hostile peer flood the log (CLAUDE.md logging rules). Shape mirrors
	// monitorTruncationDetector: the per-record count advances on every
	// occurrence via stats.MalformedRecordsDropped, while the log emits once
	// per family per SessionSync lifetime. Zero value ready; SessionSync is
	// never copied (it already holds a Mutex and atomics).
	malformedRecordWarn malformedRecordWarnDetector
	mu                  sync.Mutex
	conn0               net.Conn // written only via setConnSlotLocked
	conn1               net.Conn // written only via setConnSlotLocked
	// connSlotRemovals counts installed connections removed from a fabric
	// slot (#18521 review round 2); see setConnSlotLocked.
	connSlotRemovals atomic.Uint64
	// peerEventTail orders the OnPeerConnected / OnPeerDisconnected
	// dispatches (#18521 review round 3); see dispatchPeerEvent.
	peerEventMu   sync.Mutex
	peerEventTail chan struct{}
	// configCrypto0/configCrypto1 hold the per-connection ephemeral X25519
	// state that encrypts the config-sync payload (#6629). They sit here,
	// beside the conn they belong to and under the same mu, because their
	// lifetime is exactly a connection's: installConn replaces the slot's
	// state with a freshly generated keypair and handleDisconnect clears it,
	// which is what makes a reconnect derive a different key.
	configCrypto0 *configCryptoState
	configCrypto1 *configCryptoState
	// peerBootIncarnation is the boot id of the peer incarnation that most
	// recently primed (#5084). Zero means no incarnated prime has been seen —
	// an old peer, or none yet — and puts the fence in its fail-open state.
	// Guarded by mu, beside the connections whose primes set it.
	//
	// Compared for EQUALITY only. It is an equivalence class ("same peer
	// boot?"), never a ranking; ordering two of these is the mistake #6900
	// made and cannot express the predicate.
	peerBootIncarnation bootIncarnation
	// peerIdentity is the process identity of the peer incarnation that is
	// currently authoritative. It is set by an accepted BulkStart (#15274:
	// on every accepted prime whose connection carries a proven identity,
	// not only the first incarnated prime) and cleared on full disconnect,
	// and is deliberately distinct from peerBootIncarnation: the latter is a legacy
	// boot-id fence, while this also carries the ordered daemon boot epoch
	// (#9818). Guarded by mu.
	peerIdentity peerProcessIdentity
	// peerIncarnation identifies which run of the peer process the currently
	// installed connections belong to, and conn0Gen/conn1Gen record the
	// incarnation each slot's connection was installed under. All three are
	// guarded by mu, alongside the conn0/conn1 they describe.
	//
	// #5718 C01a (fold F1b): slot membership alone cannot answer "does this
	// connection speak for the CURRENT peer incarnation?" once there are TWO
	// fabric slots. A peer that reboots hard sends no FIN/RST, so BOTH of its
	// connections stay ESTABLISHED on our side; its new process dials in and
	// supersedes one slot, and the OTHER slot still holds the dead
	// incarnation's connection. An `s.conn0 == conn || s.conn1 == conn` test
	// accepts an in-flight heartbeat-ack off that survivor and re-arms the
	// capability the supersession just cleared — the previous incarnation
	// enforced against the current one, which is the whole defect. Stamping
	// each slot at install and comparing the stamp to peerIncarnation binds an
	// ack to the incarnation it belongs to rather than to slot membership.
	//
	// The counter advances when a supersession replaces a connection that
	// belonged to the CURRENT incarnation — evidence a new peer process took
	// over. A supersession that merely evicts an ALREADY-STALE connection (the
	// new incarnation reclaiming the second slot) is not a further incarnation
	// change and must not advance it, or the connection that legitimately
	// proved the capability would be stranded stale and could never re-arm.
	//
	// #9818 closes the previously accepted residual. A connection that
	// announces a newer process identity before retirement is re-stamped and
	// kept; an announced retired identity, or an unattributed connection, is
	// still evicted as a corpse. Unknown identity remains fail-open only until
	// the retirement decision, so genuinely dead legacy connections preserve
	// the old behavior.
	peerIncarnation uint64
	conn0Gen        uint64
	conn1Gen        uint64
	writeMu         sync.Mutex
	// conn0Announced/conn1Announced record whether the install of the
	// connection in that slot dispatched OnPeerConnected (#9636), so a
	// BulkStart that later retires the prior incarnation on the same
	// connection does not dispatch it a second time. Every install of a slot
	// overwrites it, and it is read only for a connection still installed
	// there. Guarded by mu.
	conn0Announced bool
	conn1Announced bool
	// authProvider supplies the shared control-link PSK for #4107 F23
	// session-sync stream auth. Optional: nil (or an empty key) ⇒ legacy
	// unauthenticated stream.
	//
	// #5078: a sticky syncAuthedEver downgrade-guard used to sit beside this.
	// It was removed with syncPeerAuthSeen — once a keyed node rejects every
	// unkeyed peer unconditionally, there is no admission for such a guard to
	// withdraw, and it had become write-only in effect.
	authProvider atomic.Pointer[syncAuthProviderBox]

	// #5303 pre-auth admission gate. Bounds the inbound sync connections that
	// are in setup (pre-handshake) at once so a flood of connections that stall
	// before authentication cannot exhaust FDs/goroutines/socket-memory and deny
	// a legitimate peer's reconnect. preAuthInFlight counts admitted-but-not-yet-
	// resolved inbound setups; setupConns tracks EVERY connection currently in
	// its pre-wire setup window (inbound AND outbound) so Stop() can close them
	// and unblock a stalled handshake — the bool value records whether the entry
	// holds a counted inbound admission slot. preAuthLogMono rate-limits the
	// rejection warning to ~1/sec; preAuthHandshakeLogMono does the same for
	// the handshake-failure warning (#16748). The counters are guarded by
	// preAuthMu; the mono fields are atomics.
	// peerIPs is the construction-time resolved cache of the configured peer
	// addresses (#14371): literals via parseAddrIP, hostnames resolved once
	// (all v4+v6 answers). Written only by the constructors via refreshPeerIPs
	// before any connection goroutine starts; read by isPeerRemote under
	// preAuthMu. Nil on a zero-value SessionSync (literal fallback).
	preAuthMu       sync.Mutex
	preAuthInFlight int
	setupConns      map[net.Conn]bool
	preAuthLogMono  atomic.Int64
	// preAuthHandshakeLogMono rate-limits the handshake-failure WARN
	// to ~1/sec (#16748), independently of the admission-cap WARN so
	// one flood class cannot starve the other's diagnostics.
	preAuthHandshakeLogMono atomic.Int64
	peerIPs                 map[netip.Addr]struct{}

	listener   net.Listener
	localAddr1 string
	peerAddr1  string
	listener1  net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	sendCh     chan []byte // buffered channel for outgoing messages
	// queuedFrameMu protects the accepted/resolved watermark used by an
	// authoritative table-truth bulk. Producers increment queuedFrameSeq while
	// enqueuing; sendLoop increments queuedFrameStarted when it owns
	// bulkStartMu/writeMu for a frame and queuedFrameResolved after a frame is
	// delivered or abandoned (and queuedFrameFailures records the latter).
	// BulkStart snapshots the sequence and failure count while holding this
	// mutex, so the watermark is an exact pre-marker cut and a failed frame
	// aborts rather than allowing an incomplete authoritative window to
	// reconcile.
	queuedFrameMu       sync.Mutex
	queuedFrameSeq      uint64
	queuedFrameStarted  uint64
	queuedFrameResolved uint64
	queuedFrameFailures uint64

	// incrementalPauseDepth temporarily pauses background incremental producers
	// during ordered handoff operations.
	incrementalPauseDepth atomic.Int32

	// OnPeerCapabilitiesChanged fires after a peer capability advertisement is
	// decoded. Callers use it to re-arm capability-gated sidecars that may have
	// been queued before discovery.
	OnPeerCapabilitiesChanged func()
	// OnConfigReceivedWithAncestry is the additive callback for config payloads
	// carrying rename provenance. It is preferred over the legacy text-only
	// callback; OnConfigReceivedWithProvenance takes precedence when wired.
	OnConfigReceivedWithAncestry func(configText string, ancestry []configstore.RenameDescriptor) error
	// OnConfigReceivedWithProvenance receives the per-frame authentication state
	// captured from the connection whose verified config frame carried the
	// payload. It takes precedence over the legacy callbacks when wired.
	OnConfigReceivedWithProvenance func(configText string, ancestry []configstore.RenameDescriptor, authenticated bool) error
	// OnConfigReceived is called when a config sync message arrives from the
	// peer. It returns nil ONLY when the config was actually applied (or is
	// already the active config); a non-nil error means the apply did not take
	// effect (a compile/promote failure, or a transient RG0-primary rejection).
	// The single-consumer configApplyLoop advances the config high-water mark
	// (lastAppliedConfigGen) ONLY on a nil return, so an apply failure leaves
	// the standby eligible for the primary's re-push instead of silently
	// stranded on the prior config (M-2/#4151).
	OnConfigReceived func(configText string) error
	// OnConfigApplyHealth reports the config-sync APPLY health edge (#6387).
	// failing=true fires (once per streak) when a received config generation
	// has stayed un-applied — apply hard-failing, high-water pinned per
	// M-2/#4151 — for longer than the stale-duration grace
	// (configApplyFailGrace); the raise is driven by an independent grace-expiry
	// timer so a STABLE connection with one persistent apply failure surfaces CF
	// without a second delivery. failing=false fires on EVERY successful apply
	// (an idempotent clear), NOT only the first success after a local raise:
	// a comms transport change tears down this SessionSync but keeps the cluster
	// Manager, so the replacement instance must be able to clear a CF the OLD
	// instance raised — gating the clear on this instance's own local raised
	// flag would leave the manager annotation stuck forever. reason is the raw
	// apply error on a raise (the Manager sanitizes/bounds it before storage)
	// and empty on a clear. The daemon wires this to Manager.SetConfigSyncHealth
	// so a persistently stranded standby surfaces as a CF monitor-failure /
	// degraded health instead of only the terse `Transfer ready: no` string.
	// Diagnostic only — it NEVER gates failover.
	OnConfigApplyHealth func(failing bool, reason string)
	// OnPeerConfigApplyFailed reports that the PEER refused or failed to apply
	// the config generation this node most recently sent (#7328). It fires on
	// the sender when a syncMsgConfigApplyNack arrives whose generation matches
	// `lastSentConfigDebt16756.generation` — a nack for any other generation
	// is a straggler for a push this node has already superseded and is ignored.
	//
	// The daemon wires this to invalidate the #5863 (epoch x generation) push
	// marker, which is the ONLY thing standing between the standby and the
	// re-push #4151 leaves it eligible for. The handler deliberately does NOT
	// push inline: it clears the marker and lets the ordinary reconcile tick
	// re-push, so a failure that recurs instantly cannot become a
	// push/fail/nack tight loop. That bounds the retry to the reconciler's
	// cadence, which is the same rate #5863's marker exists to protect.
	//
	// It fires ONLY on a failed apply. A successful apply sends no nack, so the
	// marker stands and a healthy connection still pushes a generation exactly
	// once — the #5863 no-storm property is preserved.
	OnPeerConfigApplyFailed func(gen uint64)
	// OnPeerConfigApplyAck reports that the PEER positively acknowledged
	// applying config generation gen (#15212). It fires on the sender when a
	// syncMsgConfigApplyAck advances peerAppliedConfigGen. The daemon wires
	// this to clear the #9530 unshared mark only when the ACK is at or beyond
	// the carrying generation of the marked content; a NACK never clears it.
	OnPeerConfigApplyAck func(gen uint64)
	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
	OnIPsecSAReceived func(connectionNames []string)
	// OnDHCPLeasesReceived is called when a DHCP-server lease set arrives from
	// the peer (#2239). family is 4 or 6; the standby holds these so it can
	// seed Kea on takeover. Fires after the peer*DHCPLeases store is updated.
	// Invoked synchronously within the DHCP apply mutex (commit order ==
	// callback order, #9915 F-117 review): it must not reenter DHCP receive
	// paths. No production consumer exists — the daemon flows via the held set.
	OnDHCPLeasesReceived func(family int, leases []dhcpserver.SyncLease)
	// OnPersistentNatLeasesReceived is called for one sender-originated idle
	// lease batch. Its durable clear generation is interpreted by the daemon's
	// userspace manager before any record reaches the helper.
	OnPersistentNatLeasesReceived func(batch userspace.PersistentNatLeaseBatch)
	// OnRemoteFailover is called when the peer requests a transfer-out for one RG.
	// reqID is the request-scoped identifier carried on the wire; the demoted
	// owner binds its auto-restore lease to it so a stale commit cannot clear a
	// newer request's lease (#5079).
	OnRemoteFailover func(rgID int, reqID uint64) error
	// OnRemoteFailoverCommit finalizes the demoted side of an acknowledged handoff.
	// reqID identifies the request being committed so the owner can clear the
	// matching auto-restore lease (#5079).
	OnRemoteFailoverCommit func(rgID int, reqID uint64) error
	// OnRemoteFailoverAbort restores this node after an abandoned transfer,
	// including a failed fence or request-ACK timeout (#15164/#16592).
	// reqID-bound, so a stale abort cannot restore a newer request's hold.
	OnRemoteFailoverAbort func(rgID int, reqID uint64) error
	// OnRemoteFailoverAbortBatch is the multi-RG form.
	OnRemoteFailoverAbortBatch func(rgIDs []int, reqID uint64) error
	// OnRemoteFailoverBatch is called when the peer requests a multi-RG transfer-out.
	OnRemoteFailoverBatch func(rgIDs []int, reqID uint64) error
	// OnRemoteFailoverCommitBatch finalizes a previously acknowledged multi-RG handoff.
	OnRemoteFailoverCommitBatch func(rgIDs []int, reqID uint64) error
	// WaitFailoverApplied, if set, blocks until the local node has ACTUATED
	// the transfer-out just requested via OnRemoteFailover for one RG — i.e.
	// the async demotion event has been consumed and the old owner fenced
	// (VRRP resignation signalled and priority driven to 0, or direct VIP
	// ownership reconciled away, plus rg_active cleared). On the RETH-VRRP
	// path the physical VIP removal runs on the VRRP instance's own loop and
	// is NOT waited for here (#6177 item 1). It gates the failoverAckApplied
	// reply: the applied-ack is the requester's authorization to run
	// commitRequestedPeerFailover, so acking applied before this barrier
	// opened a two-owner window (duplicate GARP / VIP ownership / traffic)
	// — #5640. OnRemoteFailover only ENQUEUES the demotion event and
	// returns. A non-nil error (fence not actuated within the daemon's
	// bounded timeout) downgrades the ack to failoverAckFailed; the sync
	// layer restores this owner and the requester records the aborted
	// request so its election refuses "Peer transfer out" for that hold
	// (#16592 — a failed ack alone never held the requester, which
	// promotes on the secondary-hold heartbeat).
	//
	// reqID is the same request identifier passed to OnRemoteFailover, so the
	// daemon can wait on the barrier THAT request armed rather than on
	// whatever barrier the RG happens to hold (#6177).
	WaitFailoverApplied func(rgID int, reqID uint64) error
	// WaitFailoverAppliedBatch is the multi-RG counterpart of
	// WaitFailoverApplied: it blocks until every RG in the batch has been
	// fenced before the batch failoverAckApplied reply is sent (#5640). reqID
	// identifies the batch request whose barriers are being waited on (#6177).
	WaitFailoverAppliedBatch func(rgIDs []int, reqID uint64) error
	// TransferOutStillHeld reports, at the moment the applied-ack would be
	// sent, whether every RG in rgIDs is still parked for request reqID:
	// its remote transfer-out lease is armed for reqID, its manual hold is
	// set and it is not primary (#18521 review round 3). A hold released
	// while the demotion was actuating — the 2s rescue after the request's
	// connection went away — means the owner may be primary again, and an
	// "applied" sent then would promote the requester beside it. Nil = no
	// check (tests that do not model the Manager).
	TransferOutStillHeld func(rgIDs []int, reqID uint64) bool
	// OnFenceReceived requests this node to disable all RGs, and reports what
	// that achieved so a sequenced fence can be acknowledged truthfully
	// (#7147). The returned FenceResult is encoded into syncMsgFenceAck; it is
	// ignored for an unsequenced (pre-#7147) fence.
	//
	// It is invoked SYNCHRONOUSLY on the receive loop and the ack is written
	// after it returns. That ordering is the whole guarantee: an ack sent
	// before the fence had been applied would confirm nothing.
	OnFenceReceived func() FenceResult
	// OnForwardSessionInstalled fires when a forward synced session is installed locally.
	OnForwardSessionInstalled func()
	// OnBulkSyncReceived fires when an inbound bulk sync completes.
	OnBulkSyncReceived func()
	// OnSessionInventoryBulkReceived fires after an authoritative inbound bulk
	// captured a pending inventory request and reconciled successfully.
	OnSessionInventoryBulkReceived func(generation uint64)
	// BulkSyncOverride, if set, runs as a best-effort fast-population pre-step
	// BEFORE the authoritative BulkSync in doBulkSync (it does NOT replace it,
	// #5085). It is NO LONGER wired in production — the async, lossy
	// event-stream export (#418) cannot delimit an authoritative reconcile
	// snapshot — and is retained only as a test/extension seam. doBulkSync
	// always ends with the lossless BulkSync window, so an override can never
	// reintroduce the empty-marker / skipped-reconcile regression.
	BulkSyncOverride func() error
	// BulkSnapshotSource, if set, supplies the authoritative cold-prime /
	// re-drive snapshot doBulkSync frames, REPLACING the backend session-store
	// walk BulkSync performs (#6031).
	//
	// BulkSync's ForEachV4/V6 walk reads the `sessions`/`sessions_v6` BPF
	// conntrack maps, which under the userspace dataplane are a best-effort
	// DISPLAY mirror, not the authoritative session set. Until #6965 the Rust
	// helper's transit forward install published only the shim steering map and
	// its shared session tables, never publish_bpf_conntrack_entry, so a TRANSIT
	// session was structurally absent from that walk; it is published now, but
	// the mirror is still a best-effort copy of a table the helper OWNS — a
	// publish that fails under map pressure is counted, not retried — so this
	// source stays non-authoritative however complete it becomes. Since #5085
	// made the
	// receiver reconcile authoritatively against the delimited window, framing
	// it from the mirror DELETES exactly the live peer-owned transit sessions
	// the standby needs at failover. A table-truth source closes that.
	//
	// The supplied snapshot is framed VERBATIM: doBulkSync does NOT re-apply
	// the ShouldSyncZone filter to it, because the caller already applies the
	// strictly more precise owner-RG filter the incremental delta path uses
	// (daemon shouldSyncUserspaceDelta). Re-filtering by zone could drop an
	// entry the incremental path admits — e.g. a fabric-redirect wire alias —
	// and every entry missing from the window is DELETED on the receiver. The
	// two paths must admit the same set; a divergence is always a bug.
	//
	// A source that returns an error FAILS CLOSED: doBulkSync returns the
	// error and frames NO window rather than falling back to the mirror walk.
	// Sending a known-incomplete authoritative window destroys live sessions;
	// sending none merely defers the reconcile, and every doBulkSync caller
	// leaves its cold-prime/resync obligation armed for the next retry.
	BulkSnapshotSource func() (BulkSnapshot, error)
	// OnBulkSyncAckReceived fires when the peer acknowledges our outbound bulk sync.
	OnBulkSyncAckReceived func()
	// OnPeerConnected fires when a peer sync connection is established.
	OnPeerConnected func()
	// OnPeerReconnected fires on every per-connection dispatch of
	// OnPeerConnected at the moved-policy layer (#17056): handleNewConnection
	// (sync_conn.go, only when shouldColdPrime) and the BulkStart reboot
	// switch (sync_bulkstart_recv.go, only when it announces a reboot the
	// install did not). The daemon's OnPeerConnected consumer is not
	// idempotent, so those callers keep their once-per-incarnation gating;
	// this hook is invoked at exactly those dispatch points so a reconnect
	// on the SAME SessionSync object resets the heartbeat-suppression cap
	// stamp on the Manager, restoring the pre-move per-connect reset that
	// publishing alone (once per comms epoch) cannot provide. Nil when no
	// Manager is bound (test doubles, embedders without a heartbeat).
	OnPeerReconnected func()
	// peerReconnectOwner is the Manager that installed OnPeerReconnected
	// via SetPeerSyncSource (#17056), or nil. It exists because func values
	// are not comparable: unpublish/republish must clear only the binding
	// the clearing Manager itself installed, never a successor's. Written
	// only under that Manager's mu at publish/unpublish, before the
	// connection goroutines that read OnPeerReconnected can dispatch for a
	// newly published source (wiring precedes Start).
	peerReconnectOwner *Manager
	// OnPeerDisconnected fires when all fabric connections are lost.
	OnPeerDisconnected func()
	IsPrimaryFn        func() bool
	// IsPrimaryForRGFn reports whether the local node is primary for a given RG.
	IsPrimaryForRGFn func(rgID int) bool
	// PeerBootEpochFn reports the peer's across-reboot boot-epoch floor and
	// whether the peer has PROVED it emits boot epochs (#7762).
	//
	// An injected callback rather than a clusterRuntime method, deliberately.
	// clusterRuntime is the DATAPLANE-BACKEND surface — its implementors are
	// *dataplane.Manager and *userspace.LegacyDataPlaneAdapter, and its own doc
	// warns that adding a method there gives SessionSync a new runtime
	// dependency. The boot epoch is cluster-Manager state on a different axis
	// (`d.cluster`, not `d.dataplane()`), so a dataplane backend cannot answer
	// it: every implementor would have to return 0, and 0 is exactly the silent
	// fail-open this classification must not have. Nineteen types implement
	// that method set, seventeen of them test doubles — seventeen new sites
	// defaulting to "no reboot" that no reader would recognise as a
	// classification input. This mirrors IsPrimaryFn/IsPrimaryForRGFn above,
	// which ask the same kind of cross-layer question of the same object.
	//
	// TWO return values, not one. An unlatched epoch reads as 0, and 0 is a
	// legal floor value ("none accepted yet"), so a single uint64 collapses
	// "the peer has not proved it emits epochs" into "no reboot has happened" —
	// silently, which is precisely what would make a broken fix here
	// indistinguishable from a working one. With the nil check the caller has
	// THREE states and must name each: nil (not wired), !latched (the peer
	// reboot race window, before its heartbeat has landed), and latched (the
	// ordered floor is usable).
	PeerBootEpochFn func() (epoch uint64, latched bool)
	// LocalBootEpochFn reports this node's ordered daemon boot epoch for the
	// per-connection process identity sent in syncMsgPeerCapabilities (#9818).
	// It is separate from PeerBootEpochFn: the latter is the remote floor used
	// to classify reboot evidence, while this value identifies the sender
	// process. Nil means the embedding path cannot provide the epoch, so the
	// sender carries its boot id when available and remains fail-open for the
	// missing field.
	LocalBootEpochFn func() uint64
	// LocalProcessTokenFn reports the Manager-scoped random daemon token that
	// complements LocalBootEpochFn. It prevents two incarnations that collide
	// on the persisted epoch from being treated as one process. Nil omits the
	// token for embedders that do not expose cluster heartbeat state.
	LocalProcessTokenFn func() uint64
	// localIdentity is sampled once per SessionSync. Manager's heartbeat epoch
	// may be refined upward later in the same daemon, but all connections from
	// that daemon must carry one stable process identity rather than making
	// routine refinement look like a second peer process.
	localIdentityOnce sync.Once
	localIdentity     peerProcessIdentity
	// peerEpochAtIncarnation is the boot-epoch floor observed when the current
	// peerIncarnation was established (#7762), guarded by s.mu like the
	// incarnation itself. A LATER install seeing a strictly higher floor is
	// positive evidence that the peer process was replaced — the evidence the
	// EMPTY-alternate-slot reboot otherwise leaves no local trace of. Zero
	// means "never recorded", which is why the first observation only records.
	peerEpochAtIncarnation uint64
	lastSweepTime          uint64
	// lastPrimaryLivenessSweepTime bounds full mirror walks used to find
	// previously-created sessions that are still active on their owner.
	lastPrimaryLivenessSweepTime uint64
	// primaryLivenessScanIntervalSeconds adapts full mirror walks to half the
	// shortest live owner-session timeout, bounded to [1s, 10s].
	primaryLivenessScanIntervalSeconds atomic.Uint64
	// primaryLivenessScanIntervalMu serializes queued-row cadence tightening
	// with the scanner's post-enumeration cadence publication.
	primaryLivenessScanIntervalMu             sync.Mutex
	receiverSessionTimeouts                   atomic.Pointer[ReceiverSessionTimeoutProfile]
	pendingPrimaryLivenessScanIntervalSeconds uint64
	// pendingPrimaryLivenessScanGeneration counts registrations under this
	// mutex so a publication cannot consume a request made after enumeration.
	pendingPrimaryLivenessScanGeneration uint64
	// sweepWakeCh interrupts a long idle sweep timer when peer capability
	// discovery or a newly queued shorter-timeout row tightens liveness cadence.
	sweepWakeCh chan struct{}
	// sweepWakeScanIntervalSeconds coalesces the shortest queued-row scan
	// request until the timer fires.
	sweepWakeScanIntervalSeconds atomic.Uint64
	syncBackfillNeeded           atomic.Bool
	// rebootAwaiting names the half of the CURRENT incarnation's reboot
	// evidence that has not arrived yet; it is live only while
	// rebootAwaitingInc equals peerIncarnation (#9636). Guarded by mu.
	//
	// One peer reboot reaches two classifiers, in either order: installConn
	// sees a raised heartbeat boot epoch, and the BulkStart arm sees a changed
	// boot id. Whichever retires the incarnation records that the other
	// signal is still to come, and the other consumes the record instead of
	// retiring the incarnation again, which would evict the peer's healthy
	// second fabric. Keyed to the incarnation it was recorded for, so any
	// later advance voids it. See classifyPrimeLocked.
	rebootAwaiting    rebootEvidence
	rebootAwaitingInc uint64
	// forceResync arms a full authoritative bulk resync after a delete-journal
	// overflow dropped session-delete records the standby still needs (#5450).
	// It is DISTINCT from syncBackfillNeeded: that flag re-drives the INSTALL
	// sweep (re-sends live sessions), but a dropped delete is a teardown for a
	// session that no longer exists locally, so no install sweep can re-derive
	// it — the only recovery is a full BulkSync so the peer's
	// reconcileStaleSessions deletes the sessions the primary already closed.
	// Armed once per overflow episode (CAS) by rejournalTail/journalDelete and
	// consumed by whichever of the sweep loop (syncSweep) or the next reconnect
	// (handleNewConnection) runs first.
	forceResync       atomic.Bool
	lastNewCounter    uint64
	lastClosedCounter uint64
	lastSweepEmpty    bool
	// testSweepNow overrides the monotonic-seconds reading the sweep
	// watermarks against (nil = live clock). Test-only; production never
	// sets it. Per-instance (not a package hook) so parallel tests cannot
	// observe each other's frozen time. Set before driving syncSweep.
	testSweepNow func() uint64
	// testClockPublishBeforeStore pauses a current ClockSync publication while
	// s.mu is held. Test-only interleaving seam; production never sets it.
	testClockPublishBeforeStore func()
	// testClockPublishAfterStore pauses a current ClockSync publication after
	// both offset stores and before s.mu unlocks. Test-only seam; production
	// never sets it.
	testClockPublishAfterStore func()
	vrfDevice                  string
	// clockSynced (global) says a ClockSync was accepted for the current
	// incarnation (#9653). It stays on SessionSync, NOT in
	// peerIncarnationState (#17097): a boot-ID switch keeps the surviving
	// connection's proven clock, so it is not reset at every retirement
	// the way peerClockOffset is. Cleared only on full disconnect.
	clockSynced atomic.Bool

	// peerIncarnationStatePtr holds the current peer incarnation's
	// latch/debt/capability state (#17097, sync_peer_incarnation.go).
	// A pointer (not a value field) because retirement replaces the
	// whole state in one store under mu; nil until first use, since the
	// ~98 in-package SessionSync literals run no constructor. Access
	// only via peerIncarnationState()/retirePeerIncarnationLocked.
	peerIncarnationStatePtr atomic.Pointer[peerIncarnationState]

	// localSnapshotProtocol is this node's config-snapshot protocol version,
	// advertised to the peer on every installed connection (#6650). Set by the
	// daemon at bring-up (mirroring SetSoftwareVersion); 0 means "not wired",
	// which suppresses the advertisement rather than advertising a false 0.
	localSnapshotProtocol atomic.Uint32

	// Peer held snapshots + #6650 advertised protocol: see
	// peerSnapshotState in sync_gen_state_16159.go.
	peerSnaps peerSnapshotState

	// fenceSeq numbers sequenced peer fences (#7147). Starts at 0 and is only
	// ever read via Add(1), so the first fence is seq 1 — seq 0 is reserved on
	// the wire to mean "no ack requested", which is how a pre-#7147 fence's
	// empty payload decodes.
	fenceSeq   atomic.Uint64
	fenceAckMu sync.Mutex
	// fenceAckWaiters tags each waiter with the conn its fence went out on (#9915 F-116).
	fenceAckWaiters map[uint64]fenceAckWaiter

	zoneRGMu  sync.RWMutex
	zoneRGMap ZoneRGMap
	foldRGMap map[uint32]int
	// zoneRGMapGen changes when the legacy SetZoneRGMap contents change and on
	// every SetZoneOwnership apply (#9655/#11012), so an in-flight bulk can
	// detect stale ownership or resolver snapshots. Guarded by zoneRGMu.
	zoneRGMapGen uint64

	// ingressFoldFn resolves a LOCAL interface identity (in either session
	// direction) to its cluster-stable RETH-relative fold on the sync wire.
	// #7095 introduced it for ingress; #12075 reuses it for egress because
	// both fold the same local {ifindex, vlan} through the same name resolver.
	// Injected by the daemon, which owns config; pkg/cluster deliberately holds
	// no config of its own.
	//
	// NIL IS THE UNKNOWN CASE: an unset resolver stamps 0, which is the same
	// value a legacy peer sends and a fabric-redirected session records. The
	// consumer falls back to the zone approximation, so an unwired node retains
	// the pre-#7095 behavior.
	ingressFoldFn func(ifindex uint32, vlan uint16) uint32
	// natScopeFoldFn folds a NAT-scope identity as the (parent physical
	// ifindex, VLAN) pair (#16826): NatScopeIfindex is the LOGICAL unit's
	// ifindex (a VLAN child, or a synthetic logical-only index), which is
	// not a kernel netdev an ifindex->name lookup can resolve. The daemon
	// injector derives the pair from its snapshot rows, so the wire fold
	// names `reth0.80`, not the `reth0` the child device name truncated to.
	// Nil keeps the legacy vlan-0 fold.
	natScopeFoldFn  func(ifindex int32) uint32
	deleteJournalMu sync.Mutex
	// deleteJournal is the bare deferred-delete ring; scopedDeleteJournal
	// is the #10512 deferred scoped-delete debt: scoped frames that could
	// not be queued (disconnected/full) wait there — never in the bare
	// journal — and flush only after the current peer positively
	// advertises the scoped bit (learn-triggered), so no
	// cross-incarnation raw replay can downgrade them. Same mutex, cap
	// discipline, and overflow resync-arming for both (boundedFrameJournal).
	deleteJournal       boundedFrameJournal
	scopedDeleteJournal boundedFrameJournal
	lastPeerRxMono      atomic.Int64 // CLOCK_MONOTONIC nanos of last inbound sync msg (#1792)
	readDeadline        time.Duration
	peerSilenceLimit    time.Duration
	// bulkStartMu serializes queued incremental writes with the
	// table-truth snapshot -> BulkStart boundary (#10283). A bulk holds it
	// while reading BulkSnapshotSource and until BulkStart is written under
	// writeMu; sendLoop takes it for every queued frame, so an incremental
	// cannot land ahead of the marker. The queue's existing order and install
	// generations then remain authoritative for session opens followed by
	// closes in the gap.
	bulkStartMu  sync.Mutex
	bulkSendMu   sync.Mutex
	bulkSendNext atomic.Uint64
	// bulkSnapshotGenMu serializes an authoritative table snapshot read and its
	// install-generation decisions with queue-time delete-generation draws. A
	// close observed while the source is reading therefore linearizes either
	// before the snapshot or after every snapshot row is stamped, never between
	// a row read and its stamp (#10284).
	bulkSnapshotGenMu   sync.Mutex
	pendingBulkAckEpoch atomic.Uint64
	pendingBulkAckSince atomic.Int64
	bulkEverCompleted   atomic.Bool
	// outboundBulkAcked is set ONLY when the peer acks OUR outbound bulk
	// (syncMsgBulkAck), i.e. the peer has received our complete session
	// table. It is DISTINCT from bulkEverCompleted, which is also set by an
	// inbound BulkEnd (peer->us). The survivor-fabric re-drive
	// (handleDisconnect, #4090) exists to guarantee the peer got OUR outbound
	// bulk, so its gate must key on this outbound-only flag: a small INBOUND
	// bulk completing first must not suppress re-driving a stranded OUTBOUND
	// bulk (#4360). Like bulkEverCompleted it is sticky — once acked the peer
	// holds our full table and incremental sync keeps it fresh across
	// reconnects, so it is never reset.
	outboundBulkAcked atomic.Bool
	// pendingBulkOwed is the cold-prime generation the pending outbound bulk was
	// sent to pay (#9626): coldPrimeGen as it stood when that bulk STARTED, or 0
	// when no cold prime was owed then. It is recorded beside
	// pendingBulkAckEpoch and cleared with it (clearPendingBulkAck), and the
	// matching BulkAck discharges exactly that generation (dischargeColdPrime).
	pendingBulkOwed atomic.Uint64
	// coldPrimeGen numbers the cold-prime arms (#9626). Every arm runs under s.mu
	// and bumps it (armColdPrimeLocked), so a discharge that compares it under
	// s.mu cannot clear a debt armed after the bulk it acknowledges started.
	coldPrimeGen atomic.Uint64
	// bulkRedriveInFlight guards the survivor-fabric cold-start bulk
	// re-drive (#4090). A single fabric dropping mid-cold-start-bulk while
	// the other fabric is up leaves the bulk stranded — pinned to the dead
	// conn, never retried, and not re-triggered on the survivor (the
	// wasDisconnected/bulkEverCompleted gate in handleNewConnection needs
	// BOTH fabrics to have dropped). handleDisconnect schedules ONE
	// debounced goroutine to re-run doBulkSync over the survivor; this CAS
	// flag bounds it to a single in-flight re-drive so a survivor that ALSO
	// flaps cannot cause a re-drive storm.
	bulkRedriveInFlight atomic.Bool
	// bulkAckRetryOwed keeps retry-readiness debt latched across every
	// unacknowledged-bulk re-drive. Each re-drive sets it at the start and
	// re-arms it after a failed source/write attempt. A matching BulkAck
	// (sync_conn_read.go) or storing a replacement pending bulk (sync_bulk.go)
	// clears it; clearPendingBulkAck deliberately does not.
	bulkAckRetryOwed atomic.Bool
	// bulkRequestInFlight coalesces concurrent inbound syncMsgBulkRequest
	// handlers; ordinary bulks still serialize through bulkSendMu.
	bulkRequestInFlight atomic.Bool
	// needColdPrime latches the outstanding cold-prime obligation across the
	// per-accept goroutines (#4962). It is armed under s.mu on a full
	// disconnect -> connect transition (both fabric slots were empty) and
	// consumed (cleared) only when the PEER acknowledges a cold-prime bulk
	// (#9626; see the end of this comment). Because
	// handleNewConnection now runs per-accept (post-#4370), two same-fabric
	// accepts can race: the first observes the empty registry and installs, the
	// second observes the first's connection and supersedes it — closing it and
	// aborting the first's in-flight cold-prime bulk. The pre-#4962 gate
	// recomputed wasDisconnected from the post-supersession registry, so the
	// surviving (second) connection saw a non-empty registry and SKIPPED
	// cold-prime: the peer never received the authoritative session table and
	// blackholed established flows on the next failover. The latch lets the
	// surviving connection INHERIT the obligation and re-drive the bulk. Like
	// forceResync it is a plain atomic.Bool.
	//
	// #9626: it is discharged by the PEER, not by a local write. A bulk whose
	// BulkEnd was written can still die in the kernel before the peer consumes
	// it, so only the matching BulkAck (sync_conn_read.go) clears the latch, and
	// only if no newer arm has happened since that bulk started. Every arm bumps
	// coldPrimeGen under s.mu, the bulk carries the generation it was sent to
	// pay (pendingBulkOwed), and the ack compares the two under s.mu. The success
	// paths that used to clear it (handleNewConnection, the survivor re-drive,
	// the sweep's owed re-drive) no longer do. The sweep instead waits up to
	// BulkAckPendingRetryAfter for the ack of a bulk sent for the current debt
	// before re-driving.
	needColdPrime  atomic.Bool
	bulkMu         sync.Mutex
	bulkInProgress bool
	// The next accepted bulk window captures the pending local helper
	// generation. This generation remains active through reconciliation, so
	// completion is tied to the exact helper inventory it may satisfy.
	inventoryPending           bool
	inventoryPendingGeneration uint64
	inventoryActive            bool
	inventoryActiveGeneration  uint64
	bulkRecvSerial             uint64 // accepted-window identity carried through reconciliation
	bulkRecvEpoch              uint64
	// bulkRecvIncarnation is the peer boot incarnation that started the bulk
	// `bulkRecvEpoch` names, so a BulkEnd can be matched on more than the epoch
	// (#9174 V013 — reasoning at the two sites, sync_conn_read.go's BulkEnd arm
	// and sync_bulk.go's end-marker write). Zero = primed without one, fail
	// open. Guarded by bulkMu.
	bulkRecvIncarnation bootIncarnation
	// bulkRecvConn is the connection that carried the accepted BulkStart
	// (#9716). BulkSync pins one connection for a whole bulk, so that bulk's
	// BulkEnd is accepted only on this connection. Guarded by bulkMu, compared
	// by identity, and cleared with the epoch and incarnation on a full
	// disconnect.
	bulkRecvConn net.Conn
	bulkRecvV4   map[dataplane.SessionKey]struct{}
	bulkRecvV6   map[dataplane.SessionKeyV6]struct{}
	// bulkRecvStartedAt is the wall-clock open time of the accepted bulk
	// window (#16039), guarded by bulkMu. A BulkEnd arriving after
	// bulkRecvWindowTimeout aborts the window instead of reconciling
	// it: a legitimately full table cannot be held open past the
	// sender's retry cadence.
	bulkRecvStartedAt time.Time
	// bulkIncomplete is readiness debt (#16039 fold): set when a window is
	// aborted (cap or deadline), cleared only by a successful reconcile.
	// While set, TransferReadiness keeps reporting the bulk as in
	// progress even though the window itself is closed. Guarded by bulkMu.
	bulkIncomplete bool
	// bulkRecvInvalid marks the accepted window aborted by the cap or
	// deadline (#16039). Invalid windows never reconcile, ack, or
	// release the hold; they absorb further keys without storing them
	// until their BulkEnd or the next fresh BulkStart retires them.
	bulkRecvInvalid bool
	// testBulkRecvNow overrides the wall clock read for the window
	// deadline. Test-only; production never sets it.
	testBulkRecvNow func() time.Time
	// testSlowHandlerThreshold / testConnWatchInterval shrink the #18521
	// slow-handler threshold and watchdog tick. Test-only; zero means the
	// production syncHandlerSlowThreshold / syncConnWatchInterval.
	testSlowHandlerThreshold time.Duration
	testConnWatchInterval    time.Duration
	// testStopFlushTimeout replaces syncStopFlushTimeout; testOnStopFlush is
	// called once Stop starts waiting on its flush (#18521 review round 2).
	// Test-only.
	testStopFlushTimeout time.Duration
	testOnStopFlush      func()
	// testOnWatchTick is called at the start of every connection-watchdog
	// tick, so a cell can wait for whole evaluations. Test-only.
	testOnWatchTick func()
	// bulkRerequestInFlight single-flights the #18521 (D) re-request of a
	// bulk whose reconcile was skipped because the zone map changed mid-bulk.
	bulkRerequestInFlight atomic.Bool
	// runDone is Start's context Done channel, so background waits end with
	// the SessionSync. Nil for an object that was never started (tests);
	// such waits are bounded on their own.
	runDone <-chan struct{}
	// testZoneMapSettle / testZoneMapSettleMax shrink the (D) settle window
	// and its cap. Test-only; zero means zoneMapSettleWindow/zoneMapSettleMax.
	testZoneMapSettle    time.Duration
	testZoneMapSettleMax time.Duration
	// bulkRerequestStreak counts consecutive withheld BulkAcks for the (D)
	// re-request backoff; a reconciled bulk resets it. testBulkRerequestBackoff
	// replaces the computed backoff in tests.
	bulkRerequestStreak      atomic.Uint64
	bulkRerequestLatest      atomic.Pointer[bulkRerequestPending]
	testBulkRerequestBackoff time.Duration
	// testOnBulkRerequestSent observes a queued re-request's cause and how
	// long after its bulk was withheld it went out; testBulkRerequestUnit,
	// when set, is what one second of the computed wait becomes, so a cell
	// runs the real schedule scaled down. Test-only.
	testOnBulkRerequestSent func(reason string, waited time.Duration)
	testBulkRerequestUnit   time.Duration
	// testBulkRerequestGate, when non-nil, holds a scheduled re-request's
	// decision until it is closed, so a cell orders its own frames before
	// the decision instead of racing a backoff. testOnBulkRerequestScheduled
	// observes the computed wait before testBulkRerequestBackoff replaces
	// it. Test-only.
	testBulkRerequestGate        chan struct{}
	testOnBulkRerequestScheduled func(reason string, wait time.Duration)
	// bulkInstallFailedV4/V6 retain only transient helper-install failures for
	// the active authoritative bulk. They are separate from the received-key
	// set because a failed transport write must not make that snapshot complete;
	// semantic helper refusals deliberately do not enter these sets.
	bulkInstallFailedV4   map[dataplane.SessionKey]struct{}
	bulkInstallFailedV6   map[dataplane.SessionKeyV6]struct{}
	bulkZoneSnapshot      *zoneOwnershipSnapshot
	barrierSeq            atomic.Uint64
	barrierAckSeq         atomic.Uint64
	barrierWaitMu         sync.Mutex
	barrierWaiters        map[uint64]*barrierWaiter
	fence                 barrierFence // #9508 (sync_barrier_fence_9508.go)
	failoverWaitMu        sync.Mutex
	failoverWaiters       failoverWaiterRegistry
	failoverSeq           atomic.Uint64
	sessionMirrorWarnedV4 atomic.Bool
	sessionMirrorWarnedV6 atomic.Bool

	// Generation-guard domain (#2170/#9915/#10512): see sessionGenState
	// in sync_gen_state_16159.go and the lock-order graph above.
	genState sessionGenState
	// testClockNow overrides the local monotonic-seconds reading used by the
	// ClockSync handler (nil = live clock). Test-only; production never sets
	// it. Per-instance (not a package hook) so parallel test files cannot
	// observe each other's frozen time. Set before driving handleMessage.
	testClockNow func() uint64
	// applyMu serializes the receive-side session APPLY across receive loops
	// (#9715).
	//   - Every installClusterSynced* holds it from the guard, through the
	//     dataplane write, to the generation record or rollback.
	//   - Every deleteClusterSynced* holds it from the guard through the
	//     dataplane delete.
	//   - resetRecvGen holds it around the generation-map reset.
	//
	// Why a second lock: each installed fabric connection runs its own
	// receiveLoop. When the sync stream moves (a fabric flap, or the #9508
	// preferred-fabric switch), the old loop can still be applying frames it
	// already read while the new loop applies newer frames for the same key.
	// recvGenMu covers each guard and each record separately, so without
	// applyMu:
	//   - an older install parked in its dataplane write records its
	//     generation over a newer one;
	//   - an admitted delete removes a newer install that landed during its
	//     write.
	//
	// Cost: it is uncontended in steady state, because the peer sends over one
	// stream and one loop applies at a time. It serializes only while two loops
	// apply at once, and then it also covers the reverse-companion row a forward
	// install writes.
	//
	// LOCK ORDER: applyMu -> recvGenMu. Nothing takes applyMu while holding
	// recvGenMu, bulkMu or configGenMu. OnForwardSessionInstalled runs under
	// applyMu and must not block; the daemon's only starts a goroutine.
	applyMu sync.Mutex

	// #3931 config-sync ordering guard.
	//
	// Sender side: configGenCounter is a process-wide strictly-monotonic
	// config generation, seeded at construction from CLOCK_MONOTONIC nanos
	// (the same cross-boot reasoning as the session genCounter above). Every
	// QueueConfig draws configGenCounter.Add(1) and STAMPS it on the wire
	// (encodeConfigPayload), so a rapid commit pair carries strictly
	// increasing generations.
	//
	// Receiver side: the config-sync handler no longer spawns a racing
	// goroutine per message (the pre-#3931 `go OnConfigReceived` hazard). It
	// enqueues (gen, text) onto configApplyCh, and a single ordered consumer
	// (configApplyLoop) drains it in receive order, attempting a config only
	// when its generation is strictly newer than lastAppliedConfigGen
	// (shouldApplyConfigGen). An out-of-order older config is dropped with an
	// alarm (ConfigsStaleIgnored). lastAppliedConfigGen advances ONLY AFTER a
	// successful apply (recordAppliedConfigGen, gated on OnConfigReceived
	// returning nil) — an apply failure counts ConfigsApplyFailed and leaves
	// the high-water at the last-applied generation so the primary's re-push of
	// the same generation is re-admitted and the standby re-converges instead
	// of being silently stranded on the prior config (M-2/#4151). The mark is
	// reset to 0 on a peer bulk re-prime (resetRecvGen) so a rebooted primary —
	// whose monotonic counter restarts lower — is accepted instead of refused
	// as stale (the #2198 F2 inverse-of-stale-RETAIN reasoning, applied to
	// config).
	// #17816: generation and send-time ACK capability are one coherent
	// config-apply debt. This SessionSync-lifetime state survives peer
	// incarnation retirement: disconnect alone does not prove the successor
	// applied a generation already sent.
	configApplyDebtMu       sync.RWMutex
	lastSentConfigDebt16756 configApplyDebt16756
	// peerConfigNackedGen16756 is the generation of the newest
	// current-send NACK (#16756 legacy fallback), or 0. SessionSync-
	// lifetime like the debt above — NOT peer-incarnation state — so a
	// legacy peer's NACK survives incarnation retirement until a newer
	// send supersedes it. A NACK whose generation is behind
	// lastSentConfigDebt16756.generation is a straggler and is ignored
	// by both the re-push marker and the legacy fallback.
	peerConfigNackedGen16756 atomic.Uint64
	// Highest config generation the peer positively acknowledged as applied.
	// PeerConfigStale compares this with lastSentConfigDebt16756.generation.
	peerAppliedConfigGen atomic.Uint64
	// peerAppliedConfigBoot is the peer boot incarnation that delivered
	// peerAppliedConfigGen (zero when unattributed). Guarded by mu. A reboot
	// discards the ACK only when a DIFFERENT boot delivered it (#18521).
	peerAppliedConfigBoot bootIncarnation

	configGenCounter     atomic.Uint64
	lastAppliedConfigGen atomic.Uint64
	// applyingConfigGen is the apply-in-progress config fence (#6284, item 2).
	// The single-consumer configApplyLoop sets it to the generation it is about
	// to apply BEFORE calling OnConfigReceived (which runs the receiver's
	// clearSessionsForDeletedPolicies sweep) and clears it to 0 only AFTER the
	// high-water (lastAppliedConfigGen) has advanced on success, or immediately
	// on an apply failure. The config-epoch install guard (configEpochStale)
	// folds this into its refusal threshold so a synced session stamped with an
	// epoch older than the generation being applied — one racing the sub-µs
	// window between the sweep completing and the high-water advancing — is
	// refused NOW instead of admitted against the not-yet-advanced high-water
	// (the residual stale-permit window #5274 left open). 0 means no apply is in
	// flight (or a gen==0 legacy apply, which carries no comparable epoch).
	applyingConfigGen atomic.Uint64
	// lastRecvConfigGen is the highest config generation this node has RECEIVED
	// from the peer (recorded at enqueue in the syncMsgConfig handler, BEFORE
	// apply). It is the receiver's local view of the config sender's current
	// committed generation and is the high-water the manual-failover readiness
	// gate compares against lastAppliedConfigGen (#5563). Reset to 0 alongside
	// lastAppliedConfigGen on a peer bulk re-prime (resetRecvGen) so the
	// applied<=received invariant holds after a reboot restarts the sender's
	// monotonic counter lower.
	lastRecvConfigGen atomic.Uint64

	// configEpochRoleMu tracks the config authority role when reverse stamps
	// are produced. After becoming a non-authority, a retained applied mark is
	// not proof that it belongs to the current authority tenure; require a
	// strictly newer applied generation before tagging it.
	configEpochRoleMu       sync.Mutex
	configEpochRoleKnown    bool
	configEpochRolePrimary  bool
	configEpochReverseFloor uint64
	configApplyCh           chan configApplyItem

	// configGenMu makes the reconnect RESET of the three config-generation
	// marks above atomic with respect to every ADVANCE of them (#5084).
	//
	// Each mark is advanced by a non-atomic read-modify-write — load, compare,
	// store — and each is cleared to 0 by resetRecvGen on a peer bulk re-prime.
	// Those run on DIFFERENT goroutines: resetRecvGen is called from the
	// syncMsgBulkStart handler on a receive loop, while the applied mark is
	// advanced by the single configApplyLoop consumer and the received mark by
	// a receive loop. Nothing ordered them, so a clear could land between an
	// advance's load and its store and be lost — the store then re-raises the
	// mark the reset just cleared.
	//
	// That is not benign, which is what the pre-#5084 comments assumed. The
	// whole point of the reset is that a peer which OS-rebooted restarts its
	// monotonic configGenCounter LOWER; a pre-reboot generation surviving the
	// reset means every one of the reconnected peer's CURRENT generations is
	// refused as stale. On lastAppliedConfigGen that silently strands the
	// standby on the pre-reboot config; on lastRecvConfigGen it poisons the
	// readiness comparison (PeerConfigGen > AppliedConfigGen) so the node can
	// report ready while running the wrong policy. Neither self-clears: the
	// marks are monotone-max, so only another accepted re-prime or ~1.8e12
	// commits would move them back down.
	//
	// Two prior comments stated the contract wrongly and are corrected at their
	// sites: recordAppliedConfigGen claimed it is "called ONLY from the
	// single-consumer configApplyLoop", which ignores resetRecvGen's clear; and
	// the received-mark raise claimed "the receiveLoop is single-threaded per
	// connection", which is true per connection but there are TWO of them
	// (conn0/conn1), so a raise on one fabric races a reset on the other.
	//
	// Every WRITER takes this mutex; READERS stay lock-free, because they are on
	// hot paths (configEpochStale runs per synced session install) and a reader
	// racing a writer only observes one side of a single monotone step, which is
	// the same tolerance the marks already had.
	//
	// LOCK ORDER: configGenMu is a LEAF. No site takes another lock while
	// holding it, and resetRecvGen takes it strictly after releasing recvGenMu.
	configGenMu sync.Mutex
	// configGenAdvanceBarrierFn is a test injection seam (nil in production,
	// #5084). recordAppliedConfigGen / recordRecvConfigGen call it after reading
	// the current mark and before storing the advanced value — the exact window
	// in which a concurrent clear used to be lost. A lost update cannot be
	// driven deterministically any other way: without a seam the test would have
	// to race a sleep against the window and would pass on broken code whenever
	// it lost that race. A test parks a reset in the window and asserts the
	// clear survives.
	configGenAdvanceBarrierFn func()

	// Config-sync APPLY health tracking (#6387). These drive the time-based CF
	// monitor-failure edge. Unlike the loop-local high-water logic they are NOT
	// single-goroutine-owned: an independent grace-expiry timer
	// (configApplyFailTimer, armed on the first failure of a streak) fires its
	// callback on its OWN goroutine while the single-consumer configApplyLoop
	// touches the same fields, so every access is guarded by configApplyMu.
	//
	// firstUnappliedFailNano is MonotonicNanos of the FIRST apply failure in the
	// current un-applied streak (0 = no active streak). configApplyHealthRaised
	// records whether OnConfigApplyHealth(true) has already fired for this
	// streak, so the raise fires at most once and the matching clear fires on
	// the first subsequent success. configApplyFailReason holds the latest
	// apply error so the timer callback can raise CF with a meaningful reason
	// even without a fresh delivery edge.
	//
	// configApplyFailTimer is the independent grace-expiry timer: the config
	// sender pushes a generation at most once per connection/generation, so a
	// STABLE connection with one persistent apply failure gets no second
	// delivery — the timer, not a re-delivery edge, guarantees CF surfaces once
	// the grace elapses. configApplyFailEpoch is bumped on every arm/cancel;
	// the timer callback captures its epoch and no-ops on a mismatch, so a
	// success (or re-arm) that cancels a timer already past its Stop() cannot
	// raise a stale CF (the cancelled-but-already-firing race).
	//
	// nowMonoFn/configApplyFailGrace/afterFuncFn are injection seams (nil / 0 =
	// production defaults) that let a test drive the stale-duration clock, the
	// threshold, and the timer deterministically.
	configApplyMu           sync.Mutex
	firstUnappliedFailNano  int64
	configApplyHealthRaised bool
	configApplyFailReason   string
	configApplyFailTimer    *time.Timer
	configApplyFailEpoch    uint64
	nowMonoFn               func() int64
	configApplyFailGrace    time.Duration
	afterFuncFn             func(d time.Duration, f func()) *time.Timer

	// #5706 full-set state-sync ordering guard (IPsec SA + DHCP leases).
	//
	// IPsec SA and DHCP lease sync are FULL-SET pushes — each message REPLACES
	// the peer's held set. With two fabric receiveLoops (conn0/conn1) a
	// full-set can arrive OUT OF ORDER across the redundant streams, so a stale
	// older set could overwrite a newer one (a state regression). Each push now
	// carries a trailing (incarnation, seq): syncEpoch is this process's
	// incarnation (the construction seed, constant for the process lifetime;
	// see initGenState) and the per-type counters give a strictly-monotonic
	// sequence per stream. The receiver tracks the last-applied pair per stream
	// (ipsecRecvSeq / dhcpV4RecvSeq / dhcpV6RecvSeq /
	// persistentNatLeaseRecvSeq, guarded by recvSeqMu because both receiveLoops
	// touch them; resetRecvGen resets every one through fullSetGuardsLocked,
	// #9634) and commits only a strictly-newer pair after successful decode.
	// A stale reorder is dropped and counted. A legacy peer sends no trailer ->
	// (0,0) -> accept-always (mixed-version compat). The receiver guards reset
	// on a peer bulk re-prime (resetRecvGen) so an OS-rebooted peer whose
	// restarts LOWER is re-accepted instead of stranded (the #2198 F2 reasoning
	// applied to full-set sync). IPsec/DHCP-v4/DHCP-v6 have INDEPENDENT counters
	// and high-water marks (per-type, per-family), so a v4 push never gates a v6
	// push and an IPsec seq never gates a DHCP one.
	syncEpoch        uint64
	ipsecSeqCounter  atomic.Uint64
	dhcpV4SeqCounter atomic.Uint64
	dhcpV6SeqCounter atomic.Uint64
	// #8121: idle persistent-NAT leases are a full-set push like the two
	// above, and draw from their OWN counter so a lease push never gates a
	// DHCP one (or vice versa).
	persistentNatLeaseSeqCounter atomic.Uint64

	recvSeqMu                 sync.Mutex
	ipsecRecvSeq              fullSetSeqGuard
	dhcpV4RecvSeq             fullSetSeqGuard
	dhcpV6RecvSeq             fullSetSeqGuard
	persistentNatLeaseRecvSeq fullSetSeqGuard
	// #10018: lease full-set commit and callback order must match the
	// high-water mark order across the two fabric receive loops. Decode is
	// performed without this lock, then the commit advances the guard and
	// invokes the callback while serialized so an older decoded frame cannot
	// regress the imported lease set after a newer frame.
	persistentNatLeaseApplyMu sync.Mutex
	// IPsec commits are serialized with the sequence advance and callback so
	// the held set follows the same order as its last-applied high-water.
	ipsecApplyMu sync.Mutex
	// dhcpApplyMu serializes each DHCP arm's commit (high-water advance +
	// held-set store) with its callback (#9915 F-117 review), so commit order
	// == callback order across the two fabric receive loops. It nests recvSeqMu
	// (mark+store) inside and is released only after the callback; recvSeqMu
	// is never held across the callback itself, so a consumer cannot deadlock
	// on it. Taken only by the DHCP arms; the callback must not reenter DHCP
	// receive paths (see OnDHCPLeasesReceived).
	dhcpApplyMu sync.Mutex
	// #15160: per-family pending DHCP chunk assemblies and per-incarnation
	// committed generations, guarded by dhcpApplyMu. The chunk handler fences
	// stale completions before replacing the held set; a legacy commit also
	// discards all pending assemblies.
	dhcpChunkState4 dhcpChunkState
	dhcpChunkState6 dhcpChunkState
	// #16758: pending IPsec SA chunk assemblies and per-incarnation committed
	// generations, guarded by ipsecApplyMu. The chunk handler checks the
	// generation fence before replacing the held set; a newer legacy commit
	// discards all pending assemblies.
	ipsecChunkState ipsecSAChunkState
	// recvEpoch fences full-set DHCP commits against receiver resets
	// (fold-2 HIGH-2): bumped under recvSeqMu by resetRecvGen alongside
	// the guard resets. DHCP arms capture it with the newer-check and
	// re-verify it inside the commit; a commit spanning a reset is dropped
	// as stale instead of resurrecting the dead boot's high-water over the
	// replacement's. Guarded by recvSeqMu.
	recvEpoch uint64
	// #10283: testAfterBulkSnapshot runs after a table-truth source returns but
	// before BulkStart is written. It is test-only and nil in production. The
	// production doBulkSync path holds bulkStartMu while invoking it; a
	// fail-on-revert test can TryLock that mutex on the old path and park the
	// marker until queued frames have definitely crossed the wire.
	testAfterBulkSnapshot func()
	// testAfterColdPrimeBarrierGate runs after the barrier's cold-prime gate
	// passes and before its ordered marker is admitted. It is test-only and
	// nil in production; #10387 uses it to park a replacement bulk attempt
	// behind the serialized admission lock.
	testAfterColdPrimeBarrierGate func()
	// testAfterColdPrimePendingRead runs after the barrier gate samples pending
	// state and before it re-reads the debt generation. It is test-only and
	// nil in production; #10387 uses it to pin the generation-race recheck.
	testAfterColdPrimePendingRead func()
	// testBeforeBulkRows runs after BulkStart is written and before the first
	// bulk row is stamped/serialized. It is test-only and nil in production;
	// a fail-on-revert cell can queue a close/delete in that exact marker-to-row
	// interleaving.
	testBeforeBulkRows func()
	// testBeforeDeleteGen runs immediately before a test delete attempts its
	// sender-generation critical section. It is nil in production and exists
	// only to pin a source-read/delete interleaving for #10284.
	testBeforeDeleteGen func()
	// testAfterDeleteGen runs after a test delete draws its sender generation,
	// while the sender-generation locks remain held. It is nil in production
	// and only makes the source-read race observable for #10284.
	testAfterDeleteGen func()
	// testBeforeQueuedWrite cancels a test send just before its queued frame
	// would be written, exercising the watermark failure path without
	// disconnecting the active connection in production.
	testBeforeQueuedWrite func()
	// testBeforePeerSnapshotConfigWrite changes the learned protocol after
	// queue preparation but immediately before the final guarded socket write.
	testBeforePeerSnapshotConfigWrite func()
	// testBeforeLastSentConfigDebtUnlock parks after assigning a complete
	// debt snapshot but before releasing its publication lock. Nil in production.
	testBeforeLastSentConfigDebtUnlock func()
	// testBeforeScopedJournalTake runs in flushScopedDeleteJournal after
	// the capability re-check and before the journal take, then nils
	// itself (testBeforeQueuedWrite shape). Test-only; pins the
	// caps-store-vs-append race deterministically.
	testBeforeScopedJournalTake func()
	// testBeforeJournalTake runs in flushDeleteJournal before the journal
	// take, then nils itself. Test-only twin of
	// testBeforeScopedJournalTake for the bare flush (#17110 warn-parity
	// cell drives a concurrent append during the flush).
	testBeforeJournalTake func()
	// testDHCPPreCommit, when non-nil, runs after DHCP decode+filter and
	// before the commit, with NO locks held (so the test may drive reset
	// + replacement paths from the hook rendezvous). Test-only hook for
	// deterministic reset/commit interleavings; nil in prod.
	// Single-fire discipline: the cell disables it before driving the
	// replacement push.
	testDHCPPreCommit func()
}

// configApplyItem is one config-sync payload queued for ordered apply by the
// single-consumer configApplyLoop (#3931).
type configApplyItem struct {
	gen      uint64
	text     string
	ancestry []configstore.RenameDescriptor
	// authenticated is true only when the frame arrived with a verified
	// session-sync authentication trailer.
	authenticated bool
	// conn is the exact connection that delivered the payload; acknowledgements
	// are sent only while it remains active.
	conn net.Conn
	// incarnation is the peer boot the payload arrived under (#5084). Zero
	// means un-incarnated and is never dropped on incarnation grounds.
	incarnation bootIncarnation
}
type failoverAck struct {
	status uint8
	detail string
}
type failoverWaiter struct {
	reqID uint64
	ch    chan failoverAck
	rgIDs []int
}

const (
	failoverAckApplied uint8 = iota
	failoverAckRejected
	failoverAckFailed
	failoverAckDisconnected
)

var ErrRemoteFailoverRejected = errors.New("remote failover rejected")

const maxFailoverBatchRGCount = 255

func encodeFailoverBatchRequestPayload(rgIDs []int, reqID uint64) []byte {
	payload := make([]byte, 1+len(rgIDs)+8)
	payload[0] = byte(len(rgIDs))
	for i, rgID := range rgIDs {
		payload[1+i] = byte(rgID)
	}
	binary.LittleEndian.PutUint64(payload[1+len(rgIDs):], reqID)
	return payload
}
func decodeFailoverBatchRequestPayload(payload []byte) ([]int, uint64, error) {
	if len(payload) < 1 {
		return nil, 0, fmt.Errorf("message too short")
	}
	count := int(payload[0])
	if count == 0 {
		return nil, 0, fmt.Errorf("batch has no redundancy groups")
	}
	if len(payload) < 1+count+8 {
		return nil, 0, fmt.Errorf("message too short")
	}
	rgIDs := make([]int, 0, count)
	for _, rgID := range payload[1 : 1+count] {
		rgIDs = append(rgIDs, int(rgID))
	}
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return nil, 0, err
	}
	return ids, binary.LittleEndian.Uint64(payload[1+count : 1+count+8]), nil
}
func encodeFailoverBatchAckPayload(rgIDs []int, status uint8, reqID uint64, detail string) []byte {
	// #17093: clamp the free-form detail so the payload never exceeds
	// the FailoverBatchAck per-type cap; an over-cap ack would make a
	// #16041-or-later peer drop the connection.
	if maxDetail := (1 + maxFailoverBatchRGCount + 1 + 8 + 4096) - (1 + len(rgIDs) + 1 + 8); len(detail) > maxDetail {
		detail = detail[:maxDetail]
	}
	payload := make([]byte, 1+len(rgIDs)+1+8+len(detail))
	payload[0] = byte(len(rgIDs))
	for i, rgID := range rgIDs {
		payload[1+i] = byte(rgID)
	}
	payload[1+len(rgIDs)] = status
	binary.LittleEndian.PutUint64(payload[1+len(rgIDs)+1:], reqID)
	copy(payload[1+len(rgIDs)+1+8:], detail)
	return payload
}
func decodeFailoverBatchAckPayload(payload []byte) ([]int, uint8, uint64, string, error) {
	if len(payload) < 1 {
		return nil, 0, 0, "", fmt.Errorf("message too short")
	}
	count := int(payload[0])
	if count == 0 {
		return nil, 0, 0, "", fmt.Errorf("batch has no redundancy groups")
	}
	if len(payload) < 1+count+1+8 {
		return nil, 0, 0, "", fmt.Errorf("message too short")
	}
	rgIDs := make([]int, 0, count)
	for _, rgID := range payload[1 : 1+count] {
		rgIDs = append(rgIDs, int(rgID))
	}
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return nil, 0, 0, "", err
	}
	status := payload[1+count]
	reqID := binary.LittleEndian.Uint64(payload[1+count+1 : 1+count+1+8])
	detail := string(payload[1+count+1+8:])
	return ids, status, reqID, detail, nil
}

type sessionSyncSweepProfiler interface {
	SessionSyncSweepProfile() (enabled bool, activeInterval, idleInterval time.Duration)
}
type clusterSyncedSessionInstaller interface {
	SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error
	SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error
}

const deleteJournalDefaultCap = 10000

// NewSessionSync creates a new single-fabric session synchronization manager.
//
// The runtime parameter is backend-neutral (see clusterRuntime in runtime.go).
// In-tree callers either pass nil at construction time and wire the runtime
// later via SetRuntime (the daemon's pattern, see daemon_ha_sync.go) or pass a
// runtime that already implements Sessions()/Telemetry() — both
// *dataplane.Manager and *dataplane/userspace.LegacyDataPlaneAdapter satisfy
// that contract. Callers that hold only a value typed as dataplane.DataPlane
// (the legacy bridge does NOT expose Sessions()/Telemetry() directly) can
// either: (a) wrap it in a small local type that adds Sessions() and
// Telemetry() returning dataplane.SessionStoreOf(dp) /
// dataplane.TelemetryOf(dp) and
// pass that wrapper here — Go structural typing accepts any value with the
// right method set even though clusterRuntime is package-private — or (b)
// pass nil and use the deprecated SetDataPlane alias, which performs the
// same adaptation internally.
func NewSessionSync(localAddr, peerAddr string, rt clusterRuntime) *SessionSync {
	s := &SessionSync{
		localAddr:           localAddr,
		peerAddr:            peerAddr,
		sendCh:              make(chan []byte, 4096),
		sweepWakeCh:         make(chan struct{}, 1),
		deleteJournal:       boundedFrameJournal{cap: deleteJournalDefaultCap},
		scopedDeleteJournal: boundedFrameJournal{cap: deleteJournalDefaultCap},
		failoverWaiters:     newFailoverWaiterRegistry(),
	}
	s.initGenState()
	s.refreshPeerIPs()
	s.SetRuntime(rt)
	return s
}

// initGenState seeds the #2170 install-generation counter from CLOCK_MONOTONIC
// nanos and initializes the sender/receiver generation maps. Seeding from the
// boot-relative monotonic clock keeps the counter from regressing below a
// value the peer may already hold after this node restarts (process restart)
// WITHIN a single OS boot.
//
// CROSS-BOOT (OS reboot) the monotonic clock resets, so this node's counter
// can come up LOWER than a generation the peer stored from our previous boot.
// That is handled on the RECEIVER side, not here: when a (reconnecting,
// possibly rebooted) peer begins its bulk re-prime, the receiver resets its
// per-key stored generations (resetRecvGen, called from the syncMsgBulkStart
// handler, #2198 F2). The bulk re-prime — which re-installs every owned
// session — then lands unconditionally and re-records each key's fresh
// generation, so the install guard accepts it instead of refusing it as stale
// (the stale-RETAIN inverse of #2170). A persisted cross-boot high-water mark
// is therefore unnecessary.
func (s *SessionSync) initGenState() {
	seed := uint64(MonotonicNanos())
	if seed == 0 {
		seed = 1
	}
	s.genState.genCounter.Store(seed)
	s.genState.genSentV4 = make(map[dataplane.SessionKey]uint64)
	s.genState.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.genState.closeClassSentV4 = make(map[dataplane.SessionKey]sentCloseClass)
	s.genState.closeClassSentV6 = make(map[dataplane.SessionKeyV6]sentCloseClass)
	s.genState.tcpHandshakeSentV4 = make(map[dataplane.SessionKey]sentTCPHandshakeState)
	s.genState.tcpHandshakeSentV6 = make(map[dataplane.SessionKeyV6]sentTCPHandshakeState)
	s.genState.installTableSentV4 = make(map[dataplane.SessionKey]sentInstallTable)
	s.genState.installTableSentV6 = make(map[dataplane.SessionKeyV6]sentInstallTable)
	s.genState.sourceNatICMPSentV4 = make(map[dataplane.SessionKey]sourceNatICMPMemo)
	s.genState.sourceNatICMPSentV6 = make(map[dataplane.SessionKeyV6]sourceNatICMPMemo)
	s.genState.policyIdentitySentV4 = make(map[dataplane.SessionKey]policyIdentityMemo)
	s.genState.policyIdentitySentV6 = make(map[dataplane.SessionKeyV6]policyIdentityMemo)
	s.genState.appTimeoutLogSentV4 = make(map[dataplane.SessionKey]appTimeoutLogMemo)
	s.genState.appTimeoutLogSentV6 = make(map[dataplane.SessionKeyV6]appTimeoutLogMemo)
	s.genState.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	s.genState.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.genState.installTableRecvV4 = make(map[dataplane.SessionKey]recvInstallTable)
	s.genState.installTableRecvV6 = make(map[dataplane.SessionKeyV6]recvInstallTable)
	s.genState.sourceNatICMPRecvV4 = make(map[dataplane.SessionKey]sourceNatICMPMemo)
	s.genState.sourceNatICMPRecvV6 = make(map[dataplane.SessionKeyV6]sourceNatICMPMemo)
	s.genState.policyIdentityRecvV4 = make(map[dataplane.SessionKey]policyIdentityMemo)
	s.genState.policyIdentityRecvV6 = make(map[dataplane.SessionKeyV6]policyIdentityMemo)
	s.genState.appTimeoutLogRecvV4 = make(map[dataplane.SessionKey]appTimeoutLogMemo)
	s.genState.appTimeoutLogRecvV6 = make(map[dataplane.SessionKeyV6]appTimeoutLogMemo)
	s.genState.recvGenScopedV4 = make(map[scopedDeleteKeyV4]uint64)
	s.genState.recvGenScopedV6 = make(map[scopedDeleteKeyV6]uint64)
	// #3931: seed the config generation from the same monotonic base so the
	// sender's config-gen never regresses below a value the peer may hold
	// across this node's restarts within a boot, and create the ordered
	// config-apply queue drained by configApplyLoop. Buffered generously —
	// commits are seconds apart and apply is sub-second, so the queue never
	// fills in practice; overflow drops with an alarm and re-converges on the
	// next commit/reconnect re-push (see the syncMsgConfig handler).
	s.configGenCounter.Store(seed)
	s.lastAppliedConfigGen.Store(0)
	s.lastRecvConfigGen.Store(0)
	s.configApplyCh = make(chan configApplyItem, 64)
	// #5706: the full-set (IPsec/DHCP) ordering incarnation is this process's
	// construction seed — constant for the process lifetime and, within a boot,
	// strictly greater on a process restart (monotonic clock climbs), so a
	// restart supersedes. CROSS-BOOT the monotonic clock resets lower, which is
	// handled on the RECEIVER exactly as the session/config guards are: a peer
	// bulk re-prime resets the per-stream high-water (resetRecvGen) so the
	// rebooted peer's fresh set is admitted. The per-type seq counters start at
	// 0 (first push draws 1) — since every incarnation change coincides with a
	// reconnect+reset, a per-boot restart from 1 is safe. seed is already
	// guarded >=1 above, so a stamped frame never collides with the (0,0)
	// legacy sentinel.
	s.syncEpoch = seed
	// #15182 (C03-01): seed the bulk-transfer epoch counter from the same
	// monotonic base. bulkSendNext was the one within-boot counter left at
	// zero, so a restarted daemon process re-emitted epoch 1 while a peer
	// that survived the restart (any prior-process socket still installed)
	// held bulkRecvEpoch at a high-water from the dead process. With the
	// boot incarnation unchanged across a daemon-only restart, `switched`
	// is false, so bulkStartStaleLocked refused the restarted peer's
	// authoritative re-prime between bulks: its pre-existing sessions were
	// never bulk-transferred and no BulkEnd reconcile ran. Seeding from
	// MonotonicNanos — exactly as genCounter/configGenCounter above — makes
	// the first epoch of a restarted process strictly newer than any epoch
	// its predecessor emitted within the same boot, while a cross-boot
	// restart still restarts lower and is admitted via `switched`.
	s.bulkSendNext.Store(seed)
}

// NewDualSessionSync creates a session sync manager with dual-fabric transport.
// If local1 or peer1 is empty, it falls back to single-fabric behavior. See
// NewSessionSync for the runtime parameter contract.
func NewDualSessionSync(local, peer, local1, peer1 string, rt clusterRuntime) *SessionSync {
	s := &SessionSync{
		localAddr:           local,
		peerAddr:            peer,
		localAddr1:          local1,
		peerAddr1:           peer1,
		sendCh:              make(chan []byte, 4096),
		sweepWakeCh:         make(chan struct{}, 1),
		deleteJournal:       boundedFrameJournal{cap: deleteJournalDefaultCap},
		scopedDeleteJournal: boundedFrameJournal{cap: deleteJournalDefaultCap},
		failoverWaiters:     newFailoverWaiterRegistry(),
	}
	s.initGenState()
	s.refreshPeerIPs()
	s.SetRuntime(rt)
	return s
}

// IsDualFabric reports whether this sync carries a secondary fabric
// (fab1) transport -- i.e. it was built by NewDualSessionSync with a
// non-empty fab1 pair. Read-only; the pair is fixed at construction.
func (s *SessionSync) IsDualFabric() bool {
	return s.localAddr1 != "" && s.peerAddr1 != ""
}

// SetVRFDevice sets the VRF device used for SO_BINDTODEVICE on sync sockets.
func (s *SessionSync) SetVRFDevice(dev string) {
	s.vrfDevice = dev
}

// SetZoneRGMap sets the zone ID to redundancy-group mapping used for per-RG
// session synchronization.
func (s *SessionSync) SetZoneRGMap(m map[uint16]int) {
	next := make(ZoneRGMap, len(m))
	for zone, rg := range m {
		next[zone] = []int{rg}
	}
	if m == nil {
		next = nil
	}
	s.zoneRGMu.Lock()
	// #9655/#10227: nil (unwired) and an installed empty map have different
	// reconcile safety semantics, so a nil↔empty transition is a generation
	// change.
	if (s.zoneRGMap == nil) != (next == nil) || !zoneRGMapEqual(s.zoneRGMap, next) {
		s.zoneRGMapGen++
	}
	s.zoneRGMap = next
	s.zoneRGMu.Unlock()
}

// SetZoneOwnership atomically installs the zone-to-RG set, stable-interface-
// fold to RG lookup, and local fold resolver. The resolver stamps both
// #7095 ingress and #12075 egress identity against this apply-time config.
// A nil zone map preserves the prior zone map (used when an apply result has
// no zone-ID snapshot); a non-nil empty map installs an authoritative empty
// map. Each apply advances the generation because the fold resolver closes
// over an apply-time interface snapshot.
func (s *SessionSync) SetZoneOwnership(zoneRG ZoneRGMap, foldRG map[uint32]int, foldFn func(uint32, uint16) uint32) {
	var zones ZoneRGMap
	if zoneRG != nil {
		zones = make(ZoneRGMap, len(zoneRG))
		for zone, rgs := range zoneRG {
			zones[zone] = append([]int(nil), rgs...)
		}
	}
	folds := make(map[uint32]int, len(foldRG))
	for fold, rg := range foldRG {
		folds[fold] = rg
	}
	s.zoneRGMu.Lock()
	if zoneRG != nil {
		s.zoneRGMap = zones
	}
	s.foldRGMap = folds
	s.ingressFoldFn = foldFn
	s.zoneRGMapGen++
	s.zoneRGMu.Unlock()
}

// ZoneOwnershipInstalled reports whether a non-nil zone map is wired. An
// installed empty map is true; nil remains the #9655 unwired sentinel.
func (s *SessionSync) ZoneOwnershipInstalled() bool {
	s.zoneRGMu.RLock()
	installed := s.zoneRGMap != nil
	s.zoneRGMu.RUnlock()
	return installed
}

// SetIngressFoldFn wires the shared direction-agnostic RETH-relative name
// resolver used by the #7095 ingress and #12075 egress folds. It advances the
// ownership generation as well: a bulk snapshot that captured the previous
// resolver must not reconcile against it after this changes.
func (s *SessionSync) SetIngressFoldFn(fn func(ifindex uint32, vlan uint16) uint32) {
	s.zoneRGMu.Lock()
	s.ingressFoldFn = fn
	s.zoneRGMapGen++
	s.zoneRGMu.Unlock()
}

// stampIngressIfaceFold fills in the #7095 wire field from the session's
// node-local ingress identity, just before it is encoded.
//
// It runs on the SEND path only. The fold is computed from THIS node's
// {ifindex, vlan} against THIS node's config, so the name it folds is the one
// this node would display — and the peer resolves that same fold to its own
// device. A session with no local identity (ifindex 0, the #7096
// fabric-redirected case among them) folds to 0 and stays unknown.
func (s *SessionSync) stampIngressIfaceFold(ifindex uint32, vlan uint16) uint32 {
	s.zoneRGMu.Lock()
	fn := s.ingressFoldFn
	s.zoneRGMu.Unlock()
	if fn == nil || ifindex == 0 {
		return 0
	}
	return fn(ifindex, vlan)
}

// stampEgressIfaceFold fills the #12075 wire field from the sender's
// node-local FIB egress identity. The same injected resolver used by ingress
// is direction-agnostic: both folds identify a reth-relative name.
func (s *SessionSync) stampEgressIfaceFold(ifindex uint32, vlan uint16) uint32 {
	return s.stampIngressIfaceFold(ifindex, vlan)
}

// stampNatScopeFold fills the #15176 wire field: the cluster-stable fold
// of the session's validated NAT-scope logical ingress ifindex, carried
// on the helper delta as NatScopeIfindex (0 = none recorded). The peer
// resolves it back to its own logical unit for session-hit NAT
// revalidation.
//
// #16826: the recorded ifindex names the LOGICAL unit (the VLAN child
// `ge-0-0-2.80`, or a synthetic logical-only index), not a kernel netdev
// the generic {ifindex, vlan} resolver can name — folding it with vlan 0
// truncated `ge-0-0-2.80` to the parent and shipped `reth0`, so the peer
// revalidated against the parent's interface/RI scope. When the daemon
// wired natScopeFoldFn, that injector maps the logical ifindex to its
// (parent physical, VLAN) pair and folds `reth0.80`; without it the
// legacy vlan-0 fold is kept byte-identically.
func (s *SessionSync) stampNatScopeFold(ifindex int32) uint32 {
	if ifindex <= 0 {
		return 0
	}
	s.zoneRGMu.Lock()
	fn := s.natScopeFoldFn
	s.zoneRGMu.Unlock()
	if fn != nil {
		return fn(ifindex)
	}
	return s.stampIngressIfaceFold(uint32(ifindex), 0)
}

// SetNatScopeFoldFn wires the #16826 logical-ifindex -> (parent, VLAN)
// NAT-scope fold. It advances the ownership generation with the other
// fold wiring: a bulk snapshot that captured the previous folder must
// not reconcile against it after this changes.
func (s *SessionSync) SetNatScopeFoldFn(fn func(ifindex int32) uint32) {
	s.zoneRGMu.Lock()
	s.natScopeFoldFn = fn
	s.zoneRGMapGen++
	s.zoneRGMu.Unlock()
}

// SetRuntime wires the backend-neutral runtime used by SessionSync.
//
// Passing nil clears both runtime domains, matching the existing nil-
// tolerance contract (see SetRuntimeDomains and the sweep / bulk
// reconcile paths in sync_conn.go and sync_bulk.go that check for
// s.sessions == nil / s.telemetry == nil before touching the
// dataplane).
func (s *SessionSync) SetRuntime(rt clusterRuntime) {
	if rt == nil {
		s.SetRuntimeDomains(nil, nil)
		return
	}
	s.SetRuntimeDomains(rt.Sessions(), rt.Telemetry())
}

// SetDataPlane is the deprecated alias for SetRuntime. It is kept for one
// release cycle so any out-of-tree caller still passing the legacy
// dataplane.DataPlane bridge continues to compile. In-tree callers were
// migrated to SetRuntime as part of #1518.
//
// Deprecated: use SetRuntime. Both legacy *dataplane.Manager and the
// userspace LegacyDataPlaneAdapter satisfy clusterRuntime via Sessions()/
// Telemetry(); no adapter is needed.
func (s *SessionSync) SetDataPlane(dp dataplane.DataPlane) {
	if dp == nil {
		s.SetRuntimeDomains(nil, nil)
		return
	}
	s.SetRuntimeDomains(dataplane.SessionStoreOf(dp), dataplane.TelemetryOf(dp))
}

// SetRuntimeDomains sets the backend-neutral domains used by session sync.
// The old BPF-shaped dataplane is intentionally kept outside SessionSync's
// steady-state paths; callers that still own a legacy dataplane adapt it at the
// boundary with dataplane.SessionStoreOf/TelemetryOf.
func (s *SessionSync) SetRuntimeDomains(sessions dataplane.SessionStore, telemetry dataplane.Telemetry) {
	s.sessions = sessions
	s.telemetry = telemetry
}

// Stats returns a point-in-time snapshot of sync statistics.
//
// #17107: the uint64 fields are loaded through syncStatFields (see
// sync_stats.go) so the set Stats() can populate is exactly the
// descriptor set the statistics render draws from. A SyncStats counter
// with no descriptor cannot reach the snapshot, and
// TestSyncStatsSnapshotComplete fails until a descriptor (and a render
// decision) exists. The derived snapshot fields (string/bool/int/int64)
// are populated explicitly below; they are RenderNever descriptors.
func (s *SessionSync) Stats() SyncStatsSnapshot {
	s.mu.Lock()
	activeFabric := s.preferredFabricLocked()
	s.mu.Unlock()
	snap := SyncStatsSnapshot{
		PeerBootIncarnation:         s.PeerBootIncarnation().String(),
		CleartextSyncAlarmLatched:   boolSyncStat(s, "CleartextSyncAlarmLatched"),
		IPsecSAOversizeAlarmLatched: boolSyncStat(s, "IPsecSAOversizeAlarmLatched"),
		Connected:                   boolSyncStat(s, "Connected"),
		ActiveFabric:                activeFabric,
		BulkSyncStartTime:           int64SyncStat(s, "BulkSyncStartTime"),
		BulkSyncEndTime:             int64SyncStat(s, "BulkSyncEndTime"),
		LastConfigSyncTime:          int64SyncStat(s, "LastConfigSyncTime"),
		LastFenceAckAt:              int64SyncStat(s, "LastFenceAckAt"),
	}
	for _, f := range syncStatFields {
		switch f.name {
		case "PeerBootIncarnation", "CleartextSyncAlarmLatched", "IPsecSAOversizeAlarmLatched", "Connected", "ActiveFabric", "BulkSyncStartTime", "BulkSyncEndTime", "LastConfigSyncTime", "LastFenceAckAt":
			continue
		}
		setSyncStatUint(&snap, f.name, loadSyncStat(s, f.name))
	}
	return snap
}

// IsConnected reports whether a peer sync connection is currently established.
func (s *SessionSync) IsConnected() bool {
	return s.stats.Connected.Load()
}

// BulkEverCompleted reports whether at least one full bulk sync exchange has
// completed during this daemon instance's lifetime.
func (s *SessionSync) BulkEverCompleted() bool {
	return s.bulkEverCompleted.Load()
}

// ActiveFabric reports which fabric carries sync traffic: 0, 1, or -1 if disconnected.
func (s *SessionSync) ActiveFabric() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preferredFabricLocked()
}

// LastPeerReceiveAge reports how long it has been since the last inbound sync
// message was received from the peer. The age is computed in the
// CLOCK_MONOTONIC domain (#1792): the previous time.Unix(0, last) round-trip
// stripped Go's monotonic reading, so a forward wall-clock step aged the
// peer past maxPeerSyncSilence at exactly the moment the heartbeat-timeout
// suppression guard needed it. Negative ages (impossible on a correct
// monotonic clock) clamp to 0.
func (s *SessionSync) LastPeerReceiveAge() (time.Duration, bool) {
	last := s.lastPeerRxMono.Load()
	if last == 0 {
		return 0, false
	}
	age := time.Duration(MonotonicNanos() - last)
	if age < 0 {
		age = 0
	}
	return age, true
}
func (s *SessionSync) readDeadlineDuration() time.Duration {
	if s.readDeadline > 0 {
		return s.readDeadline
	}
	return syncReadDeadline
}
func (s *SessionSync) peerSilenceDuration() time.Duration {
	if s.peerSilenceLimit > 0 {
		return s.peerSilenceLimit
	}
	return syncPeerSilenceTimeout
}

// PeerRecentlyActive reports whether an inbound sync message has been observed
// from the peer within maxAge.
func (s *SessionSync) PeerRecentlyActive(maxAge time.Duration) bool {
	age, ok := s.LastPeerReceiveAge()
	return ok && age <= maxAge
}

// PeerRecentlyActiveWithinSilenceWindow reports whether an inbound sync
// message has been observed within the full peer-silence timeout. This
// window must cover the sync heartbeat/ACK cadence: an idle peer may send no
// session traffic and reply only when the local read deadline triggers a
// heartbeat probe.
func (s *SessionSync) PeerRecentlyActiveWithinSilenceWindow() bool {
	return s.PeerRecentlyActive(s.peerSilenceDuration())
}

// PeerHealthy reports whether the sync path is connected and, once the peer
// has proved heartbeat-ack support, has been observed within the silence window.
func (s *SessionSync) PeerHealthy() bool {
	if !s.stats.Connected.Load() {
		return false
	}
	if !s.peerIncarnationState().peerHeartbeatAckEver.Load() {
		return true
	}
	return s.PeerRecentlyActive(s.peerSilenceDuration())
}
func (s *SessionSync) WaitForIdle(timeout time.Duration, stableSamples int, sampleInterval time.Duration) error {
	if stableSamples <= 0 {
		stableSamples = 3
	}
	if sampleInterval <= 0 {
		sampleInterval = 200 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	var lastSent uint64
	var lastDeletes uint64
	var lastQueue int
	stable := 0
	initialized := false
	for {
		stats := s.Stats()
		queueLen := len(s.sendCh)
		if initialized && stats.SessionsSent == lastSent && stats.DeletesSent == lastDeletes && queueLen == lastQueue {
			stable++
			if stable >= stableSamples {
				return nil
			}
		} else {
			stable = 0
			lastSent = stats.SessionsSent
			lastDeletes = stats.DeletesSent
			lastQueue = queueLen
			initialized = true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for session sync idle sessions_sent=%d deletes_sent=%d queue_len=%d", lastSent, lastDeletes, lastQueue)
		}
		time.Sleep(sampleInterval)
	}
}

// zoneOwnershipSnapshot is the zone ownership a bulk's stale-session reconcile
// judges by, taken when the bulk STARTS (#9655).
type zoneOwnershipSnapshot struct {
	// zones stores ShouldSyncZone's answer for each named zone.
	zones map[uint16]bool
	// fallbackPrimary is the captured RG 0 answer for absent zones.
	fallbackPrimary bool
	// Per-session ownership is evaluated only against these bulk-start answers.
	useRG   bool
	foldRG  map[uint32]int
	foldFn  func(uint32, uint16) uint32
	primary map[int]bool
	// zoneRGsByZone is the bulk-start RG set per zone (#14357), so
	// shouldSyncV4/V6 can tell a multi-RG zone from a single-RG one without
	// re-reading the live map.
	zoneRGsByZone ZoneRGMap
	// mapGen is the ownership-map generation captured at bulk start.
	mapGen uint64
}

// shouldSync reports whether a zone's sessions are KEPT by this reconcile. It
// answers from the zone->RG map and RG 0 fallback the bulk started with.
func (z *zoneOwnershipSnapshot) shouldSync(zoneID uint16) bool {
	if v, ok := z.zones[zoneID]; ok {
		return v
	}
	return z.fallbackPrimary
}

// isMapped reports whether the zone was named by the same ownership snapshot.
// It is separate from shouldSync because false means both "mapped to the
// peer" and "unmapped"; only the latter needs the per-session origin guard.
func (z *zoneOwnershipSnapshot) isMapped(zoneID uint16) bool {
	_, ok := z.zones[zoneID]
	return ok
}

func (s *SessionSync) snapshotZoneOwnership() *zoneOwnershipSnapshot {
	s.zoneRGMu.RLock()
	m := s.zoneRGMap
	foldRG := s.foldRGMap
	foldFn := s.ingressFoldFn
	isPrimaryForRG := s.IsPrimaryForRGFn
	mapGen := s.zoneRGMapGen
	s.zoneRGMu.RUnlock()
	// #9655/#10227: nil is unwired; empty is an authoritative all-unmapped
	// snapshot. Copy the installed maps so this snapshot remains immutable.
	if m == nil {
		return nil
	}
	zoneRG := make(ZoneRGMap, len(m))
	for zone, rgs := range m {
		zoneRG[zone] = append([]int(nil), rgs...)
	}
	foldRGCapture := make(map[uint32]int, len(foldRG))
	for fold, rg := range foldRG {
		foldRGCapture[fold] = rg
	}
	fallbackPrimary := s.IsPrimaryFn != nil && s.IsPrimaryFn()
	snap := &zoneOwnershipSnapshot{
		zones:           make(map[uint16]bool, len(zoneRG)),
		fallbackPrimary: fallbackPrimary,
		useRG:           isPrimaryForRG != nil,
		foldRG:          foldRGCapture,
		foldFn:          foldFn,
		primary:         make(map[int]bool),
		zoneRGsByZone:   zoneRG,
		mapGen:          mapGen,
	}
	if isPrimaryForRG != nil {
		for _, rgs := range zoneRG {
			for _, rg := range rgs {
				if _, ok := snap.primary[rg]; !ok {
					snap.primary[rg] = isPrimaryForRG(rg)
				}
			}
		}
		for _, rg := range foldRGCapture {
			if _, ok := snap.primary[rg]; !ok {
				snap.primary[rg] = isPrimaryForRG(rg)
			}
		}
	}
	for zoneID, rgs := range zoneRG {
		// Record membership separately from ownership. A mapped zone whose
		// RGs are all peer-owned must remain distinguishable from an unmapped
		// zone during stale-session reconciliation.
		snap.zones[zoneID] = false
		if isPrimaryForRG == nil {
			snap.zones[zoneID] = fallbackPrimary
			continue
		}
		for _, rg := range rgs {
			if snap.primary[rg] {
				snap.zones[zoneID] = true
				break
			}
		}
	}
	return snap
}

func (s *SessionSync) reconcileStaleSessions(bulkSerial uint64) (bool, uint64, bool) {
	s.bulkMu.Lock()
	if !s.bulkInProgress || s.bulkRecvSerial != bulkSerial || s.bulkRecvInvalid {
		s.bulkMu.Unlock()
		return false, 0, false
	}
	recvV4 := s.bulkRecvV4
	recvV6 := s.bulkRecvV6
	zoneSnap := s.bulkZoneSnapshot
	inventoryGeneration := s.inventoryActiveGeneration
	inventoryRequested := s.inventoryActive
	s.bulkInProgress = false
	s.inventoryActive = false
	s.inventoryActiveGeneration = 0
	s.bulkRecvV4 = nil
	s.bulkRecvV6 = nil
	s.bulkRecvStartedAt = time.Time{}
	s.bulkRecvInvalid = false
	s.bulkIncomplete = false
	s.bulkInstallFailedV4 = nil
	s.bulkInstallFailedV6 = nil
	s.bulkZoneSnapshot = nil
	s.bulkMu.Unlock()
	start := time.Now()
	zones := -1
	if zoneSnap != nil {
		zones = len(zoneSnap.zones)
	}
	slog.Info("cluster sync: reconcile stale sessions starting", "recv_v4", len(recvV4), "recv_v6", len(recvV6), "zones", zones)
	// #5085: do NOT skip on an empty received set. A completed bulk window
	// (BulkStart -> BulkEnd, #5272-gated on bulkInProgress) is authoritative:
	// an EMPTY authoritative snapshot means the peer legitimately holds no
	// syncable sessions, so every eligible-absent stale peer-owned session
	// MUST be reconciled away. The previous empty-bulk skip masked the #5085
	// bug (the event-stream override sent empty markers), letting stale
	// sessions survive cold-prime. The snapshot is now authoritative and
	// lossless (doBulkSync always runs BulkSync's direct-write window), so the
	// natural reconcile against an empty set is correct — no dangerous
	// "empty means delete-all" heuristic, just the normal absent-key delete.
	if s.sessions == nil {
		slog.Info("cluster sync: reconcile stale sessions skipped (no dataplane)")
		return false, inventoryGeneration, inventoryRequested
	}
	// #9655: a bulk with no zone snapshot has nothing to judge ownership by, and
	// deleting on a guess is the failure this reconcile can cause. Only a nil
	// (unwired) zone map takes no snapshot; an installed empty map is the
	// all-unmapped snapshot whose rows are filtered by #10227 origin gating.
	if zoneSnap == nil {
		slog.Info("cluster sync: reconcile stale sessions skipped (no zone snapshot)")
		return false, inventoryGeneration, inventoryRequested
	}
	// #9655: the snapshot answers for the zone map it was taken from. A map with
	// different contents installed during the bulk can move a zone to this node,
	// and judging by the old answers would delete a session this node now owns.
	// Keep everything; the next bulk reconciles.
	s.zoneRGMu.RLock()
	mapGen := s.zoneRGMapGen
	s.zoneRGMu.RUnlock()
	if mapGen != zoneSnap.mapGen {
		slog.Info("cluster sync: reconcile stale sessions skipped (zone map changed during the bulk)",
			"snapshot_map_gen", zoneSnap.mapGen, "map_gen", mapGen)
		// #18521 (D): "the next bulk reconciles" — handleBulkEnd now asks the
		// peer for it (scheduleBulkRerequest), after the map settles.
		return false, inventoryGeneration, inventoryRequested
	}
	// #9655: judged by the zone answers this bulk started with. A zone the map
	// does not name uses the captured RG 0 fallback.
	// #10227: when that absent-zone answer is false, the dataplane origin bit
	// preserves local rows while allowing stale peer-synced rows to be deleted.
	shouldSyncAtBulkStart := zoneSnap.shouldSync
	isZoneMappedAtBulkStart := zoneSnap.isMapped
	var deleted int
	result, err := s.sessions.ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput{
		ReceivedV4:     recvV4,
		ReceivedV6:     recvV6,
		ShouldSyncZone: shouldSyncAtBulkStart,
		ShouldSyncV4:   zoneSnap.shouldSyncV4,
		ShouldSyncV6:   zoneSnap.shouldSyncV6,
		IsZoneMapped:   isZoneMappedAtBulkStart,
		DeleteReason:   dataplane.DeleteReasonClusterStale,
	})
	deleted = result.DeletedV4 + result.DeletedV6
	if err != nil {
		slog.Warn("cluster sync: reconcile stale sessions failed", "err", err)
		s.stats.Errors.Add(1)
		return false, inventoryGeneration, inventoryRequested
	}
	slog.Info(
		"cluster sync: reconcile stale sessions applied",
		"stale_v4", result.StaleV4,
		"stale_v6", result.StaleV6,
		"deleted_v4", result.DeletedV4,
		"deleted_v6", result.DeletedV6,
	)
	if deleted > 0 {
		slog.Info("cluster sync: reconciled stale sessions", "deleted", deleted)
	}
	slog.Info("cluster sync: reconcile stale sessions complete", "deleted", deleted, "elapsed", time.Since(start))
	return true, inventoryGeneration, inventoryRequested
}

func (s *SessionSync) PeerIPsecSAs() []string {
	s.peerSnaps.peerIPsecSAsMu.Lock()
	defer s.peerSnaps.peerIPsecSAsMu.Unlock()
	cp := make([]string, len(s.peerSnaps.peerIPsecSAs))
	copy(cp, s.peerSnaps.peerIPsecSAs)
	return cp
}

// QueueIPsecSA advertises the active IPsec connection-name set to the peer over
// the sync channel. It returns whether the frame was actually queued to an
// ACTIVE connection: false when there is no active conn (nothing sent) or the
// write failed (conn dropped). The #4385 caller uses this to advance its
// last-sent fingerprint ONLY on a confirmed send, so a drop-to-zero (empty)
// advertisement that lands during a reconnect gap is RETRIED on the next tick
// instead of being silently lost (which would leave the standby holding a stale
// set that resurrects the tunnel on takeover).
func (s *SessionSync) QueueIPsecSA(connectionNames []string) bool {
	conn := s.getActiveConn()
	if conn == nil {
		return false
	}
	// #5706: stamp the (incarnation, seq) ordering trailer so the receiver can
	// reject a stale full-set reordered across the redundant fabric streams.
	// The seq is drawn even on a subsequent write failure (a gap is harmless —
	// the receiver only requires strictly-increasing, not contiguous).
	// appendIPsecFullSetSeq (not the bare appendFullSetSeq) inserts a '\n'
	// delimiter before the trailer so an OLD pre-#5706 receiver decodes every
	// real SA name cleanly instead of fusing the trailer onto the last name
	// (#5706 review fold; see ipsecFullSetDelim).
	// #16758: a set over the receiver's per-frame bound must be chunked,
	// not emitted whole for the standby to refuse. Legacy shape is kept
	// for every set that fits, so a pre-#16758 peer decodes it identically.
	if len(connectionNames) <= maxIPsecSANames {
		seq := s.ipsecSeqCounter.Add(1)
		payload := appendIPsecFullSetSeq(encodeIPsecSAPayload(connectionNames), s.syncEpoch, seq)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgIPsecSA, payload)
		s.writeMu.Unlock()
		if err != nil {
			slog.Warn("cluster sync: IPsec SA send error", "err", err)
			s.stats.Errors.Add(1)
			s.disconnectConn(conn, "IPsec SA write failed", err)
			return false
		}
		s.stats.IPsecSASent.Add(1)
		slog.Debug("cluster sync: IPsec SA list sent", "count", len(connectionNames))
		return true
	}
	// Over-bound: alarm on the primary (latched + counted + Warn) and
	// split into maxIPsecSANames-sized chunks. A single name over
	// maxIPsecSANameLen can never be installed by any receiver; count it
	// malformed and refuse the push rather than chunking a set the peer
	// must refuse.
	for _, n := range connectionNames {
		if len(n) > maxIPsecSANameLen {
			s.stats.IPsecSAMalformedIgnored.Add(1)
			slog.Warn("cluster sync: refusing IPsec SA set with over-long name",
				"name_bytes", len(n), "cap", maxIPsecSANameLen, "count", len(connectionNames))
			return false
		}
	}
	if len(connectionNames) > ipsecChunkMaxTotalNames {
		s.stats.IPsecSAMalformedIgnored.Add(1)
		slog.Warn("cluster sync: refusing IPsec SA set over chunked-set name cap",
			"count", len(connectionNames), "cap", ipsecChunkMaxTotalNames)
		return false
	}
	s.stats.IPsecSAOverCapSets.Add(1)
	s.stats.IPsecSAOversizeAlarmLatched.Store(true)
	slog.Warn("cluster sync: IPsec SA set exceeds single-frame bound; sending chunked",
		"count", len(connectionNames), "cap", maxIPsecSANames)
	bodies, total := encodeIPsecSAChunkBodies(connectionNames)
	generation := s.ipsecSeqCounter.Add(1)
	for i, body := range bodies {
		seq := generation
		if i > 0 {
			seq = s.ipsecSeqCounter.Add(1)
		}
		payload := appendFullSetSeq(encodeIPsecSAChunkPayload(body, generation, uint32(i), uint32(len(bodies)), uint32(total)), s.syncEpoch, seq)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgIPsecSAChunk, payload)
		s.writeMu.Unlock()
		if err != nil {
			slog.Warn("cluster sync: IPsec SA chunk send error", "err", err)
			s.stats.Errors.Add(1)
			s.disconnectConn(conn, "IPsec SA chunk write failed", err)
			return false
		}
	}
	s.stats.IPsecSASent.Add(1)
	slog.Debug("cluster sync: IPsec SA list sent chunked", "count", total, "chunks", len(bodies))
	return true
}

// RecordDHCPLeasesSeeded adds n to the seeded-leases counter (#2239). The
// daemon calls this after seeding a freshly-started Kea on takeover.
func (s *SessionSync) RecordDHCPLeasesSeeded(n int) {
	if n > 0 {
		s.stats.DHCPLeasesSeeded.Add(uint64(n))
	}
}

// PeerDHCPLeaseSnapshot4 returns the v4 peer snapshot with standby residence
// subtracted from lease lifetimes. Received remains true for a valid empty
// snapshot, while a zero-value snapshot means no full set has arrived.
func (s *SessionSync) PeerDHCPLeaseSnapshot4() dhcpserver.LeaseSyncSnapshot {
	return s.peerDHCPLeaseSnapshotAged(4, time.Now())
}

// PeerDHCPLeaseSnapshot6 is the v6 counterpart.
func (s *SessionSync) PeerDHCPLeaseSnapshot6() dhcpserver.LeaseSyncSnapshot {
	return s.peerDHCPLeaseSnapshotAged(6, time.Now())
}

// PeerDHCPLeases4 returns the v4 lease set held from the peer, AGED by this
// node's standby residence (#2239/#4871). The standby seeds these into Kea on
// takeover.
func (s *SessionSync) PeerDHCPLeases4() []dhcpserver.SyncLease {
	return s.peerDHCPLeaseSnapshotAged(4, time.Now()).Leases
}

// PeerDHCPLeases6 returns the aged v6 peer set.
func (s *SessionSync) PeerDHCPLeases6() []dhcpserver.SyncLease {
	return s.peerDHCPLeaseSnapshotAged(6, time.Now()).Leases
}

// peerDHCPLeaseSnapshotAged returns a copy of the held peer lease set for a
// family with each lease's Remaining lifetime reduced by this node's standby
// RESIDENCE — the monotonic time elapsed since the set was received — and
// leases that have aged to zero DROPPED (#4871). Remaining is seconds of
// lifetime left at the SENDER's read time and carries no sample epoch.
// Without this subtraction a lease held on the standby for minutes is
// re-anchored at seed to now_local+Remaining and resurrected past its true
// expiry, so the promoted node could re-allocate an address/prefix the
// original server already reassigned (duplicate allocation). A lease at or
// below zero is dropped, NOT floored to one second — a floor would revive an
// expired binding just as surely. now is injected for tests; production passes
// time.Now(), whose monotonic reading makes the residence immune to wall-clock
// steps.
func (s *SessionSync) peerDHCPLeaseSnapshotAged(family int, now time.Time) dhcpserver.LeaseSyncSnapshot {
	s.peerSnaps.peerDHCPLeasesMu.Lock()
	defer s.peerSnaps.peerDHCPLeasesMu.Unlock()
	var snap dhcpserver.LeaseSyncSnapshot
	var src []dhcpserver.SyncLease
	var recvAt time.Time
	if family == 6 {
		snap = s.peerSnaps.peerDHCPLeaseSnapshot6
		src = s.peerSnaps.peerDHCPLeases6
		recvAt = s.peerSnaps.peerDHCPLeases6RecvAt
	} else {
		snap = s.peerSnaps.peerDHCPLeaseSnapshot4
		src = s.peerSnaps.peerDHCPLeases4
		recvAt = s.peerSnaps.peerDHCPLeases4RecvAt
	}
	if !snap.Received && src == nil && recvAt.IsZero() {
		return snap
	}
	if !snap.Received {
		// Tests and older in-process callers may populate the legacy slices
		// directly; preserve that behavior while making receipt explicit.
		snap = dhcpserver.LeaseSyncSnapshot{
			Leases:   src,
			Received: true,
		}
	}
	if src == nil {
		src = snap.Leases
	}
	var residence int
	if !recvAt.IsZero() {
		if d := int(now.Sub(recvAt).Seconds()); d > 0 {
			residence = d
		}
	}
	snap.Leases = ageDHCPLeases(src, residence)
	snap.Scopes = append([]dhcpserver.LeaseScopeAuthority(nil), snap.Scopes...)
	return snap
}

// ageDHCPLeases ages PreferredRemaining by the same residence as Remaining.
// A deprecated lease held on the standby is never revived at seed, and the
// invariant PreferredRemaining <= Remaining survives the residence adjustment.
func ageDHCPLeases(src []dhcpserver.SyncLease, residence int) []dhcpserver.SyncLease {
	out := make([]dhcpserver.SyncLease, 0, len(src))
	for _, l := range src {
		l.Remaining -= residence
		if l.Remaining <= 0 {
			continue
		}
		l.PreferredRemaining -= residence
		if l.PreferredRemaining < 0 {
			l.PreferredRemaining = 0
		}
		if l.PreferredRemaining > l.Remaining {
			l.PreferredRemaining = l.Remaining
		}
		out = append(out, l)
	}
	return out
}

// SetPeerDHCPLeasesForTesting injects a held peer lease set for a family.
func (s *SessionSync) SetPeerDHCPLeasesForTesting(family int, leases []dhcpserver.SyncLease) {
	s.storePeerDHCPLeaseSnapshot(family, dhcpserver.LeaseSyncSnapshot{
		Leases:     leases,
		Generation: 1,
		Received:   true,
	})
}

// SetPeerDHCPLeaseSnapshotForTesting injects a complete authority-bearing
// snapshot for cross-package takeover tests.
func (s *SessionSync) SetPeerDHCPLeaseSnapshotForTesting(family int, snapshot dhcpserver.LeaseSyncSnapshot) {
	s.storePeerDHCPLeaseSnapshot(family, snapshot)
}

func (s *SessionSync) storePeerDHCPLeases(family int, leases []dhcpserver.SyncLease) {
	s.storePeerDHCPLeaseSnapshot(family, dhcpserver.LeaseSyncSnapshot{
		Leases:   leases,
		Received: true,
	})
}

func (s *SessionSync) storePeerDHCPLeaseSnapshot(family int, snapshot dhcpserver.LeaseSyncSnapshot) {
	recvAt := time.Now()
	snapshot.Leases = append([]dhcpserver.SyncLease(nil), snapshot.Leases...)
	snapshot.Scopes = append([]dhcpserver.LeaseScopeAuthority(nil), snapshot.Scopes...)
	s.peerSnaps.peerDHCPLeasesMu.Lock()
	if family == 6 {
		s.peerSnaps.peerDHCPLeaseSnapshot6 = snapshot
		s.peerSnaps.peerDHCPLeases6 = snapshot.Leases
		s.peerSnaps.peerDHCPLeases6RecvAt = recvAt
	} else {
		s.peerSnaps.peerDHCPLeaseSnapshot4 = snapshot
		s.peerSnaps.peerDHCPLeases4 = snapshot.Leases
		s.peerSnaps.peerDHCPLeases4RecvAt = recvAt
	}
	s.peerSnaps.peerDHCPLeasesMu.Unlock()
}

// QueueDHCPLeases sends a legacy-compatible full-set DHCP-server lease push.
func (s *SessionSync) QueueDHCPLeases(family int, leases []dhcpserver.SyncLease) {
	s.queueDHCPLeaseSnapshot(family, dhcpserver.LeaseSyncSnapshot{
		Leases:   leases,
		Received: true,
	})
}

// QueueDHCPLeaseSnapshot sends a full-set lease push with #10170 ownership
// generation and served-scope proof. The old decoder ignores the trailing
// metadata, so this is safe during rolling upgrades.
func (s *SessionSync) QueueDHCPLeaseSnapshot(family int, snapshot dhcpserver.LeaseSyncSnapshot) {
	s.queueDHCPLeaseSnapshot(family, snapshot)
}

func (s *SessionSync) queueDHCPLeaseSnapshot(family int, snapshot dhcpserver.LeaseSyncSnapshot) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	msgType := byte(syncMsgDHCPLeaseV4)
	chunkMsgType := byte(syncMsgDHCPLeaseV4Chunk)
	seqCounter := &s.dhcpV4SeqCounter
	if family == 6 {
		msgType = syncMsgDHCPLeaseV6
		chunkMsgType = syncMsgDHCPLeaseV6Chunk
		seqCounter = &s.dhcpV6SeqCounter
	}
	base := encodeDHCPLeasePayload(snapshot.Leases)
	hasMeta := snapshot.Generation != 0 || len(snapshot.Scopes) > 0
	if hasMeta {
		base = appendDHCPLeaseSnapshotMeta(base, snapshot)
	}
	// Fast path (#15160): the whole set, metadata included, fits one frame
	// under the receiver cap — keep the exact pre-#15160 wire shape so an
	// old peer decodes it identically.
	if len(base)+fullSetSeqTrailerLen <= maxSyncPayload {
		seq := seqCounter.Add(1)
		s.writeMu.Lock()
		err := writeMsg(conn, msgType, appendFullSetSeq(base, s.syncEpoch, seq))
		s.writeMu.Unlock()
		if err != nil {
			slog.Warn("cluster sync: DHCP lease send error", "family", family, "err", err)
			s.stats.Errors.Add(1)
			s.disconnectConn(conn, "DHCP lease write failed", err)
			return
		}
		s.stats.DHCPLeasesSent.Add(1)
		slog.Debug("cluster sync: DHCP lease set sent", "family", family, "count", len(snapshot.Leases))
		return
	}
	// Over-cap (#15160): chunk the lease RECORDS below the frame budget.
	// The chunk generation is this push's first full-set sequence; every
	// chunk frame carries its own strictly increasing sequence so the
	// receiver's per-chunk admission stays monotone even across the two
	// fabrics, and the receiver assembles by (incarnation, generation)
	// and commits exactly once when the last chunk lands. The authority
	// trailer rides the last chunk only. A lease whose single record
	// cannot fit any frame is dropped and counted — never emitted
	// over-cap (the #14607 disposition).
	generation := seqCounter.Add(1) // the set's identity; every chunk carries it
	chunks, kept, dropped := encodeDHCPLeaseChunkFrames(snapshot.Leases)
	if dropped > 0 {
		s.stats.MalformedRecordsDropped.Add(uint64(dropped))
	}
	if kept > dhcpChunkMaxTotalLeases {
		// #16036 fold: never announce a totalLeases a new receiver must
		// refuse (kept is the totalLeases stamped below). The production
		// producer (daemon -> GetSyncLeases) is bounded by the 64 MiB Kea
		// response / ~200 B-per-lease JSON (~300k leases) on the socket
		// path, but the unbounded memfile fallback and direct
		// QueueDHCPLeaseSnapshot callers have no such bound — enforce the
		// same [., dhcpChunkMaxTotalLeases] cap here, before any frame is
		// written. Without this, one push would emit chunks the peer
		// counts malformed, and the 30s heartbeat would repeat the storm
		// while lease sync silently stays on the receiver's prior set.
		slog.Warn("cluster sync: refusing DHCP lease chunk set over lease-count cap",
			"family", family, "leases", kept, "cap", dhcpChunkMaxTotalLeases)
		s.stats.MalformedRecordsDropped.Add(1)
		return
	}
	for i, chunkBody := range chunks {
		body := encodeDHCPLeaseChunkPayload(chunkBody, generation, uint32(i), uint32(len(chunks)), uint32(kept))
		if i == len(chunks)-1 && hasMeta {
			body = appendDHCPLeaseSnapshotMeta(body, snapshot)
		}
		if len(body)+fullSetSeqTrailerLen > maxSyncPayload {
			slog.Warn("cluster sync: refusing oversize DHCP lease chunk",
				"family", family, "bytes", len(body)+fullSetSeqTrailerLen, "cap", maxSyncPayload)
			s.stats.MalformedRecordsDropped.Add(1)
			return
		}
		seq := generation
		if i > 0 {
			seq = seqCounter.Add(1)
		}
		s.writeMu.Lock()
		err := writeMsg(conn, chunkMsgType, appendFullSetSeq(body, s.syncEpoch, seq))
		s.writeMu.Unlock()
		if err != nil {
			slog.Warn("cluster sync: DHCP lease chunk send error", "family", family, "err", err)
			s.stats.Errors.Add(1)
			s.disconnectConn(conn, "DHCP lease chunk write failed", err)
			return
		}
	}
	s.stats.DHCPLeasesSent.Add(1)
	slog.Debug("cluster sync: DHCP lease set sent chunked", "family", family,
		"count", kept, "chunks", len(chunks), "dropped_oversize", dropped)
}
