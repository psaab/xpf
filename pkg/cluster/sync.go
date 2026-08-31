package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
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
// (upgrade.GateMixedBaseSwap, mirrored in scripts/deploy/xpf-deploy.py):
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
// CurrentHAProtocolVersion. GateMixedBaseSwap treats them differently:
// session-sync must match EXACTLY, so bumping here is what makes the mixed-base
// swap refuse up front instead of letting an operator discover a fabric that
// will not come up. The HA protocol is accepted over a window
// [MinCompat, Current] that is a single point today, so bumping THAT as well
// would additionally refuse a peer at N over heartbeat/failover semantics this
// change does not touch — a second, unnecessary failure on top of the one this
// change genuinely costs. #7925 split the counters precisely so a session-wire
// change stops dragging the HA protocol out from under its own compat floor.
const SessionSyncWireVersion = uint16(2)

const (
	syncMsgSessionV4              = 1
	syncMsgSessionV6              = 2
	syncMsgDeleteV4               = 3
	syncMsgDeleteV6               = 4
	syncMsgBulkStart              = 5
	syncMsgBulkEnd                = 6
	syncMsgHeartbeat              = 7
	syncMsgConfig                 = 8
	syncMsgIPsecSA                = 9
	syncMsgFailover               = 10
	syncMsgFence                  = 11
	syncMsgClockSync              = 12
	syncMsgBarrier                = 13
	syncMsgBarrierAck             = 14
	syncMsgBulkAck                = 15
	syncMsgFailoverAck            = 16
	syncMsgFailoverCommit         = 17
	syncMsgFailoverCommitAck      = 18
	syncMsgPrepareActivation      = 19
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
)

// syncHeader is the wire header for each sync message.
type syncHeader struct {
	Magic  [4]byte
	Type   uint8
	Pad    [3]byte
	Length uint32
}

const syncHeaderSize = 12
const syncWriteDeadline = 2 * time.Second
const failoverAckTimeout = 20 * time.Second
const syncReadDeadline = 10 * time.Second
const syncPeerSilenceTimeout = 30 * time.Second

// SyncStats tracks session synchronization statistics.
type SyncStats struct {
	SessionsSent     atomic.Uint64
	SessionsReceived atomic.Uint64
	// MalformedRecordsDropped counts sync records REJECTED by the #7175 decode
	// contract: a session record truncated before its policy/zone/NAT block, or
	// a DHCP full-set push that did not decode completely. Before #7175 these
	// decoded ok=true and installed partial state — a session whose SessionID,
	// PolicyID, zone ids and NAT fields were all fabricated zeros, or a lease
	// set silently truncated to a prefix.
	//
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
	// ConfigApplyNacksReceived counts #7328 config-apply nacks accepted from the
	// peer — one per generation this node pushed that the peer refused or failed
	// to apply. A nack for a superseded generation is ignored and not counted.
	// A persistently-nonzero, climbing value means the peer is repeatedly
	// failing to apply what this node sends; pair it with the peer's own
	// ConfigsApplyFailed to see why.
	ConfigApplyNacksReceived atomic.Uint64
	IPsecSASent              atomic.Uint64
	IPsecSAReceived          atomic.Uint64
	// IPsecSAStaleIgnored counts IPsec SA full-sets dropped by the #5706
	// ordering guard: an incoming (incarnation, seq) that was NOT strictly
	// newer than the last-applied pair — a full-set reordered across the
	// redundant fabric streams. A nonzero value means the guard prevented a
	// stale IPsec SA set from regressing the standby's held set.
	IPsecSAStaleIgnored atomic.Uint64
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
	FencesSent             atomic.Uint64
	FencesReceived         atomic.Uint64
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
	// StrictAuthEvictions counts session-sync connections closed by the #7441
	// strict session-auth posture: admitted before the control-link key was
	// committed, never authenticated, and past the in-place-upgrade grace.
	// A non-zero value on a healthy cluster means the posture was declared
	// while the peer could not answer — check the peer's build.
	StrictAuthEvictions atomic.Uint64
	DeletesDropped      atomic.Uint64
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
	// echo or receiver stored) was at genGuardMapCap and a NEW key therefore
	// could not be recorded (#2198 F1). The key degrades to gen-0 (safe,
	// unconditional) behavior. A nonzero value means a churn workload pushed
	// a generation map to its cap; the map is never cleared, so existing live
	// keys retain their stored generation and the guard stays correct for
	// them.
	GenMapOverflow atomic.Uint64
	// PreAuthRejected counts inbound sync connections dropped by the #5303
	// pre-auth admission cap: a connection accepted while the pre-auth setup
	// pool was saturated (a flood of connections that stall before
	// authentication). Excess connections are closed immediately and never
	// allocate the large session-sync socket buffers. A nonzero value means the
	// cap absorbed a connection flood on the sync/control network; the reserved
	// tail (preAuthPeerReserve) still admits the legitimate peer's reconnect.
	PreAuthRejected    atomic.Uint64
	Connected          atomic.Bool
	BulkSyncStartTime  atomic.Int64
	BulkSyncEndTime    atomic.Int64
	BulkSyncSessions   atomic.Uint64
	LastConfigSyncTime atomic.Int64
	LastConfigSyncSize atomic.Uint64
	LastFenceSeq       atomic.Uint64
	LastFenceAckAt     atomic.Int64
}

// SyncStatsSnapshot is a point-in-time copy of SyncStats with plain
// non-atomic fields, safe to copy by value and pass across API boundaries.
type SyncStatsSnapshot struct {
	SessionsSent        uint64
	SessionsReceived    uint64
	SessionsInstalled   uint64
	DeletesSent         uint64
	DeletesReceived     uint64
	BulkSyncs           uint64
	ConfigsSent         uint64
	ConfigsReceived     uint64
	ConfigsStaleIgnored uint64
	// #5084 observability. A fail-open fence is silent by construction, so
	// both halves are counted: primes that arrived without an incarnation
	// (the peer is old, or half-upgraded and hiding), and payloads dropped
	// because their incarnation was replaced (the fence doing its job).
	BulkPrimesWithoutIncarnation  uint64
	ConfigsDeadIncarnationDropped uint64
	// PeerBootIncarnation renders the boot id of the peer incarnation that
	// most recently primed, or "none". It travels in the snapshot rather than
	// through a new Manager accessor because the Manager holds only the
	// SyncStatsProvider interface, and this is the same transport every other
	// field in the status render already uses.
	PeerBootIncarnation    string
	ConfigsApplyFailed     uint64
	ImportsRefusedByHelper uint64
	// #6778 receive-edge loss, and #7328's nack counter alongside it: the
	// queue-full drop is recovered BY a nack, so a drop that is climbing while
	// nacks are not tells the operator the recovery path itself is broken (a
	// pre-#7328 peer, or a nack that never matched lastSentConfigGen). Both are
	// rendered only when nonzero.
	ConfigsQueueFullDropped    uint64
	ConfigApplyNacksReceived   uint64
	IPsecSASent                uint64
	IPsecSAReceived            uint64
	IPsecSAStaleIgnored        uint64
	DHCPLeasesSent             uint64
	DHCPLeasesReceived         uint64
	DHCPLeasesStaleIgnored     uint64
	DHCPLeasesSeeded           uint64
	FencesSent                 uint64
	FencesReceived             uint64
	FenceAcksSent              uint64
	FenceAcksReceived          uint64
	FenceAcksTimedOut          uint64
	Errors                     uint64
	DeletesDropped             uint64
	DeletesStaleIgnored        uint64
	InstallsStaleIgnored       uint64
	SessionsStaleConfigIgnored uint64
	GenMapOverflow             uint64
	PreAuthRejected            uint64
	Connected                  bool
	ActiveFabric               int
	BulkSyncStartTime          int64
	BulkSyncEndTime            int64
	BulkSyncSessions           uint64
	LastConfigSyncTime         int64
	LastConfigSyncSize         uint64
	LastFenceSeq               uint64
	LastFenceAckAt             int64
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
	Connected             bool
	PendingBulkAckEpoch   uint64
	PendingBulkAckAge     time.Duration
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
	return s.PendingBulkAckEpoch == 0 && !s.BulkReceiveInProgress && !s.ConfigStale()
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
	case s.BulkReceiveInProgress:
		return fmt.Sprintf("local bulk receive still in progress epoch=%d sessions=%d", s.BulkReceiveEpoch, s.BulkReceiveSessions)
	case s.ConfigStale():
		return fmt.Sprintf("standby config stale: applied gen=%d behind peer committed gen=%d", s.AppliedConfigGen, s.PeerConfigGen)
	default:
		return ""
	}
}

// SessionSync manages TCP-based session state replication between cluster
// peers for stateful failover.
type SessionSync struct {
	// strictSessionAuth is the #7441 operator-declared posture, published from
	// the config-apply path. Atomic because the enforcement tick, the
	// commit-driven reconciler and the status readers all touch it from
	// different goroutines, and it must never be read under a lock this
	// package's connection paths already hold.
	//
	// Zero value false = pre-#7441 behaviour exactly: nothing is ever evicted.
	strictSessionAuth strictSessionAuthState

	localAddr string
	peerAddr  string
	sessions  dataplane.SessionStore
	telemetry dataplane.Telemetry
	stats     SyncStats
	mu        sync.Mutex
	conn0     net.Conn
	conn1     net.Conn
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
	// Residual, deliberately not closed here. This used to be described as a
	// THIRD incarnation dialling into the slot that still held a stale
	// connection — fold r4b's eviction made that shape unreachable, because no
	// RETIRED-STAMPED connection remains installed after a recognized
	// supersession for a later incarnation to land on. (Precisely that: the
	// accepted residual below can still leave a semantically dead connection
	// installed carrying a falsely-CURRENT stamp, and a third incarnation can
	// physically land on that corpse — but it is then classified as replacing a
	// current connection, which advances the incarnation and evicts, so it does
	// not reach the old no-advance outcome.)
	//
	// The residual that survives is narrower to state and wider in effect: a
	// peer whose replacement enters through an EMPTY alternate slot is never
	// classified as a supersession at all, so the incarnation never advances
	// and none of this machinery runs. See evictStaleIncarnationConnsLocked's
	// KNOWN-INCOMPLETE note and pkg/cluster/README.md for the sequence. Both
	// the old shape and this one need the same thing — a peer-supplied boot
	// incarnation on the wire, which #5480 tracks and #6669 implements. It is a
	// wire change, not a local one, which is why it is not closed here.
	peerIncarnation uint64
	conn0Gen        uint64
	conn1Gen        uint64
	writeMu         sync.Mutex
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
	// rejection warning to ~1/sec. All three are guarded by preAuthMu.
	preAuthMu       sync.Mutex
	preAuthInFlight int
	setupConns      map[net.Conn]bool
	preAuthLogMono  atomic.Int64

	listener   net.Listener
	localAddr1 string
	peerAddr1  string
	listener1  net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	sendCh     chan []byte // buffered channel for outgoing messages

	// incrementalPauseDepth temporarily pauses background incremental producers
	// during ordered handoff operations.
	incrementalPauseDepth atomic.Int32

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
	// lastSentConfigGen — a nack for any other generation is a straggler for a
	// push this node has already superseded and is ignored.
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
	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
	OnIPsecSAReceived func(connectionNames []string)
	// OnDHCPLeasesReceived is called when a DHCP-server lease set arrives from
	// the peer (#2239). family is 4 or 6; the standby holds these so it can
	// seed Kea on takeover. Fires after the peer*DHCPLeases store is updated.
	OnDHCPLeasesReceived func(family int, leases []dhcpserver.SyncLease)
	// OnRemoteFailover is called when the peer requests a transfer-out for one RG.
	// reqID is the request-scoped identifier carried on the wire; the demoted
	// owner binds its auto-restore lease to it so a stale commit cannot clear a
	// newer request's lease (#5079).
	OnRemoteFailover func(rgID int, reqID uint64) error
	// OnRemoteFailoverCommit finalizes the demoted side of an acknowledged handoff.
	// reqID identifies the request being committed so the owner can clear the
	// matching auto-restore lease (#5079).
	OnRemoteFailoverCommit func(rgID int, reqID uint64) error
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
	// reply so the peer cannot promote while this node still externally owns
	// the RG. OnRemoteFailover only ENQUEUES the demotion event and returns;
	// acking before this barrier opened a two-owner window (duplicate GARP /
	// VIP ownership / traffic) — #5640. A non-nil error (fence not actuated
	// within the daemon's bounded timeout) downgrades the ack to
	// failoverAckFailed so the peer holds instead of promoting into the
	// two-owner window.
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
	// OnFenceReceived requests this node to disable all RGs, and reports what
	// that achieved so a sequenced fence can be acknowledged truthfully
	// (#7147). The returned FenceResult is encoded into syncMsgFenceAck; it is
	// ignored for an unsequenced (pre-#7147) fence.
	//
	// It is invoked SYNCHRONOUSLY on the receive loop and the ack is written
	// after it returns. That ordering is the whole guarantee: an ack sent
	// before the fence had been applied would confirm nothing.
	OnFenceReceived func() FenceResult
	// OnPrepareActivation asks the peer to pre-warm neighbors for the given RG.
	OnPrepareActivation func(rgID int)
	// OnForwardSessionInstalled fires when a forward synced session is installed locally.
	OnForwardSessionInstalled func()
	// OnBulkSyncReceived fires when an inbound bulk sync completes.
	OnBulkSyncReceived func()
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
	// OnPeerDisconnected fires when all fabric connections are lost.
	OnPeerDisconnected func()
	peerIPsecSAs       []string
	peerIPsecSAsMu     sync.Mutex
	// #2239: the standby holds the peer's most-recent full lease set per
	// family (the peerIPsecSAs precedent). On takeover the daemon reads these
	// and seeds the just-started Kea. Replaced wholesale on each full-set push.
	//
	// #4871: peerDHCPLeases{4,6}RecvAt records WHEN this node received each
	// family's held set. SyncLease.Remaining is seconds-of-lifetime-left at the
	// SENDER's read time and carries no sample epoch, so a set held on the
	// standby ages only if the receiver subtracts its own residence before
	// seeding — otherwise a lease held for minutes is re-anchored to
	// now_local+Remaining on takeover and RESURRECTED past its true expiry
	// (duplicate allocation). RecvAt is a time.Now() reading (monotonic in
	// production), so PeerDHCPLeases{4,6} subtract a monotonic residence.
	peerDHCPLeases4       []dhcpserver.SyncLease
	peerDHCPLeases6       []dhcpserver.SyncLease
	peerDHCPLeases4RecvAt time.Time
	peerDHCPLeases6RecvAt time.Time
	peerDHCPLeasesMu      sync.Mutex
	// IsPrimaryFn reports whether the local node is primary for the default sync scope.
	IsPrimaryFn func() bool
	// IsPrimaryForRGFn reports whether the local node is primary for a given RG.
	IsPrimaryForRGFn   func(rgID int) bool
	lastSweepTime      uint64
	syncBackfillNeeded atomic.Bool
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
	vrfDevice         string
	peerClockOffset   atomic.Int64
	clockSynced       atomic.Bool

	// localSnapshotProtocol is this node's config-snapshot protocol version,
	// advertised to the peer on every installed connection (#6650). Set by the
	// daemon at bring-up (mirroring SetSoftwareVersion); 0 means "not wired",
	// which suppresses the advertisement rather than advertising a false 0.
	localSnapshotProtocol atomic.Uint32

	// peerSnapshotProtocol is the peer's advertised config-snapshot protocol
	// version, or 0 when the peer has not advertised one.
	//
	// 0 is NOT "unknown, assume compatible": a connected peer that advertises
	// nothing is by definition running a build that predates #6650, so it also
	// predates every snapshot version this gate could care about. It is cleared
	// on full disconnect alongside clockSynced -- the capability belongs to the
	// peer INCARNATION that proved it, and the peer that reconnects may be a
	// different, older process.
	peerSnapshotProtocol atomic.Uint32

	// peerCapabilityFlags holds the peer's advertised capability bits (#7147),
	// carried in the trailing byte of syncMsgPeerCapabilities on top of #6650's
	// version field. 0 means "advertises nothing", which for every bit means
	// INCAPABLE — a pre-#7147 peer sends a 2-byte frame with no flags at all.
	//
	// Cleared on full disconnect alongside peerSnapshotProtocol and for the
	// identical reason: the capability belongs to the peer INCARNATION that
	// proved it, and the process that reconnects may be an older build. A
	// retained fence-ack bit would make a confirmed-fence gate wait out its
	// whole timeout against a downgraded peer that can never answer.
	peerCapabilityFlags atomic.Uint32

	// peerSessionSyncWire holds the peer's advertised SessionSyncWireVersion
	// (#7990), carried as a trailing u16 on syncMsgPeerCapabilities on top of
	// #6650's version field and #7147's flags byte. 0 means UNKNOWN — a peer
	// predating #7990 advertises nothing, and that is genuinely different from
	// "advertises 0": there is no valid sync wire version 0, so the two cannot
	// be confused the way #6650's 0-means-incapable had to be.
	//
	// Why this is not derivable from anything already exchanged: the heartbeat
	// carries HAProtocolVersion, and since #7925 the sync wire version is its
	// OWN counter — so a peer's HA version says nothing about whether its
	// session frames will decode. That was the gap: the image-replace gate
	// compares both versions from the image manifest, and the LANE-1 in-place
	// path had no channel to learn the peer's at all.
	//
	// Cleared on full disconnect alongside peerSnapshotProtocol and
	// peerCapabilityFlags, for the identical reason: the version belongs to the
	// peer INCARNATION that advertised it, and the process that reconnects may
	// be an older build — which is precisely the rolling-upgrade case this
	// exists for.
	peerSessionSyncWire atomic.Uint32

	// fenceSeq numbers sequenced peer fences (#7147). Starts at 0 and is only
	// ever read via Add(1), so the first fence is seq 1 — seq 0 is reserved on
	// the wire to mean "no ack requested", which is how a pre-#7147 fence's
	// empty payload decodes.
	fenceSeq        atomic.Uint64
	fenceAckMu      sync.Mutex
	fenceAckWaiters map[uint64]chan FenceAck

	zoneRGMu  sync.RWMutex
	zoneRGMap map[uint16]int

	// ingressFoldFn resolves a session's LOCAL ingress identity to the
	// #7095 cluster-stable fold that rides the sync wire. Injected by the
	// daemon, which owns the config; pkg/cluster deliberately holds no
	// config of its own.
	//
	// NIL IS THE UNKNOWN CASE, not an error: an unset resolver stamps 0,
	// which is the same value a legacy peer sends and a fabric-redirected
	// session records, and the consumer falls back to the zone
	// approximation for all three. So a node that has not wired it yet
	// syncs exactly what it synced before #7095.
	ingressFoldFn    func(ifindex uint32, vlan uint16) uint32
	deleteJournalMu  sync.Mutex
	deleteJournal    [][]byte
	deleteJournalCap int
	lastPeerRxMono   atomic.Int64 // CLOCK_MONOTONIC nanos of last inbound sync msg (#1792)
	// peerHeartbeatAckEver latches when the CURRENTLY connected peer proves it
	// understands syncMsgHeartbeat by replying syncMsgHeartbeatAck. It gates
	// the two enforcement paths that would otherwise punish a legacy peer that
	// simply never acks: the receiveLoop missed-heartbeat teardown
	// (sync_conn_read.go) and PeerHealthy's silence window (below).
	//
	// #5718 C01a: this is peer-INCARNATION scoped, NOT SessionSync-lifetime.
	// handleDisconnect clears it on full disconnect (alongside clockSynced) so
	// a peer downgrade — new build acks, then rolls back to a build that never
	// acks — cannot leave the flag latched and turn a healthy old peer into
	// permanent connection churn plus a failover-readiness block. Do not
	// promote this back to a set-once flag.
	peerHeartbeatAckEver atomic.Bool
	readDeadline         time.Duration
	peerSilenceLimit     time.Duration
	bulkSendMu           sync.Mutex
	bulkSendNext         atomic.Uint64
	pendingBulkAckEpoch  atomic.Uint64
	pendingBulkAckSince  atomic.Int64
	bulkEverCompleted    atomic.Bool
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
	// needColdPrime latches the outstanding cold-prime obligation across the
	// per-accept goroutines (#4962). It is armed under s.mu on a full
	// disconnect -> connect transition (both fabric slots were empty) and
	// consumed (cleared) only when a cold-prime bulk actually SUCCEEDS. Because
	// handleNewConnection now runs per-accept (post-#4370), two same-fabric
	// accepts can race: the first observes the empty registry and installs, the
	// second observes the first's connection and supersedes it — closing it and
	// aborting the first's in-flight cold-prime bulk. The pre-#4962 gate
	// recomputed wasDisconnected from the post-supersession registry, so the
	// surviving (second) connection saw a non-empty registry and SKIPPED
	// cold-prime: the peer never received the authoritative session table and
	// blackholed established flows on the next failover. The latch lets the
	// surviving connection INHERIT the obligation and re-drive the bulk. Like
	// forceResync it is a plain atomic.Bool; the narrow window where a newer
	// full-disconnect epoch's arm is cleared by an older epoch's success
	// self-heals via forceResync / the #4090 survivor re-drive / the next
	// reconnect.
	needColdPrime              atomic.Bool
	bulkMu                     sync.Mutex
	bulkInProgress             bool
	bulkRecvEpoch              uint64
	bulkRecvV4                 map[dataplane.SessionKey]struct{}
	bulkRecvV6                 map[dataplane.SessionKeyV6]struct{}
	bulkZoneSnapshot           map[uint16]bool
	barrierSeq                 atomic.Uint64
	barrierAckSeq              atomic.Uint64
	barrierWaitMu              sync.Mutex
	barrierWaiters             map[uint64]chan struct{}
	failoverWaitMu             sync.Mutex
	failoverWaiters            map[int]failoverWaiter
	failoverCommitWaiters      map[int]failoverWaiter
	failoverBatchWaiters       map[string]failoverWaiter
	failoverBatchCommitWaiters map[string]failoverWaiter
	failoverSeq                atomic.Uint64
	sessionMirrorWarnedV4      atomic.Bool
	sessionMirrorWarnedV6      atomic.Bool

	// #2170 HA deferred-delete generation guard.
	//
	// Sender side: genCounter is a single process-wide strictly-monotonic
	// install generation, seeded at construction from CLOCK_MONOTONIC nanos
	// so it never regresses below a value a peer may already hold across
	// this node's restarts within a boot. Every session install (Queue*,
	// sweep, bulk) draws genCounter.Add(1) and records it in genSentV4/V6
	// keyed by the wire key. A delete draws a FRESH generation strictly
	// greater than the install it cancels (takeDeleteGen*, #2221) and evicts
	// the sender map entry, so the delete always out-ranks its install — the
	// property that lets the receiver order a reordered delete/install pair.
	// Generations are only ever compared per-(sender,key), never across keys,
	// so a single sender-local counter is sufficient and no cross-node
	// agreement on absolute values is required.
	//
	// Receiver side: recvGenV4/V6 is the authoritative per-key stored
	// generation (the BPF C struct stays generation-free, SMR fix #3). It is
	// set on install-apply and consulted by both the install guard and the
	// delete guard. An applied non-zero delete upgrades the entry to the
	// delete generation as a TOMBSTONE (#2221) rather than evicting, so a
	// reordered older install of the cancelled session is refused; a gen-0
	// (legacy) delete evicts.
	genCounter atomic.Uint64
	genSentMu  sync.Mutex
	genSentV4  map[dataplane.SessionKey]uint64
	genSentV6  map[dataplane.SessionKeyV6]uint64
	recvGenMu  sync.Mutex
	recvGenV4  map[dataplane.SessionKey]uint64
	recvGenV6  map[dataplane.SessionKeyV6]uint64

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
	// #7328: the config generation this node most recently PUT ON THE WIRE
	// (QueueConfig). Distinct from configGenCounter, which is the next value to
	// draw: a nack naming an older generation is a straggler for a push already
	// superseded and must not re-arm the marker for the current one.
	lastSentConfigGen    atomic.Uint64
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
	configApplyCh     chan configApplyItem

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
	// sequence PER stream. The receiver tracks the last-applied (incarnation,
	// seq) per stream (ipsecRecvSeq / dhcpV4RecvSeq / dhcpV6RecvSeq, guarded by
	// recvSeqMu because both receiveLoops touch them) and admits only a
	// strictly-newer pair (fullSetSeqGuard.admit); a stale reorder is dropped
	// and counted. A legacy peer sends no trailer -> (0,0) -> accept-always
	// (mixed-version compat). The receiver guards are reset on a peer bulk
	// re-prime (resetRecvGen) so an OS-rebooted peer whose monotonic epoch
	// restarts LOWER is re-accepted instead of stranded (the #2198 F2 reasoning
	// applied to full-set sync). IPsec/DHCP-v4/DHCP-v6 have INDEPENDENT counters
	// and high-water marks (per-type, per-family), so a v4 push never gates a v6
	// push and an IPsec seq never gates a DHCP one.
	syncEpoch        uint64
	ipsecSeqCounter  atomic.Uint64
	dhcpV4SeqCounter atomic.Uint64
	dhcpV6SeqCounter atomic.Uint64

	recvSeqMu     sync.Mutex
	ipsecRecvSeq  fullSetSeqGuard
	dhcpV4RecvSeq fullSetSeqGuard
	dhcpV6RecvSeq fullSetSeqGuard
}

// configApplyItem is one config-sync payload queued for ordered apply by the
// single-consumer configApplyLoop (#3931).
type configApplyItem struct {
	gen  uint64
	text string
	// incarnation is the peer boot the payload arrived under (#5084), taken
	// from the connection that carried it. Zero = un-incarnated: the payload
	// is never dropped on incarnation grounds (plan §6 rule 4).
	//
	// This field is the whole fix. Without it a payload queued from a peer's
	// PRIOR boot can apply after resetRecvGen has zeroed the high-water, record
	// a high mark, and then refuse the rebooted peer's lower-generation current
	// config permanently.
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
		localAddr:                  localAddr,
		peerAddr:                   peerAddr,
		sendCh:                     make(chan []byte, 4096),
		deleteJournalCap:           deleteJournalDefaultCap,
		failoverWaiters:            make(map[int]failoverWaiter),
		failoverCommitWaiters:      make(map[int]failoverWaiter),
		failoverBatchWaiters:       make(map[string]failoverWaiter),
		failoverBatchCommitWaiters: make(map[string]failoverWaiter),
	}
	s.initGenState()
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
	s.genCounter.Store(seed)
	s.genSentV4 = make(map[dataplane.SessionKey]uint64)
	s.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
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
}

// NewDualSessionSync creates a session sync manager with dual-fabric transport.
// If local1 or peer1 is empty, it falls back to single-fabric behavior. See
// NewSessionSync for the runtime parameter contract.
func NewDualSessionSync(local, peer, local1, peer1 string, rt clusterRuntime) *SessionSync {
	s := &SessionSync{
		localAddr:                  local,
		peerAddr:                   peer,
		localAddr1:                 local1,
		peerAddr1:                  peer1,
		sendCh:                     make(chan []byte, 4096),
		deleteJournalCap:           deleteJournalDefaultCap,
		failoverWaiters:            make(map[int]failoverWaiter),
		failoverCommitWaiters:      make(map[int]failoverWaiter),
		failoverBatchWaiters:       make(map[string]failoverWaiter),
		failoverBatchCommitWaiters: make(map[string]failoverWaiter),
	}
	s.initGenState()
	s.SetRuntime(rt)
	return s
}

// SetVRFDevice sets the VRF device used for SO_BINDTODEVICE on sync sockets.
func (s *SessionSync) SetVRFDevice(dev string) {
	s.vrfDevice = dev
}

// SetZoneRGMap sets the zone ID to redundancy-group mapping used for per-RG
// session synchronization.
func (s *SessionSync) SetZoneRGMap(m map[uint16]int) {
	s.zoneRGMu.Lock()
	s.zoneRGMap = m
	s.zoneRGMu.Unlock()
}

// SetIngressFoldFn wires the #7095 cluster-stable ingress-interface resolver.
//
// It is guarded by zoneRGMu because it is read on the send path exactly where
// the zone map is, and passing nil restores the pre-#7095 behaviour of stamping
// nothing — which the wire already treats as "unknown".
func (s *SessionSync) SetIngressFoldFn(fn func(ifindex uint32, vlan uint16) uint32) {
	s.zoneRGMu.Lock()
	s.ingressFoldFn = fn
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
func (s *SessionSync) Stats() SyncStatsSnapshot {
	s.mu.Lock()
	var activeFabric int
	if s.conn0 != nil {
		activeFabric = 0
	} else if s.conn1 != nil {
		activeFabric = 1
	} else {
		activeFabric = -1
	}
	s.mu.Unlock()
	return SyncStatsSnapshot{SessionsSent: s.stats.SessionsSent.Load(), SessionsReceived: s.stats.SessionsReceived.Load(), SessionsInstalled: s.stats.SessionsInstalled.Load(), DeletesSent: s.stats.DeletesSent.Load(), DeletesReceived: s.stats.DeletesReceived.Load(), BulkSyncs: s.stats.BulkSyncs.Load(), ConfigsSent: s.stats.ConfigsSent.Load(), ConfigsReceived: s.stats.ConfigsReceived.Load(), ConfigsStaleIgnored: s.stats.ConfigsStaleIgnored.Load(), BulkPrimesWithoutIncarnation: s.stats.BulkPrimesWithoutIncarnation.Load(), PeerBootIncarnation: s.PeerBootIncarnation().String(), ConfigsDeadIncarnationDropped: s.stats.ConfigsDeadIncarnationDropped.Load(), ConfigsApplyFailed: s.stats.ConfigsApplyFailed.Load(), ImportsRefusedByHelper: s.stats.ImportsRefusedByHelper.Load(), ConfigsQueueFullDropped: s.stats.ConfigsQueueFullDropped.Load(), ConfigApplyNacksReceived: s.stats.ConfigApplyNacksReceived.Load(), IPsecSASent: s.stats.IPsecSASent.Load(), IPsecSAReceived: s.stats.IPsecSAReceived.Load(), IPsecSAStaleIgnored: s.stats.IPsecSAStaleIgnored.Load(), DHCPLeasesSent: s.stats.DHCPLeasesSent.Load(), DHCPLeasesReceived: s.stats.DHCPLeasesReceived.Load(), DHCPLeasesStaleIgnored: s.stats.DHCPLeasesStaleIgnored.Load(), DHCPLeasesSeeded: s.stats.DHCPLeasesSeeded.Load(), FencesSent: s.stats.FencesSent.Load(), FencesReceived: s.stats.FencesReceived.Load(), FenceAcksSent: s.stats.FenceAcksSent.Load(), FenceAcksReceived: s.stats.FenceAcksReceived.Load(), FenceAcksTimedOut: s.stats.FenceAcksTimedOut.Load(), Errors: s.stats.Errors.Load(), DeletesDropped: s.stats.DeletesDropped.Load(), DeletesStaleIgnored: s.stats.DeletesStaleIgnored.Load(), InstallsStaleIgnored: s.stats.InstallsStaleIgnored.Load(), SessionsStaleConfigIgnored: s.stats.SessionsStaleConfigIgnored.Load(), GenMapOverflow: s.stats.GenMapOverflow.Load(), PreAuthRejected: s.stats.PreAuthRejected.Load(), Connected: s.stats.Connected.Load(), ActiveFabric: activeFabric, BulkSyncStartTime: s.stats.BulkSyncStartTime.Load(), BulkSyncEndTime: s.stats.BulkSyncEndTime.Load(), BulkSyncSessions: s.stats.BulkSyncSessions.Load(), LastConfigSyncTime: s.stats.LastConfigSyncTime.Load(), LastConfigSyncSize: s.stats.LastConfigSyncSize.Load(), LastFenceSeq: s.stats.LastFenceSeq.Load(), LastFenceAckAt: s.stats.LastFenceAckAt.Load()}
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
	if s.conn0 != nil {
		return 0
	}
	if s.conn1 != nil {
		return 1
	}
	return -1
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

// PeerHealthy reports whether the sync path is connected and, once the peer
// has proved heartbeat-ack support, has been observed within the silence window.
func (s *SessionSync) PeerHealthy() bool {
	if !s.stats.Connected.Load() {
		return false
	}
	if !s.peerHeartbeatAckEver.Load() {
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

func (s *SessionSync) snapshotZoneOwnership() map[uint16]bool {
	s.zoneRGMu.RLock()
	m := s.zoneRGMap
	s.zoneRGMu.RUnlock()
	snap := make(map[uint16]bool, len(m))
	for zoneID := range m {
		snap[zoneID] = s.ShouldSyncZone(zoneID)
	}
	return snap
}

func (s *SessionSync) reconcileStaleSessions() {
	s.bulkMu.Lock()
	if !s.bulkInProgress {
		s.bulkMu.Unlock()
		return
	}
	recvV4 := s.bulkRecvV4
	recvV6 := s.bulkRecvV6
	zoneSnap := s.bulkZoneSnapshot
	s.bulkInProgress = false
	s.bulkRecvV4 = nil
	s.bulkRecvV6 = nil
	s.bulkZoneSnapshot = nil
	s.bulkMu.Unlock()
	start := time.Now()
	slog.Info("cluster sync: reconcile stale sessions starting", "recv_v4", len(recvV4), "recv_v6", len(recvV6), "zones", len(zoneSnap))
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
		return
	}
	if len(zoneSnap) == 0 {
		slog.Info("cluster sync: reconcile stale sessions skipped (no zone snapshot)")
		return
	}
	shouldSyncAtBulkStart := func(zoneID uint16) bool {
		if v, ok := zoneSnap[zoneID]; ok {
			return v
		}
		return true
	}
	var deleted int
	result, err := s.sessions.ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput{
		ReceivedV4:     recvV4,
		ReceivedV6:     recvV6,
		ShouldSyncZone: shouldSyncAtBulkStart,
		DeleteReason:   dataplane.DeleteReasonClusterStale,
	})
	deleted = result.DeletedV4 + result.DeletedV6
	if err != nil {
		slog.Warn("cluster sync: reconcile stale sessions failed", "err", err)
		s.stats.Errors.Add(1)
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
}

func (s *SessionSync) FormatStats() string {
	activeFabric := s.ActiveFabric()
	fabricStr := "none"
	if activeFabric >= 0 {
		fabricStr = fmt.Sprintf("fab%d", activeFabric)
	}
	fenceSeq := s.stats.LastFenceSeq.Load()
	fenceAckAt := s.stats.LastFenceAckAt.Load()
	fenceAckStr := "never"
	if fenceAckAt > 0 {
		fenceAckStr = time.Unix(0, fenceAckAt).Format("Jan 02 15:04:05.000")
	}
	return fmt.Sprintf("Session sync statistics:\n"+"  Connected:          %v\n"+"  Active fabric:      %s\n"+"  Sessions sent:      %d\n"+"  Sessions received:  %d\n"+"  Sessions installed: %d\n"+"  Deletes sent:       %d\n"+"  Deletes received:   %d\n"+"  Bulk syncs:         %d\n"+"  Configs sent:       %d\n"+"  Configs received:   %d\n"+"  IPsec SAs sent:     %d\n"+"  IPsec SAs received: %d\n"+"  Fences sent:        %d\n"+"  Fences received:    %d\n"+"  Install fence seq:  %d\n"+"  Last fence ack:     %s\n"+"  Errors:             %d\n", s.stats.Connected.Load(), fabricStr, s.stats.SessionsSent.Load(), s.stats.SessionsReceived.Load(), s.stats.SessionsInstalled.Load(), s.stats.DeletesSent.Load(), s.stats.DeletesReceived.Load(), s.stats.BulkSyncs.Load(), s.stats.ConfigsSent.Load(), s.stats.ConfigsReceived.Load(), s.stats.IPsecSASent.Load(), s.stats.IPsecSAReceived.Load(), s.stats.FencesSent.Load(), s.stats.FencesReceived.Load(), fenceSeq, fenceAckStr, s.stats.Errors.Load())
}

func (s *SessionSync) PeerIPsecSAs() []string {
	s.peerIPsecSAsMu.Lock()
	defer s.peerIPsecSAsMu.Unlock()
	cp := make([]string, len(s.peerIPsecSAs))
	copy(cp, s.peerIPsecSAs)
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
	seq := s.ipsecSeqCounter.Add(1)
	payload := appendIPsecFullSetSeq(encodeIPsecSAPayload(connectionNames), s.syncEpoch, seq)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgIPsecSA, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: IPsec SA send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return false
	}
	s.stats.IPsecSASent.Add(1)
	slog.Debug("cluster sync: IPsec SA list sent", "count", len(connectionNames))
	return true
}

// RecordDHCPLeasesSeeded adds n to the seeded-leases counter (#2239). The
// daemon calls this after seeding a freshly-started Kea on takeover.
func (s *SessionSync) RecordDHCPLeasesSeeded(n int) {
	if n > 0 {
		s.stats.DHCPLeasesSeeded.Add(uint64(n))
	}
}

// PeerDHCPLeases4 returns the v4 lease set held from the peer, AGED by this
// node's standby residence (#2239/#4871). The standby seeds these into Kea on
// takeover.
func (s *SessionSync) PeerDHCPLeases4() []dhcpserver.SyncLease {
	return s.peerDHCPLeasesAged(4, time.Now())
}

// PeerDHCPLeases6 returns the aged v6 lease set held from the peer (#2239/#4871).
func (s *SessionSync) PeerDHCPLeases6() []dhcpserver.SyncLease {
	return s.peerDHCPLeasesAged(6, time.Now())
}

// peerDHCPLeasesAged returns a copy of the held peer lease set for a family with
// each lease's Remaining lifetime reduced by this node's standby RESIDENCE —
// the monotonic time elapsed since the set was received — and leases that have
// aged to zero DROPPED (#4871).
//
// Remaining is seconds-of-lifetime-left at the SENDER's read time and carries
// no sample epoch. Without this subtraction a lease held on the standby for
// minutes is re-anchored at seed to now_local+Remaining and resurrected past
// its true expiry, so the promoted node could re-allocate an address/prefix the
// original server already reassigned (duplicate allocation). A lease at or below
// zero is dropped, NOT floored to one second — a floor would revive an expired
// binding just as surely. now is injected for tests; production passes
// time.Now() (which, like the stored RecvAt, carries a monotonic reading, so
// the residence is a monotonic delta immune to wall-clock steps).
func (s *SessionSync) peerDHCPLeasesAged(family int, now time.Time) []dhcpserver.SyncLease {
	s.peerDHCPLeasesMu.Lock()
	defer s.peerDHCPLeasesMu.Unlock()
	src := s.peerDHCPLeases4
	recvAt := s.peerDHCPLeases4RecvAt
	if family == 6 {
		src = s.peerDHCPLeases6
		recvAt = s.peerDHCPLeases6RecvAt
	}
	var residence int
	if !recvAt.IsZero() {
		if d := int(now.Sub(recvAt).Seconds()); d > 0 {
			residence = d
		}
	}
	out := make([]dhcpserver.SyncLease, 0, len(src))
	for _, l := range src {
		l.Remaining -= residence // l is a value copy; the held set is untouched
		if l.Remaining <= 0 {
			continue // aged out on the standby — drop, never resurrect at seed
		}
		// #5073: the PREFERRED remaining counts down in the same real time as the
		// valid remaining, so it must age by the same residence. Floor at 0
		// (already-deprecated stays deprecated) and cap at the aged Remaining so
		// the invariant PreferredRemaining <= Remaining survives residence. A
		// deprecated lease held on the standby is never revived at seed.
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

// SetPeerDHCPLeasesForTesting injects a held peer lease set for a family so
// cross-package tests (pkg/daemon) can drive the takeover-seed path without a
// live sync connection. Production fills this via the receive path.
func (s *SessionSync) SetPeerDHCPLeasesForTesting(family int, leases []dhcpserver.SyncLease) {
	s.storePeerDHCPLeases(family, leases)
}

// storePeerDHCPLeases replaces the held lease set for a family (full-set push
// semantics). Called from the receive path.
func (s *SessionSync) storePeerDHCPLeases(family int, leases []dhcpserver.SyncLease) {
	// #4871: stamp the receipt time so PeerDHCPLeases{4,6} can subtract standby
	// residence before seeding. time.Now() carries a monotonic reading, so the
	// later now.Sub(recvAt) is a monotonic residence.
	recvAt := time.Now()
	s.peerDHCPLeasesMu.Lock()
	if family == 6 {
		s.peerDHCPLeases6 = leases
		s.peerDHCPLeases6RecvAt = recvAt
	} else {
		s.peerDHCPLeases4 = leases
		s.peerDHCPLeases4RecvAt = recvAt
	}
	s.peerDHCPLeasesMu.Unlock()
}

// QueueDHCPLeases sends a full-set DHCP-server lease push for one family to the
// peer over the sync channel (#2239). family must be 4 or 6. Fail-open: a write
// error is logged + counted and disconnects the conn (the next reconnect
// re-pushes), it NEVER blocks lease granting on this node. Mirrors QueueIPsecSA.
func (s *SessionSync) QueueDHCPLeases(family int, leases []dhcpserver.SyncLease) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	msgType := byte(syncMsgDHCPLeaseV4)
	seqCounter := &s.dhcpV4SeqCounter
	if family == 6 {
		msgType = syncMsgDHCPLeaseV6
		seqCounter = &s.dhcpV6SeqCounter
	}
	// #5706: stamp the per-family (incarnation, seq) ordering trailer. v4 and v6
	// draw from INDEPENDENT counters so a v4 push never gates a v6 one. An old
	// receiver's lease decoder reads exactly its record count and ignores the
	// trailer, so this stays backward compatible.
	seq := seqCounter.Add(1)
	payload := appendFullSetSeq(encodeDHCPLeasePayload(leases), s.syncEpoch, seq)
	s.writeMu.Lock()
	err := writeMsg(conn, msgType, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: DHCP lease send error", "family", family, "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.DHCPLeasesSent.Add(1)
	slog.Debug("cluster sync: DHCP lease set sent", "family", family, "count", len(leases))
}
