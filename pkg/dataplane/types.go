// Package dataplane manages eBPF program loading, map operations,
// and XDP/TC attachment for the xpf firewall dataplane.
package dataplane

import (
	"strconv"

	"github.com/psaab/xpf/pkg/config"
	"strings"
)

// SessionKey mirrors the C struct session_key (5-tuple).
type SessionKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// SessionValue mirrors the C struct session_value.
type SessionValue struct {
	State uint8
	// Flags is uint16 (not uint8): SessFlagNPTV6 is bit 8 (0x100), which
	// overflows a byte (#5460). The C `struct session_value.flags` and the Rust
	// `BpfSessionValueV4::flags` mirror this width; the on-map ABI is size-
	// asserted at 144 (bpf_session_value_test.go / bpf_map_tests.rs).
	Flags      uint16
	TCPState   uint8
	IsReverse  uint8
	AppTimeout uint32 // per-application inactivity timeout (seconds), 0=use default

	// SessionID is the NODE-LOCAL conntrack id. It is a display/correlation
	// value, never a lookup key — forwarding, installs, and deletes are all
	// 5-tuple keyed. In userspace mode the control plane mints it per converted
	// HA-synced session (nextUserspaceSyncedSessionID, #6198); the helper stamps
	// its own dataplane id for sessions it owns (#4915). The two nodes do NOT
	// agree on it: the cross-node correlatable id is RTFlowSessionID below.
	// See "Node-Local BPF-ABI Session Id" in docs/session-sync-architecture.md.
	SessionID uint64

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   uint32
	NATDstIP   uint32
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKey

	ALGType  uint8
	LogFlags uint8
	AppID    uint16

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16

	// IngressIfindex is the #4983 TRUE ingress-interface identity: the ifindex
	// of the binding the session's FIRST packet arrived on. The helper stamps
	// it ONCE at session install from the packet's ingress binding
	// (SessionMetadata.ingress_ifindex -> publish_conntrack) and never
	// re-derives it from the zone — re-deriving is exactly the approximation
	// this field exists to remove. It rides the on-map C conntrack ABI
	// (session_value.ingress_ifindex), NOT the sync-only trailing fields below,
	// so it is present on bpfSessionValue and round-trips through the BPF
	// mirror.
	//
	// SCOPE (#6965): the stamp is on every forward session installed FROM A
	// RECEIVED FRAME — i.e. at the three frame-driven install sites, the only
	// places an observed ingress binding exists to copy. Two production sites
	// install a forward (is_reverse=false) session with 0 and are not
	// exceptions to the rule but instances of it: the host-outbound GRE
	// encapsulation path (afxdp/tunnel.rs), where firewall-originated traffic
	// read off the TUN device never arrived on a binding, and the HA peer
	// import (server/helpers/session_sync.rs), which deliberately does not
	// carry the peer's node-local ifindex. Both are listed among the
	// legitimate zeros below.
	//
	// The frame-driven stamps reach THIS map, which is what IterateSessions —
	// and therefore `show`/`clear security flow session` — enumerates. The
	// helper's publish_bpf_conntrack_entry is called from four sites in
	// afxdp/poll_descriptor: the TRANSIT forward install (#6965), the
	// host-inbound (LocalMiss) install, the missing-neighbor-seed install, and
	// the reverse-companion repair (whose row is IsReverse != 0 and is skipped
	// before filtering). Before #6965 the transit install did NOT publish here
	// — it wrote only the shim's separate steering table via
	// publish_live_session_entry — so a transit session had NO row in this map
	// at all, and an interface filter could not select it either way. That gap
	// predated #4983 (it dated to the commit that first added the conntrack
	// mirror). This field is now operator-visible for the transit, host-inbound
	// and missing-neighbor-seed populations plus peer-synced sessions the Go
	// side installs directly. What it carries is the {parent ifindex, VLAN}
	// PAIR; the unit is resolved on this side.
	//
	// 0 means "no ingress identity carried" and is NEVER a valid ifindex. These
	// populations legitimately carry 0 and MUST keep working:
	//   - the reverse companion (its own ingress has not been OBSERVED yet).
	//     The forward flow's egress IS known at install — it is the wrong
	//     datum, being a prediction of where the reply will arrive rather than
	//     an observation of where it did, and routing may be asymmetric. Note
	//     every pkg/cli show/clear call site skips IsReverse != 0 before
	//     filtering, so a reverse row is never interface-matched anyway;
	//   - an HA peer-synced session (an ifindex is NODE-LOCAL — the peer's
	//     number names a different NIC on this node, so carrying it across the
	//     cluster wire would be confidently wrong, worse than approximating);
	//   - the helper's host-outbound GRE encapsulation path, where the traffic
	//     is firewall-self-originated off the TUN device and has no ingress
	//     binding to record;
	//   - the helper's flow-cache descriptor seed, which is replay state for an
	//     already-installed session and is never published as one.
	//
	// FABRIC INGRESS is the one population where this field and IngressZone
	// name DIFFERENT interfaces, so the list above is not exhaustive without
	// it. A frame arriving over the fabric carries a zone-encoded override, so
	// IngressZone is the ORIGINATING chassis's zone while this stamp records
	// the LOCAL fabric NIC the frame physically arrived on. Both answer
	// different questions correctly; they simply disagree, and an exact
	// interface filter follows the ifindex rather than the zone. Inert today —
	// the fabric member is declared with no config unit, so it has no
	// {ifindex, vlan} name, the lookup misses and the CLI falls back to the
	// zone as before. See userspace-dp/src/session/entry.rs for the full note
	// and the operator consequence if a unit is ever added.
	// There is deliberately NO "pre-#4983 helper, rolling upgrade" population:
	// `sessions`/`sessions_v6` are in the shim ABI pre-flight's checked set, and
	// validateUserspaceShimLivePins (loader_userspace_shim.go) hard-refuses a
	// ValueSize mismatch against the live pin, so a new daemon never reads an
	// old helper's 136/184-byte rows — the recovery is to unlink the named pin
	// (docs/operations/userspace-shim-pin-recovery.md) so the next load
	// recreates it at the new size. Whether a plain restart suffices is
	// MODE-DEPENDENT (#6928): a bpffs pin outlives its process, and a HITLESS
	// shutdown deliberately preserves the pins (Manager.Close), so there a
	// restart leaves the old-size pin in place and the pre-flight refuses
	// again; a NON-hitless HA shutdown calls Manager.Teardown, which unpins
	// everything, so there a restart is enough. dataplane.Cleanup() therefore
	// has TWO production reference sites — the `xpfd cleanup` subcommand
	// (cmd/xpfd/main.go, a direct call) and `var teardownCleanupFn = Cleanup`
	// (loader.go), the #6743 test seam Manager.Teardown invokes — not one.
	// Teardown's reach became INDIRECT in #6743; it did not go away.
	// TestCleanupProductionCallersMatchRemediation_6928 binds that reference
	// set, TestTeardownInvokesTheCleanupSeam_6928 binds that Teardown actually
	// invokes the seam (a func value sitting in a var proves nothing on its
	// own — deleting the invocation leaves the set unchanged), and
	// TestShutdownModeChoosesCloseOrTeardown6928 (pkg/daemon) binds WHICH
	// shutdown arm calls Teardown versus Close. None binds this comment's
	// wording — no test can; read it against those three.
	// Consumers MUST fall back to the zone approximation for those (see
	// sessionFilter.resolveIngressIfaces in pkg/cli), never treat 0 as "matches
	// nothing" or "matches everything".
	//
	// All THREE session surfaces consume it (#6960): pkg/cli (the in-daemon
	// console), pkg/grpcapi (what the REMOTE cli binary uses for show AND
	// clear, and what a console clear propagates to the HA peer over) and
	// pkg/api (REST). Each resolves the ingress interface from this identity
	// and falls back to the zone only where it is absent. Before #6960 the two
	// remote surfaces answered from the ingress ZONE in the pre-#4792
	// first-interface-only form, so an interface-scoped clear through gRPC
	// deleted every session of that zone (#6975).
	//
	// An interface-filtered SHOW is exact for rows this node owns ONLY when the
	// row's {ifindex, vlan} names a currently-configured unit; it is
	// approximate for peer rows and for three local shapes besides (#6928
	// derivation). The resolvers return a single name only on a hit in the
	// {ifindex, vlan} name map, and that map is rebuilt per query from the
	// CURRENT config and the CURRENT kernel ifindex:
	//   - a non-zero ifindex the config cannot name (unit deleted since
	//     install, tunnel/fabric ingress with no config unit) MISSES and falls
	//     back to the zone — the resolver's own doc says so;
	//   - a RECYCLED ifindex can HIT a key the kernel has since reassigned to a
	//     different interface, which is worse than approximate: it renders one
	//     confident WRONG name rather than a zone list. All three surfaces
	//     CORROBORATE a hit against the row's own recorded ingress zone and,
	//     when the two disagree, treat it as a MISS and answer from the zone
	//     — the filter feeds `clear`, so an untrustworthy name must not select
	//     anything (#6960/#6987). The reported column declines to name an
	//     interface at all on such a disagreement, and names a zone's
	//     interface only where the zone binds exactly ONE. Corroboration
	//     cannot separate a recycle WITHIN one zone from the truth, on any
	//     surface;
	//   - the map keys a unit under `vlan-id`, else `unit number`
	//     (`sessionDisplayVLANID`), while the row carries the VID OBSERVED ON
	//     THE WIRE. Those agree when the unit number equals the vlan id, or
	//     when both are 0; a unit whose number is populated and whose traffic
	//     is untagged — a plain `ge-0/0/0 unit 3` with no `vlan-id`, the
	//     concrete case — keys 0 on the wire and `number` in the map, and
	//     misses. Only the VLAN half diverges there: BOTH sides name the
	//     PHYSICAL parent netdev. The helper binds AF_XDP to the parent and
	//     stamps that bind (`UserspaceDpMeta::ingress_ifindex`); the LOGICAL
	//     child ifindex is what `ingress_logical_ifindex` maps the
	//     {parent, vid} pair TO, never what the row carries. So a reader
	//     chasing this miss should not go looking for a `ge-0-0-0.3` child
	//     ifindex in the row — it is not there (#6928 review).
	// (Note the collision the map DOES avoid: units do not collapse onto
	// {ifindex, 0}, because that same number-fallback separates them; a
	// first-writer-wins insert still decides any genuine key collision.)
	//
	// An interface-filtered CLEAR propagates to the peer unconditionally
	// (`clearFilteredSessions`, `pkg/cli/cli_clear.go`). The peer honours the
	// filter through this same identity since #6960, so on zone
	// `[reth0.50, reth0.80]` clearing `reth0.50` no longer deletes peer flows
	// received on `reth0.80` — but only for peer rows that CARRY an identity,
	// and a peer-synced row does not: the ifindex is node-local and is
	// deliberately imported as 0 (#7095). Those rows still fall back to the
	// zone on the peer, so a cross-node interface-scoped clear remains
	// zone-wide in practice until #7095 lands.
	//
	// Do not read the local exactness this field buys as an end-to-end
	// guarantee. It is bounded on BOTH sides, and the local bound is the one
	// easy to lose: "this node is the authority" does NOT upgrade to "exact"
	// — the three shapes enumerated above are all rows this node owns
	// outright, and the recycled-ifindex one is not even a miss.
	//
	// REST has no clear to be wrong about at all: pkg/api sessions.go REJECTS
	// any filtered clear with HTTP 400 rather than degrading it to a clear-all
	// (#6928 review). Its interface filter still reads this identity, because
	// the REST session QUERY reports the same rows (#6960).
	IngressIfindex uint32

	// IngressVlanID is the #4983 ingress 802.1Q VLAN id the session's first
	// packet carried. 0 means the first packet's VID was zero, which is BOTH an untagged frame AND an 802.1p priority-tagged one (a real 802.1Q tag with VID 0 and PCP/DEI set). The row stores a bare VID, so it does not distinguish them; the TX side does, via TxVlanTag on tag PRESENCE (#2149, userspace-dp/src/afxdp/README.md). Do not read 0 as "arrived untagged" (#6928).
	//
	// It is meaningful ONLY alongside a
	// non-zero IngressIfindex: the pair {IngressIfindex, IngressVlanID} is
	// exactly the sessionIfaceKey the CLI already resolves the EGRESS
	// interface name by (buildSessionEgressIfaces keys on the PARENT netdev
	// ifindex + the unit's VLAN), so the ingress side reuses that one map and
	// two VLAN units of a single trunk NIC do not alias onto each other.
	// Also part of the on-map C conntrack ABI.
	IngressVlanID uint16

	// RoutingDomain is the #7239 (#7160/#2387) session-key ROUTING DOMAIN.
	//
	// #9546: it is ALSO part of the on-map C conntrack ABI
	// (session_value.routing_domain, appended after ingress_vlan_id), which is
	// why it sits HERE in the shared prefix instead of among the sync-only
	// trailing fields below. Until #9546 the BPF mirror had no slot for it, so
	// every value read back out of the mirror carried 0 — measured, with
	// TCPState and Timeout surviving the same round trip — and that made the
	// #9146 singular and #9364 batch delete scoping inert on the real path.
	// Both writers now stamp it: Go (SetSessionV4 -> toBPF) copies this value
	// as-is, and the helper (publish_conntrack) states it for FORWARD rows
	// only. The cluster sync wire is UNCHANGED: pkg/cluster/sync_protocol.go
	// encodes this field explicitly at its own length-gated trailing
	// position, never by struct layout.
	//
	// It exists because the peer used to DERIVE the domain from IngressIfaceFold,
	// and that fold is computed on the SEND path against the CURRENT config
	// (#7239) — so an ifindex recycled onto a sibling between install and sync
	// folded to the sibling's name and the session was imported into the
	// sibling's routing domain. If the two interfaces are in different routing
	// instances that is a cross-tenant mis-file, and a CONFIDENT one, because
	// the helper's two-pass reverse preference matches a reply in the wrong
	// tenant's domain on pass 1.
	//
	// Carried OPAQUELY: this is the #7239 encoded value, not a raw domain. 0
	// means the sender did not state one, and the default instance has its own
	// non-zero marker, so absence and default-instance stay distinguishable
	// across every hop. Only the helper encodes and decodes it.
	RoutingDomain uint32

	// Generation is a per-(sender,key) monotonic install generation used
	// by the HA session-sync deferred-delete guard (#2170). It is
	// userspace-sync-only metadata — like the LogFlagUserspace* bits — and
	// is NOT mirrored into the BPF C conntrack struct. The cluster sync
	// sender stamps every install with a strictly increasing generation;
	// the receiver refuses a delete (or a stale install) whose generation
	// is strictly older than the currently-stored entry's, so a journaled
	// delete for a closed incarnation cannot kill a same-5-tuple
	// replacement that was re-synced with a newer generation. A value of 0
	// means "unknown / legacy peer" and falls back to unconditional
	// delete (rolling-upgrade safe).
	//
	// Because this field is sync-only, the BPF conntrack maps are NOT
	// registered at sizeof(SessionValue): they use the dedicated on-map ABI
	// type bpfSessionValue (bpf_session_value.go), which omits Generation and
	// matches the C/Rust layout — 144 bytes for v4 post-#4983 (128 was the
	// figure before the #5460 flags widen and this issue's ingress-identity
	// growth; corrected here, #6928 review). Registering at sizeof(SessionValue)
	// would over-size value_size and OOB-write the Rust helper's smaller lookup
	// buffer (#2360). The excess is NOT a fixed 8 bytes either: SessionValue
	// carries several sync-only trailing fields, so the gap is whatever they sum
	// to. Do NOT mirror Generation into the BPF map.
	Generation uint64

	// PolicyCounterIdx is the #3073 1-based handle to the admitting rule's
	// per-rule hit counter, carried across the HA session-sync wire (#3301)
	// so a peer-promoted session increments the correct policy counter after
	// failover. Like Generation, it is userspace-sync-only HA metadata: it is
	// NOT part of the BPF/C conntrack ABI (bpfSessionValue), so it MUST NOT
	// be added to bpfSessionValue. A value of 0 means "no per-rule counter"
	// (default policy / non-policy-forwarded), the rolling-upgrade-safe
	// default for an old peer that omits it.
	PolicyCounterIdx uint32

	// ConfigEpoch is the #5274 admitting config epoch: the value of the HA
	// config-sync generation (#3931 configGenCounter) the SENDER held when it
	// queued this session for sync. The cluster receiver rejects an install
	// whose ConfigEpoch is STRICTLY OLDER than its own lastAppliedConfigGen —
	// the peer has since committed (and this node has applied) a newer config
	// that may DENY the session, so a delayed stale-permit install that lands
	// after the receiver's clearSessionsForDeletedPolicies scan is refused
	// (SessionsStaleConfigIgnored). Like Generation/PolicyCounterIdx it is
	// userspace-sync-only HA metadata carried as a length-gated trailing field
	// in encodeSessionV4Payload; it is NOT part of the BPF/C conntrack ABI
	// (bpfSessionValue) and MUST NOT be added to it. A value of 0 means
	// "unknown / legacy peer" and disables the config-epoch check (the
	// rolling-upgrade-safe default an old peer omits). The epoch is only
	// cross-node comparable in the #3931 config-sync-generation namespace,
	// which is authoritative in the Go cluster layer — see
	// SessionSync.installClusterSyncedV4 for the guard.
	ConfigEpoch uint64

	// RTFlowSessionID is the #5212 ORIGINATING node's stable RT_FLOW session id
	// (the Rust dataplane's SessionTable.alloc_session_id value: the assigning
	// worker's id in the high 16 bits + a per-worker monotonic counter). The
	// dataplane assigns it at install and stamps it on every RT_FLOW
	// SESSION_CREATE/CLOSE record (#4915); this field carries it across the HA
	// session-sync wire so a PEER-SYNCED session ADOPTS the originating node's id
	// instead of minting a fresh node-local one on import. A session that opens
	// on the primary and closes on the peer after a failover then emits its
	// SESSION_CREATE and SESSION_CLOSE records under ONE correlatable id across
	// both nodes. Distinct from the BPF-ABI SessionID above (that is the Go
	// dataplane's own conntrack id — node-local by construction; in userspace mode
	// it is minted per converted session by nextUserspaceSyncedSessionID, #6198,
	// replacing a now<<16|Slot composition that collapsed every session converted
	// in one second onto a single id). Like Generation/ConfigEpoch this is
	// userspace-sync-only
	// HA metadata carried as a length-gated trailing field in the encode*Payload
	// functions; it is NOT part of the BPF/C conntrack ABI and MUST NOT be added
	// to it. 0 = "no id carried" (a legacy peer that omits the field, or a
	// synthesized delta with no live entry): the receiver falls back to a fresh
	// locally-allocated id, bit-identical to the pre-#5212 import
	// (rolling-upgrade safe). A real id is never 0 (the allocator counter starts
	// at 1), so the sentinel is unambiguous.
	RTFlowSessionID uint64

	// IngressIfaceFold is the #7095 CLUSTER-STABLE fold of the session's
	// ingress interface name, carried on the HA session-sync wire so the
	// #4983 identity survives a failover.
	//
	// It exists because IngressIfindex cannot cross the wire: an ifindex is
	// NODE-LOCAL, so the originating node's value names a different NIC on the
	// importing node. This is instead a fold of the RETH-RELATIVE name
	// (config.StableIfaceID over config.ClusterStableIfaceName), which both
	// chassis agree on by construction and each resolves to its own member.
	//
	// ZERO MEANS UNKNOWN, and three different things produce it on purpose:
	// a legacy peer that sends no field at all (the wire slot is length-gated,
	// the #2170 Generation pattern), a session whose ingress interface has no
	// cluster-stable name, and a fabric-redirected session, which records no
	// ingress identity at all because the fabric stamp carries a u16 zone id
	// and nothing else (#7096). The consumer's answer to all three is the same:
	// fall back to the #4792 zone approximation rather than name a device.
	//
	// It is HA-wire metadata only and is not part of the on-map C conntrack
	// ABI.
	IngressIfaceFold uint32

	// TunnelDiscriminator is the #7188 tunnel session-identity discriminator,
	// as encoded by the Rust helper's TunnelDiscriminator::to_wire
	// (userspace-dp session/discriminator.rs). It is OPAQUE on this side: Go
	// carries the tag across the cluster wire and hands it back to the peer
	// helper, which is the only place the encoding is defined.
	//
	// It exists because GRE is protocol 47 and has no L4 ports, so two RFC 2890
	// tunnels between one pair of outer endpoints are ONE 5-tuple. The helper's
	// own session key separates them on this typed discriminator; the sync path
	// did not carry it, so the standby rebuilt both records as the same key and
	// the second install evicted the first — one session for two tunnels, and
	// after a failover one policy decision, one NAT state, one counter set and
	// one timeout for both.
	//
	// It rides as a VALUE field, not a key field: the fixed-width wire key block
	// and the BPF/C conntrack ABI both stay untouched, and the receiver folds it
	// into the key it reconstructs (the plan v5 §0a shape — see
	// userspace-dp/src/afxdp/forwarding/README.md). Like Generation/ConfigEpoch
	// it is userspace-sync-only HA metadata carried as a length-gated trailing
	// field in the encode*Payload functions, and MUST NOT be added to the
	// BPF/C conntrack ABI.
	//
	// 0 = "not carried" (a legacy peer, or a delete request built from a key
	// with no value). It is RESERVED and is NOT the encoding of the helper's
	// None class, which is what lets the peer helper withhold a protocol-47
	// session it cannot express rather than importing it aliased (#7188
	// decision 2). Every other protocol imports unchanged.
	TunnelDiscriminator uint64
	// PLACEMENT: this sits after RTFlowSessionID, not before Generation.
	// Generation must be the FIRST field past the on-map conntrack layout —
	// TestSessionValueCarriesSyncOnlyGeneration asserts that offset exactly —
	// so every sync-only field added later belongs behind it, not between.
}

// SessionKeyV6 mirrors the C struct session_key_v6 (5-tuple with 128-bit IPs).
type SessionKeyV6 struct {
	SrcIP    [16]byte
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// SessionValueV6 mirrors the C struct session_value_v6.
type SessionValueV6 struct {
	State uint8
	// Flags is uint16: see SessionValue.Flags (#5460). SessFlagNPTV6 is bit 8.
	Flags      uint16
	TCPState   uint8
	IsReverse  uint8
	AppTimeout uint32 // per-application inactivity timeout (seconds), 0=use default

	// SessionID is the NODE-LOCAL conntrack id. It is a display/correlation
	// value, never a lookup key — forwarding, installs, and deletes are all
	// 5-tuple keyed. In userspace mode the control plane mints it per converted
	// HA-synced session (nextUserspaceSyncedSessionID, #6198); the helper stamps
	// its own dataplane id for sessions it owns (#4915). The two nodes do NOT
	// agree on it: the cross-node correlatable id is RTFlowSessionID below.
	// See "Node-Local BPF-ABI Session Id" in docs/session-sync-architecture.md.
	SessionID uint64

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   [16]byte
	NATDstIP   [16]byte
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKeyV6

	ALGType  uint8
	LogFlags uint8
	AppID    uint16

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16

	// IngressIfindex is the #4983 TRUE ingress-interface identity: the ifindex
	// of the binding the session's FIRST packet arrived on. The helper stamps
	// it ONCE at session install from the packet's ingress binding
	// (SessionMetadata.ingress_ifindex -> publish_conntrack) and never
	// re-derives it from the zone — re-deriving is exactly the approximation
	// this field exists to remove. It rides the on-map C conntrack ABI
	// (session_value.ingress_ifindex), NOT the sync-only trailing fields below,
	// so it is present on bpfSessionValue and round-trips through the BPF
	// mirror.
	//
	// SCOPE (#6965): the stamp is on every forward session installed FROM A
	// RECEIVED FRAME — i.e. at the three frame-driven install sites, the only
	// places an observed ingress binding exists to copy. Two production sites
	// install a forward (is_reverse=false) session with 0 and are not
	// exceptions to the rule but instances of it: the host-outbound GRE
	// encapsulation path (afxdp/tunnel.rs), where firewall-originated traffic
	// read off the TUN device never arrived on a binding, and the HA peer
	// import (server/helpers/session_sync.rs), which deliberately does not
	// carry the peer's node-local ifindex. Both are listed among the
	// legitimate zeros below.
	//
	// The frame-driven stamps reach THIS map, which is what IterateSessions —
	// and therefore `show`/`clear security flow session` — enumerates. The
	// helper's publish_bpf_conntrack_entry is called from four sites in
	// afxdp/poll_descriptor: the TRANSIT forward install (#6965), the
	// host-inbound (LocalMiss) install, the missing-neighbor-seed install, and
	// the reverse-companion repair (whose row is IsReverse != 0 and is skipped
	// before filtering). Before #6965 the transit install did NOT publish here
	// — it wrote only the shim's separate steering table via
	// publish_live_session_entry — so a transit session had NO row in this map
	// at all, and an interface filter could not select it either way. That gap
	// predated #4983 (it dated to the commit that first added the conntrack
	// mirror). This field is now operator-visible for the transit, host-inbound
	// and missing-neighbor-seed populations plus peer-synced sessions the Go
	// side installs directly. What it carries is the {parent ifindex, VLAN}
	// PAIR; the unit is resolved on this side.
	//
	// 0 means "no ingress identity carried" and is NEVER a valid ifindex. These
	// populations legitimately carry 0 and MUST keep working:
	//   - the reverse companion (its own ingress has not been OBSERVED yet).
	//     The forward flow's egress IS known at install — it is the wrong
	//     datum, being a prediction of where the reply will arrive rather than
	//     an observation of where it did, and routing may be asymmetric. Note
	//     every pkg/cli show/clear call site skips IsReverse != 0 before
	//     filtering, so a reverse row is never interface-matched anyway;
	//   - an HA peer-synced session (an ifindex is NODE-LOCAL — the peer's
	//     number names a different NIC on this node, so carrying it across the
	//     cluster wire would be confidently wrong, worse than approximating);
	//   - the helper's host-outbound GRE encapsulation path, where the traffic
	//     is firewall-self-originated off the TUN device and has no ingress
	//     binding to record;
	//   - the helper's flow-cache descriptor seed, which is replay state for an
	//     already-installed session and is never published as one.
	//
	// FABRIC INGRESS is the one population where this field and IngressZone
	// name DIFFERENT interfaces, so the list above is not exhaustive without
	// it. A frame arriving over the fabric carries a zone-encoded override, so
	// IngressZone is the ORIGINATING chassis's zone while this stamp records
	// the LOCAL fabric NIC the frame physically arrived on. Both answer
	// different questions correctly; they simply disagree, and an exact
	// interface filter follows the ifindex rather than the zone. Inert today —
	// the fabric member is declared with no config unit, so it has no
	// {ifindex, vlan} name, the lookup misses and the CLI falls back to the
	// zone as before. See userspace-dp/src/session/entry.rs for the full note
	// and the operator consequence if a unit is ever added.
	// There is deliberately NO "pre-#4983 helper, rolling upgrade" population:
	// `sessions`/`sessions_v6` are in the shim ABI pre-flight's checked set, and
	// validateUserspaceShimLivePins (loader_userspace_shim.go) hard-refuses a
	// ValueSize mismatch against the live pin, so a new daemon never reads an
	// old helper's 136/184-byte rows — the recovery is to unlink the named pin
	// (docs/operations/userspace-shim-pin-recovery.md) so the next load
	// recreates it at the new size. Whether a plain restart suffices is
	// MODE-DEPENDENT (#6928): a bpffs pin outlives its process, and a HITLESS
	// shutdown deliberately preserves the pins (Manager.Close), so there a
	// restart leaves the old-size pin in place and the pre-flight refuses
	// again; a NON-hitless HA shutdown calls Manager.Teardown, which unpins
	// everything, so there a restart is enough. dataplane.Cleanup() therefore
	// has TWO production reference sites — the `xpfd cleanup` subcommand
	// (cmd/xpfd/main.go, a direct call) and `var teardownCleanupFn = Cleanup`
	// (loader.go), the #6743 test seam Manager.Teardown invokes — not one.
	// Teardown's reach became INDIRECT in #6743; it did not go away.
	// TestCleanupProductionCallersMatchRemediation_6928 binds that reference
	// set, TestTeardownInvokesTheCleanupSeam_6928 binds that Teardown actually
	// invokes the seam (a func value sitting in a var proves nothing on its
	// own — deleting the invocation leaves the set unchanged), and
	// TestShutdownModeChoosesCloseOrTeardown6928 (pkg/daemon) binds WHICH
	// shutdown arm calls Teardown versus Close. None binds this comment's
	// wording — no test can; read it against those three.
	// Consumers MUST fall back to the zone approximation for those (see
	// sessionFilter.resolveIngressIfaces in pkg/cli), never treat 0 as "matches
	// nothing" or "matches everything".
	//
	// All THREE session surfaces consume it (#6960): pkg/cli (the in-daemon
	// console), pkg/grpcapi (what the REMOTE cli binary uses for show AND
	// clear, and what a console clear propagates to the HA peer over) and
	// pkg/api (REST). Each resolves the ingress interface from this identity
	// and falls back to the zone only where it is absent. Before #6960 the two
	// remote surfaces answered from the ingress ZONE in the pre-#4792
	// first-interface-only form, so an interface-scoped clear through gRPC
	// deleted every session of that zone (#6975).
	//
	// An interface-filtered SHOW is exact for rows this node owns ONLY when the
	// row's {ifindex, vlan} names a currently-configured unit; it is
	// approximate for peer rows and for three local shapes besides (#6928
	// derivation). The resolvers return a single name only on a hit in the
	// {ifindex, vlan} name map, and that map is rebuilt per query from the
	// CURRENT config and the CURRENT kernel ifindex:
	//   - a non-zero ifindex the config cannot name (unit deleted since
	//     install, tunnel/fabric ingress with no config unit) MISSES and falls
	//     back to the zone — the resolver's own doc says so;
	//   - a RECYCLED ifindex can HIT a key the kernel has since reassigned to a
	//     different interface, which is worse than approximate: it renders one
	//     confident WRONG name rather than a zone list. All three surfaces
	//     CORROBORATE a hit against the row's own recorded ingress zone and,
	//     when the two disagree, treat it as a MISS and answer from the zone
	//     — the filter feeds `clear`, so an untrustworthy name must not select
	//     anything (#6960/#6987). The reported column declines to name an
	//     interface at all on such a disagreement, and names a zone's
	//     interface only where the zone binds exactly ONE. Corroboration
	//     cannot separate a recycle WITHIN one zone from the truth, on any
	//     surface;
	//   - the map keys a unit under `vlan-id`, else `unit number`
	//     (`sessionDisplayVLANID`), while the row carries the VID OBSERVED ON
	//     THE WIRE. Those agree when the unit number equals the vlan id, or
	//     when both are 0; a unit whose number is populated and whose traffic
	//     is untagged — a plain `ge-0/0/0 unit 3` with no `vlan-id`, the
	//     concrete case — keys 0 on the wire and `number` in the map, and
	//     misses. Only the VLAN half diverges there: BOTH sides name the
	//     PHYSICAL parent netdev. The helper binds AF_XDP to the parent and
	//     stamps that bind (`UserspaceDpMeta::ingress_ifindex`); the LOGICAL
	//     child ifindex is what `ingress_logical_ifindex` maps the
	//     {parent, vid} pair TO, never what the row carries. So a reader
	//     chasing this miss should not go looking for a `ge-0-0-0.3` child
	//     ifindex in the row — it is not there (#6928 review).
	// (Note the collision the map DOES avoid: units do not collapse onto
	// {ifindex, 0}, because that same number-fallback separates them; a
	// first-writer-wins insert still decides any genuine key collision.)
	//
	// An interface-filtered CLEAR propagates to the peer unconditionally
	// (`clearFilteredSessions`, `pkg/cli/cli_clear.go`). The peer honours the
	// filter through this same identity since #6960, so on zone
	// `[reth0.50, reth0.80]` clearing `reth0.50` no longer deletes peer flows
	// received on `reth0.80` — but only for peer rows that CARRY an identity,
	// and a peer-synced row does not: the ifindex is node-local and is
	// deliberately imported as 0 (#7095). Those rows still fall back to the
	// zone on the peer, so a cross-node interface-scoped clear remains
	// zone-wide in practice until #7095 lands.
	//
	// Do not read the local exactness this field buys as an end-to-end
	// guarantee. It is bounded on BOTH sides, and the local bound is the one
	// easy to lose: "this node is the authority" does NOT upgrade to "exact"
	// — the three shapes enumerated above are all rows this node owns
	// outright, and the recycled-ifindex one is not even a miss.
	//
	// REST has no clear to be wrong about at all: pkg/api sessions.go REJECTS
	// any filtered clear with HTTP 400 rather than degrading it to a clear-all
	// (#6928 review). Its interface filter still reads this identity, because
	// the REST session QUERY reports the same rows (#6960).
	IngressIfindex uint32

	// IngressVlanID is the #4983 ingress 802.1Q VLAN id the session's first
	// packet carried. 0 means the first packet's VID was zero, which is BOTH an untagged frame AND an 802.1p priority-tagged one (a real 802.1Q tag with VID 0 and PCP/DEI set). The row stores a bare VID, so it does not distinguish them; the TX side does, via TxVlanTag on tag PRESENCE (#2149, userspace-dp/src/afxdp/README.md). Do not read 0 as "arrived untagged" (#6928).
	//
	// It is meaningful ONLY alongside a
	// non-zero IngressIfindex: the pair {IngressIfindex, IngressVlanID} is
	// exactly the sessionIfaceKey the CLI already resolves the EGRESS
	// interface name by (buildSessionEgressIfaces keys on the PARENT netdev
	// ifindex + the unit's VLAN), so the ingress side reuses that one map and
	// two VLAN units of a single trunk NIC do not alias onto each other.
	// Also part of the on-map C conntrack ABI.
	IngressVlanID uint16

	// RoutingDomain is the #7239 (#7160/#2387) session-key ROUTING DOMAIN.
	//
	// #9546: it is ALSO part of the on-map C conntrack ABI
	// (session_value.routing_domain, appended after ingress_vlan_id), which is
	// why it sits HERE in the shared prefix instead of among the sync-only
	// trailing fields below. Until #9546 the BPF mirror had no slot for it, so
	// every value read back out of the mirror carried 0 — measured, with
	// TCPState and Timeout surviving the same round trip — and that made the
	// #9146 singular and #9364 batch delete scoping inert on the real path.
	// Both writers now stamp it: Go (SetSessionV4 -> toBPF) copies this value
	// as-is, and the helper (publish_conntrack) states it for FORWARD rows
	// only. The cluster sync wire is UNCHANGED: pkg/cluster/sync_protocol.go
	// encodes this field explicitly at its own length-gated trailing
	// position, never by struct layout.
	//
	// It exists because the peer used to DERIVE the domain from IngressIfaceFold,
	// and that fold is computed on the SEND path against the CURRENT config
	// (#7239) — so an ifindex recycled onto a sibling between install and sync
	// folded to the sibling's name and the session was imported into the
	// sibling's routing domain. If the two interfaces are in different routing
	// instances that is a cross-tenant mis-file, and a CONFIDENT one, because
	// the helper's two-pass reverse preference matches a reply in the wrong
	// tenant's domain on pass 1.
	//
	// Carried OPAQUELY: this is the #7239 encoded value, not a raw domain. 0
	// means the sender did not state one, and the default instance has its own
	// non-zero marker, so absence and default-instance stay distinguishable
	// across every hop. Only the helper encodes and decodes it.
	RoutingDomain uint32

	// Generation: see SessionValue.Generation. Userspace-sync-only HA
	// deferred-delete guard metadata (#2170), not in the BPF C struct.
	Generation uint64

	// PolicyCounterIdx: see SessionValue.PolicyCounterIdx. Userspace-sync-only
	// #3073 per-rule hit-counter handle carried on the HA wire (#3301); NOT in
	// the BPF/C conntrack ABI (bpfSessionValueV6).
	PolicyCounterIdx uint32

	// Nat64SnatV4 is the #4565 NAT64 translated pool SOURCE (4-byte IPv4). A
	// NAT64 forward flow is keyed on the ORIGINAL IPv6 5-tuple (this V6 value),
	// but its reverse (v4->v6) reply is keyed on the translated
	// (server_v4 -> snat_v4) tuple, and the pool source is chosen by the
	// helper's allocate_source — it is NOT embedded in the synced forward v6
	// key (unlike the orig v6 src/dst, which ARE the key, and dst_v4, the /96
	// low 32 of the key dst). A non-zero value marks the session as NAT64 and
	// lets the peer-PROMOTED session rebuild its RFC 6146 reverse BIB after
	// failover. Like Generation/PolicyCounterIdx this is userspace-sync-only HA
	// metadata carried on the cluster wire (a length-gated trailing field in
	// encodeSessionV6Payload); it is NOT part of the BPF/C conntrack ABI
	// (bpfSessionValueV6) and MUST NOT be added to it. All-zero => not NAT64
	// (the rolling-upgrade-safe default an old peer omits).
	Nat64SnatV4 [4]byte

	// ConfigEpoch: see SessionValue.ConfigEpoch (#5274). The #3931 config-sync
	// generation the sender held when it queued this session; the cluster
	// receiver refuses an install whose epoch is strictly older than its
	// lastAppliedConfigGen (a stale permit across a config that now denies it).
	// Userspace-sync-only HA metadata carried as a length-gated trailing field
	// in encodeSessionV6Payload; NOT part of the BPF/C conntrack ABI
	// (bpfSessionValueV6) and MUST NOT be added to it. 0 = unknown/legacy peer
	// (check disabled), the rolling-upgrade-safe default.
	ConfigEpoch uint64

	// RTFlowSessionID is the #5212 ORIGINATING node's stable RT_FLOW session id
	// (the Rust dataplane's SessionTable.alloc_session_id value: the assigning
	// worker's id in the high 16 bits + a per-worker monotonic counter). The
	// dataplane assigns it at install and stamps it on every RT_FLOW
	// SESSION_CREATE/CLOSE record (#4915); this field carries it across the HA
	// session-sync wire so a PEER-SYNCED session ADOPTS the originating node's id
	// instead of minting a fresh node-local one on import. A session that opens
	// on the primary and closes on the peer after a failover then emits its
	// SESSION_CREATE and SESSION_CLOSE records under ONE correlatable id across
	// both nodes. Distinct from the BPF-ABI SessionID above (that is the Go
	// dataplane's own conntrack id — node-local by construction; in userspace mode
	// it is minted per converted session by nextUserspaceSyncedSessionID, #6198,
	// replacing a now<<16|Slot composition that collapsed every session converted
	// in one second onto a single id). Like Generation/ConfigEpoch this is
	// userspace-sync-only
	// HA metadata carried as a length-gated trailing field in the encode*Payload
	// functions; it is NOT part of the BPF/C conntrack ABI and MUST NOT be added
	// to it. 0 = "no id carried" (a legacy peer that omits the field, or a
	// synthesized delta with no live entry): the receiver falls back to a fresh
	// locally-allocated id, bit-identical to the pre-#5212 import
	// (rolling-upgrade safe). A real id is never 0 (the allocator counter starts
	// at 1), so the sentinel is unambiguous.
	RTFlowSessionID uint64

	// IngressIfaceFold is the #7095 cluster-stable ingress-interface fold, the
	// v6 twin of the field on SessionValue. Same contract: a fold of the
	// RETH-RELATIVE name (node-local ifindexes cannot cross the wire), carried
	// as a length-gated trailing wire field, and 0 means unknown — legacy peer,
	// no cluster-stable name, or a fabric-redirected session (#7096) — with the
	// #4792 zone approximation as the consumer fallback for all three.
	//
	// It is a SEPARATE field on a SEPARATE type because v6 sessions travel
	// through their own encoder and decoder; wiring only the v4 pair leaves
	// every IPv6 session degraded after a failover.
	IngressIfaceFold uint32

	// TunnelDiscriminator is the #7188 tunnel session-identity discriminator,
	// as encoded by the Rust helper's TunnelDiscriminator::to_wire
	// (userspace-dp session/discriminator.rs). It is OPAQUE on this side: Go
	// carries the tag across the cluster wire and hands it back to the peer
	// helper, which is the only place the encoding is defined.
	//
	// It exists because GRE is protocol 47 and has no L4 ports, so two RFC 2890
	// tunnels between one pair of outer endpoints are ONE 5-tuple. The helper's
	// own session key separates them on this typed discriminator; the sync path
	// did not carry it, so the standby rebuilt both records as the same key and
	// the second install evicted the first — one session for two tunnels, and
	// after a failover one policy decision, one NAT state, one counter set and
	// one timeout for both.
	//
	// It rides as a VALUE field, not a key field: the fixed-width wire key block
	// and the BPF/C conntrack ABI both stay untouched, and the receiver folds it
	// into the key it reconstructs (the plan v5 §0a shape — see
	// userspace-dp/src/afxdp/forwarding/README.md). Like Generation/ConfigEpoch
	// it is userspace-sync-only HA metadata carried as a length-gated trailing
	// field in the encode*Payload functions, and MUST NOT be added to the
	// BPF/C conntrack ABI.
	//
	// 0 = "not carried" (a legacy peer, or a delete request built from a key
	// with no value). It is RESERVED and is NOT the encoding of the helper's
	// None class, which is what lets the peer helper withhold a protocol-47
	// session it cannot express rather than importing it aliased (#7188
	// decision 2). Every other protocol imports unchanged.
	TunnelDiscriminator uint64
	// PLACEMENT: this sits after RTFlowSessionID, not before Generation.
	// Generation must be the FIRST field past the on-map conntrack layout —
	// TestSessionValueCarriesSyncOnlyGeneration asserts that offset exactly —
	// so every sync-only field added later belongs behind it, not between.

}

// ZoneConfig mirrors the C struct zone_config.
type ZoneConfig struct {
	ZoneID          uint16
	ScreenProfileID uint16
	HostInbound     uint32
	TCPRst          uint8
	Pad             [3]uint8
}

// ZonePairKey mirrors the C struct zone_pair_key.
type ZonePairKey struct {
	FromZone uint16
	ToZone   uint16
}

// PolicySet mirrors the C struct policy_set.
type PolicySet struct {
	PolicySetID   uint32
	NumRules      uint16
	DefaultAction uint16
}

// PolicyRule mirrors the C struct policy_rule.
type PolicyRule struct {
	RuleID      uint32
	PolicySetID uint32
	Sequence    uint16
	Action      uint8
	Log         uint8

	SrcAddrID   uint32
	DstAddrID   uint32
	DstPortLow  uint16
	DstPortHigh uint16
	Protocol    uint8
	Active      uint8
	Pad         [2]byte

	AppID     uint32
	NATRuleID uint32
	CounterID uint32
}

// CounterValue mirrors the C struct counter_value.
type CounterValue struct {
	Packets uint64
	Bytes   uint64
}

// InterfaceCounterValue mirrors the C struct iface_counter_value.
type InterfaceCounterValue struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
}

// Event mirrors the C struct event (with 16-byte IPs).
type Event struct {
	Timestamp      uint64
	SrcIP          [16]byte
	DstIP          [16]byte
	SrcPort        uint16
	DstPort        uint16
	PolicyID       uint32
	IngressZone    uint16
	EgressZone     uint16
	EventType      uint8
	Protocol       uint8
	Action         uint8
	AddrFamily     uint8
	SessionPackets uint64
	SessionBytes   uint64
	NATSrcIP       [16]byte
	NATDstIP       [16]byte
	NATSrcPort     uint16
	NATDstPort     uint16
	Created        uint32
	// Extended fields for structured logging (vSRX RT_FLOW compat)
	RevPackets     uint64
	RevBytes       uint64
	IngressIfindex uint32
	AppID          uint16
	CloseReason    uint8
	PadEvent       uint8
	// #3056: the admitting policy's ID on a SESSION_CLOSE frame. The other
	// frames (deny/screen/filter/create) carry the policy id in the [44:48]
	// PolicyID slot, but #2853 repurposed [44:48] on a close for the
	// created-subsec-nanos remainder, so the close frame carries the policy id
	// in this trailing [136:140] slot instead. 0 on every non-close frame and
	// on a close with no admitting policy. PadEvent2 keeps the struct 8-byte
	// aligned (144 bytes total) so it matches the Rust SECURITY_EVENT_PAYLOAD_SIZE.
	PolicyIDClose uint32
	PadEvent2     [4]uint8
}

// Close reason constants (must match C CLOSE_REASON_* defines).
const (
	CloseReasonNone    = 0
	CloseReasonTimeout = 1
	CloseReasonTCPFIN  = 2
	CloseReasonTCPRST  = 3
	CloseReasonAgeOut  = 4
	CloseReasonPolicy  = 5
)

// Tail call program indices -- must match C constants.
const (
	XDPProgScreen    = 0
	XDPProgZone      = 1
	XDPProgConntrack = 2
	XDPProgPolicy    = 3
	XDPProgNAT       = 4
	XDPProgForward   = 5
	XDPProgNAT64     = 6

	TCProgConntrack    = 0
	TCProgNAT          = 1
	TCProgScreenEgress = 2
	TCProgForward      = 3
)

// Global counter indices -- must match C constants.
const (
	GlobalCtrRxPackets       = 0
	GlobalCtrTxPackets       = 1
	GlobalCtrDrops           = 2
	GlobalCtrSessionsNew     = 3
	GlobalCtrSessionsClosed  = 4
	GlobalCtrScreenDrops     = 5
	GlobalCtrPolicyDeny      = 6
	GlobalCtrNATAllocFail    = 7
	GlobalCtrHostInboundDeny = 8
	GlobalCtrTCEgressPackets = 9
	GlobalCtrNAT64Xlate      = 10
	GlobalCtrHostInbound     = 11
	// Per-screen-type drop counters (12..25)
	GlobalCtrScreenSynFlood      = 12
	GlobalCtrScreenICMPFlood     = 13
	GlobalCtrScreenUDPFlood      = 14
	GlobalCtrScreenPortScan      = 15
	GlobalCtrScreenIPSweep       = 16
	GlobalCtrScreenLandAttack    = 17
	GlobalCtrScreenPingOfDeath   = 18
	GlobalCtrScreenTearDrop      = 19
	GlobalCtrScreenTCPSynFin     = 20
	GlobalCtrScreenTCPNoFlag     = 21
	GlobalCtrScreenTCPFinNoAck   = 22
	GlobalCtrScreenWinNuke       = 23
	GlobalCtrScreenIPSrcRoute    = 24
	GlobalCtrScreenSynFrag       = 25
	GlobalCtrFabricRedirect      = 26
	GlobalCtrSyncookieSent       = 27
	GlobalCtrSyncookieValid      = 28
	GlobalCtrSyncookieInvalid    = 29
	GlobalCtrSyncookieBypass     = 30
	GlobalCtrScreenSessionLimit  = 31
	GlobalCtrFabricFwdDrop       = 32
	GlobalCtrFabricRedirectFab0  = 33
	GlobalCtrFabricRedirectFab1  = 34
	GlobalCtrFabricRedirectZone  = 35
	GlobalCtrFlowCacheHit        = 36
	GlobalCtrFlowCacheMiss       = 37
	GlobalCtrFlowCacheFlush      = 38
	GlobalCtrFlowCacheInvalidate = 39
	GlobalCtrVlanPushFail        = 40
	GlobalCtrMax                 = 41
)

// CurrentSessions returns the live local-forwarding session count derived
// from the monotonic create/close counters as a saturating (floored-at-0)
// unsigned subtraction.
//
// #2428: callers historically computed `sessNew - sessClosed` directly.
// On the secondary/standby node the close counter could legitimately race
// ahead of the create counter for a brief window (and, before the dataplane
// balance fix, structurally — peer-synced sessions were reaped without ever
// being create-counted on the node that did not create them locally). A raw
// u64 subtraction wraps to ~1.8e19 in that case. The dataplane balance fix
// (only local-origin expiries bump session_expires) is the primary fix; this
// floor is the defense-in-depth backstop so the displayed gauge can never
// surface a wrapped value if a future imbalance reappears.
func CurrentSessions(sessNew, sessClosed uint64) uint64 {
	if sessClosed >= sessNew {
		return 0
	}
	return sessNew - sessClosed
}

// Host-inbound-traffic service flags (bitmap in zone_config.host_inbound_flags).
const (
	HostInboundSSH             = 1 << 0
	HostInboundPing            = 1 << 1
	HostInboundDNS             = 1 << 2
	HostInboundHTTP            = 1 << 3
	HostInboundHTTPS           = 1 << 4
	HostInboundDHCP            = 1 << 5
	HostInboundNTP             = 1 << 6
	HostInboundSNMP            = 1 << 7
	HostInboundBGP             = 1 << 8
	HostInboundOSPF            = 1 << 9
	HostInboundTraceroute      = 1 << 10
	HostInboundTelnet          = 1 << 11
	HostInboundFTP             = 1 << 12
	HostInboundNetconf         = 1 << 13
	HostInboundSyslog          = 1 << 14
	HostInboundRadius          = 1 << 15
	HostInboundIKE             = 1 << 16
	HostInboundDHCPv6          = 1 << 17
	HostInboundVRRP            = 1 << 18
	HostInboundESP             = 1 << 19
	HostInboundRouterDiscovery = 1 << 20
	HostInboundGRE             = 1 << 21
	HostInboundAll             = 0xFFFFFFFF
)

// HostInboundServiceFlags maps system-service names to flag bits.
var HostInboundServiceFlags = map[string]uint32{
	"ssh":        HostInboundSSH,
	"ping":       HostInboundPing,
	"dns":        HostInboundDNS,
	"http":       HostInboundHTTP,
	"https":      HostInboundHTTPS,
	"dhcp":       HostInboundDHCP,
	"ntp":        HostInboundNTP,
	"snmp":       HostInboundSNMP,
	"traceroute": HostInboundTraceroute,
	"telnet":     HostInboundTelnet,
	"ftp":        HostInboundFTP,
	"netconf":    HostInboundNetconf,
	"syslog":     HostInboundSyslog,
	"radius":     HostInboundRadius,
	"ike":        HostInboundIKE,
	"dhcpv6":     HostInboundDHCPv6,
	"ipsec":      HostInboundESP,
	"gre":        HostInboundGRE,
	"all":        HostInboundAll,
}

// HostInboundProtocolFlags maps protocol names to flag bits.
var HostInboundProtocolFlags = map[string]uint32{
	"ospf":             HostInboundOSPF,
	"bgp":              HostInboundBGP,
	"router-discovery": HostInboundRouterDiscovery,
	"vrrp":             HostInboundVRRP,
	"all":              HostInboundAll,
}

// Session state constants.
const (
	SessStateNone        = 0
	SessStateNew         = 1
	SessStateSynSent     = 2
	SessStateSynRecv     = 3
	SessStateEstablished = 4
	SessStateFINWait     = 5
	SessStateCloseWait   = 6
	SessStateTimeWait    = 7
	SessStateClosed      = 8
)

// Policy action constants.
const (
	ActionDeny   = 0
	ActionPermit = 1
	ActionReject = 2
)

// MaxZones must match MAX_ZONES in xpf_common.h.
const MaxZones = 64

// MaxRulesPerPolicy is the maximum number of rules in a single policy set.
const MaxRulesPerPolicy = 256

// DefaultPolicySentinelID is the reserved policy ID the userspace dataplane
// stamps on an RT_FLOW deny/reject event produced by the IMPLICIT
// default-policy (a flow matched no configured zone-pair or junos-global
// policy). #3057.
//
// A real configured policy ID is policySetID*MaxRulesPerPolicy + ruleIndex
// (see pkg/dataplane/userspace/policies.go and compiler.go), where ruleIndex is
// capped strictly below MaxRulesPerPolicy (256) and policySetID counts the
// configured zone-pair policy blocks (plus one for the global set) — far below
// 16,777,216 in any real config. Reaching 0xFFFFFFFF as a real ID would require
// ~16.7M policy sets, which is impossible, so this sentinel can never collide
// with a configured policy ID (in particular not the first policy's ID 0, the
// value the default used to emit and which mis-attributed the deny to the first
// rule). It is rendered as DefaultPolicyName in logs and session displays.
//
// MUST equal DEFAULT_POLICY_SENTINEL_ID in userspace-dp/src/policy.rs — the
// value travels in the existing policy_id u32 wire field (no layout change) and
// is pinned by a cross-language contract test.
const DefaultPolicySentinelID uint32 = 0xFFFFFFFF

// DefaultPolicyName is the human-readable pseudo-policy name rendered for the
// implicit default-policy sentinel (DefaultPolicySentinelID) in RT_FLOW logs,
// `show security flow session` displays, and gRPC session entries. It matches
// the Junos `security policies default-policy` config stanza. #3057.
const DefaultPolicyName = "default-policy"

// MaxSNATRulesPerPair must match MAX_SNAT_RULES_PER_PAIR in xpf_maps.h.
const MaxSNATRulesPerPair = 8

// LPMKeyV4 mirrors the C struct lpm_key_v4 for address book LPM trie.
type LPMKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // network byte order
}

// LPMKeyV6 mirrors the C struct lpm_key_v6 for IPv6 address book LPM trie.
type LPMKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

// AddrValue mirrors the C struct addr_value.
type AddrValue struct {
	AddressID uint32
}

// AddrMembershipKey mirrors the C struct addr_membership_key.
type AddrMembershipKey struct {
	IP        uint32 // stores resolved address_id (reused field)
	AddressID uint32
}

// AppKey mirrors the C struct app_key.
type AppKey struct {
	Protocol uint8
	Pad      uint8
	DstPort  uint16 // network byte order
}

// AppValue mirrors the C struct app_value.
type AppValue struct {
	AppID       uint32
	ALGType     uint8
	Pad         uint8
	Pad2        uint16
	Timeout     uint32 // inactivity timeout override (seconds), 0=default
	SrcPortLow  uint16 // source port range low (host byte order), 0=any
	SrcPortHigh uint16 // source port range high (host byte order), 0=any
}

// AppRangeEntry mirrors the C struct app_range_entry.
// Used for large port ranges stored in the app_ranges ARRAY map.
type AppRangeEntry struct {
	Protocol    uint8
	ALGType     uint8
	PortLow     uint16 // host byte order
	PortHigh    uint16 // host byte order
	SrcPortLow  uint16 // host byte order, 0=any
	SrcPortHigh uint16 // host byte order, 0=any
	Pad         uint16
	AppID       uint32
	Timeout     uint32
}

// MaxAppRanges is the maximum number of range-based application entries.
const MaxAppRanges = 32

// NAT pool types.
type NATPoolConfig struct {
	NumIPs         uint16
	NumIPsV6       uint16
	PortLow        uint16
	PortHigh       uint16
	AddrPersistent uint8
	Deterministic  uint8 // 0=off, 1=IPv4 host, 2=IPv6 host
	BlockSize      uint16
	HostBase       uint32 // network byte order (deterministic==1)
	HostCount      uint32
	BlocksPerIP    uint16
	HostPrefixLen  uint8     // IPv6 prefix length: 32 or 64 (deterministic==2)
	InterfaceMode  uint8     // 1 = source-nat interface: use egress IP from snat_egress_ips
	HostBaseV6     [4]uint32 // IPv6 subscriber base (deterministic==2)
}

type NATPoolIPV6 struct {
	IP [16]byte
}

// SNATEgressKey identifies an egress interface for interface-mode SNAT.
// Mirrors struct snat_egress_key in xpf_common.h.
type SNATEgressKey struct {
	Ifindex uint32
	VlanID  uint16
	Pad     uint16
}

// SNATEgressValue holds the SNAT address for a specific egress interface.
// Mirrors struct snat_egress_value in xpf_common.h.
type SNATEgressValue struct {
	IPv4 uint32
	IPv6 [16]byte
}

type NATPortCounter struct {
	Counter uint64
}

const MaxNATPoolIPsPerPool = 256
const MaxNATRuleCounters = 256
const SNATModeOff = 0xFF // source-nat off: match but don't translate

// Session flag constants. These mirror the C SESS_FLAG_* defines
// (bpf/headers/xpf_common.h) and are stored in SessionValue.Flags (uint16).
// SessFlagNPTV6 is bit 8, which is why Flags is uint16 and not a byte (#5460).
const (
	SessFlagSNAT      = 1 << 0
	SessFlagDNAT      = 1 << 1
	SessFlagStaticNAT = 1 << 6
	SessFlagNAT64     = 1 << 7
	SessFlagNPTV6     = 1 << 8 // bit 8 -- requires uint16 Flags
)

// StaticNATKeyV4 mirrors the C struct static_nat_key_v4.
type StaticNATKeyV4 struct {
	IP        uint32 // network byte order
	Direction uint8
	Pad       [3]byte
}

// StaticNATKeyV6 mirrors the C struct static_nat_key_v6.
type StaticNATKeyV6 struct {
	IP        [16]byte
	Direction uint8
	Pad       [3]byte
}

// StaticNATValueV6 mirrors the C struct static_nat_value_v6.
type StaticNATValueV6 struct {
	IP [16]byte
}

// Static NAT direction constants.
const (
	StaticNATDNAT = 0
	StaticNATSNAT = 1
)

// NPTv6 direction constants (RFC 6296).
const (
	NPTv6Inbound  = 0 // external → internal (rewrite dst)
	NPTv6Outbound = 1 // internal → external (rewrite src)
)

// NPTv6Key mirrors the C struct nptv6_key.
type NPTv6Key struct {
	Prefix    [8]byte // first 48 or 64 bits of IPv6 address (zero-padded for /48)
	Direction uint8   // NPTv6Inbound or NPTv6Outbound
	PrefixLen uint8   // 48 or 64
	Pad       [6]byte
}

// NPTv6Value mirrors the C struct nptv6_value.
type NPTv6Value struct {
	XlatPrefix  [8]byte // replacement prefix (first 48 or 64 bits)
	Adjustment  uint16  // ones'-complement adjustment (native byte order)
	PrefixWords uint8   // 3 for /48, 4 for /64
	Pad         [5]byte
}

// DNAT table flags.
const (
	DNATFlagDynamic = 0 // dynamic/SNAT-return entry
	DNATFlagStatic  = 1 // static/DNAT-config entry
)

// DNATKey mirrors the C struct dnat_key.
//
// #2406 BYTE-ORDER: DstPort is HOST-ORDER numeric (NOT network order). The
// AF_XDP shim is the only reader of this BPF map key; it builds its lookup
// key port via u16::from_be_bytes(wire) — the host-order numeric value — and
// stores it natively, identical to the proven session_map_key. Writers MUST
// match: session-derived keys go through DNATKeyForSessionV4 (ntohs of the
// network-order SessionValue.NATSrcPort); static-DNAT config writes the
// already-host-order port raw (no htons). DstIP stays in network byte order
// (the shim reads it with from_ne_bytes against octets() on both sides).
type DNATKey struct {
	Protocol uint8
	Pad      [3]byte
	DstIP    uint32 // network byte order
	DstPort  uint16 // host byte order (#2406 — matches shim from_be_bytes reader)
	FromZone uint16 // 0 = wildcard / dynamic SNAT-return entry
}

// DNATValue mirrors the C struct dnat_value.
type DNATValue struct {
	NewDstIP   uint32 // network byte order
	NewDstPort uint16 // network byte order
	Flags      uint8
	Pad        uint8
}

// DNATKeyV6 mirrors the C struct dnat_key_v6.
// DstPort is HOST-ORDER numeric (see DNATKey doc, #2406).
type DNATKeyV6 struct {
	Protocol uint8
	Pad      [3]byte
	DstIP    [16]byte
	DstPort  uint16 // host byte order (#2406 — matches shim from_be_bytes reader)
	FromZone uint16 // 0 = wildcard / dynamic SNAT-return entry
}

// DNATValueV6 mirrors the C struct dnat_value_v6.
type DNATValueV6 struct {
	NewDstIP   [16]byte
	NewDstPort uint16 // network byte order
	Flags      uint8
	Pad        uint8
}

// SNATKey mirrors the C struct snat_key.
type SNATKey struct {
	FromZone uint16
	ToZone   uint16
	RuleIdx  uint16
	Pad      uint16
}

// SNATValue mirrors the C struct snat_value.
type SNATValue struct {
	SNATIP    uint32 // network byte order
	SrcAddrID uint32 // 0 = any
	DstAddrID uint32 // 0 = any
	Mode      uint8
	Pad       uint8
	CounterID uint16 // index into nat_rule_counters
}

// SNATValueV6 mirrors the C struct snat_value_v6.
type SNATValueV6 struct {
	SNATIP    [16]byte
	SrcAddrID uint32 // 0 = any
	DstAddrID uint32 // 0 = any
	Mode      uint8
	Pad       uint8
	CounterID uint16 // index into nat_rule_counters
}

// FabricFwdInfo mirrors the C struct fabric_fwd_info for cluster
// cross-chassis forwarding via the fabric link.
type FabricFwdInfo struct {
	Ifindex    uint32  // fabric interface ifindex, 0 = disabled
	FIBIfindex uint32  // non-VRF ifindex for zone-decoded FIB lookups
	PeerMAC    [6]byte // peer's fabric MAC
	LocalMAC   [6]byte // our fabric MAC
}

// MirrorConfig mirrors the C struct mirror_config for port mirroring.
// Key is the ingress ifindex; value tells XDP where to clone-redirect.
type MirrorConfig struct {
	MirrorIfindex uint32 // destination interface ifindex
	Rate          uint32 // 1-in-N sampling rate (0 = mirror all)
}

// ScreenConfig mirrors the C struct screen_config.
type ScreenConfig struct {
	Flags             uint32
	SynFloodThresh    uint32
	ICMPFloodThresh   uint32
	UDPFloodThresh    uint32
	SynFloodSrcThresh uint32
	SynFloodDstThresh uint32
	SynFloodTimeout   uint32
	PortScanThresh    uint32
	IPSweepThresh     uint32
	SessionLimitSrc   uint32
	SessionLimitDst   uint32
}

// FloodState mirrors the C struct flood_state.
type FloodState struct {
	SynCount       uint64
	ICMPCount      uint64
	UDPCount       uint64
	WindowStart    uint64
	SynproxyActive uint8
	PadFS          [7]uint8
}

// Screen flag constants -- must match C SCREEN_* defines.
const (
	ScreenSynFlood        = 1 << 0
	ScreenICMPFlood       = 1 << 1
	ScreenUDPFlood        = 1 << 2
	ScreenPortScan        = 1 << 3
	ScreenIPSweep         = 1 << 4
	ScreenLandAttack      = 1 << 5
	ScreenPingOfDeath     = 1 << 6
	ScreenTearDrop        = 1 << 7
	ScreenTCPSynFin       = 1 << 8
	ScreenTCPNoFlag       = 1 << 9
	ScreenTCPFinNoAck     = 1 << 10
	ScreenWinNuke         = 1 << 11
	ScreenIPSourceRoute   = 1 << 12
	ScreenSynFrag         = 1 << 13
	ScreenSynCookie       = 1 << 14
	ScreenSessionLimitSrc = 1 << 15
	ScreenSessionLimitDst = 1 << 16
	// Bits 17-19 mirror the userspace-dp screen reason flags added after the
	// original eBPF parity set: ICMP fragment (#2146 sibling), IP malformed
	// (#2146 fail-closed parse error), and scan-table pressure (#2234, the
	// bounded stalest-eviction operator alarm — NOT a packet drop).
	ScreenICMPFragment      = 1 << 17
	ScreenIPMalformed       = 1 << 18
	ScreenScanTablePressure = 1 << 19
)

// ScreenFlagNames maps screen flag values to human-readable names.
var ScreenFlagNames = map[uint32]string{
	ScreenSynFlood:          "SYN flood",
	ScreenICMPFlood:         "ICMP flood",
	ScreenUDPFlood:          "UDP flood",
	ScreenPortScan:          "port scan",
	ScreenIPSweep:           "IP sweep",
	ScreenLandAttack:        "LAND attack",
	ScreenPingOfDeath:       "ping of death",
	ScreenTearDrop:          "tear drop",
	ScreenTCPSynFin:         "TCP SYN+FIN",
	ScreenTCPNoFlag:         "TCP no-flag",
	ScreenTCPFinNoAck:       "TCP FIN-no-ACK",
	ScreenWinNuke:           "WinNuke",
	ScreenIPSourceRoute:     "IP source-route",
	ScreenSynFrag:           "SYN fragment",
	ScreenSynCookie:         "SYN cookie",
	ScreenSessionLimitSrc:   "session limit (source)",
	ScreenSessionLimitDst:   "session limit (destination)",
	ScreenICMPFragment:      "ICMP fragment",
	ScreenIPMalformed:       "IP malformed",
	ScreenScanTablePressure: "scan-table pressure",
}

// ScreenReasonDropCount is the number of published per-screen-reason DROP
// counters. It MUST equal the userspace-dp Rust constant
// `screen::SCREEN_REASON_DROP_COUNT` and the length of the
// `BindingStatus.screen_reason_drops` wire array; the committed wire fixture
// (`userspace-dp/tests/fixtures/protocol_wire_v1.json`) pins that array length,
// so a drift between the two sides fails the Rust wire-invariant test.
const ScreenReasonDropCount = 15

// ScreenReasonCounter describes one published per-screen-reason DROP counter
// (#3343). Before #3343 the userspace counter bridge surfaced only the
// aggregate screen_drops, so every per-reason GlobalCtrScreen* counter read a
// permanent 0 and the CLI/gRPC/REST/Prometheus screen-statistics surfaces could
// not attribute a drop to a specific screen check. This table is the single
// source of truth for those surfaces: the ordinal order matches the Rust
// `BindingStatus.screen_reason_drops` wire array (each ordinal's count is pushed
// into Index by the userspace manager), and Reason/Label give consistent
// machine keys (gRPC detail map / Prometheus label) and display strings so the
// previously-duplicated, reason-omitting hardcoded lists agree.
type ScreenReasonCounter struct {
	Index  uint32 // GlobalCtrScreen* global-counter index this reason feeds
	Reason string // stable machine key (Prometheus label, gRPC detail-map key)
	Label  string // human display label for CLI / gRPC text surfaces
}

// ScreenReasonCounters is ordered to match the userspace-dp wire array ordinal
// for ordinal i. The two Rust session-limit reasons fold onto the single
// combined GlobalCtrScreenSessionLimit entry here.
var ScreenReasonCounters = [ScreenReasonDropCount]ScreenReasonCounter{
	{GlobalCtrScreenSynFlood, "syn-flood", "SYN flood"},
	{GlobalCtrScreenICMPFlood, "icmp-flood", "ICMP flood"},
	{GlobalCtrScreenUDPFlood, "udp-flood", "UDP flood"},
	{GlobalCtrScreenPortScan, "port-scan", "port scan"},
	{GlobalCtrScreenIPSweep, "ip-sweep", "IP sweep"},
	{GlobalCtrScreenLandAttack, "land-attack", "LAND attack"},
	{GlobalCtrScreenPingOfDeath, "ping-of-death", "ping of death"},
	{GlobalCtrScreenTearDrop, "teardrop", "teardrop"},
	{GlobalCtrScreenTCPSynFin, "tcp-syn-fin", "TCP SYN+FIN"},
	{GlobalCtrScreenTCPNoFlag, "tcp-no-flag", "TCP no-flag"},
	{GlobalCtrScreenTCPFinNoAck, "tcp-fin-no-ack", "TCP FIN-no-ACK"},
	{GlobalCtrScreenWinNuke, "winnuke", "WinNuke"},
	{GlobalCtrScreenIPSrcRoute, "ip-source-route", "IP source-route"},
	{GlobalCtrScreenSynFrag, "syn-frag", "SYN fragment"},
	{GlobalCtrScreenSessionLimit, "session-limit", "session limit"},
}

// SessionCountKey mirrors the C struct session_count_key.
type SessionCountKey struct {
	IP     uint32
	ZoneID uint16
	Pad    uint16
}

// SessionCountValue mirrors the C struct session_count_value.
type SessionCountValue struct {
	Count uint32
}

// Per-rule logging flags (matches C LOG_FLAG_* defines in bpf/headers/).
const (
	LogFlagSessionInit  = 1 << 0
	LogFlagSessionClose = 1 << 1
)

// Userspace-only session sync metadata piggybacked through SessionValue.LogFlags.
// These bits are NOT defined in the BPF C headers — they are only used by the
// Go/Rust userspace dataplane for session sync and are never written by eBPF.
const (
	LogFlagUserspaceTunnelEndpoint = 1 << 6
	LogFlagUserspaceFabricIngress  = 1 << 7
)

// Event type constants.
const (
	EventTypeSessionOpen  = 1
	EventTypeSessionClose = 2
	EventTypePolicyDeny   = 3
	EventTypeScreenDrop   = 4
	EventTypeFilterLog    = 6
)

// Flow timeout indices -- must match C FLOW_TIMEOUT_* defines.
const (
	FlowTimeoutTCPEstablished = 0
	FlowTimeoutTCPInitial     = 1
	FlowTimeoutTCPClosing     = 2
	FlowTimeoutTCPTimeWait    = 3
	FlowTimeoutUDP            = 4
	FlowTimeoutICMP           = 5
	FlowTimeoutOther          = 6
	FlowTimeoutMax            = 7
)

// Address family constants.
const (
	AFInet  = 2
	AFInet6 = 10
)

// IfaceZoneKey mirrors the C struct iface_zone_key (composite key for HASH map).
type IfaceZoneKey struct {
	Ifindex uint32
	VlanID  uint16
	Pad     uint16
}

// IfaceZoneValue mirrors the C struct iface_zone_value.
type IfaceZoneValue struct {
	ZoneID       uint16
	Flags        uint8  // IFACE_FLAG_* bits
	RGID         uint8  // redundancy group ID (0 = standalone/non-RETH)
	RoutingTable uint32 // kernel table ID, 0 = main table
	ScreenFlags  uint32 // precomputed screen_config.flags for ingress fast-path
}

// MaxRedundancyGroups is the maximum number of RG entries.
//
// #8317: an ALIAS of config.MaxRedundancyGroups, not a second literal. The
// commit-time bound on a redundancy-group id has to be the same number as the
// length of the arrays that id indexes, and a duplicate is what let them
// diverge — ids 16..255 committed against arrays whose valid indices are 0..15.
// Aliasing makes the agreement a compile-time identity rather than something a
// test has to remember to assert, and it keeps this name (and every reference
// to it, including the #7465 array-declaration cell) working unchanged.
const MaxRedundancyGroups = config.MaxRedundancyGroups

// IfaceFlagTunnel marks an interface as a tunnel (GRE/IPsec).
const IfaceFlagTunnel = 1 << 0

// IfaceFlagNativeXDP marks an interface with native/driver XDP (no CHECKSUM_PARTIAL).
const IfaceFlagNativeXDP = 1 << 1

// IfaceFlagXDPAttached (#863) marks an interface where XDP is actually
// attached on the ingress side (native or generic). Set by AttachXDP,
// cleared by DetachXDP. Used by the tc_main tunnel-egress bypass to
// prove the inner packet went through the XDP pipeline; without this
// gate, packets from non-XDP interfaces (loopback, veth, mgmt NIC)
// routed via a tunnel device would skip screen/conntrack/NAT.
const IfaceFlagXDPAttached = 1 << 2

// VlanIfaceInfo mirrors the C struct vlan_iface_info.
type VlanIfaceInfo struct {
	ParentIfindex uint32
	VlanID        uint16
	Pad           uint16
}

// Protocol number constants.
const (
	ProtoICMPv6 = 58
)

// NAT64PrefixKey mirrors the C struct nat64_prefix_key (hash map key).
type NAT64PrefixKey struct {
	Prefix [3]uint32
}

// NAT64Config mirrors the C struct nat64_config.
type NAT64Config struct {
	Prefix     [3]uint32 // first 96 bits of NAT64 prefix (3 x 32-bit words, network order)
	SNATPoolID uint8
	Pad        [3]byte
}

// FilterConfig mirrors the C struct filter_config.
type FilterConfig struct {
	NumRules     uint32
	RuleStart    uint32
	AllHaveProto uint8    // 1 if every term specifies FILTER_MATCH_PROTOCOL
	ProtoCount   uint8    // distinct protocol values across all terms (max 4)
	ProtoList    [4]uint8 // the distinct protocol numbers
	Pad          [2]uint8
}

// IfaceFilterKey mirrors the C struct iface_filter_key.
type IfaceFilterKey struct {
	Ifindex   uint32
	VlanID    uint16
	Family    uint8
	Direction uint8 // 0=input, 1=output
}

// FilterRule mirrors the C struct filter_rule.
type FilterRule struct {
	MatchFlags   uint16
	DSCP         uint8
	Protocol     uint8
	Action       uint8
	ICMPType     uint8
	ICMPCode     uint8
	Family       uint8
	DstPort      uint16 // network byte order
	SrcPort      uint16 // network byte order
	DstPortHi    uint16 // range upper bound (network byte order), 0=exact match
	SrcPortHi    uint16 // range upper bound (network byte order), 0=exact match
	DSCPRewrite  uint8  // DSCP rewrite value (0xFF = no rewrite)
	LogFlag      uint8  // 1 = emit ring buffer event on match
	TCPFlags     uint8  // TCP flags bitmask to match
	IsFragment   uint8  // 1 = match IP fragments
	SrcAddr      [16]byte
	SrcMask      [16]byte
	DstAddr      [16]byte
	DstMask      [16]byte
	RoutingTable uint32
	PolicerID    uint8 // policer index (0=none, 1-based)
	FlexOffset   uint8 // flexible match: byte offset from L3 header start
	FlexLength   uint8 // flexible match: match length in bytes (1,2,4)
	PadRule      byte
	FlexValue    uint32 // flexible match: expected value (host byte order, masked)
	FlexMask     uint32 // flexible match: mask to apply before comparison
}

// PolicerConfig mirrors the C struct policer_config.
type PolicerConfig struct {
	RateBytesSec uint64 // CIR: token refill rate (bytes per second)
	BurstBytes   uint64 // CBS: max committed bucket capacity (bytes)
	Action       uint8  // POLICER_ACTION_DISCARD=0
	ColorMode    uint8  // 0=single-rate, 1=two-rate, 2=single-rate-3c
	Pad          [6]byte
	PeakRate     uint64 // PIR: peak refill rate (two-rate only)
	PeakBurst    uint64 // PBS/EBS: peak/excess burst size
}

// Filter match flag constants.
const (
	FilterMatchDSCP      = 1 << 0
	FilterMatchProtocol  = 1 << 1
	FilterMatchSrcAddr   = 1 << 2
	FilterMatchDstAddr   = 1 << 3
	FilterMatchDstPort   = 1 << 4
	FilterMatchICMPType  = 1 << 5
	FilterMatchICMPCode  = 1 << 6
	FilterMatchSrcPort   = 1 << 7
	FilterMatchSrcNegate = 1 << 8  // negate source address match (prefix-list except)
	FilterMatchDstNegate = 1 << 9  // negate destination address match (prefix-list except)
	FilterMatchTCPFlags  = 1 << 10 // match TCP flags bitmask
	FilterMatchFragment  = 1 << 11 // match IP fragments
	FilterMatchFlex      = 1 << 12 // flexible byte-offset match
)

// Policer color mode constants.
const (
	PolicerModeSingleRate = 0 // single-rate two-color (default)
	PolicerModeTwoRate    = 1 // two-rate three-color (RFC 2698)
	PolicerModeSR3C       = 2 // single-rate three-color (RFC 2697)
)

// Filter action constants.
const (
	FilterActionAccept  = 0
	FilterActionDiscard = 1
	FilterActionReject  = 2
	FilterActionRoute   = 3
)

// ResolveFilterDSCP resolves a firewall-filter `dscp` / `traffic-class` token
// — a `from dscp` MATCH value or a `then dscp` REWRITE value — to its 6-bit
// codepoint. It accepts a codepoint alias (case-insensitive, e.g. `ef`,
// `af11`) or a decimal 0..63; anything else is UNREPRESENTABLE.
//
// #7422: this is the SINGLE SOURCE for a predicate that had two readers
// disagreeing. The snapshot builder (pkg/dataplane/userspace/filters.go)
// resolved the token and, on failure, dropped the `then dscp` rewrite with a
// slog.Warn — while `show firewall` printed `then dscp <token>`
// unconditionally, so the CLI reported a CoS marking the dataplane was not
// applying. The builder and the renderer now ask the SAME function, which is
// what stops them drifting again; a renderer that re-implemented the alias
// table would be correct only until the table changed.
//
// pkg/config cannot import pkg/dataplane (import cycle), so the commit-time
// gate keeps its own inline mirror (config.filterDSCPResolvable, #3309) — that
// mirror is pinned to THIS function by the bidirectional drift guard
// TestFilterDSCPResolvableMatchesDSCPValues.
//
// This is deliberately NOT a #6534 showaudit registry family. That registry
// covers an object the builder REFUSES TO INSTALL, and its census is per
// config collection: a dropped `then dscp` still installs the term, which
// still matches and still acts (#3406 — a rewrite is CoS-only, so failing the
// snapshot closed over it would brick forwarding for a marking). Registering
// it against Firewall.FiltersInet would drag in every filter renderer,
// including pkg/api/metrics_counters.go:emitFilters and the gRPC/REST text
// surfaces that emit no `then dscp` at all, and demand they annotate a field
// they never print.
func ResolveFilterDSCP(token string) (uint8, bool) {
	if token == "" {
		return 0, false
	}
	if val, ok := DSCPValues[strings.ToLower(token)]; ok {
		return val, true
	}
	if v, err := strconv.Atoi(token); err == nil && v >= 0 && v <= 63 {
		return uint8(v), true
	}
	return 0, false
}

// DSCPValues maps DSCP codepoint names to numeric values.
var DSCPValues = map[string]uint8{
	"ef":   46,
	"af11": 10, "af12": 12, "af13": 14,
	"af21": 18, "af22": 20, "af23": 22,
	"af31": 26, "af32": 28, "af33": 30,
	"af41": 34, "af42": 36, "af43": 38,
	"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
	"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
	"be": 0,
}

// MaxFilterRules is the maximum number of filter rules.
const MaxFilterRules = 512

// MaxFilterConfigs is the maximum number of filter configs.
const MaxFilterConfigs = 64

// MaxPolicers is the maximum number of policer configurations.
const MaxPolicers = 64
