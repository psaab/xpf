package cluster

// SessionSync sub-struct storage for the two lock-local domains extracted
// by #16159 (W2.6): the generation-guard domain and the peer held-snapshot
// domain. Only STORAGE moved here — every method keeps its name, receiver
// and signature on *SessionSync, so call sites and the forwarding surface
// are unchanged. The other candidate domains (connTable, bulkEngine,
// configReplicator) stay deferred per the narrowed survivor form.
//
// Why value fields, not pointers: SessionSync is constructed by ~98
// in-package SessionSync{ literals that never run a constructor. A pointer
// sub-struct would be nil in all of them and every generation/peer access
// would need a lazy-init branch on hot paths. A value field is zero-ready
// (mutexes and atomics need no setup; maps are allocated by initGenState,
// exactly as before), so a zero SessionSync behaves identically.

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// sessionGenState owns the #2170 deferred-delete generation-guard domain
// (#16159): the sender install stamps, receiver generations and tombstones,
// scoped (#10512/#15039) spaces, #9915 caps, and the sent/received identity
// memos guarded by the same two mutexes. It is a VALUE field of SessionSync
// (never a pointer, never copied after construction): a zero SessionSync
// must have a usable generation domain without a constructor, which the
// ~98 in-package SessionSync{ literals rely on. Maps are allocated by
// initGenState; every other field is zero-ready.
//
// The name deliberately does NOT collide with the #9915 genGuard* cap
// counters (genGuardMapCap/genGuardMapDefaultCap/genGuardSessionCap): those
// name the per-map caps, this names the lock domain that owns them.
//
// Locking: genSentMu guards every sender field, recvGenMu every receiver
// field; genCounter/genGuardSessionCap are atomics. The full lock-order
// contract is the graph on SessionSync (sync.go). Methods stay on
// *SessionSync as forwarding names — only the storage moved.
type sessionGenState struct {
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
	// genSentScopedV4/V6 stamp per-(domain, tuple) install generations for
	// scoped policy deletes (#10512, plan §1.2 keyed sender state):
	// takeDeleteGenScoped draws fresh strictly greater than the last
	// install it cancels. Guarded by genSentMu; same cap/overflow
	// discipline as the bare stamp maps.
	genSentScopedV4 map[scopedDeleteKeyV4]uint64
	genSentScopedV6 map[scopedDeleteKeyV6]uint64
	// scopedTupleIndex* invert the scoped stamp maps by bare tuple
	// (#15039) so a bare close reclaims its tuple's scoped stamps in
	// O(domains-per-tuple), not O(map). Guarded by genSentMu.
	genSentScopedByTupleV4 scopedTupleIndex[dataplane.SessionKey, scopedDeleteKeyV4]
	genSentScopedByTupleV6 scopedTupleIndex[dataplane.SessionKeyV6, scopedDeleteKeyV6]
	// genSentOverflowV4/V6 latch, per family and for the life of the process, that
	// the stamp map has ever been at its effective cap and skipped a key (#9719).
	// After that, a delete for an unstamped key may be for a live session whose
	// stamp was skipped, so takeDeleteGen* draws a fresh generation instead of 0.
	// Guarded by genSentMu.
	genSentOverflowV4 bool
	genSentOverflowV6 bool
	// genSentOverflowScopedV4/V6 are the #9719 overflow latches for the
	// scoped stamp maps (see genSentOverflowV4). Guarded by genSentMu.
	genSentOverflowScopedV4 bool
	genSentOverflowScopedV6 bool
	// sentGenGuardCap/recvGenGuardCap are the effective sender/receiver-side
	// generation-guard caps (#9915 F-044): genGuardMapDefaultCap until demand
	// growth doubles them toward genGuardMapCap. Zero means never grown.
	// Guarded by genSentMu/recvGenMu respectively (see sentCap/growSentCap);
	// resetRecvGen returns the receiver side to zero with the maps it bounds.
	sentGenGuardCap int
	recvGenGuardCap int
	// genGuardSessionCap is the helper-provisioned session capacity wired by
	// the daemon (SetGenGuardSessionCap tracks current, 0 = unwired). It
	// bounds demand growth to provisioned RAM. Atomic so the daemon tick
	// never contends the guard mutexes (a mutex here would invert lock order
	// against the BPF-walking guard paths it gates).
	genGuardSessionCap atomic.Uint64
	// genGuardMapCeilingOverride injects a small growth ceiling for tests (0 =
	// production ceiling). Skip/overflow paths are otherwise reachable only at
	// 5M entries; the override keeps call-site coverage executed at unit-test
	// volumes. Test-only; production never sets it. Same mutex as its side cap.
	genGuardMapCeilingOverride int
	// testGenCapAfterCeilingRead runs after growGuardCapSide snapshots its
	// ceiling and before it decides/stores the next cap. Test-only seam for a
	// deterministic ceiling-shrink interleaving; production never sets it.
	testGenCapAfterCeilingRead func()
	// #9412: per tuple, the TCP close class this node last SENT for one session
	// incarnation (matched on SessionID), so a mirror-sourced resend cannot
	// regress it. Guarded by genSentMu, beside the generation maps it mirrors;
	// see stampCloseClassLocked.
	closeClassSentV4 map[dataplane.SessionKey]sentCloseClass
	closeClassSentV6 map[dataplane.SessionKeyV6]sentCloseClass
	// #10888: per tuple, the TCP handshake state this node last SENT for one
	// session incarnation (matched on SessionID), so mirror-sourced sweeps
	// cannot regress the opening/handshake phase to legacy zero. Guarded by
	// genSentMu, beside the generation maps it mirrors.
	tcpHandshakeSentV4 map[dataplane.SessionKey]sentTCPHandshakeState
	tcpHandshakeSentV6 map[dataplane.SessionKeyV6]sentTCPHandshakeState
	// #9752: per tuple, the installing-table identity this node last SENT for
	// one session incarnation (matched on SessionID), so a mirror-sourced
	// resend cannot regress it to (0,0). Guarded by genSentMu, beside the
	// maps it mirrors; see stampInstallTableLocked.
	installTableSentV4 map[dataplane.SessionKey]sentInstallTable
	installTableSentV6 map[dataplane.SessionKeyV6]sentInstallTable
	// #11064: source-NAT ICMP type used when the active selected its typed
	// allocator. Like the table stamp, this sync-only identity is restored on
	// mirror resends and is guarded by genSentMu.
	sourceNatICMPSentV4 map[dataplane.SessionKey]sourceNatICMPMemo
	sourceNatICMPSentV6 map[dataplane.SessionKeyV6]sourceNatICMPMemo
	// #14359: per tuple, the admitting-policy identity (PolicyRuleID +
	// PolicyCounterIdx) this node last SENT for one session incarnation
	// (matched on SessionID), so a mirror-sourced resend cannot wipe it to
	// ""/0. Guarded by genSentMu; see stampPolicyIdentityLocked.
	policyIdentitySentV4 map[dataplane.SessionKey]policyIdentityMemo
	policyIdentitySentV6 map[dataplane.SessionKeyV6]policyIdentityMemo
	// #16700: per tuple, the per-app timeout (seconds, 86401=never) and
	// then-log flags this node last SENT for one session incarnation
	// (matched on SessionID), so a mirror-sourced resend cannot wipe
	// them to 0. Guarded by genSentMu; see stampAppTimeoutLogLocked.
	appTimeoutLogSentV4 map[dataplane.SessionKey]appTimeoutLogMemo
	appTimeoutLogSentV6 map[dataplane.SessionKeyV6]appTimeoutLogMemo
	recvGenMu           sync.Mutex
	// #9752 round 3: per tuple, the installing-table identity this node last
	// RECEIVED for one session incarnation (matched on SessionID), so a
	// stamp-less resend from an old sender cannot erase it. The BPF mirror
	// cannot be the source — it drops sync-only fields on read — so the
	// record lives here, beside the install generations, and is consulted on
	// the receive apply before the dataplane write. Guarded by recvGenMu;
	// see restoreInstallTableLocked.
	installTableRecvV4 map[dataplane.SessionKey]recvInstallTable
	installTableRecvV6 map[dataplane.SessionKeyV6]recvInstallTable
	// #11064: last received source-NAT ICMP identity, kept outside the lossy
	// BPF mirror so a promoted standby can resend the same allocator selector.
	sourceNatICMPRecvV4 map[dataplane.SessionKey]sourceNatICMPMemo
	sourceNatICMPRecvV6 map[dataplane.SessionKeyV6]sourceNatICMPMemo
	// #14359: last RECEIVED policy identity, kept outside the lossy BPF
	// mirror so a stamp-less resend cannot erase it and a promoted standby
	// can resend the same binding. Guarded by recvGenMu.
	policyIdentityRecvV4 map[dataplane.SessionKey]policyIdentityMemo
	policyIdentityRecvV6 map[dataplane.SessionKeyV6]policyIdentityMemo
	// #16700: last RECEIVED app timeout / log flags, kept outside the
	// mirror so a stamp-less resend cannot erase them and a promoted
	// standby can resend the same values. Guarded by recvGenMu.
	appTimeoutLogRecvV4 map[dataplane.SessionKey]appTimeoutLogMemo
	appTimeoutLogRecvV6 map[dataplane.SessionKeyV6]appTimeoutLogMemo
	recvGenV4           map[dataplane.SessionKey]uint64
	recvGenV6           map[dataplane.SessionKeyV6]uint64
	// recvGenScopedV4/V6 + recvTombScopedV4/V6 are the #10512 scoped
	// policy-delete receiver spaces, keyed by (domain, tuple). #14358
	// couples deletes across spaces (a delete in either space tombstones
	// the other at the same generation; install guards stay per-space).
	// Guarded by recvGenMu; reclaimed/reset alongside the bare maps.
	recvGenScopedV4 map[scopedDeleteKeyV4]uint64
	recvGenScopedV6 map[scopedDeleteKeyV6]uint64
	// recvGenScopedByTuple* invert the scoped receiver maps by bare tuple
	// (#15039), guarded by recvGenMu, so a bare delete reaches its tuple's
	// scoped entries without scanning the tombstone-pinned map.
	recvGenScopedByTupleV4 scopedTupleIndex[dataplane.SessionKey, scopedDeleteKeyV4]
	recvGenScopedByTupleV6 scopedTupleIndex[dataplane.SessionKeyV6, scopedDeleteKeyV6]
	// recvTombV4/V6 order the TOMBSTONE entries of recvGenV4/V6, oldest first, so a
	// map at its effective cap evicts the oldest tombstone to record a new key instead
	// of skip-recording it (#9719). Guarded by recvGenMu; retained across same-namespace
	// resets and cleared by a namespace reset.
	recvTombV4 genTombstoneOrder[dataplane.SessionKey]
	recvTombV6 genTombstoneOrder[dataplane.SessionKeyV6]
	// Scoped tombstone orders (see the recvGenScoped comment above).
	recvTombScopedV4 genTombstoneOrder[scopedDeleteKeyV4]
	recvTombScopedV6 genTombstoneOrder[scopedDeleteKeyV6]
}

// peerSnapshotState owns the peer's held full-set snapshots and its
// advertised config-snapshot protocol (#16159): the IPsec SA set, the
// per-family DHCP lease snapshots with their receive times, and the
// #6650 peerSnapshotProtocol triple. (The PeerSnapshotState RETURN TYPE in
// sync_capabilities_6650.go is the public observation snapshot; this is the
// private storage it is read from.) Value field of SessionSync for the
// same zero-value reason as sessionGenState.
//
// Locking: peerIPsecSAsMu guards the IPsec set, peerDHCPLeasesMu the lease
// sets, peerSnapshotProtocolWriteMu serializes capability-incarnation
// changes with gated and ungated config writes, and
// peerSnapshotProtocolGeneration is guarded by SessionSync.mu. See the
// lock-order graph on SessionSync.
type peerSnapshotState struct {
	peerIPsecSAs   []string
	peerIPsecSAsMu sync.Mutex
	// #2239/#10170: the standby holds the peer's most-recent full lease
	// snapshot per family (the peerIPsecSAs precedent), including explicit
	// receipt state, ownership generation, and served-scope proof. The
	// legacy slices remain the aged lease view used by existing callers.
	//
	// #4871: peerDHCPLeases{4,6}RecvAt records WHEN this node received each
	// family's held set. SyncLease.Remaining is seconds-of-lifetime-left at the
	// SENDER's read time and carries no sample epoch, so a set held on the
	// standby ages only if the receiver subtracts its own residence before
	// seeding — otherwise a lease held for minutes is re-anchored to
	// now_local+Remaining on takeover and RESURRECTED past its true expiry
	// (duplicate allocation). RecvAt is a time.Now() reading (monotonic in
	// production), so PeerDHCPLeases{4,6} subtract a monotonic residence.
	peerDHCPLeases4        []dhcpserver.SyncLease
	peerDHCPLeases6        []dhcpserver.SyncLease
	peerDHCPLeaseSnapshot4 dhcpserver.LeaseSyncSnapshot
	peerDHCPLeaseSnapshot6 dhcpserver.LeaseSyncSnapshot
	peerDHCPLeases4RecvAt  time.Time
	peerDHCPLeases6RecvAt  time.Time
	peerDHCPLeasesMu       sync.Mutex
	// peerSnapshotProtocol is the peer's advertised config-snapshot protocol
	// version, or 0 when the peer has not advertised one.
	//
	// 0 is NOT "unknown, assume compatible": a connected peer that advertises
	// nothing is by definition running a build that predates #6650, so it also
	// predates every snapshot version this gate could care about. It is cleared
	// at every incarnation retirement (#17097, retirePeerIncarnationLocked) --
	// the capability belongs to the peer INCARNATION that proved it, and the
	// peer that reconnects may be a different, older process.
	peerSnapshotProtocol atomic.Uint32

	// peerSnapshotProtocolWriteMu serializes capability-incarnation changes
	// with config-send debt sampling and final writes (gated and ungated).
	// Lock order is mu then this mutex for gated writes; ungated config writers
	// take this mutex before writeMu. Gated writers release mu while holding
	// this mutex over the write.
	peerSnapshotProtocolWriteMu sync.Mutex

	// peerSnapshotProtocolGeneration advances when this incarnation's
	// advertised snapshot version changes or is cleared, binding an outgoing
	// config push to the observation that authorized it; guarded by mu.
	peerSnapshotProtocolGeneration uint64
}
