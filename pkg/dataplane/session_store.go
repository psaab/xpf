package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"golang.org/x/sys/unix"
)

type DeleteReason string

const (
	DeleteReasonClusterStale DeleteReason = "cluster-stale"
	DeleteReasonGCExpired    DeleteReason = "gc-expired"
	// DeleteReasonPolicyDeleted labels the commit-time invalidation of a
	// session whose admitting policy was removed from the config (#4234, the
	// Junos-default deletion-clear). Like the other reasons it is a documentary
	// label — DeleteBatchKnownV4/V6 ignore it — but it names the call site.
	DeleteReasonPolicyDeleted DeleteReason = "policy-deleted"
	// DeleteReasonPolicyModified labels the commit-time invalidation of a
	// session whose admitting policy had its MATCH or ACTION changed while
	// `security policies policy-rematch` is set (#4234 modified-policy re-eval).
	// A documentary label only.
	DeleteReasonPolicyModified DeleteReason = "policy-modified"
	// DeleteReasonDefaultPolicyChanged labels the commit-time invalidation of a
	// default-PERMIT session (stamped DefaultPolicySentinelID, 0xFFFFFFFF) when
	// the implicit default-policy's verdict changed (permit->deny/reject) or,
	// under `policy-rematch`, its session-logging intent flipped (#4342). Like
	// the other reasons it is a documentary label — DeleteBatchKnownV4/V6 ignore
	// it — but it names the call site.
	DeleteReasonDefaultPolicyChanged DeleteReason = "default-policy-changed"
)

const sessionDeleteBatchSize = 64

type SessionEntryV4 struct {
	Key   SessionKey
	Value SessionValue
	// PurgeTunnelVariants is set only by policy invalidation when the BPF
	// mirror lost a protocol-47 discriminator. It is a delete option, not part
	// of SessionValue or the BPF ABI.
	PurgeTunnelVariants bool
}

type SessionEntryV6 struct {
	Key                 SessionKeyV6
	Value               SessionValueV6
	PurgeTunnelVariants bool
}

type SessionStore interface {
	ForEachV4(func(SessionKey, SessionValue) bool) error
	ForEachV6(func(SessionKeyV6, SessionValueV6) bool) error
	GetV4(SessionKey) (SessionValue, error)
	GetV6(SessionKeyV6) (SessionValueV6, error)
	// PutClusterSyncedV4/V6 installs a peer-owned forward or reverse session.
	// Forward entries also install their reverse-key companion and dynamic
	// DNAT/NAT64 companion state through the same backend-owned path used by
	// stale bulk reconciliation.
	PutClusterSyncedV4(SessionKey, SessionValue) error
	PutClusterSyncedV6(SessionKeyV6, SessionValueV6) error
	DeleteV4(SessionKey) error
	DeleteV6(SessionKeyV6) error
	DeleteKnownV4(SessionKey, SessionValue, DeleteReason, bool) error
	DeleteKnownV6(SessionKeyV6, SessionValueV6, DeleteReason, bool) error
	DeleteBatchKnownV4([]SessionEntryV4, DeleteReason, bool) (int, error)
	DeleteBatchKnownV6([]SessionEntryV6, DeleteReason, bool) (int, error)
	// DeleteBatchKnownExactV4/V6 (#10598) delete exactly like their count-only
	// twins but return the FORWARD keys this call removed, in input order,
	// instead of a bare count. A count cannot name a non-prefix partial: the
	// recovery loop keeps deleting the tail after a per-key failure, so the
	// deleted set has holes and consumers must not treat [:deleted] as the
	// set. Absent (NotFound) keys are excluded, never listed, never an error;
	// reverse companions are deleted but never listed (they were never
	// HA-synced individually). A total failure returns (nil, err); len()==0
	// means none either way.
	DeleteBatchKnownExactV4([]SessionEntryV4, DeleteReason, bool) ([]SessionKey, error)
	DeleteBatchKnownExactV6([]SessionEntryV6, DeleteReason, bool) ([]SessionKeyV6, error)
	// forwardOnly (#9752): retract exactly the named keys, skipping
	// companion deletes (a purge-retirement close whose pair the sender
	// already decided). False keeps the historical derive-and-retract.
	DeleteWithCompanionsV4(SessionKey, DeleteReason, bool) error
	DeleteWithCompanionsV6(SessionKeyV6, DeleteReason, bool) error
	ReconcileClusterBulk(ClusterBulkReconcileInput) (ClusterBulkReconcileResult, error)
	SessionDeltas() dpruntime.SessionDeltaSource
	Count() (v4, v6 int)
	Clear() (v4, v6 int, err error)
}

type ClusterBulkReconcileInput struct {
	ReceivedV4     map[SessionKey]struct{}
	ReceivedV6     map[SessionKeyV6]struct{}
	ShouldSyncZone func(uint16) bool
	// IsZoneMapped distinguishes a zone named by the RG ownership snapshot
	// from an unmapped (node-local or otherwise unowned) zone. When provided,
	// stale rows in an unmapped zone are deletable only if their map value
	// carries SessFlagClusterSynced (#10227/#9655 second half).
	IsZoneMapped func(uint16) bool
	DeleteReason DeleteReason
}

type ClusterBulkReconcileResult struct {
	StaleV4   int
	StaleV6   int
	DeletedV4 int
	DeletedV6 int
}

// ScopedSessionKey is a session key plus the ROUTING DOMAIN the row was
// installed under (#9364). It exists because `SessionKey` deliberately has no
// domain axis (#7160), so a batch delete that carries only keys has already lost
// the one thing the helper needs to make the delete land.
//
// A bare delete reaches the helper as `routing_domain = 0`, which it reads as
// WIRE_ABSENT and resolves by PROBING every routing instance for the 5-tuple.
// When two tenants hold that tuple the probe is ambiguous and the helper REFUSES
// (#8636). #9146 fixed the SINGULAR delete this way; the batch path — which is
// the one that retires sessions continuously, from the conntrack GC — still
// stripped the value.
//
// `RoutingDomain == 0` means "no domain to name", which is both the default
// instance and "the caller had no value". Both want the pre-#9364 bare delete, so
// one value serves both and no reserved sentinel is needed.
type ScopedSessionKey struct {
	Key           SessionKey
	RoutingDomain uint32
	// PurgeTunnelVariants is an explicit policy-invalidation delete option.
	PurgeTunnelVariants bool
}

// ScopedSessionKeyV6 is the IPv6 analogue of ScopedSessionKey (#9364).
type ScopedSessionKeyV6 struct {
	Key                 SessionKeyV6
	RoutingDomain       uint32
	PurgeTunnelVariants bool
}

// sessionDomainBatchDeleter is the #9364 optional capability: a dataplane that
// can carry a routing domain on each key of a BATCH delete.
//
// LIVE SINCE #9546. Until then this plumbing was inert on the real path: every
// production caller of `DeleteBatchKnownV4/V6` sources its `SessionEntry`
// values from `store.ForEachV4` -> `dp.BatchIterateSessions` -> a BatchLookup
// over the BPF session mirror, and the `session_value` ABI had no routing-domain
// slot, so those values always carried 0 (measured: `RoutingDomain 100007 -> 0`
// while `TCPState` and `Timeout` survived the same round trip). #9546 appended
// `routing_domain` to the on-map ABI, stamped by both mirror writers, and the
// round trip now preserves it (`routing_domain_mirror_9546_test.go`).
//
// The END-TO-END proof is privileged, because the mirror is a real BPF map:
// `TestBatchDeleteNamesTheMirroredDomainOnTheWire9546` seeds a tenant row, reads
// it back through ForEachV4 exactly as the GC does, deletes it through this path
// and asserts the helper delete names the domain. Its singular twin,
// `TestDeleteSessionItselfNamesTheDomainOnTheWire9146`, failed on master until
// #9546 and passes now. Both SKIP without CAP_BPF (#9337), so an ordinary run
// cannot see them — run them with CAP_BPF and `XPF_REQUIRE_MEMLOCK_GUARDS=1`.
//
// What it still cannot do (#7160, out of scope here): the BPF key has no domain
// axis, so two tenants holding one 5-tuple share ONE mirror row. This path
// deletes the surviving row's tenant exactly instead of refusing both as
// ambiguous; it does not recover the other tenant's row.
//
// The house pattern, matching clusterSyncedSessionInstaller below: a narrow
// interface resolved by type assertion, implemented only by the userspace
// dataplane, with the existing key-only `BatchDeleteSessions` as the fallback for
// anything that does not implement it. That keeps the wide `DataPlane` interface
// unchanged and leaves `ClearAllSessions` — which has no values by construction
// and is exactly the caller #8636's refusal was designed for — sending bare
// deletes.
//
// THE SEAM THIS CREATES IS THE ONE #9482 WAS ABOUT, so it is bolted shut at
// compile time in scoped_batch_delete_published_9364.go rather than left to a
// runtime assertion. #9344 moved a daemon-side interface to a new method and did
// not add it to `*LegacyDataPlaneAdapter` — the type the userspace backend
// actually publishes, and the type this store is constructed with
// (`NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m))`). The assertion then
// failed silently on the only type it was ever handed and the HA cold prime never
// ran. An optional interface whose miss is a silent downgrade to the OLD
// behaviour has exactly that failure mode: the fix would be inert and every test
// that supplies its own double would still pass.
type sessionDomainBatchDeleter interface {
	BatchDeleteSessionsScoped([]ScopedSessionKey) (int, error)
	BatchDeleteSessionsScopedV6([]ScopedSessionKeyV6) (int, error)
}

// peerSyncedSessionDeleter (#9714) is the optional capability a dataplane offers
// for deletes made on behalf of the PEER. It marks the helper request so the
// helper can refuse a peer delete of a key it holds as a LOCAL session whose
// owner redundancy group is locally active (a dual-primary split). The store uses
// it only for DeleteReasonClusterStale and only when the dataplane implements it.
// A miss falls back to the unmarked delete, which is the #9714 defect, so the
// capability is pinned at compile time on both published types
// (peer_synced_session_delete_published_9714.go and its userspace twin).
type peerSyncedSessionDeleter interface {
	// BatchDeletePeerSyncedSessionsScoped asks the helper FIRST. It returns how
	// many BPF mirror rows it deleted and the keys the helper REFUSED, which keep
	// their mirror rows. forwardOnly (#9752 round 3) marks the helper request
	// so the helper retires exactly the named keys (no reverse fan-out).
	BatchDeletePeerSyncedSessionsScoped([]ScopedSessionKey, bool) (int, []ScopedSessionKey, error)
	BatchDeletePeerSyncedSessionsScopedV6([]ScopedSessionKeyV6, bool) (int, []ScopedSessionKeyV6, error)
	// Exact variants return (deleted mirror keys, helper-applied keys). The
	// first excludes refused and already-absent rows; the second is used only
	// to retire companions for helper-applied forwards.
	BatchDeletePeerSyncedSessionsExactScoped([]ScopedSessionKey, bool) ([]ScopedSessionKey, []ScopedSessionKey, error)
	BatchDeletePeerSyncedSessionsExactScopedV6([]ScopedSessionKeyV6, bool) ([]ScopedSessionKeyV6, []ScopedSessionKeyV6, error)
	// DeletePeerSyncedSession reports whether the helper refused the delete.
	DeletePeerSyncedSession(SessionKey, bool) (bool, error)
	DeletePeerSyncedSessionV6(SessionKeyV6, bool) (bool, error)
}

type clusterSyncedSessionInstaller interface {
	SetClusterSyncedSessionV4(SessionKey, SessionValue) error
	SetClusterSyncedSessionV6(SessionKeyV6, SessionValueV6) error
}

type dataPlaneSessionStore struct {
	dp DataPlane
}

type sessionSnapshotV4 struct {
	key     SessionKey
	val     SessionValue
	existed bool
}

type sessionSnapshotV6 struct {
	key     SessionKeyV6
	val     SessionValueV6
	existed bool
}

func NewDataPlaneSessionStore(dp DataPlane) SessionStore {
	return dataPlaneSessionStore{dp: dp}
}

func (s dataPlaneSessionStore) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (s dataPlaneSessionStore) ForEachV4(fn func(SessionKey, SessionValue) bool) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	return s.dp.BatchIterateSessions(fn)
}

func (s dataPlaneSessionStore) ForEachV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	return s.dp.BatchIterateSessionsV6(fn)
}

func (s dataPlaneSessionStore) GetV4(key SessionKey) (SessionValue, error) {
	if s.dp == nil {
		return SessionValue{}, errors.New("nil dataplane")
	}
	return s.dp.GetSessionV4(key)
}

func (s dataPlaneSessionStore) GetV6(key SessionKeyV6) (SessionValueV6, error) {
	if s.dp == nil {
		return SessionValueV6{}, errors.New("nil dataplane")
	}
	return s.dp.GetSessionV6(key)
}

func sessionNotFound(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, unix.ENOENT)
}

func ignoreSessionNotFound(err error) error {
	if err == nil || sessionNotFound(err) {
		return nil
	}
	return err
}

// DNATKeyForSessionV4 builds the reverse-SNAT dnat_table KEY for a forward
// SNAT'd session. It is the single source of truth for the session-derived
// dnat-table key encoding — every writer AND every companion-delete site (in
// this package and in pkg/grpcapi, pkg/cli) MUST route through it so a delete
// finds what an install wrote.
//
// The KEY port MUST be host-order numeric to match the AF_XDP shim reader,
// which builds its dnat lookup key port from u16::from_be_bytes(wire)
// (host-order numeric) and stores it natively. val.NATSrcPort is stored
// network-order in the SessionValue, so convert it with ntohs (#2406). The
// value side of the dnat_table is never read by the shim (steering uses
// .is_some() only); the reverse-NAT rewrite detail lives in the helper's
// in-memory session state, not this entry.
func DNATKeyForSessionV4(key SessionKey, val SessionValue) DNATKey {
	return DNATKey{
		Protocol: key.Protocol,
		DstIP:    val.NATSrcIP,
		DstPort:  ntohs(val.NATSrcPort),
	}
}

// DNATKeyForSessionV6 is the IPv6 sibling of DNATKeyForSessionV4 (#2406).
func DNATKeyForSessionV6(key SessionKeyV6, val SessionValueV6) DNATKeyV6 {
	return DNATKeyV6{
		Protocol: key.Protocol,
		DstIP:    val.NATSrcIP,
		DstPort:  ntohs(val.NATSrcPort),
	}
}

func dnatKeyForSessionV4(key SessionKey, val SessionValue) DNATKey {
	return DNATKeyForSessionV4(key, val)
}

func dnatKeyForSessionV6(key SessionKeyV6, val SessionValueV6) DNATKeyV6 {
	return DNATKeyForSessionV6(key, val)
}

func (s dataPlaneSessionStore) snapshotV4(key SessionKey) (sessionSnapshotV4, error) {
	snap := sessionSnapshotV4{key: key}
	val, err := s.dp.GetSessionV4(key)
	if err == nil {
		snap.val = val
		snap.existed = true
		return snap, nil
	}
	if sessionNotFound(err) {
		return snap, nil
	}
	return snap, err
}

func (s dataPlaneSessionStore) snapshotV6(key SessionKeyV6) (sessionSnapshotV6, error) {
	snap := sessionSnapshotV6{key: key}
	val, err := s.dp.GetSessionV6(key)
	if err == nil {
		snap.val = val
		snap.existed = true
		return snap, nil
	}
	if sessionNotFound(err) {
		return snap, nil
	}
	return snap, err
}

func (s dataPlaneSessionStore) restoreV4(snap sessionSnapshotV4) error {
	if snap.existed {
		return s.dp.SetSessionV4(snap.key, snap.val)
	}
	return ignoreSessionNotFound(s.dp.DeleteSession(snap.key))
}

func (s dataPlaneSessionStore) restoreV6(snap sessionSnapshotV6) error {
	if snap.existed {
		return s.dp.SetSessionV6(snap.key, snap.val)
	}
	return ignoreSessionNotFound(s.dp.DeleteSessionV6(snap.key))
}

func (s dataPlaneSessionStore) rollbackV4(written []sessionSnapshotV4) error {
	var errs []error
	for i := len(written) - 1; i >= 0; i-- {
		if err := s.restoreV4(written[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s dataPlaneSessionStore) rollbackV6(written []sessionSnapshotV6) error {
	var errs []error
	for i := len(written) - 1; i >= 0; i-- {
		if err := s.restoreV6(written[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s dataPlaneSessionStore) PutClusterSyncedV4(key SessionKey, val SessionValue) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	// Every row arriving through the peer-install API is peer-owned on this
	// node, regardless of whether the sender's copy was originally local or
	// itself imported after failover. Stamp the local map origin so an unmapped
	// bulk reconcile can delete only this synced copy (#10227/#9655).
	val.Flags |= SessFlagClusterSynced
	forwardSnap, err := s.snapshotV4(key)
	if err != nil {
		return err
	}
	// #9752 round 3: NO keep-rule here. The first shape kept a stamp-less
	// resend from erasing the installed row's stamp — but the row is read
	// back from the BPF mirror, which drops sync-only fields, so the rule
	// was dead in production and green only against full-struct doubles.
	// The live rule is restoreInstallTableLocked on the cluster receive
	// path, sourced from Go memory beside the install generations.
	var reverseSnap sessionSnapshotV4
	needsReverse := val.IsReverse == 0 && val.ReverseKey.Protocol != 0
	if needsReverse {
		reverseSnap, err = s.snapshotV4(val.ReverseKey)
		if err != nil {
			return err
		}
	}
	var written []sessionSnapshotV4
	if err := s.putClusterSyncedV4Raw(key, val); err != nil {
		return err
	}
	written = append(written, forwardSnap)
	if needsReverse {
		revVal := val
		revVal.IsReverse = 1
		revVal.ReverseKey = key
		revVal.IngressZone = val.EgressZone
		revVal.EgressZone = val.IngressZone
		// #8597 K74. The companion inherits the FORWARD row's observations
		// unless they are cleared, and the rule for which ones is single-sourced
		// in session_reverse_companion.go — the same discipline #7097 imposed on
		// the node-local list after four sites kept their own copies and all
		// four went quietly incomplete in one change.
		//
		// The fallback below applies only ScrubNodeLocal, which deliberately
		// PRESERVES IngressIfaceFold (it is cluster-stable by design), so
		// without this the companion carried the forward direction's ingress
		// binding — a confident value on a binding the reply has not made.
		revVal.ResetUnobservedForReverseCompanion()
		if err := s.putClusterSyncedV4Raw(val.ReverseKey, revVal); err != nil {
			return errors.Join(err, s.rollbackV4(written))
		}
		written = append(written, reverseSnap)
	}
	if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
		if err := s.dp.SetDNATEntry(dnatKeyForSessionV4(key, val), DNATValue{
			NewDstIP:   binary.NativeEndian.Uint32(key.SrcIP[:]),
			NewDstPort: key.SrcPort,
		}); err != nil {
			return errors.Join(err, s.rollbackV4(written))
		}
	}
	return nil
}

func (s dataPlaneSessionStore) putClusterSyncedV4Raw(key SessionKey, val SessionValue) error {
	if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
		return installer.SetClusterSyncedSessionV4(key, val)
	}
	// The row belongs to the PEER: strip every field that is meaningful only on
	// the node that produced it before it lands in this node's maps. The list
	// is single-sourced (#7097) — see ScrubNodeLocal in session_node_local.go
	// for which fields and why, and for what went wrong when each install site
	// kept its own copy.
	val.ScrubNodeLocal()
	return s.dp.SetSessionV4(key, val)
}

func (s dataPlaneSessionStore) PutClusterSyncedV6(key SessionKeyV6, val SessionValueV6) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	// See the v4 path: all receiver-side peer installs are marked synced,
	// including imports whose sender copy was itself imported after failover.
	val.Flags |= SessFlagClusterSynced
	forwardSnap, err := s.snapshotV6(key)
	if err != nil {
		return err
	}
	// #9752 round 3: v6 twin — no keep-rule here either (see the v4 twin).
	var reverseSnap sessionSnapshotV6
	needsReverse := val.IsReverse == 0 && val.ReverseKey.Protocol != 0
	if needsReverse {
		reverseSnap, err = s.snapshotV6(val.ReverseKey)
		if err != nil {
			return err
		}
	}
	var written []sessionSnapshotV6
	if err := s.putClusterSyncedV6Raw(key, val); err != nil {
		return err
	}
	written = append(written, forwardSnap)
	if needsReverse {
		revVal := val
		revVal.IsReverse = 1
		revVal.ReverseKey = key
		revVal.IngressZone = val.EgressZone
		revVal.EgressZone = val.IngressZone
		// #8597 K74. The companion inherits the FORWARD row's observations
		// unless they are cleared, and the rule for which ones is single-sourced
		// in session_reverse_companion.go — the same discipline #7097 imposed on
		// the node-local list after four sites kept their own copies and all
		// four went quietly incomplete in one change.
		//
		// The fallback below applies only ScrubNodeLocal, which deliberately
		// PRESERVES IngressIfaceFold (it is cluster-stable by design), so
		// without this the companion carried the forward direction's ingress
		// binding — a confident value on a binding the reply has not made.
		revVal.ResetUnobservedForReverseCompanion()
		if err := s.putClusterSyncedV6Raw(val.ReverseKey, revVal); err != nil {
			return errors.Join(err, s.rollbackV6(written))
		}
		written = append(written, reverseSnap)
	}
	if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
		if err := s.dp.SetDNATEntryV6(dnatKeyForSessionV6(key, val), DNATValueV6{
			NewDstIP:   key.SrcIP,
			NewDstPort: key.SrcPort,
		}); err != nil {
			return errors.Join(err, s.rollbackV6(written))
		}
	}
	return nil
}

func (s dataPlaneSessionStore) putClusterSyncedV6Raw(key SessionKeyV6, val SessionValueV6) error {
	if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
		return installer.SetClusterSyncedSessionV6(key, val)
	}
	// IPv6 twin of the peer-owned scrub in putClusterSyncedV4Raw (#7097).
	val.ScrubNodeLocal()
	return s.dp.SetSessionV6(key, val)
}

func (s dataPlaneSessionStore) DeleteV4(key SessionKey) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	return s.dp.DeleteSession(key)
}

func (s dataPlaneSessionStore) DeleteV6(key SessionKeyV6) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	return s.dp.DeleteSessionV6(key)
}

func (s dataPlaneSessionStore) DeleteKnownV4(key SessionKey, val SessionValue, reason DeleteReason, forwardOnly bool) error {
	_, err := s.DeleteBatchKnownExactV4([]SessionEntryV4{{Key: key, Value: val}}, reason, forwardOnly)
	return err
}

func (s dataPlaneSessionStore) DeleteKnownV6(key SessionKeyV6, val SessionValueV6, reason DeleteReason, forwardOnly bool) error {
	_, err := s.DeleteBatchKnownExactV6([]SessionEntryV6{{Key: key, Value: val}}, reason, forwardOnly)
	return err
}

func (s dataPlaneSessionStore) DeleteBatchKnownV4(entries []SessionEntryV4, reason DeleteReason, forwardOnly bool) (int, error) {
	// Count-only projection of the canonical exact loop (#10598): unmigrated
	// callers keep their (count, error) behavior while the exact set lives one
	// call down. New callers that sync or account per-key must use
	// DeleteBatchKnownExactV4 — [:deleted] is not the deleted set.
	exact, err := s.DeleteBatchKnownExactV4(entries, reason, forwardOnly)
	return len(exact), err
}

// DeleteBatchKnownExactV4 is the canonical (#10598) known-delete path:
// DeleteBatchKnownV4 counts it and drops the set. The returned keys are
// exactly the forward rows this call removed, in input order; see the
// SessionStore interface for the absent/companion contract.
func (s dataPlaneSessionStore) DeleteBatchKnownExactV4(entries []SessionEntryV4, reason DeleteReason, forwardOnly bool) ([]SessionKey, error) {
	if s.dp == nil {
		return nil, errors.New("nil dataplane")
	}
	if len(entries) == 0 {
		return nil, nil
	}
	// #9714: a delete made on behalf of the PEER asks the helper first; see
	// deletePeerBatchKnownExactV4.
	if peerDeleter, ok := s.dp.(peerSyncedSessionDeleter); ok && reason == DeleteReasonClusterStale {
		return s.deletePeerBatchKnownExactV4(peerDeleter, entries, forwardOnly)
	}

	reverseKeys := make([]ScopedSessionKey, 0, len(entries))
	for _, entry := range entries {
		val := entry.Value
		s.preservePersistentNATV4(entry.Key, val)
		if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			if err := ignoreSessionNotFound(s.dp.DeleteDNATEntry(dnatKeyForSessionV4(entry.Key, val))); err != nil {
				return nil, err
			}
		}
		// #9752: a forward-only delete retires exactly the named keys; the
		// sender already decided every companion (linked-removed or
		// deliberately preserved), so deriving here would destroy sessions
		// the purge kept. DNAT + persistent-NAT handling above still run.
		if !forwardOnly && val.ReverseKey.Protocol != 0 {
			// #9364: the reverse companion is the SAME flow in the SAME tenant,
			// so it carries the same domain — the identical derivation #9146's
			// syncDeleteV4Locked uses for the singular path.
			reverseKeys = append(reverseKeys, ScopedSessionKey{
				Key:                 val.ReverseKey,
				RoutingDomain:       val.RoutingDomain,
				PurgeTunnelVariants: entry.PurgeTunnelVariants,
			})
		}
	}

	// One backing array serves both phases: reverseKeys holds at most one key
	// per entry, so out already fits the reverse exact set, which is dropped
	// (companions were never HA-synced individually) before the forward phase
	// reuses the array from [:0]. The returned slice names FORWARD keys only.
	out := make([]SessionKey, 0, len(entries))
	if _, err := s.batchDeleteExactV4(reverseKeys, out); err != nil {
		return nil, err
	}
	out = out[:0]

	forwardKeys := make([]ScopedSessionKey, 0, len(entries))
	for _, entry := range entries {
		forwardKeys = append(forwardKeys, ScopedSessionKey{
			Key:                 entry.Key,
			RoutingDomain:       entry.Value.RoutingDomain,
			PurgeTunnelVariants: entry.PurgeTunnelVariants,
		})
	}
	return s.batchDeleteExactV4(forwardKeys, out)
}

func (s dataPlaneSessionStore) DeleteBatchKnownV6(entries []SessionEntryV6, reason DeleteReason, forwardOnly bool) (int, error) {
	// Count-only projection of the canonical exact loop (#10598); see the V4
	// twin. New callers that sync or account per-key must use
	// DeleteBatchKnownExactV6.
	exact, err := s.DeleteBatchKnownExactV6(entries, reason, forwardOnly)
	return len(exact), err
}

// DeleteBatchKnownExactV6 is the IPv6 analogue of DeleteBatchKnownExactV4
// (#10598).
func (s dataPlaneSessionStore) DeleteBatchKnownExactV6(entries []SessionEntryV6, reason DeleteReason, forwardOnly bool) ([]SessionKeyV6, error) {
	if s.dp == nil {
		return nil, errors.New("nil dataplane")
	}
	if len(entries) == 0 {
		return nil, nil
	}
	// #9714: a delete made on behalf of the PEER asks the helper first; see
	// deletePeerBatchKnownExactV6.
	if peerDeleter, ok := s.dp.(peerSyncedSessionDeleter); ok && reason == DeleteReasonClusterStale {
		return s.deletePeerBatchKnownExactV6(peerDeleter, entries, forwardOnly)
	}

	reverseKeys := make([]ScopedSessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		val := entry.Value
		s.preservePersistentNATV6(entry.Key, val)
		if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			if err := ignoreSessionNotFound(s.dp.DeleteDNATEntryV6(dnatKeyForSessionV6(entry.Key, val))); err != nil {
				return nil, err
			}
		}
		// #9752: v6 twin of the forward-only gate above.
		if !forwardOnly && val.ReverseKey.Protocol != 0 {
			// #9364: same tenant as its forward half — see the V4 twin.
			reverseKeys = append(reverseKeys, ScopedSessionKeyV6{
				Key:                 val.ReverseKey,
				RoutingDomain:       val.RoutingDomain,
				PurgeTunnelVariants: entry.PurgeTunnelVariants,
			})
		}
	}

	// One backing array serves both phases — see the V4 twin.
	out := make([]SessionKeyV6, 0, len(entries))
	if _, err := s.batchDeleteExactV6(reverseKeys, out); err != nil {
		return nil, err
	}
	out = out[:0]

	forwardKeys := make([]ScopedSessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		forwardKeys = append(forwardKeys, ScopedSessionKeyV6{
			Key:                 entry.Key,
			RoutingDomain:       entry.Value.RoutingDomain,
			PurgeTunnelVariants: entry.PurgeTunnelVariants,
		})
	}
	return s.batchDeleteExactV6(forwardKeys, out)
}

// batchDeleteV4 removes keys from the v4 session map in
// sessionDeleteBatchSize chunks. cilium/ebpf BatchDelete stops at the first
// missing key and returns (count_before_stop, ErrKeyNotExist); the stopped
// key sits at index chunkDeleted, so keys[chunkDeleted+1:n] were never
// attempted. Mirror clearSessionsV4 (pkg/dataplane/maps_session.go): on the
// not-found error, retry the chunk remainder one key at a time before
// advancing, so the unattempted tail is not silently dropped (#5448) — a
// dropped tail leaks stale peer-synced sessions after HA bulk reconcile.
func (s dataPlaneSessionStore) batchDeleteV4(keys []ScopedSessionKey) (int, error) {
	deleted, err := s.batchDeleteExactV4(keys, nil)
	return len(deleted), err
}

// batchDeleteExactV4 is the canonical V4 delete loop (#10598). It returns
// exactly the forward keys removed, in input order. BatchDelete can stop at a
// missing key; the missing key is excluded and the remainder is retried one
// at a time so a later success cannot be mistaken for a prefix success.
func (s dataPlaneSessionStore) batchDeleteExactV4(keys []ScopedSessionKey, out []SessionKey) ([]SessionKey, error) {
	for len(keys) > 0 {
		n := sessionDeleteBatchSize
		if len(keys) < n {
			n = len(keys)
		}
		chunk := keys[:n]
		chunkDeleted, err := s.batchDeleteChunkV4(chunk)
		if chunkDeleted < 0 {
			chunkDeleted = 0
		} else if chunkDeleted > len(chunk) {
			chunkDeleted = len(chunk)
		}
		for _, sk := range chunk[:chunkDeleted] {
			out = append(out, sk.Key)
		}
		if err != nil {
			if !sessionNotFound(err) {
				if len(out) == 0 {
					out = nil
				}
				return out, err
			}
			// Batch stopped at the first missing key (index chunkDeleted):
			// that key is already gone, but chunk[chunkDeleted+1:] were
			// never attempted. Finish the remainder per-key so nothing is
			// dropped (#5448).
			// #9364: the per-key retry is domain-correct. DeleteSession on
			// the userspace manager fetches the row's own value and names
			// its domain (#9146), so no scope is needed here.
			var firstErr error
			for _, sk := range chunk[chunkDeleted:] {
				if delErr := s.dp.DeleteSession(sk.Key); delErr == nil {
					out = append(out, sk.Key)
				} else if firstErr == nil && !sessionNotFound(delErr) {
					firstErr = delErr
				}
			}
			if firstErr != nil {
				if len(out) == 0 {
					out = nil
				}
				return out, firstErr
			}
		}
		keys = keys[n:]
	}
	return out, nil
}

// batchDeleteV6 is the IPv6 count projection of batchDeleteExactV6 (#10598).
func (s dataPlaneSessionStore) batchDeleteV6(keys []ScopedSessionKeyV6) (int, error) {
	deleted, err := s.batchDeleteExactV6(keys, nil)
	return len(deleted), err
}

// batchDeleteExactV6 is the IPv6 analogue of batchDeleteExactV4.
func (s dataPlaneSessionStore) batchDeleteExactV6(keys []ScopedSessionKeyV6, out []SessionKeyV6) ([]SessionKeyV6, error) {
	for len(keys) > 0 {
		n := sessionDeleteBatchSize
		if len(keys) < n {
			n = len(keys)
		}
		chunk := keys[:n]
		chunkDeleted, err := s.batchDeleteChunkV6(chunk)
		if chunkDeleted < 0 {
			chunkDeleted = 0
		} else if chunkDeleted > len(chunk) {
			chunkDeleted = len(chunk)
		}
		for _, sk := range chunk[:chunkDeleted] {
			out = append(out, sk.Key)
		}
		if err != nil {
			if !sessionNotFound(err) {
				if len(out) == 0 {
					out = nil
				}
				return out, err
			}
			// The batch stopped at a missing key; retry the unattempted
			// remainder one at a time, excluding absent keys and retaining
			// later successful keys in the exact output.
			var firstErr error
			for _, sk := range chunk[chunkDeleted:] {
				if delErr := s.dp.DeleteSessionV6(sk.Key); delErr == nil {
					out = append(out, sk.Key)
				} else if firstErr == nil && !sessionNotFound(delErr) {
					firstErr = delErr
				}
			}
			if firstErr != nil {
				if len(out) == 0 {
					out = nil
				}
				return out, firstErr
			}
		}
		keys = keys[n:]
	}
	return out, nil
}

// batchDeleteChunkV4 issues ONE chunk of v4 deletes, preferring the #9364 scoped
// capability and falling back to the key-only call.
//
// Extracted rather than inlined so the CHOICE is drivable by a cell: the callers
// above read and write real BPF maps, so a cell for them skips wherever CAP_BPF
// is unavailable — and a skipping cell scores every mutation as SURVIVED, which
// is the reading that argues for deleting a guard doing its job. #9146 split
// `syncDeleteV4Locked` out of `DeleteSession` for the same reason.
func (s dataPlaneSessionStore) batchDeleteChunkV4(chunk []ScopedSessionKey) (int, error) {
	if scoped, ok := s.dp.(sessionDomainBatchDeleter); ok {
		return scoped.BatchDeleteSessionsScoped(chunk)
	}
	return s.dp.BatchDeleteSessions(bareSessionKeys(chunk))
}

// batchDeleteChunkV6 is the IPv6 analogue of batchDeleteChunkV4 (#9364).
func (s dataPlaneSessionStore) batchDeleteChunkV6(chunk []ScopedSessionKeyV6) (int, error) {
	if scoped, ok := s.dp.(sessionDomainBatchDeleter); ok {
		return scoped.BatchDeleteSessionsScopedV6(chunk)
	}
	return s.dp.BatchDeleteSessionsV6(bareSessionKeysV6(chunk))
}

// deletePeerBatchKnownExactV4 is the exact V4 path for a delete made on behalf
// of the PEER (#9714, #10598). The helper answers FIRST. A forward key it
// refuses (a live local session whose owner RG is locally active: a dual-primary
// split) keeps everything this node holds for it. The helper-applied forward
// keys whose mirror delete succeeded are the exact set returned to the caller;
// reverse companions are never included.
func (s dataPlaneSessionStore) deletePeerBatchKnownExactV4(dp peerSyncedSessionDeleter, entries []SessionEntryV4, forwardOnly bool) ([]SessionKey, error) {
	forwardKeys := make([]ScopedSessionKey, 0, len(entries))
	for _, entry := range entries {
		forwardKeys = append(forwardKeys, ScopedSessionKey{
			Key:           entry.Key,
			RoutingDomain: entry.Value.RoutingDomain,
		})
	}
	deleted, applied, err := dp.BatchDeletePeerSyncedSessionsExactScoped(forwardKeys, forwardOnly)
	deletedSet := make(map[ScopedSessionKey]struct{}, len(deleted))
	for _, scoped := range deleted {
		deletedSet[scoped] = struct{}{}
	}
	appliedSet := make(map[ScopedSessionKey]struct{}, len(applied))
	for _, scoped := range applied {
		appliedSet[scoped] = struct{}{}
	}
	exact := make([]SessionKey, 0, len(deleted))
	appliedEntries := make([]SessionEntryV4, 0, len(applied))
	for _, entry := range entries {
		scoped := ScopedSessionKey{Key: entry.Key, RoutingDomain: entry.Value.RoutingDomain}
		if _, ok := deletedSet[scoped]; ok {
			exact = append(exact, scoped.Key)
		}
		if _, ok := appliedSet[scoped]; ok {
			appliedEntries = append(appliedEntries, entry)
		}
	}
	if err != nil {
		if len(exact) == 0 {
			exact = nil
		}
		return exact, err
	}

	reverseKeys := make([]ScopedSessionKey, 0, len(appliedEntries))
	for _, entry := range appliedEntries {
		// #9752: a forward-only delete retires exactly the named keys; the
		// sender already decided every companion. DNAT + persistent-NAT
		// handling below still run.
		if !forwardOnly && entry.Value.ReverseKey.Protocol != 0 {
			// #9364: the reverse companion is the SAME flow in the SAME tenant.
			reverseKeys = append(reverseKeys, ScopedSessionKey{
				Key:           entry.Value.ReverseKey,
				RoutingDomain: entry.Value.RoutingDomain,
			})
		}
	}
	if len(reverseKeys) > 0 {
		if _, _, err := dp.BatchDeletePeerSyncedSessionsExactScoped(reverseKeys, false); err != nil {
			return exact, err
		}
	}
	for _, entry := range appliedEntries {
		val := entry.Value
		s.preservePersistentNATV4(entry.Key, val)
		if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			if err := ignoreSessionNotFound(s.dp.DeleteDNATEntry(dnatKeyForSessionV4(entry.Key, val))); err != nil {
				return exact, err
			}
		}
	}
	return exact, nil
}

// deletePeerBatchKnownExactV6 is the IPv6 analogue of
// deletePeerBatchKnownExactV4 (#10598).
func (s dataPlaneSessionStore) deletePeerBatchKnownExactV6(dp peerSyncedSessionDeleter, entries []SessionEntryV6, forwardOnly bool) ([]SessionKeyV6, error) {
	forwardKeys := make([]ScopedSessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		forwardKeys = append(forwardKeys, ScopedSessionKeyV6{
			Key:           entry.Key,
			RoutingDomain: entry.Value.RoutingDomain,
		})
	}
	deleted, applied, err := dp.BatchDeletePeerSyncedSessionsExactScopedV6(forwardKeys, forwardOnly)
	deletedSet := make(map[ScopedSessionKeyV6]struct{}, len(deleted))
	for _, scoped := range deleted {
		deletedSet[scoped] = struct{}{}
	}
	appliedSet := make(map[ScopedSessionKeyV6]struct{}, len(applied))
	for _, scoped := range applied {
		appliedSet[scoped] = struct{}{}
	}
	exact := make([]SessionKeyV6, 0, len(deleted))
	appliedEntries := make([]SessionEntryV6, 0, len(applied))
	for _, entry := range entries {
		scoped := ScopedSessionKeyV6{Key: entry.Key, RoutingDomain: entry.Value.RoutingDomain}
		if _, ok := deletedSet[scoped]; ok {
			exact = append(exact, scoped.Key)
		}
		if _, ok := appliedSet[scoped]; ok {
			appliedEntries = append(appliedEntries, entry)
		}
	}
	if err != nil {
		if len(exact) == 0 {
			exact = nil
		}
		return exact, err
	}

	reverseKeys := make([]ScopedSessionKeyV6, 0, len(appliedEntries))
	for _, entry := range appliedEntries {
		// #9752: v6 twin of the forward-only gate above.
		if !forwardOnly && entry.Value.ReverseKey.Protocol != 0 {
			// #9364: the reverse companion is the SAME flow in the SAME tenant.
			reverseKeys = append(reverseKeys, ScopedSessionKeyV6{
				Key:           entry.Value.ReverseKey,
				RoutingDomain: entry.Value.RoutingDomain,
			})
		}
	}
	if len(reverseKeys) > 0 {
		if _, _, err := dp.BatchDeletePeerSyncedSessionsExactScopedV6(reverseKeys, false); err != nil {
			return exact, err
		}
	}
	for _, entry := range appliedEntries {
		val := entry.Value
		s.preservePersistentNATV6(entry.Key, val)
		if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			if err := ignoreSessionNotFound(s.dp.DeleteDNATEntryV6(dnatKeyForSessionV6(entry.Key, val))); err != nil {
				return exact, err
			}
		}
	}
	return exact, nil
}

// bareSessionKeys strips the domain for a dataplane that cannot carry one.
func bareSessionKeys(scoped []ScopedSessionKey) []SessionKey {
	keys := make([]SessionKey, 0, len(scoped))
	for _, sk := range scoped {
		keys = append(keys, sk.Key)
	}
	return keys
}

// bareSessionKeysV6 is the IPv6 analogue of bareSessionKeys (#9364).
func bareSessionKeysV6(scoped []ScopedSessionKeyV6) []SessionKeyV6 {
	keys := make([]SessionKeyV6, 0, len(scoped))
	for _, sk := range scoped {
		keys = append(keys, sk.Key)
	}
	return keys
}

func (s dataPlaneSessionStore) DeleteWithCompanionsV4(key SessionKey, reason DeleteReason, forwardOnly bool) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	val, err := s.dp.GetSessionV4(key)
	if err != nil {
		if sessionNotFound(err) {
			return ignoreSessionNotFound(s.deleteSessionV4For(key, reason == DeleteReasonClusterStale, forwardOnly))
		}
		return err
	}
	return s.DeleteKnownV4(key, val, reason, forwardOnly)
}

// deleteSessionV4For issues a single-key delete, marked as a #9714 peer delete
// when peer is set and the dataplane offers the capability.
// The helper's refusal is not an error here: a key the mirror could not find has
// no DNAT row or reverse half of its own for the store to keep.
func (s dataPlaneSessionStore) deleteSessionV4For(key SessionKey, peer, forwardOnly bool) error {
	if peerDeleter, ok := s.dp.(peerSyncedSessionDeleter); peer && ok {
		_, err := peerDeleter.DeletePeerSyncedSession(key, forwardOnly)
		return err
	}
	return s.dp.DeleteSession(key)
}

// deleteSessionV6For is the IPv6 analogue of deleteSessionV4For (#9714).
func (s dataPlaneSessionStore) deleteSessionV6For(key SessionKeyV6, peer, forwardOnly bool) error {
	if peerDeleter, ok := s.dp.(peerSyncedSessionDeleter); peer && ok {
		_, err := peerDeleter.DeletePeerSyncedSessionV6(key, forwardOnly)
		return err
	}
	return s.dp.DeleteSessionV6(key)
}

func (s dataPlaneSessionStore) DeleteWithCompanionsV6(key SessionKeyV6, reason DeleteReason, forwardOnly bool) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	val, err := s.dp.GetSessionV6(key)
	if err != nil {
		if sessionNotFound(err) {
			return ignoreSessionNotFound(s.deleteSessionV6For(key, reason == DeleteReasonClusterStale, forwardOnly))
		}
		return err
	}
	return s.DeleteKnownV6(key, val, reason, forwardOnly)
}

func (s dataPlaneSessionStore) preservePersistentNATV4(key SessionKey, val SessionValue) {
	if val.IsReverse != 0 || val.Flags&SessFlagSNAT == 0 || val.Flags&SessFlagStaticNAT != 0 {
		return
	}
	pnat := s.dp.GetPersistentNAT()
	if pnat == nil {
		return
	}
	var natIPBytes [4]byte
	binary.NativeEndian.PutUint32(natIPBytes[:], val.NATSrcIP)
	natIP := netip.AddrFrom4(natIPBytes)
	if poolName, poolCfg, ok := pnat.LookupPool(natIP); ok {
		pnat.Save(&PersistentNATBinding{
			SrcIP:    netip.AddrFrom4(key.SrcIP),
			SrcPort:  key.SrcPort,
			NatIP:    natIP,
			NatPort:  val.NATSrcPort,
			PoolName: poolName,
			LastSeen: time.Now(),
			Timeout:  poolCfg.Timeout,
			Permit:   poolCfg.Permit,
		})
	}
}

func (s dataPlaneSessionStore) preservePersistentNATV6(key SessionKeyV6, val SessionValueV6) {
	if val.IsReverse != 0 || val.Flags&SessFlagSNAT == 0 || val.Flags&SessFlagStaticNAT != 0 {
		return
	}
	pnat := s.dp.GetPersistentNAT()
	if pnat == nil {
		return
	}
	natIP := netip.AddrFrom16(val.NATSrcIP)
	if poolName, poolCfg, ok := pnat.LookupPool(natIP); ok {
		pnat.Save(&PersistentNATBinding{
			SrcIP:    netip.AddrFrom16(key.SrcIP),
			SrcPort:  key.SrcPort,
			NatIP:    natIP,
			NatPort:  val.NATSrcPort,
			PoolName: poolName,
			LastSeen: time.Now(),
			Timeout:  poolCfg.Timeout,
			Permit:   poolCfg.Permit,
		})
	}
}

func (s dataPlaneSessionStore) ReconcileClusterBulk(input ClusterBulkReconcileInput) (ClusterBulkReconcileResult, error) {
	var result ClusterBulkReconcileResult
	if s.dp == nil {
		return result, errors.New("nil dataplane")
	}
	if input.ShouldSyncZone == nil {
		return result, nil
	}
	reason := input.DeleteReason
	if reason == "" {
		reason = DeleteReasonClusterStale
	}

	// #8597 K73. errs is declared BEFORE the first sweep, not between them.
	//
	// The V4 enumerate error used to `return result, err`, which skipped the V4
	// delete phase AND the entire V6 sweep — so V6 stale rows were neither
	// counted nor deleted, and the caller could not tell "V6 clean" from "V6
	// never looked at" because StaleV6 is 0 either way. The two families are
	// independent map dumps; a failure to enumerate one says nothing about the
	// other.
	//
	// A partial staleV4 is still SAFE to act on. Every entry in it was
	// classified by the same predicate as in a complete sweep — not in the
	// received set, not in a synced zone — so the set is a subset of the true
	// stale set, never a superset. Deleting a subset is progress; the next bulk
	// reconcile finds the rest. (DeleteBatchKnownV4 no-ops on an empty slice, so
	// a failure on the very first entry costs nothing either.)
	//
	// The errors are wrapped with the family so the caller's single joined error
	// says WHICH sweep was partial. Without that the operator sees a warning
	// beside a complete-looking stale_v4/stale_v6 pair and cannot tell which
	// number to distrust.
	var errs []error
	// An unmapped zone uses the bulk-start RG 0 fallback. When that fallback
	// says this node is primary, keep every row; when it says secondary, only
	// local-origin rows are kept. Mapped zones retain the existing RG answer.
	var staleV4 []SessionEntryV4
	if err := s.ForEachV4(func(key SessionKey, val SessionValue) bool {
		mapped := input.IsZoneMapped == nil || input.IsZoneMapped(val.IngressZone)
		shouldSync := input.ShouldSyncZone(val.IngressZone)
		if shouldSync || (!mapped && val.Flags&SessFlagClusterSynced == 0) {
			return true
		}
		if val.IsReverse == 0 {
			if _, ok := input.ReceivedV4[key]; !ok {
				staleV4 = append(staleV4, SessionEntryV4{Key: key, Value: val})
			}
		}
		return true
	}); err != nil {
		errs = append(errs, fmt.Errorf("enumerate v4 sessions: %w", err))
	}
	result.StaleV4 = len(staleV4)

	deletedV4, err := s.DeleteBatchKnownV4(staleV4, reason, false)
	result.DeletedV4 = deletedV4
	if err != nil {
		errs = append(errs, err)
	}

	var staleV6 []SessionEntryV6
	if err := s.ForEachV6(func(key SessionKeyV6, val SessionValueV6) bool {
		mapped := input.IsZoneMapped == nil || input.IsZoneMapped(val.IngressZone)
		shouldSync := input.ShouldSyncZone(val.IngressZone)
		if shouldSync || (!mapped && val.Flags&SessFlagClusterSynced == 0) {
			return true
		}
		if val.IsReverse == 0 {
			if _, ok := input.ReceivedV6[key]; !ok {
				staleV6 = append(staleV6, SessionEntryV6{Key: key, Value: val})
			}
		}
		return true
	}); err != nil {
		errs = append(errs, fmt.Errorf("enumerate v6 sessions: %w", err))
	}
	result.StaleV6 = len(staleV6)

	deletedV6, err := s.DeleteBatchKnownV6(staleV6, reason, false)
	result.DeletedV6 = deletedV6
	if err != nil {
		errs = append(errs, err)
	}
	return result, errors.Join(errs...)
}

func (s dataPlaneSessionStore) Count() (int, int) {
	if s.dp == nil {
		return 0, 0
	}
	return s.dp.SessionCount()
}

func (s dataPlaneSessionStore) Clear() (int, int, error) {
	if s.dp == nil {
		return 0, 0, errors.New("nil dataplane")
	}
	return s.dp.ClearAllSessions()
}
