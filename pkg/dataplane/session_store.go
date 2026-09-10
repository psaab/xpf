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
}

type SessionEntryV6 struct {
	Key   SessionKeyV6
	Value SessionValueV6
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
	DeleteKnownV4(SessionKey, SessionValue, DeleteReason) error
	DeleteKnownV6(SessionKeyV6, SessionValueV6, DeleteReason) error
	DeleteBatchKnownV4([]SessionEntryV4, DeleteReason) (int, error)
	DeleteBatchKnownV6([]SessionEntryV6, DeleteReason) (int, error)
	DeleteWithCompanionsV4(SessionKey, DeleteReason) error
	DeleteWithCompanionsV6(SessionKeyV6, DeleteReason) error
	ReconcileClusterBulk(ClusterBulkReconcileInput) (ClusterBulkReconcileResult, error)
	SessionDeltas() dpruntime.SessionDeltaSource
	Count() (v4, v6 int)
	Clear() (v4, v6 int, err error)
}

type ClusterBulkReconcileInput struct {
	ReceivedV4     map[SessionKey]struct{}
	ReceivedV6     map[SessionKeyV6]struct{}
	ShouldSyncZone func(uint16) bool
	DeleteReason   DeleteReason
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
}

// ScopedSessionKeyV6 is the IPv6 analogue of ScopedSessionKey (#9364).
type ScopedSessionKeyV6 struct {
	Key           SessionKeyV6
	RoutingDomain uint32
}

// sessionDomainBatchDeleter is the #9364 optional capability: a dataplane that
// can carry a routing domain on each key of a BATCH delete.
//
// !! THIS PLUMBING IS CURRENTLY INERT ON THE REAL PATH (#9546). !!
//
// It carries whatever domain it is GIVEN, correctly — but every production caller
// of `DeleteBatchKnownV4/V6` sources its `SessionEntry` values from
// `store.ForEachV4`, i.e. `dp.BatchIterateSessions`, i.e. a BatchLookup over the
// BPF session mirror. The BPF `session_value` ABI has NO routing-domain field, so
// those values always carry 0. Measured, with a positive control in the same
// probe: `RoutingDomain 100007 -> 0` while `TCPState 3 -> 3` and
// `Timeout 300 -> 300` survive
// (`routing_domain_mirror_inert_9364_test.go`).
//
// The same is true of #9146's singular delete, whose own acceptance cell has been
// FAILING on master since it landed — it writes real BPF maps, so it SKIPS
// without CAP_BPF and nobody saw it (#9337).
//
// So this is a prerequisite, not the fix: it is what a real remedy for #9546
// plugs into. Do not read the #9364 cells as evidence the GC's deletes name a
// domain today — they prove that a domain SUPPLIED here reaches the wire, which
// is a different claim.
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
	forwardSnap, err := s.snapshotV4(key)
	if err != nil {
		return err
	}
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
	forwardSnap, err := s.snapshotV6(key)
	if err != nil {
		return err
	}
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

func (s dataPlaneSessionStore) DeleteKnownV4(key SessionKey, val SessionValue, reason DeleteReason) error {
	_, err := s.DeleteBatchKnownV4([]SessionEntryV4{{Key: key, Value: val}}, reason)
	return err
}

func (s dataPlaneSessionStore) DeleteKnownV6(key SessionKeyV6, val SessionValueV6, reason DeleteReason) error {
	_, err := s.DeleteBatchKnownV6([]SessionEntryV6{{Key: key, Value: val}}, reason)
	return err
}

func (s dataPlaneSessionStore) DeleteBatchKnownV4(entries []SessionEntryV4, _ DeleteReason) (int, error) {
	if s.dp == nil {
		return 0, errors.New("nil dataplane")
	}
	if len(entries) == 0 {
		return 0, nil
	}

	reverseKeys := make([]ScopedSessionKey, 0, len(entries))
	for _, entry := range entries {
		val := entry.Value
		s.preservePersistentNATV4(entry.Key, val)
		if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			if err := ignoreSessionNotFound(s.dp.DeleteDNATEntry(dnatKeyForSessionV4(entry.Key, val))); err != nil {
				return 0, err
			}
		}
		if val.ReverseKey.Protocol != 0 {
			// #9364: the reverse companion is the SAME flow in the SAME tenant,
			// so it carries the same domain — the identical derivation #9146's
			// syncDeleteV4Locked uses for the singular path.
			reverseKeys = append(reverseKeys, ScopedSessionKey{
				Key:           val.ReverseKey,
				RoutingDomain: val.RoutingDomain,
			})
		}
	}

	if _, err := s.batchDeleteV4(reverseKeys); err != nil {
		return 0, err
	}

	forwardKeys := make([]ScopedSessionKey, 0, len(entries))
	for _, entry := range entries {
		forwardKeys = append(forwardKeys, ScopedSessionKey{
			Key:           entry.Key,
			RoutingDomain: entry.Value.RoutingDomain,
		})
	}
	deleted, err := s.batchDeleteV4(forwardKeys)
	if err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (s dataPlaneSessionStore) DeleteBatchKnownV6(entries []SessionEntryV6, _ DeleteReason) (int, error) {
	if s.dp == nil {
		return 0, errors.New("nil dataplane")
	}
	if len(entries) == 0 {
		return 0, nil
	}

	reverseKeys := make([]ScopedSessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		val := entry.Value
		s.preservePersistentNATV6(entry.Key, val)
		if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			if err := ignoreSessionNotFound(s.dp.DeleteDNATEntryV6(dnatKeyForSessionV6(entry.Key, val))); err != nil {
				return 0, err
			}
		}
		if val.ReverseKey.Protocol != 0 {
			// #9364: same tenant as its forward half — see the V4 twin.
			reverseKeys = append(reverseKeys, ScopedSessionKeyV6{
				Key:           val.ReverseKey,
				RoutingDomain: val.RoutingDomain,
			})
		}
	}

	if _, err := s.batchDeleteV6(reverseKeys); err != nil {
		return 0, err
	}

	forwardKeys := make([]ScopedSessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		forwardKeys = append(forwardKeys, ScopedSessionKeyV6{
			Key:           entry.Key,
			RoutingDomain: entry.Value.RoutingDomain,
		})
	}
	deleted, err := s.batchDeleteV6(forwardKeys)
	if err != nil {
		return deleted, err
	}
	return deleted, nil
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
	deleted := 0
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
		deleted += chunkDeleted
		if err != nil {
			if !sessionNotFound(err) {
				return deleted, err
			}
			// Batch stopped at the first missing key (index chunkDeleted):
			// that key is already gone, but chunk[chunkDeleted+1:] were never
			// attempted. Finish the remainder per-key so nothing is dropped.
			// #9364: the per-key retry is UNCHANGED and is already
			// domain-correct. `DeleteSession` on the userspace manager fetches
			// the row's own value and names its domain (#9146), so re-scoping it
			// here would be redundant, and passing a scope it did not ask for
			// would be a second derivation of the same fact.
			for _, sk := range chunk[chunkDeleted:] {
				if delErr := s.dp.DeleteSession(sk.Key); delErr == nil {
					deleted++
				}
			}
		}
		keys = keys[n:]
	}
	return deleted, nil
}

// batchDeleteV6 is the IPv6 variant of batchDeleteV4 (#5448).
func (s dataPlaneSessionStore) batchDeleteV6(keys []ScopedSessionKeyV6) (int, error) {
	deleted := 0
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
		deleted += chunkDeleted
		if err != nil {
			if !sessionNotFound(err) {
				return deleted, err
			}
			// #9364: unchanged, and already domain-correct — see the V4 twin.
			for _, sk := range chunk[chunkDeleted:] {
				if delErr := s.dp.DeleteSessionV6(sk.Key); delErr == nil {
					deleted++
				}
			}
		}
		keys = keys[n:]
	}
	return deleted, nil
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

func (s dataPlaneSessionStore) DeleteWithCompanionsV4(key SessionKey, reason DeleteReason) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	val, err := s.dp.GetSessionV4(key)
	if err != nil {
		if sessionNotFound(err) {
			return ignoreSessionNotFound(s.dp.DeleteSession(key))
		}
		return err
	}
	return s.DeleteKnownV4(key, val, reason)
}

func (s dataPlaneSessionStore) DeleteWithCompanionsV6(key SessionKeyV6, reason DeleteReason) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	val, err := s.dp.GetSessionV6(key)
	if err != nil {
		if sessionNotFound(err) {
			return ignoreSessionNotFound(s.dp.DeleteSessionV6(key))
		}
		return err
	}
	return s.DeleteKnownV6(key, val, reason)
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

	var staleV4 []SessionEntryV4
	if err := s.ForEachV4(func(key SessionKey, val SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if input.ShouldSyncZone(val.IngressZone) {
			return true
		}
		if _, ok := input.ReceivedV4[key]; !ok {
			staleV4 = append(staleV4, SessionEntryV4{Key: key, Value: val})
		}
		return true
	}); err != nil {
		errs = append(errs, fmt.Errorf("enumerate v4 sessions: %w", err))
	}
	result.StaleV4 = len(staleV4)

	deletedV4, err := s.DeleteBatchKnownV4(staleV4, reason)
	result.DeletedV4 = deletedV4
	if err != nil {
		errs = append(errs, err)
	}

	var staleV6 []SessionEntryV6
	if err := s.ForEachV6(func(key SessionKeyV6, val SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if input.ShouldSyncZone(val.IngressZone) {
			return true
		}
		if _, ok := input.ReceivedV6[key]; !ok {
			staleV6 = append(staleV6, SessionEntryV6{Key: key, Value: val})
		}
		return true
	}); err != nil {
		errs = append(errs, fmt.Errorf("enumerate v6 sessions: %w", err))
	}
	result.StaleV6 = len(staleV6)

	deletedV6, err := s.DeleteBatchKnownV6(staleV6, reason)
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
