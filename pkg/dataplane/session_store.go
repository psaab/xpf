package dataplane

import (
	"encoding/binary"
	"errors"
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
)

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
		if err := s.putClusterSyncedV4Raw(val.ReverseKey, revVal); err != nil {
			return errors.Join(err, s.rollbackV4(written))
		}
		written = append(written, reverseSnap)
	}
	if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
		if err := s.dp.SetDNATEntry(DNATKey{
			Protocol: key.Protocol,
			DstIP:    val.NATSrcIP,
			DstPort:  val.NATSrcPort,
		}, DNATValue{
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
	val.FibIfindex = 0
	val.FibVlanID = 0
	val.FibDmac = [6]byte{}
	val.FibSmac = [6]byte{}
	val.FibGen = 0
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
		if err := s.putClusterSyncedV6Raw(val.ReverseKey, revVal); err != nil {
			return errors.Join(err, s.rollbackV6(written))
		}
		written = append(written, reverseSnap)
	}
	if val.IsReverse == 0 && val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
		if err := s.dp.SetDNATEntryV6(DNATKeyV6{
			Protocol: key.Protocol,
			DstIP:    val.NATSrcIP,
			DstPort:  val.NATSrcPort,
		}, DNATValueV6{
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
	val.FibIfindex = 0
	val.FibVlanID = 0
	val.FibDmac = [6]byte{}
	val.FibSmac = [6]byte{}
	val.FibGen = 0
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

func (s dataPlaneSessionStore) DeleteWithCompanionsV4(key SessionKey, _ DeleteReason) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	var errs []error
	if val, err := s.dp.GetSessionV4(key); err == nil {
		s.preservePersistentNATV4(key, val)
		if val.ReverseKey.Protocol != 0 {
			errs = append(errs, s.dp.DeleteSession(val.ReverseKey))
		}
		if val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			errs = append(errs, s.dp.DeleteDNATEntry(DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			}))
		}
	}
	errs = append(errs, s.dp.DeleteSession(key))
	return errors.Join(errs...)
}

func (s dataPlaneSessionStore) DeleteWithCompanionsV6(key SessionKeyV6, _ DeleteReason) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	var errs []error
	if val, err := s.dp.GetSessionV6(key); err == nil {
		s.preservePersistentNATV6(key, val)
		if val.ReverseKey.Protocol != 0 {
			errs = append(errs, s.dp.DeleteSessionV6(val.ReverseKey))
		}
		if val.Flags&SessFlagSNAT != 0 && val.Flags&SessFlagStaticNAT == 0 {
			errs = append(errs, s.dp.DeleteDNATEntryV6(DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			}))
		}
	}
	errs = append(errs, s.dp.DeleteSessionV6(key))
	return errors.Join(errs...)
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
			SrcIP:               netip.AddrFrom4(key.SrcIP),
			SrcPort:             key.SrcPort,
			NatIP:               natIP,
			NatPort:             val.NATSrcPort,
			PoolName:            poolName,
			LastSeen:            time.Now(),
			Timeout:             poolCfg.Timeout,
			PermitAnyRemoteHost: poolCfg.PermitAnyRemoteHost,
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
			SrcIP:               netip.AddrFrom16(key.SrcIP),
			SrcPort:             key.SrcPort,
			NatIP:               natIP,
			NatPort:             val.NATSrcPort,
			PoolName:            poolName,
			LastSeen:            time.Now(),
			Timeout:             poolCfg.Timeout,
			PermitAnyRemoteHost: poolCfg.PermitAnyRemoteHost,
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

	var staleV4 []SessionKey
	if err := s.ForEachV4(func(key SessionKey, val SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if input.ShouldSyncZone(val.IngressZone) {
			return true
		}
		if _, ok := input.ReceivedV4[key]; !ok {
			staleV4 = append(staleV4, key)
		}
		return true
	}); err != nil {
		return result, err
	}
	result.StaleV4 = len(staleV4)

	var errs []error
	for _, key := range staleV4 {
		if err := s.DeleteWithCompanionsV4(key, reason); err != nil {
			errs = append(errs, err)
		}
		result.DeletedV4++
	}

	var staleV6 []SessionKeyV6
	if err := s.ForEachV6(func(key SessionKeyV6, val SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if input.ShouldSyncZone(val.IngressZone) {
			return true
		}
		if _, ok := input.ReceivedV6[key]; !ok {
			staleV6 = append(staleV6, key)
		}
		return true
	}); err != nil {
		return result, errors.Join(append(errs, err)...)
	}
	result.StaleV6 = len(staleV6)

	for _, key := range staleV6 {
		if err := s.DeleteWithCompanionsV6(key, reason); err != nil {
			errs = append(errs, err)
		}
		result.DeletedV6++
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
