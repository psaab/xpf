package dataplane

import "errors"

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
	PutClusterSyncedV4(SessionKey, SessionValue) error
	PutClusterSyncedV6(SessionKeyV6, SessionValueV6) error
	DeleteV4(SessionKey) error
	DeleteV6(SessionKeyV6) error
	DeleteWithCompanionsV4(SessionKey, DeleteReason) error
	DeleteWithCompanionsV6(SessionKeyV6, DeleteReason) error
	ReconcileClusterBulk(ClusterBulkReconcileInput) (ClusterBulkReconcileResult, error)
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

func NewDataPlaneSessionStore(dp DataPlane) SessionStore {
	return dataPlaneSessionStore{dp: dp}
}

func (s dataPlaneSessionStore) ForEachV4(fn func(SessionKey, SessionValue) bool) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	return s.dp.IterateSessions(fn)
}

func (s dataPlaneSessionStore) ForEachV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	return s.dp.IterateSessionsV6(fn)
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

func (s dataPlaneSessionStore) PutClusterSyncedV4(key SessionKey, val SessionValue) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
		return installer.SetClusterSyncedSessionV4(key, val)
	}
	return s.dp.SetSessionV4(key, val)
}

func (s dataPlaneSessionStore) PutClusterSyncedV6(key SessionKeyV6, val SessionValueV6) error {
	if s.dp == nil {
		return errors.New("nil dataplane")
	}
	if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
		return installer.SetClusterSyncedSessionV6(key, val)
	}
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
