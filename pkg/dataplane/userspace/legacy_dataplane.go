package userspace

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

var _ dataplane.DataPlane = (*LegacyDataPlaneAdapter)(nil)
var _ dataplane.RuntimeDataPlane = (*LegacyDataPlaneAdapter)(nil)

// LegacyDataPlaneAdapter is the compatibility boundary for callers that still
// depend on the old BPF-shaped dataplane.DataPlane interface.
//
// The userspace Manager intentionally does not implement dataplane.DataPlane.
// Until the daemon and operator surfaces move fully to RuntimeDataPlane domain
// interfaces, this adapter delegates legacy eBPF-shaped methods to the shim
// manager and routes userspace-owned behavior back through Manager.
type LegacyDataPlaneAdapter struct {
	dataplane.DataPlane
	manager *Manager
}

func NewLegacyDataPlaneAdapter(manager *Manager) *LegacyDataPlaneAdapter {
	if manager == nil {
		return &LegacyDataPlaneAdapter{}
	}
	adapter := &LegacyDataPlaneAdapter{
		manager: manager,
	}
	if manager.inner != nil {
		adapter.DataPlane = manager.inner
	}
	return adapter
}

func (a *LegacyDataPlaneAdapter) managerOrErr() (*Manager, error) {
	if a == nil || a.manager == nil {
		return nil, errors.New("nil userspace dataplane")
	}
	return a.manager, nil
}

func (a *LegacyDataPlaneAdapter) Start(ctx context.Context) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.Start(ctx)
}

func (a *LegacyDataPlaneAdapter) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return nil, err
	}
	return m.ApplyConfig(ctx, cfg)
}

func (a *LegacyDataPlaneAdapter) LastApplyResult() *dataplane.ApplyResult {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.LastApplyResult()
}

func (a *LegacyDataPlaneAdapter) Link() dataplane.LinkController {
	m, err := a.managerOrErr()
	if err != nil {
		return dataplane.NewDataPlaneLinkController(nil)
	}
	return m.Link()
}

func (a *LegacyDataPlaneAdapter) HA() dataplane.HAController {
	m, err := a.managerOrErr()
	if err != nil {
		return dataplane.NewDataPlaneHAController(nil)
	}
	return m.HA()
}

func (a *LegacyDataPlaneAdapter) Sessions() dataplane.SessionStore {
	m, err := a.managerOrErr()
	if err != nil {
		return dataplane.NewDataPlaneSessionStore(nil)
	}
	return m.Sessions()
}

func (a *LegacyDataPlaneAdapter) SessionDeltas() dpruntime.SessionDeltaSource {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.SessionDeltas()
}

func (a *LegacyDataPlaneAdapter) RuntimeSessionDeltaSource() dpruntime.SessionDeltaSource {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.RuntimeSessionDeltaSource()
}

func (a *LegacyDataPlaneAdapter) Telemetry() dataplane.Telemetry {
	m, err := a.managerOrErr()
	if err != nil {
		return dataplane.NewDataPlaneTelemetry(nil)
	}
	return m.Telemetry()
}

func (a *LegacyDataPlaneAdapter) Load() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.Load()
}

func (a *LegacyDataPlaneAdapter) Close() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.Close()
}

func (a *LegacyDataPlaneAdapter) Teardown() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.Teardown()
}

func (a *LegacyDataPlaneAdapter) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return nil, err
	}
	return m.Compile(cfg)
}

func (a *LegacyDataPlaneAdapter) UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.UpdatePolicyScheduleState(cfg, activeState)
}

func (a *LegacyDataPlaneAdapter) SetPolicySchedulerActiveState(activeState map[string]bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetPolicySchedulerActiveState(activeState)
}

func (a *LegacyDataPlaneAdapter) BumpFIBGeneration() uint32 {
	m, err := a.managerOrErr()
	if err != nil {
		return 0
	}
	return m.BumpFIBGeneration()
}

func (a *LegacyDataPlaneAdapter) NotifyLinkCycle() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.NotifyLinkCycle()
}

func (a *LegacyDataPlaneAdapter) SyncFabricState() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SyncFabricState()
}

func (a *LegacyDataPlaneAdapter) UpdateRGActive(rgID int, active bool) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.UpdateRGActive(rgID, active)
}

func (a *LegacyDataPlaneAdapter) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.UpdateHAWatchdog(rgID, timestamp)
}

func (a *LegacyDataPlaneAdapter) UpdateFabricFwd(info dataplane.FabricFwdInfo) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.inner.UpdateFabricFwd(info)
}

func (a *LegacyDataPlaneAdapter) UpdateFabricFwd1(info dataplane.FabricFwdInfo) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.inner.UpdateFabricFwd1(info)
}

func (a *LegacyDataPlaneAdapter) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.SetSessionV4(key, val)
}

func (a *LegacyDataPlaneAdapter) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.SetSessionV6(key, val)
}

func (a *LegacyDataPlaneAdapter) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.SetClusterSyncedSessionV4(key, val)
}

func (a *LegacyDataPlaneAdapter) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.SetClusterSyncedSessionV6(key, val)
}

func (a *LegacyDataPlaneAdapter) DeleteSession(key dataplane.SessionKey) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.DeleteSession(key)
}

func (a *LegacyDataPlaneAdapter) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.DeleteSessionV6(key)
}

func (a *LegacyDataPlaneAdapter) SetDeferWorkers(v bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetDeferWorkers(v)
}

func (a *LegacyDataPlaneAdapter) PrepareLinkCycle() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.PrepareLinkCycle()
}

func (a *LegacyDataPlaneAdapter) RegenerateNeighborSnapshot() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.RegenerateNeighborSnapshot()
}

func (a *LegacyDataPlaneAdapter) LookupSnapshotNeighbor(ifindex int, ip net.IP) *NeighborSnapshot {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.LookupSnapshotNeighbor(ifindex, ip)
}

func (a *LegacyDataPlaneAdapter) IsMonitoredIfindex(ifindex int) bool {
	m, err := a.managerOrErr()
	if err != nil {
		return false
	}
	return m.IsMonitoredIfindex(ifindex)
}

func (a *LegacyDataPlaneAdapter) ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP)) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.ForEachSnapshotNeighbor(fn)
}

func (a *LegacyDataPlaneAdapter) SnapshotHasIfindex(ifindex int) bool {
	m, err := a.managerOrErr()
	if err != nil {
		return false
	}
	return m.SnapshotHasIfindex(ifindex)
}

func (a *LegacyDataPlaneAdapter) SnapshotNeighbors() []struct {
	Ifindex int
	IP      net.IP
	MAC     net.HardwareAddr
	Family  int
} {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.SnapshotNeighbors()
}

func (a *LegacyDataPlaneAdapter) Status() (ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return ProcessStatus{}, err
	}
	return m.Status()
}

func (a *LegacyDataPlaneAdapter) SetForwardingArmed(armed bool) (ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return ProcessStatus{}, err
	}
	return m.SetForwardingArmed(armed)
}

func (a *LegacyDataPlaneAdapter) SetQueueState(queueID uint32, registered, armed bool) (ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return ProcessStatus{}, err
	}
	return m.SetQueueState(queueID, registered, armed)
}

func (a *LegacyDataPlaneAdapter) SetBindingState(slot uint32, registered, armed bool) (ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return ProcessStatus{}, err
	}
	return m.SetBindingState(slot, registered, armed)
}

func (a *LegacyDataPlaneAdapter) InjectPacket(req InjectPacketRequest) (ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return ProcessStatus{}, err
	}
	return m.InjectPacket(req)
}

func (a *LegacyDataPlaneAdapter) DrainSessionDeltas(max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	return m.DrainSessionDeltas(max)
}

func (a *LegacyDataPlaneAdapter) ExportOwnerRGSessions(rgIDs []int, max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	return m.ExportOwnerRGSessions(rgIDs, max)
}

func (a *LegacyDataPlaneAdapter) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	m, err := a.managerOrErr()
	if err != nil {
		return false, 0, 0
	}
	return m.SessionSyncSweepProfile()
}

func (a *LegacyDataPlaneAdapter) EventStream() *EventStream {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.EventStream()
}

func (a *LegacyDataPlaneAdapter) ExportAllSessionsViaEventStream() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.ExportAllSessionsViaEventStream()
}

func (a *LegacyDataPlaneAdapter) Mode() DataplaneMode {
	m, err := a.managerOrErr()
	if err != nil {
		return ModeEBPFOnly
	}
	return m.Mode()
}

func (a *LegacyDataPlaneAdapter) XSKBoundNotified() bool {
	m, err := a.managerOrErr()
	if err != nil {
		return false
	}
	return m.XSKBoundNotified()
}

func (a *LegacyDataPlaneAdapter) SetOnXSKBound(fn func()) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetOnXSKBound(fn)
}

func (a *LegacyDataPlaneAdapter) TakeoverReady() (bool, []string) {
	m, err := a.managerOrErr()
	if err != nil {
		return false, []string{err.Error()}
	}
	return m.TakeoverReady()
}
