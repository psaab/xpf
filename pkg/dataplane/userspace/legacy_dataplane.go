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

// #1516 sub-#1451 S1 — guard against signature drift on the
// LegacyDataPlaneAdapter cursor-pagination delegation methods. The
// gRPC server's session-pagination handler (server_sessions.go)
// performs a runtime type assertion against an unexported
// `sessionCursorIterator` interface declared in pkg/grpcapi. If
// either of the signatures below drifts away from that interface,
// the assertion would silently fail at runtime and the handler
// would fall through to the full-table scan path under userspace —
// exactly the silent-degradation hazard #1516 closed. This compile-
// time assertion catches the drift at build time instead.
var _ interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
} = (*LegacyDataPlaneAdapter)(nil)

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
	if manager.bpfShim != nil {
		adapter.DataPlane = manager.bpfShim
	}
	return adapter
}

func (a *LegacyDataPlaneAdapter) managerOrErr() (*Manager, error) {
	if a == nil || a.manager == nil {
		return nil, errors.New("nil userspace dataplane")
	}
	return a.manager, nil
}

// #1620: Manager returns the underlying *Manager so the daemon can
// call SetColdPathSampleMask after Boot(). Returns nil if the
// adapter has no manager (test/null-adapter case).
func (a *LegacyDataPlaneAdapter) Manager() *Manager {
	if a == nil {
		return nil
	}
	return a.manager
}

// AppliedNATView exposes the manager's last-applied NAT view through the
// adapter so the gRPC/REST/CLI deterministic-mapping lookup (#5794) can
// reach it via a single narrow interface (no packet-path I/O). Returns an
// unavailable view when the adapter has no manager.
func (a *LegacyDataPlaneAdapter) AppliedNATView() AppliedNATView {
	m := a.Manager()
	if m == nil {
		return AppliedNATView{Available: false}
	}
	return m.AppliedNATView()
}

// ReadAllPolicyCounters forwards the #3965 bulk policy-counter snapshot.
//
// Codex PR #6743 r7-N2: the bulk reader existed on *Manager only, and the
// daemon publishes the ADAPTER, so NewPolicyCounterReader's probe missed on
// every one of its seven observability call sites and each of them silently
// took the O(P*(P+C)) per-policy fallback the bulk path was written to
// replace. Same capability-erasure class as the #2114 optional-probe bug,
// with a performance cliff rather than a missing metric as the symptom.
// This is a pure in-memory read of the manager's last published status (no
// control-socket round trip), so forwarding it costs nothing on the path it
// restores. Returns the manager's error when there is no manager, matching
// every other forwarder here.
func (a *LegacyDataPlaneAdapter) ReadAllPolicyCounters(cfg *config.Config) (map[uint32]dataplane.CounterValue, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return nil, err
	}
	return m.ReadAllPolicyCounters(cfg)
}

func (a *LegacyDataPlaneAdapter) IsLoaded() bool {
	m, err := a.managerOrErr()
	if err != nil || m.bpfShim == nil {
		return false
	}
	return m.bpfShim.IsLoaded()
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

// BeginControlShutdown forwards the #8526 stop bound to the manager.
//
// This pass-through is load-bearing, not boilerplate. The daemon holds the
// userspace runtime as a *LegacyDataPlaneAdapter (userspace.Boot returns one),
// and runShutdownSequence reaches this behaviour through an optional-interface
// type assertion. Without a method here the assertion simply does not match:
// the daemon stops bounding its control socket, no build fails, and every test
// in this package still passes because they drive the Manager directly.
// TestLegacyAdapterForwardsBeginControlShutdown8526 pins the forwarding, and
// pkg/daemon asserts this type against the daemon's interface at compile time.
func (a *LegacyDataPlaneAdapter) BeginControlShutdown() {
	if a == nil || a.manager == nil {
		return
	}
	a.manager.BeginControlShutdown()
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

func (a *LegacyDataPlaneAdapter) UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) error {
	m, err := a.managerOrErr()
	if err != nil {
		// #3780: no manager attached — nothing is enforcing, so there
		// is no stale permit to converge. Report success so the daemon
		// scheduler self-heal does not spin.
		return nil
	}
	return m.UpdatePolicyScheduleState(cfg, activeState)
}

func (a *LegacyDataPlaneAdapter) SetPolicySchedulerActiveState(activeState map[string]bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetPolicySchedulerActiveState(activeState)
}

// PolicySchedulerActiveState surfaces the manager's daemon-maintained
// scheduler active-state map to the read-only show surfaces (#3062).
// Returns nil when no manager is attached so the CLI/gRPC detail views
// fall back to rendering every policy enabled (bit-identical to today).
func (a *LegacyDataPlaneAdapter) PolicySchedulerActiveState() map[string]bool {
	m, err := a.managerOrErr()
	if err != nil {
		return nil
	}
	return m.PolicySchedulerActiveState()
}

// SetRouteOverlay forwards the ip-monitoring overlay cache (#1827).
func (a *LegacyDataPlaneAdapter) SetRouteOverlay(overlay []config.RouteOverlayEntry) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetRouteOverlay(overlay)
}

// SetFeedSnapshots forwards the dynamic-address feed overlay (#2049).
//
// The daemon's feedSnapshotSetter hand-off asserts on the runtime
// dataplane, which on the default path is *LegacyDataPlaneAdapter (from
// dpuserspace.Boot -> NewLegacyDataPlaneAdapter). Without this method the
// type assertion fails and SetFeedSnapshots is never reached, leaving
// m.feedOverlay empty so feed enforcement is a no-op on the real runtime
// path. Mirrors SetRouteOverlay exactly.
func (a *LegacyDataPlaneAdapter) SetFeedSnapshots(overlay map[string][]string) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetFeedSnapshots(overlay)
}

// PublishRouteOverlaySnapshot forwards the routes-only partial
// republish (#1827). Returns whether a snapshot was actually
// published (duplicate-skips and helperless caching return false).
func (a *LegacyDataPlaneAdapter) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (bool, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return false, err
	}
	return m.PublishRouteOverlaySnapshot(cfg, overlay, schedulerState)
}

func (a *LegacyDataPlaneAdapter) BumpFIBGeneration() (uint32, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, err
	}
	return m.BumpFIBGeneration()
}

// NotifyLinkCycle on the adapter is NOT the live path, exactly as
// PrepareLinkCycle below is not: the daemon reaches the manager through Link().
// This method satisfies dataplane.DataPlane, whose NotifyLinkCycle is void
// because the eBPF Manager's is a genuine no-op, so the manager's #6871 error has
// nowhere to go here. It is discarded deliberately and only here — the live path
// (userspaceLinkController.NotifyLinkCycle) propagates it to the commit.
func (a *LegacyDataPlaneAdapter) NotifyLinkCycle() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	_ = m.NotifyLinkCycle()
}

func (a *LegacyDataPlaneAdapter) SyncFabricState() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SyncFabricState()
}

// ClearNATRuleCounters routes the operator NAT-counter clear through the
// userspace Manager override (#2218) rather than the embedded bpfShim method.
// The bpfShim method only zeroes the Go offset map; the Manager override ALSO
// sends the clear_nat_counters IPC so the helper's cumulative store resets and
// the cleared value does not snap back on the next status poll. The embedded
// dataplane.DataPlane (= bpfShim) would otherwise be promoted here, so this
// explicit method is required for the durable clear.
func (a *LegacyDataPlaneAdapter) ClearNATRuleCounters() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.ClearNATRuleCounters()
}

// ClearZoneCounters routes the operator per-zone traffic-counter clear through
// the userspace Manager override (#3651) rather than the embedded bpfShim
// method. The bpfShim method only zeroes the Go offset map; the Manager
// override ALSO sends the clear_zone_counters IPC so the helper's cumulative
// ZoneCounterStore resets and the cleared value does not snap back on the next
// status poll. The embedded dataplane.DataPlane (= bpfShim) would otherwise be
// promoted here, so this explicit method is required for the durable clear.
func (a *LegacyDataPlaneAdapter) ClearZoneCounters() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.ClearZoneCounters()
}

// ClearPolicyCounters routes the operator per-policy hit-count clear through
// the userspace Manager override rather than the embedded bpfShim method
// (#6566 member 2).
//
// Without this method the embedded dataplane.DataPlane (= bpfShim) is PROMOTED
// here, and its ClearPolicyCounters zeroes the retired-eBPF `policy_counters`
// per-CPU array — 4096 slots that nothing has incremented since the eBPF
// dataplane was retired (#1373/#1476). It returns nil, so both operator
// surfaces print "policy hit counters cleared" while the counters the display
// actually READS — the helper's live PolicyCounterStore, via the
// ReadAllPolicyCounters override — are untouched.
//
// The operator-visible symptom is an asymmetry on one box: `clear security
// counters` DOES reset policy hit counts (it routes through the ClearAllCounters
// override, which reaches clearHelperPolicyCountersLocked), while `clear
// security policies hit-count` does NOT. Same counters, two commands, opposite
// outcomes, both reporting success — which also silently breaks the
// clear-and-watch baseline an operator relies on during incident response.
//
// This is the same defect #3651 fixed for ClearZoneCounters and #2218 for
// ClearAllCounters; natcounters.go names it outright ("Clearing requires TWO
// actions, exactly mirroring ClearPolicyCounters") while the mirror was never
// installed on the adapter.
func (a *LegacyDataPlaneAdapter) ClearPolicyCounters() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.ClearPolicyCounters()
}

// ClearAllCounters routes the operator clear-all through the userspace Manager
// override (#2218) so the helper NAT translation hit store is reset alongside
// the BPF maps; otherwise the per-rule NAT totals snap back on the next poll.
func (a *LegacyDataPlaneAdapter) ClearAllCounters() error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.ClearAllCounters()
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
	return m.bpfShim.UpdateFabricFwd(info)
}

func (a *LegacyDataPlaneAdapter) UpdateFabricFwd1(info dataplane.FabricFwdInfo) error {
	m, err := a.managerOrErr()
	if err != nil {
		return err
	}
	return m.bpfShim.UpdateFabricFwd1(info)
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

// BatchDeleteSessions overrides the promoted bpfShim batch delete so the
// authoritative Rust helper is told to delete every key too (#5096). Without
// this override Go method promotion routes policy-invalidation and cluster-
// stale batch deletes (dataPlaneSessionStore.batchDeleteV4 -> s.dp.Batch...)
// to the BPF mirror ONLY, leaving the helper forwarding under the revoked
// decision until it re-publishes the mirror. The singular DeleteSession
// override already routes per-session deletes to the helper; see
// Manager.BatchDeleteSessions.
func (a *LegacyDataPlaneAdapter) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, err
	}
	return m.BatchDeleteSessions(keys)
}

// BatchDeleteSessionsV6 is the IPv6 analogue of BatchDeleteSessions (#5096).
func (a *LegacyDataPlaneAdapter) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, err
	}
	return m.BatchDeleteSessionsV6(keys)
}

// ClearAllSessions overrides the promoted bpfShim clear-all so an operator
// `clear security flow session all` reaches the authoritative Rust helper and
// not merely the BPF mirror (#5096). Without it the promoted bpfShim clear
// empties the mirror only; the helper keeps forwarding under revoked decisions
// until it re-publishes the mirror ~10s later. See Manager.ClearAllSessions.
func (a *LegacyDataPlaneAdapter) ClearAllSessions() (int, int, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, 0, err
	}
	return m.ClearAllSessions()
}

func (a *LegacyDataPlaneAdapter) SetDeferWorkers(v bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.SetDeferWorkers(v)
}

// RecordDeferredWorkerArmDebt forwards the #5134 deferred-MAC worker-arm debt to
// the underlying manager so the daemon can record it without swallowing the
// failed re-apply error.
func (a *LegacyDataPlaneAdapter) RecordDeferredWorkerArmDebt() {
	m, err := a.managerOrErr()
	if err != nil {
		return
	}
	m.RecordDeferredWorkerArmDebt()
}

// PrepareLinkCycle on the adapter is NOT the live path. The daemon reaches the
// manager through Link(), which resolves a nil/unavailable manager to
// dataplane.NewDataPlaneLinkController(nil) — a no-op controller that returns nil
// ("nothing to join, proceed"). This method answers the same condition with an
// error ("worker state unknown, abort") and is retained for the retirement
// canary's LegacyDataPlaneAdapter surface. The divergence is deliberate: a nil
// manager reached via Link() means no userspace dataplane is wired at all, while a
// managerOrErr failure here means one was expected and could not be resolved. A
// future caller must pick Link() unless it specifically wants the second reading.
func (a *LegacyDataPlaneAdapter) PrepareLinkCycle() error {
	m, err := a.managerOrErr()
	if err != nil {
		// #5103: surface the resolution failure rather than reporting a
		// successful worker join. A caller that cycles the link on this
		// return would do so with an unknown worker state.
		return err
	}
	return m.PrepareLinkCycle()
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

// HelperCrashState returns the manager's helper crash record (#7250).
//
// Returns ok=false when there is no manager to ask, deliberately rather than
// returning a zero record: a zero HelperCrashRecord is EXACTLY what a healthy
// helper looks like, so collapsing "no manager" into it would render an
// unreachable dataplane as a clean one. Same comma-ok shape as CachedStatus
// below, for the same reason.
//
// This delegate exists because `dataplane.Unwrap()` hands a status surface
// THIS adapter, not the bare *Manager — so without it the accessor the #7250
// data half exported is unreachable from pkg/cli and pkg/grpcapi.
func (a *LegacyDataPlaneAdapter) HelperCrashState() (HelperCrashRecord, bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return HelperCrashRecord{}, false
	}
	return m.HelperCrashState(), true
}

// CachedStatus returns the last control-socket-captured ProcessStatus
// without issuing a new request (#3970). Returns ok=false when the
// manager is unavailable or no status has been captured yet.
func (a *LegacyDataPlaneAdapter) CachedStatus() (ProcessStatus, bool) {
	m, err := a.managerOrErr()
	if err != nil {
		return ProcessStatus{}, false
	}
	return m.CachedStatus()
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

// ExportOwnerRGSessionsPaged forwards the #9344 paged owner-RG export.
//
// #9482: this method was MISSING, and its absence disabled the HA cold-prime
// bulk sync entirely. `pkg/daemon`'s `userspaceSessionExporter` names exactly
// one method, and #9344 changed which one — from the unpaged form above to this
// one. `userspaceBulkSnapshot` resolves it by RUNTIME TYPE ASSERTION against
// `d.dataplane()`, and the value the daemon publishes for the userspace backend
// is `*LegacyDataPlaneAdapter` (`Boot()` in manager.go returns
// `NewLegacyDataPlaneAdapter(New())`), not the `*Manager` that grew the new
// method. So the assertion failed on the only type it is ever handed, and
// `doBulkSync` — which fails CLOSED, correctly — framed no window at all.
//
// Measured on the loss userspace cluster before the fix: BOTH nodes logged
//
//	cluster sync: owed cold-prime re-drive failed, will retry
//	  err="bulk sync table-truth snapshot: dataplane does not export owner-RG sessions"
//
// once a minute, indefinitely, and every cold-start edge logged
// `cluster sync: bulk sync failed` with the same cause. A rejoining node
// therefore received NO bulk window — only the incremental deltas that arrived
// afterwards.
//
// WHY A ONE-LINE FORWARDER NEEDED A COMPILE-TIME BELT. Nothing linked the two
// sides: the interface is unexported in `pkg/daemon` and satisfied by runtime
// assertion, so removing or re-signing a method here is invisible until a
// cluster rejoins. The existing coverage could not see it either — every
// `pkg/daemon` bulk-snapshot test supplies its OWN exporter fake
// (`wiringExporterDP`, `recordingExporter`), which proves the resolver correct
// for a type that satisfies the interface and says nothing about the type the
// daemon actually publishes. The assertion in `bulk_snapshot_published_type_9482.go`
// binds the real interface to the real published types, so either side drifting
// breaks the BUILD.
func (a *LegacyDataPlaneAdapter) ExportOwnerRGSessionsPaged(rgIDs []int) ([]SessionDeltaInfo, ProcessStatus, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	return m.ExportOwnerRGSessionsPaged(rgIDs)
}

// BatchDeleteSessionsScoped forwards the #9364 domain-carrying batch delete.
//
// THIS FORWARDER IS THE WHOLE POINT, and its omission is #9482. `Manager.Sessions()`
// constructs the store as
// `dataplane.NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m))`, so the value
// the store type-asserts against `sessionDomainBatchDeleter` is THIS adapter, not
// the Manager that grew the method. #9344 made exactly that mistake on the
// owner-RG export interface and the HA cold-prime bulk sync silently never ran.
//
// Here the failure would be quieter still: `sessionDomainBatchDeleter` is an
// OPTIONAL capability whose miss falls back to the key-only call, so a missing
// forwarder would not error — it would just restore the bare delete this issue
// exists to remove, with every test green. That is why
// `scoped_batch_delete_published_9364.go` bolts the assertion shut at compile
// time instead of trusting the runtime miss to be noticed.
func (a *LegacyDataPlaneAdapter) BatchDeleteSessionsScoped(scoped []dataplane.ScopedSessionKey) (int, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, err
	}
	return m.BatchDeleteSessionsScoped(scoped)
}

// BatchDeleteSessionsScopedV6 forwards the IPv6 analogue (#9364).
func (a *LegacyDataPlaneAdapter) BatchDeleteSessionsScopedV6(scoped []dataplane.ScopedSessionKeyV6) (int, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, err
	}
	return m.BatchDeleteSessionsScopedV6(scoped)
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

// ErrCursorIterationUnsupported is returned by
// LegacyDataPlaneAdapter.IterateSessionsFrom and
// IterateSessionsV6From when the underlying wrapped dataplane does
// not expose cursor-based iteration. Callers that probe for cursor
// support via type assertion (e.g. gRPC pagination) MUST detect
// this error and fall back to non-cursor iteration so the user-
// visible behavior matches the master/pre-#1516 path on
// dataplanes that lack cursor support.
//
// In production the wrapped dataplane is a *dataplane.Manager (set
// by NewLegacyDataPlaneAdapter from manager.bpfShim) which does
// implement cursor iteration, so the production code path never
// returns this sentinel. The sentinel guards test/edge
// configurations where the adapter is constructed with a nil
// manager or with an embedded DataPlane that does not implement
// cursor iteration.
var ErrCursorIterationUnsupported = errors.New("underlying dataplane does not support cursor iteration")

func (a *LegacyDataPlaneAdapter) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	if a == nil || a.DataPlane == nil {
		return ErrCursorIterationUnsupported
	}
	if iter, ok := a.DataPlane.(interface {
		IterateSessionsFrom(*dataplane.SessionKey, func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	}); ok {
		return iter.IterateSessionsFrom(cursor, fn)
	}
	return ErrCursorIterationUnsupported
}

func (a *LegacyDataPlaneAdapter) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	if a == nil || a.DataPlane == nil {
		return ErrCursorIterationUnsupported
	}
	if iter, ok := a.DataPlane.(interface {
		IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	}); ok {
		return iter.IterateSessionsV6From(cursor, fn)
	}
	return ErrCursorIterationUnsupported
}
