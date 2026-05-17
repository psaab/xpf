package dataplane

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/psaab/xpf/pkg/config"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"github.com/psaab/xpf/pkg/networkd"
)

// RuntimeDataPlane is the target daemon-facing dataplane shape for #1381.
// It is introduced beside the legacy BPF-shaped DataPlane while callers move
// one domain at a time.
//
// TODO(#1381): Add compile-time assertions (var _ RuntimeDataPlane = (*Manager)(nil))
// for BPF/DPDK/userspace Managers once Start/Link/HA/Sessions/Telemetry/SessionDeltas
// are wired on each backend in a later migration slice.
type RuntimeDataPlane interface {
	Start(context.Context) error
	ConfigSink
	Close() error
	Teardown() error

	Link() LinkController
	HA() HAController
	Sessions() SessionStore
	Telemetry() Telemetry

	// SessionDeltas returns the backend-neutral session-delta source used for
	// HA session sync. Backends that do not support delta streaming return a
	// nil source; callers must nil-check before use.
	// TODO(#1381): daemon_ha_userspace.go still imports dpuserspace directly;
	// migrate it to use dp.SessionDeltas() once all backends wire this method.
	SessionDeltas() dpruntime.SessionDeltaSource
}

type ConfigSink interface {
	ApplyConfig(context.Context, *config.Config) (*ApplyResult, error)
	LastApplyResult() *ApplyResult
}

type ApplyResult struct {
	ZoneIDs           map[string]uint16
	ManagedInterfaces []networkd.InterfaceConfig
	FilterIDs         map[string]uint32
	FilterSpans       map[string]FilterCounterSpan
	NATCounterIDs     map[string]uint32

	// Display metadata carried from CompileResult so callers can migrate from
	// LastCompileResult() to LastApplyResult() without losing runtime lookups.
	PoolIDs     map[string]uint8  // NAT pool name -> pool ID (0-based)
	PolicyNames map[uint32]string // rule_id -> policy path (zone/policy or global/policy)
	AppNames    map[uint16]string // app_id -> application name (structured logging)

	// PolicyScheduleRuleSlots records the compiled slots used by runtime
	// scheduler updates. Callers must not recompute these slots from config
	// policy positions because app-term expansion can make them diverge.
	PolicyScheduleRuleSlots []PolicyScheduleRuleSlot

	Capabilities Capabilities
	Generation   uint64
}

type FilterCounterSpan struct {
	FilterID  uint32
	RuleStart uint32
	RuleCount uint32
}

type Capabilities struct {
	ForwardingSupported bool
	UnsupportedReasons  []string
}

type LinkController interface {
	SetDeferWorkers(bool)
	PrepareLinkCycle()
	NotifyLinkCycle()
}

type FabricID uint8

type HAController interface {
	SetRGActive(context.Context, int, bool) error
	SetHAWatchdog(context.Context, int, uint64) error
	SetFabricForwarding(context.Context, FabricID, FabricFwdInfo) error
	SyncFabricState(context.Context) error
}

type Telemetry interface {
	NewEventSource() (EventSource, error)
	GlobalCounter(uint32) (uint64, error)
	InterfaceCounters(int) (InterfaceCounterValue, error)
	ZoneCounters(uint16, int) (CounterValue, error)
	PolicyCounters(uint32) (CounterValue, error)
	FilterCounters(uint32) (CounterValue, error)
	NATRuleCounter(uint32) (CounterValue, error)
	NATPortCounter(uint32) (uint64, error)
	MapStats() []MapStats
	// ReadFloodCounters returns the per-CPU aggregated flood/screen state for
	// the given zone. Backends without BPF flood maps return a zero FloodState.
	ReadFloodCounters(zoneID uint16) (FloodState, error)
}

func ApplyResultFromCompileResult(result *CompileResult) *ApplyResult {
	if result == nil {
		return nil
	}
	out := &ApplyResult{
		ZoneIDs:                 maps.Clone(result.ZoneIDs),
		ManagedInterfaces:       slices.Clone(result.ManagedInterfaces),
		FilterIDs:               maps.Clone(result.FilterIDs),
		FilterSpans:             maps.Clone(result.FilterSpans),
		NATCounterIDs:           make(map[string]uint32, len(result.NATCounterIDs)),
		Capabilities:            Capabilities{ForwardingSupported: true},
		PoolIDs:                 maps.Clone(result.PoolIDs),
		PolicyNames:             maps.Clone(result.PolicyNames),
		AppNames:                maps.Clone(result.AppNames),
		PolicyScheduleRuleSlots: slices.Clone(result.PolicyScheduleRuleSlots),
	}
	for key, id := range result.NATCounterIDs {
		out.NATCounterIDs[key] = uint32(id)
	}
	return out
}

func (r *ApplyResult) Clone() *ApplyResult {
	if r == nil {
		return nil
	}
	out := *r
	out.ZoneIDs = maps.Clone(r.ZoneIDs)
	out.ManagedInterfaces = slices.Clone(r.ManagedInterfaces)
	out.FilterIDs = maps.Clone(r.FilterIDs)
	out.FilterSpans = maps.Clone(r.FilterSpans)
	out.NATCounterIDs = maps.Clone(r.NATCounterIDs)
	out.Capabilities.UnsupportedReasons = slices.Clone(r.Capabilities.UnsupportedReasons)
	out.PoolIDs = maps.Clone(r.PoolIDs)
	out.PolicyNames = maps.Clone(r.PolicyNames)
	out.AppNames = maps.Clone(r.AppNames)
	out.PolicyScheduleRuleSlots = slices.Clone(r.PolicyScheduleRuleSlots)
	return &out
}

func (m *Manager) Start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return m.Load()
}

func (m *Manager) Link() LinkController {
	return NewDataPlaneLinkController(m)
}

func (m *Manager) HA() HAController {
	return NewDataPlaneHAController(m)
}

func (m *Manager) Sessions() SessionStore {
	return NewDataPlaneSessionStore(m)
}

func (m *Manager) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (m *Manager) Telemetry() Telemetry {
	return NewDataPlaneTelemetry(m)
}

func (m *Manager) ApplyConfig(ctx context.Context, cfg *config.Config) (*ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if _, err := m.Compile(cfg); err != nil {
		return nil, err
	}
	return m.LastApplyResult(), nil
}

func (m *Manager) LastApplyResult() *ApplyResult {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.lastApply.Clone()
}

func (m *Manager) recordApplyResult(result *ApplyResult) *ApplyResult {
	if result == nil {
		return nil
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.applyGeneration++
	next := result.Clone()
	next.Generation = m.applyGeneration
	m.lastApply = next
	return next.Clone()
}

func NewDataPlaneLinkController(dp DataPlane) LinkController {
	return dataPlaneLinkController{dp: dp}
}

type dataPlaneLinkController struct {
	dp DataPlane
}

func (c dataPlaneLinkController) SetDeferWorkers(bool) {}

func (c dataPlaneLinkController) PrepareLinkCycle() {}

func (c dataPlaneLinkController) NotifyLinkCycle() {
	if c.dp != nil {
		c.dp.NotifyLinkCycle()
	}
}

func NewDataPlaneHAController(dp DataPlane) HAController {
	return dataPlaneHAController{dp: dp}
}

type dataPlaneHAController struct {
	dp DataPlane
}

func (c dataPlaneHAController) SetRGActive(ctx context.Context, rgID int, active bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.dp == nil {
		return errors.New("nil dataplane")
	}
	return c.dp.UpdateRGActive(rgID, active)
}

func (c dataPlaneHAController) SetHAWatchdog(ctx context.Context, rgID int, timestamp uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.dp == nil {
		return errors.New("nil dataplane")
	}
	return c.dp.UpdateHAWatchdog(rgID, timestamp)
}

func (c dataPlaneHAController) SetFabricForwarding(ctx context.Context, id FabricID, info FabricFwdInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.dp == nil {
		return errors.New("nil dataplane")
	}
	if id == 1 {
		return c.dp.UpdateFabricFwd1(info)
	}
	return c.dp.UpdateFabricFwd(info)
}

func (c dataPlaneHAController) SyncFabricState(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.dp == nil {
		return errors.New("nil dataplane")
	}
	c.dp.SyncFabricState()
	return nil
}

func NewDataPlaneTelemetry(dp DataPlane) Telemetry {
	return dataPlaneTelemetry{dp: dp}
}

type dataPlaneTelemetry struct {
	dp DataPlane
}

func (t dataPlaneTelemetry) NewEventSource() (EventSource, error) {
	if t.dp == nil {
		return nil, errors.New("nil dataplane")
	}
	return t.dp.NewEventSource()
}

func (t dataPlaneTelemetry) GlobalCounter(index uint32) (uint64, error) {
	if t.dp == nil {
		return 0, errors.New("nil dataplane")
	}
	return t.dp.ReadGlobalCounter(index)
}

func (t dataPlaneTelemetry) ReadFloodCounters(zoneID uint16) (FloodState, error) {
	if t.dp == nil {
		return FloodState{}, errors.New("nil dataplane")
	}
	return t.dp.ReadFloodCounters(zoneID)
}

func (t dataPlaneTelemetry) InterfaceCounters(ifindex int) (InterfaceCounterValue, error) {
	if t.dp == nil {
		return InterfaceCounterValue{}, errors.New("nil dataplane")
	}
	return t.dp.ReadInterfaceCounters(ifindex)
}

func (t dataPlaneTelemetry) ZoneCounters(zoneID uint16, direction int) (CounterValue, error) {
	if t.dp == nil {
		return CounterValue{}, errors.New("nil dataplane")
	}
	return t.dp.ReadZoneCounters(zoneID, direction)
}

func (t dataPlaneTelemetry) PolicyCounters(policyID uint32) (CounterValue, error) {
	if t.dp == nil {
		return CounterValue{}, errors.New("nil dataplane")
	}
	return t.dp.ReadPolicyCounters(policyID)
}

func (t dataPlaneTelemetry) FilterCounters(ruleIdx uint32) (CounterValue, error) {
	if t.dp == nil {
		return CounterValue{}, errors.New("nil dataplane")
	}
	return t.dp.ReadFilterCounters(ruleIdx)
}

func (t dataPlaneTelemetry) NATRuleCounter(counterID uint32) (CounterValue, error) {
	if t.dp == nil {
		return CounterValue{}, errors.New("nil dataplane")
	}
	return t.dp.ReadNATRuleCounter(counterID)
}

func (t dataPlaneTelemetry) NATPortCounter(poolID uint32) (uint64, error) {
	if t.dp == nil {
		return 0, errors.New("nil dataplane")
	}
	return t.dp.ReadNATPortCounter(poolID)
}

func (t dataPlaneTelemetry) MapStats() []MapStats {
	if t.dp == nil {
		return nil
	}
	return t.dp.GetMapStats()
}
