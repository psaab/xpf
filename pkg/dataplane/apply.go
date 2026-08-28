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
// one domain at a time. The eBPF, DPDK, and userspace managers have
// compile-time assertions against this shape.
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
	// TODO(#1381): migrate daemon HA session sync from direct userspace type
	// assertions to this backend-neutral source.
	SessionDeltas() dpruntime.SessionDeltaSource
}

type ConfigSink interface {
	ApplyConfig(context.Context, *config.Config) (*ApplyResult, error)
	LastApplyResult() *ApplyResult
}

type ApplyResultReader interface {
	LastApplyResult() *ApplyResult
}

type SessionStoreProvider interface {
	Sessions() SessionStore
}

type TelemetryProvider interface {
	Telemetry() Telemetry
}

// The three ...Of helpers below are OPTIONAL-CAPABILITY probes: they ask
// "does this provider happen to expose X?" and degrade to a null object
// when it does not. Each therefore resolves through Unwrap first — a live
// indirection (pkg/daemon's liveDataPlane, #2114) declares only the
// MANDATORY management surface, so probing the adapter itself would report
// "capability absent" for a perfectly healthy backend that has it.

func LastApplyResultOf(provider any) *ApplyResult {
	provider = Unwrap(provider)
	if provider == nil {
		return nil
	}
	reader, ok := provider.(ApplyResultReader)
	if !ok {
		return nil
	}
	return reader.LastApplyResult()
}

func SessionStoreOf(provider any) SessionStore {
	switch p := Unwrap(provider).(type) {
	case nil:
		return NewDataPlaneSessionStore(nil)
	case SessionStore:
		return p
	case SessionStoreProvider:
		if store := p.Sessions(); store != nil {
			return store
		}
	case DataPlane:
		return NewDataPlaneSessionStore(p)
	}
	return NewDataPlaneSessionStore(nil)
}

func TelemetryOf(provider any) Telemetry {
	switch p := Unwrap(provider).(type) {
	case nil:
		return NewDataPlaneTelemetry(nil)
	case Telemetry:
		return p
	case TelemetryProvider:
		if telemetry := p.Telemetry(); telemetry != nil {
			return telemetry
		}
	case DataPlane:
		return NewDataPlaneTelemetry(p)
	}
	return NewDataPlaneTelemetry(nil)
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
	// PrepareLinkCycle joins the AF_XDP workers so no thread touches UMEM
	// during a link DOWN/UP. It returns an error when the join could not be
	// completed or verified; the caller MUST NOT cycle the link in that case
	// (#5103). A void return made a failed join indistinguishable from a
	// successful one, so the link cycled with workers still live.
	PrepareLinkCycle() error
	// NotifyLinkCycleKeepingLease performs the same rebind as NotifyLinkCycle
	// but leaves the #6871 link-cycle lease HELD (#7007).
	//
	// It exists because acquire and release do not pair on a multi-member RETH
	// apply: acquire is per MEMBER, inside the loop, while release was per
	// REPAIR — so an aborted member's in-loop rollback ended a lease an
	// already-cycled sibling still depended on. The aborted member must still
	// rebind (its own workers are joined, its ctrl is off); it must not end the
	// apply's lease to do it. The apply-wide site outside the loop releases.
	NotifyLinkCycleKeepingLease() error
	// NotifyLinkCycle sends the "rebind" that recreates the AF_XDP workers
	// PrepareLinkCycle joined. It is the documented inverse of "stop_workers",
	// and the daemon uses it both to finish a cycle and to unwind an aborted
	// one. It returns an error when the rebind did not land (#6871): a void
	// return made a total forwarding outage — every worker stopped, ctrl off,
	// nothing to re-arm them — indistinguishable from a clean rebind to the
	// caller that reports the commit.
	NotifyLinkCycle() error
	// RenewLinkCycle extends a link-cycle lease that is already held, and does
	// nothing when none is. The daemon calls it once per RETH member it walks
	// so the lease's TTL bounds ONE loop iteration rather than the whole loop —
	// there is no constant that bounds the latter, since the member count is
	// operator-configurable up to 128 (#6871). It is part of this interface,
	// not an optional type assertion, so a new implementation has to answer for
	// it at compile time instead of silently no-opping the renewal.
	RenewLinkCycle()
	// AbandonLinkCycle drops a link-cycle lease that is still held, WITHOUT
	// rebinding, and reports whether one was. The daemon defers it over the
	// whole apply so a lease can never outlive the apply that took it — which
	// is what makes the #6871 round-8 self-renewing lease safe: a heartbeat
	// keeps a live lease alive indefinitely, so the leak case needs a
	// guaranteed release rather than a wall-clock backstop that is also
	// capable of expiring a cycle that is still running.
	//
	// Interface member, not an optional assertion, for the same reason
	// RenewLinkCycle is: a backend that silently no-ops it would turn a leaked
	// lease into a permanently suppressed reconcile loop.
	AbandonLinkCycle() bool
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
		ManagedInterfaces:       cloneManagedInterfaces(result.ManagedInterfaces),
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
	out.ManagedInterfaces = cloneManagedInterfaces(r.ManagedInterfaces)
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

func cloneManagedInterfaces(in []networkd.InterfaceConfig) []networkd.InterfaceConfig {
	out := slices.Clone(in)
	for i := range out {
		out[i].Addresses = slices.Clone(out[i].Addresses)
	}
	return out
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

// nextApplyGeneration reports the generation recordApplyResult will stamp on
// the compile now in flight.
//
// Used to give the #5275 arm-coverage line a DISTINCT stage label per compile:
// a single daemon apply can compile TWICE on the RETH deferred-MAC path
// (daemon_apply_dataplane.go's reapplyAfterDeferredMAC), and two proof lines
// carrying an identical stage label are indistinguishable in a log archive.
func (m *Manager) nextApplyGeneration() uint64 {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.applyGeneration + 1
}

func NewDataPlaneLinkController(dp DataPlane) LinkController {
	return dataPlaneLinkController{dp: dp}
}

type dataPlaneLinkController struct {
	dp DataPlane
}

func (c dataPlaneLinkController) SetDeferWorkers(bool) {}

func (c dataPlaneLinkController) PrepareLinkCycle() error { return nil }

// RenewLinkCycle on the eBPF-backed controller is a no-op for the same reason
// PrepareLinkCycle is: this controller never takes a link-cycle lease, so there
// is never one to extend.
func (c dataPlaneLinkController) RenewLinkCycle() {}

// AbandonLinkCycle on the eBPF-backed controller reports "nothing was held" for
// the same reason: no lease is ever taken here, so there is never one to
// abandon. The daemon's deferred call is a no-op on this backend.
func (c dataPlaneLinkController) AbandonLinkCycle() bool { return false }

// NotifyLinkCycle on the eBPF-backed controller is always a success: the
// DataPlane-level NotifyLinkCycle it forwards to is a no-op for the eBPF
// dataplane (eBPF programs survive a link cycle, so there is nothing to rebind
// and nothing that can fail), and a nil dp means no dataplane is wired at all.
// The error exists for the userspace controller, which does the real rebind.
func (c dataPlaneLinkController) NotifyLinkCycle() error {
	if c.dp != nil {
		c.dp.NotifyLinkCycle()
	}
	return nil
}

// NotifyLinkCycleKeepingLease is the same rebind here, because this adapter has
// no lease to keep: the #6871 lease lives on the userspace Manager, and this
// shim wraps a DataPlane whose NotifyLinkCycle is void. Identical behaviour is
// therefore correct rather than a stub — there is nothing for the #7007
// separation to separate.
func (c dataPlaneLinkController) NotifyLinkCycleKeepingLease() error {
	return c.NotifyLinkCycle()
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
