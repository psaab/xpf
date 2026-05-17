package dataplane

import (
	"context"
	"maps"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// RuntimeDataPlane is the target daemon-facing dataplane shape for #1381.
// It is introduced beside the legacy BPF-shaped DataPlane while callers move
// one domain at a time.
type RuntimeDataPlane interface {
	Start(context.Context) error
	ConfigSink
	Close() error
	Teardown() error

	Link() LinkController
	HA() HAController
	Sessions() SessionStore
	Telemetry() Telemetry
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
	Capabilities      Capabilities
	Generation        uint64
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
}

func ApplyResultFromCompileResult(result *CompileResult) *ApplyResult {
	if result == nil {
		return nil
	}
	out := &ApplyResult{
		ZoneIDs:           maps.Clone(result.ZoneIDs),
		ManagedInterfaces: append([]networkd.InterfaceConfig(nil), result.ManagedInterfaces...),
		FilterIDs:         maps.Clone(result.FilterIDs),
		FilterSpans:       maps.Clone(result.FilterSpans),
		NATCounterIDs:     make(map[string]uint32, len(result.NATCounterIDs)),
		Capabilities:      Capabilities{ForwardingSupported: true},
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
	out.ManagedInterfaces = append([]networkd.InterfaceConfig(nil), r.ManagedInterfaces...)
	out.FilterIDs = maps.Clone(r.FilterIDs)
	out.FilterSpans = maps.Clone(r.FilterSpans)
	out.NATCounterIDs = maps.Clone(r.NATCounterIDs)
	out.Capabilities.UnsupportedReasons = append([]string(nil), r.Capabilities.UnsupportedReasons...)
	return &out
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
