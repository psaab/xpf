package dpdk

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Compile-time assertion.
var _ dataplane.DataPlane = (*Manager)(nil)
var _ dataplane.ConfigSink = (*Manager)(nil)

func init() {
	dataplane.RegisterBackend(dataplane.TypeDPDK, func() dataplane.DataPlane {
		return New()
	})
}

// Manager is the DPDK dataplane backend (stub implementation).
type Manager struct {
	loaded          bool
	lastCompile     *dataplane.CompileResult
	applyMu         sync.Mutex
	applyGeneration uint64
	lastApply       *dataplane.ApplyResult
	persistentNAT   *dataplane.PersistentNATTable
	platform        platformState
}

// New creates a new DPDK Manager.
func New() *Manager {
	return &Manager{
		persistentNAT: dataplane.NewPersistentNATTable(),
	}
}

// --- Common methods (build-tag independent) ---

func (m *Manager) IsLoaded() bool                                  { return m.loaded }
func (m *Manager) LastCompileResult() *dataplane.CompileResult     { return m.lastCompile }
func (m *Manager) GetPersistentNAT() *dataplane.PersistentNATTable { return m.persistentNAT }
func (m *Manager) Map(_ string) *ebpf.Map                          { return nil }

func (m *Manager) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
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

func (m *Manager) LastApplyResult() *dataplane.ApplyResult {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.lastApply.Clone()
}

func (m *Manager) recordApplyResult(result *dataplane.ApplyResult) {
	if result == nil {
		return
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.applyGeneration++
	next := result.Clone()
	next.Generation = m.applyGeneration
	m.lastApply = next
}
