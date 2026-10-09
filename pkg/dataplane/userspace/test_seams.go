package userspace

import (
	"io"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

const policySnapshotRecoveryApplySnapshotTypeForTest = "apply_snapshot"

// PolicySnapshotRecoveryFixtureForTest drives a Manager synchronously with a
// scripted helper. This file exists only for cross-package tests; constructing
// or calling the fixture from a test explicitly drives its isolated Manager.
type PolicySnapshotRecoveryFixtureForTest struct {
	manager *Manager
	ctrl    *policyRecoveryCtrlMapForTest

	sends            int
	neighborSends    int
	helperGeneration uint64
	loseNextAck      bool
	neighborChanged  bool
}

// PolicySnapshotRecoveryStateForTest is the observable state of the recovery
// fixture, limited to publication, control-gate, and neighbor-update results.
type PolicySnapshotRecoveryStateForTest struct {
	Sends         int
	NeighborSends int
	Unknown       bool
	Pending       bool
	CtrlHeld      bool
	Published     uint64
	Retained      uint64
	Stamp         uint64
	CtrlEnabled   uint32
}

type policyRecoveryCtrlMapForTest struct {
	value userspaceCtrlValue
	have  bool
}

func (m *policyRecoveryCtrlMapForTest) Lookup(_ interface{}, valueOut interface{}) error {
	if !m.have {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*userspaceCtrlValue) = m.value
	return nil
}

func (m *policyRecoveryCtrlMapForTest) Update(_ interface{}, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.value = value.(userspaceCtrlValue)
	m.have = true
	return nil
}

type policyRecoveryBindingsMapForTest struct{}

func (*policyRecoveryBindingsMapForTest) Lookup(_, _ interface{}) error {
	return ebpf.ErrKeyNotExist
}

func (*policyRecoveryBindingsMapForTest) Update(_, _ interface{}, _ ebpf.MapUpdateFlags) error {
	return nil
}

func (f *PolicySnapshotRecoveryFixtureForTest) statusLocked() ProcessStatus {
	return ProcessStatus{
		Enabled: true,
		Workers: 1,
		Bindings: []BindingStatus{{
			Slot: 0, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-1",
			Ifindex: 7, Registered: true, Armed: true, Ready: true, Bound: true,
			RXPackets: 1000,
		}},
		NeighborGeneration:            1,
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        f.helperGeneration,
	}
}

// NewPolicySnapshotRecoveryFixtureForTest creates a map-free Manager with an
// initial published generation and a retained full snapshot. The supplied
// socket is used only by the real session-list request path.
func NewPolicySnapshotRecoveryFixtureForTest(oldCfg, nextCfg *config.Config, socket string) *PolicySnapshotRecoveryFixtureForTest {
	m := New()
	f := &PolicySnapshotRecoveryFixtureForTest{
		manager:          m,
		ctrl:             &policyRecoveryCtrlMapForTest{},
		helperGeneration: 6,
	}
	m.proc = &exec.Cmd{Process: &os.Process{}}
	m.cfg.ControlSocket = socket
	m.syncCancel = func() {}
	m.helperStatusCtrlMapHook = f.ctrl
	m.helperStatusBindingsMapHook = &policyRecoveryBindingsMapForTest{}
	m.failClosedCtrlMapHook = f.ctrl
	m.disableCtrlMapHook = f.ctrl
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.xskLivenessProven = true
	m.neighborsPrewarmed = true
	m.initialCtrlCleanupDone = true
	m.appliedSnapshot = appliedSnapshot{Config: oldCfg, Generation: 6}
	m.lastSnapshot = &ConfigSnapshot{Version: ProtocolVersion, Generation: 7, Config: nextCfg}
	m.generation = 7
	m.publishedSnapshot = 6
	m.pendingFullSnapshotMetadata = true
	m.lastStatus = f.statusLocked()
	m.helperStatusObserved = true
	m.neighborSnapshotBuilder = func(*config.Config) []NeighborSnapshot {
		if !f.neighborChanged {
			return nil
		}
		return []NeighborSnapshot{{
			Ifindex: 7, IP: "192.0.2.2", MAC: "02:00:00:00:00:02", State: "reachable",
		}}
	}
	m.controlRequestHook = func(req ControlRequest, out *ProcessStatus) error {
		if req.Type == policySnapshotRecoveryApplySnapshotTypeForTest {
			f.sends++
			f.helperGeneration = req.Snapshot.Generation
			if f.loseNextAck {
				f.loseNextAck = false
				return io.ErrUnexpectedEOF
			}
		}
		if req.Type == "update_neighbors" {
			f.neighborSends++
		}
		if out != nil {
			*out = f.statusLocked()
			if req.Type == "update_neighbors" {
				applied := true
				out.ManagerNeighborGeneration = req.NeighborGeneration
				out.NeighborReplaceApplied = &applied
			}
		}
		return nil
	}
	return f
}

// ManagerForTest returns the fixture Manager so a daemon test can attach the
// actual Manager to its local RuntimeDataPlane adapter and install the real
// prepublish callback.
func (f *PolicySnapshotRecoveryFixtureForTest) ManagerForTest() *Manager {
	return f.manager
}

// ScriptLostNextApplyAckForTest makes the next apply_snapshot request reach
// the scripted helper but lose its acknowledgement.
func (f *PolicySnapshotRecoveryFixtureForTest) ScriptLostNextApplyAckForTest() {
	f.manager.mu.Lock()
	f.loseNextAck = true
	f.manager.mu.Unlock()
}

// TickForTest runs one real Manager status and deferred-publication turn
// synchronously, without starting its background status loop.
func (f *PolicySnapshotRecoveryFixtureForTest) TickForTest() (bool, error) {
	m := f.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	status := f.statusLocked()
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return false, err
	}
	prepared := m.prepareDeferredPolicySnapshotLocked()
	if !prepared {
		return false, nil
	}
	return true, m.syncSnapshotLocked()
}

// RegenerateNeighborForTest performs a real neighbor snapshot regeneration
// using a newly reachable row and the scripted successful update response.
func (f *PolicySnapshotRecoveryFixtureForTest) RegenerateNeighborForTest() {
	f.manager.mu.Lock()
	f.neighborChanged = true
	f.manager.mu.Unlock()
	f.manager.RegenerateNeighborSnapshot()
}

// StateForTest snapshots the fixture's recovery state under Manager.mu.
func (f *PolicySnapshotRecoveryFixtureForTest) StateForTest() PolicySnapshotRecoveryStateForTest {
	m := f.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	return PolicySnapshotRecoveryStateForTest{
		Sends:         f.sends,
		NeighborSends: f.neighborSends,
		Unknown:       m.applySnapshotOutcomeUnknown,
		Pending:       m.pendingFullSnapshotMetadata,
		CtrlHeld:      m.ctrlMustStayDisabledLocked(true),
		Published:     m.publishedSnapshot,
		Retained:      m.lastSnapshot.Generation,
		Stamp:         m.policySnapshotPrepublishGeneration,
		CtrlEnabled:   f.ctrl.value.Enabled,
	}
}
