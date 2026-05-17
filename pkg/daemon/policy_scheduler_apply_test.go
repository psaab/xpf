package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type policySchedulerApplyTestDP struct {
	*dataplane.Manager

	compileErr      error
	compileCalls    int
	deferStates     []bool
	updateCalls     int
	updateStateSeen map[string]bool
}

func (d *policySchedulerApplyTestDP) Compile(*config.Config) (*dataplane.CompileResult, error) {
	d.compileCalls++
	if d.compileErr != nil {
		return nil, d.compileErr
	}
	return &dataplane.CompileResult{}, nil
}

func (d *policySchedulerApplyTestDP) SetDeferWorkers(v bool) {
	d.deferStates = append(d.deferStates, v)
}

func (d *policySchedulerApplyTestDP) UpdatePolicyScheduleState(_ *config.Config, activeState map[string]bool) {
	d.updateCalls++
	d.updateStateSeen = activeState
}

func TestApplyConfigClearsDeferWorkersOnAbortCompileError(t *testing.T) {
	dp := &policySchedulerApplyTestDP{
		compileErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	d := &Daemon{
		cluster: &cluster.Manager{},
		dp:      dp,
	}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				ClusterID: 1,
				NodeID:    0,
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1},
				"lo":    {Name: "lo", RedundantParent: "reth0"},
			},
		},
	}

	if err := d.applyConfigLocked(cfg); !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want protocol incompatibility", err)
	}
	if dp.compileCalls != 1 {
		t.Fatalf("Compile calls = %d, want 1", dp.compileCalls)
	}
	if len(dp.deferStates) != 2 || !dp.deferStates[0] || dp.deferStates[1] {
		t.Fatalf("defer worker states = %v, want [true false]", dp.deferStates)
	}
}

func TestApplyConfigPublishesScheduleStateToNonUserspaceDataplane(t *testing.T) {
	dp := &policySchedulerApplyTestDP{}
	d := &Daemon{dp: dp}
	cfg := &config.Config{}
	activeState := map[string]bool{"workhours": true}

	d.publishInitialPolicySchedulerStateLocked(cfg, activeState, &dataplane.CompileResult{})

	if dp.updateCalls != 1 {
		t.Fatalf("UpdatePolicyScheduleState calls = %d, want 1", dp.updateCalls)
	}
	if got, ok := dp.updateStateSeen["workhours"]; !ok || !got {
		t.Fatalf("active state for workhours = %t, present=%t; want active true", got, ok)
	}
}
