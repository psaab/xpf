package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/scheduler"
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

func TestApplyConfigProtocolAbortPreservesExistingScheduler(t *testing.T) {
	oldCfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"old": {Name: "old"},
		},
	}
	oldScheduler, oldState := scheduler.NewPrimed(oldCfg.Schedulers, func(map[string]bool) {}, testPolicySchedulerApplyNow())
	oldHash, _ := policySchedulerConfigHash(oldCfg)
	dp := &policySchedulerApplyTestDP{
		compileErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	d := &Daemon{
		dp:                        dp,
		scheduler:                 oldScheduler,
		policySchedulerConfigHash: oldHash,
	}
	d.policySchedulerEpoch.Store(42)
	newCfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"new": {Name: "new"},
		},
	}

	if err := d.applyConfigLocked(newCfg); !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want protocol incompatibility", err)
	}
	if d.scheduler != oldScheduler {
		t.Fatal("protocol abort replaced scheduler before apply completed")
	}
	if got := d.policySchedulerEpoch.Load(); got != 42 {
		t.Fatalf("policySchedulerEpoch = %d, want unchanged 42", got)
	}
	if d.policySchedulerConfigHash != oldHash {
		t.Fatal("protocol abort changed scheduler config hash")
	}
	if got := d.scheduler.ActiveState()["old"]; got != oldState["old"] {
		t.Fatalf("old scheduler active state = %t, want %t", got, oldState["old"])
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

func testPolicySchedulerApplyNow() time.Time {
	return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
}
