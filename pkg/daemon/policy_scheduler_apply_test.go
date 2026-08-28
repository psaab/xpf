package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
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
	updateErr       error
}

func (d *policySchedulerApplyTestDP) Compile(*config.Config) (*dataplane.CompileResult, error) {
	d.compileCalls++
	if d.compileErr != nil {
		return nil, d.compileErr
	}
	return &dataplane.CompileResult{}, nil
}

func (d *policySchedulerApplyTestDP) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	result, err := d.Compile(cfg)
	if err != nil {
		return nil, err
	}
	return dataplane.ApplyResultFromCompileResult(result), nil
}

func (d *policySchedulerApplyTestDP) SetDeferWorkers(v bool) {
	d.deferStates = append(d.deferStates, v)
}

func (d *policySchedulerApplyTestDP) UpdatePolicyScheduleState(_ *config.Config, activeState map[string]bool) error {
	d.updateCalls++
	d.updateStateSeen = activeState
	return d.updateErr
}

type userspacePolicySchedulerApplyTestDP struct {
	policySchedulerApplyTestDP

	seedCalls          int
	seedStateSeen      map[string]bool
	compileStateSeen   map[string]bool
	compileCfgPolicy   string
	compileCfgSchedule string
}

type runtimeOnlyApplyTestDP struct {
	applyCalls  int
	applyErr    error
	applyResult *dataplane.ApplyResult
}

func (d *runtimeOnlyApplyTestDP) Start(context.Context) error { return nil }
func (d *runtimeOnlyApplyTestDP) Close() error                { return nil }
func (d *runtimeOnlyApplyTestDP) Teardown() error             { return nil }

func (d *runtimeOnlyApplyTestDP) ApplyConfig(ctx context.Context, _ *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	d.applyCalls++
	if d.applyErr != nil {
		return nil, d.applyErr
	}
	if d.applyResult != nil {
		return d.applyResult.Clone(), nil
	}
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint16{}}, nil
}

func (d *runtimeOnlyApplyTestDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint16{}}
}

func (d *runtimeOnlyApplyTestDP) Link() dataplane.LinkController {
	return noopLinkController{}
}

func (d *runtimeOnlyApplyTestDP) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}

func (d *runtimeOnlyApplyTestDP) Sessions() dataplane.SessionStore {
	return dataplane.SessionStoreOf(nil)
}

func (d *runtimeOnlyApplyTestDP) Telemetry() dataplane.Telemetry {
	return dataplane.TelemetryOf(nil)
}

func (d *runtimeOnlyApplyTestDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

type noopLinkController struct{}

func (noopLinkController) SetDeferWorkers(bool)    {}
func (noopLinkController) PrepareLinkCycle() error { return nil }
func (noopLinkController) NotifyLinkCycle() error  { return nil }

// #7007: the repair-without-release variant. A no-op fake has no lease to keep;
// the separation is asserted by leaseTracingLinkController.
func (noopLinkController) NotifyLinkCycleKeepingLease() error { return nil }
func (noopLinkController) RenewLinkCycle()         {}
func (noopLinkController) AbandonLinkCycle() bool  { return false }

type runtimeOnlyPolicyUpdaterTestDP struct {
	runtimeOnlyApplyTestDP
	updateCalls int
	stateSeen   map[string]bool
	updateErr   error
}

func (d *runtimeOnlyPolicyUpdaterTestDP) UpdatePolicyScheduleState(_ *config.Config, activeState map[string]bool) error {
	d.updateCalls++
	d.stateSeen = copyPolicySchedulerApplyState(activeState)
	return d.updateErr
}

func (d *userspacePolicySchedulerApplyTestDP) SetPolicySchedulerActiveState(activeState map[string]bool) {
	d.seedCalls++
	d.seedStateSeen = copyPolicySchedulerApplyState(activeState)
}

func (d *userspacePolicySchedulerApplyTestDP) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	d.compileCalls++
	d.compileStateSeen = copyPolicySchedulerApplyState(d.seedStateSeen)
	if cfg != nil && len(cfg.Security.Policies) > 0 && len(cfg.Security.Policies[0].Policies) > 0 {
		pol := cfg.Security.Policies[0].Policies[0]
		d.compileCfgPolicy = pol.Name
		d.compileCfgSchedule = pol.SchedulerName
	}
	if d.compileErr != nil {
		return nil, d.compileErr
	}
	return &dataplane.CompileResult{}, nil
}

func (d *userspacePolicySchedulerApplyTestDP) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	result, err := d.Compile(cfg)
	if err != nil {
		return nil, err
	}
	return dataplane.ApplyResultFromCompileResult(result), nil
}

func (d *userspacePolicySchedulerApplyTestDP) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}

func copyPolicySchedulerApplyState(in map[string]bool) map[string]bool {
	if in == nil {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestApplyConfigClearsDeferWorkersOnAbortCompileError(t *testing.T) {
	dp := &policySchedulerApplyTestDP{
		compileErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	d := &Daemon{
		cluster: &cluster.Manager{},
	}
	d.setDataplane(dp) // #2114: publish through the cell
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

	if err := d.applyConfigLocked(context.Background(), cfg); !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
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
	oldScheduler, oldState := scheduler.NewPrimed(oldCfg.Schedulers, func(map[string]bool) error { return nil }, testPolicySchedulerApplyNow())
	oldHash, _ := policySchedulerConfigHash(oldCfg)
	dp := &policySchedulerApplyTestDP{
		compileErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	d := &Daemon{
		policySchedulerConfigHash: oldHash,
	}
	d.setDataplane(dp) // #2114: publish through the cell
	d.scheduler.Store(oldScheduler)
	d.policySchedulerEpoch.Store(42)
	newCfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"new": {Name: "new"},
		},
	}

	if err := d.applyConfigLocked(context.Background(), newCfg); !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want protocol incompatibility", err)
	}
	if d.scheduler.Load() != oldScheduler {
		t.Fatal("protocol abort replaced scheduler before apply completed")
	}
	if got := d.policySchedulerEpoch.Load(); got != 42 {
		t.Fatalf("policySchedulerEpoch = %d, want unchanged 42", got)
	}
	if d.policySchedulerConfigHash != oldHash {
		t.Fatal("protocol abort changed scheduler config hash")
	}
	if got := d.scheduler.Load().ActiveState()["old"]; got != oldState["old"] {
		t.Fatalf("old scheduler active state = %t, want %t", got, oldState["old"])
	}
}

func TestApplyConfigPublishesScheduleStateToNonUserspaceDataplane(t *testing.T) {
	dp := &policySchedulerApplyTestDP{}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell
	cfg := &config.Config{}
	activeState := map[string]bool{"workhours": true}

	d.publishInitialPolicySchedulerStateLocked(cfg, activeState, &dataplane.ApplyResult{})

	if dp.updateCalls != 1 {
		t.Fatalf("UpdatePolicyScheduleState calls = %d, want 1", dp.updateCalls)
	}
	if got, ok := dp.updateStateSeen["workhours"]; !ok || !got {
		t.Fatalf("active state for workhours = %t, present=%t; want active true", got, ok)
	}
}

func TestApplyConfigUsesRuntimeConfigSinkWithoutLegacyDataplane(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{
		applyErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	if _, ok := any(dp).(dataplane.DataPlane); ok {
		t.Fatal("test dataplane unexpectedly implements legacy DataPlane")
	}
	d := &Daemon{
		opts: Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	err := d.applyConfigLocked(context.Background(), &config.Config{})
	if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want runtime apply error", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1", dp.applyCalls)
	}
}

func TestPolicySchedulerUpdateUsesRuntimeUpdaterWithoutLegacyDataplane(t *testing.T) {
	dp := &runtimeOnlyPolicyUpdaterTestDP{}
	if _, ok := any(dp).(dataplane.DataPlane); ok {
		t.Fatal("test dataplane unexpectedly implements legacy DataPlane")
	}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell

	d.updatePolicyScheduleStateLocked(&config.Config{}, map[string]bool{"workhours": true})

	if dp.updateCalls != 1 {
		t.Fatalf("UpdatePolicyScheduleState calls = %d, want 1", dp.updateCalls)
	}
	if got, ok := dp.stateSeen["workhours"]; !ok || !got {
		t.Fatalf("stateSeen[workhours] = %t, present=%t; want true", got, ok)
	}
}

func TestApplyConfigSeedsUserspacePolicySchedulerStateBeforeCompile(t *testing.T) {
	dp := &userspacePolicySchedulerApplyTestDP{}
	dp.compileErr = dpuserspace.ErrPolicySchedulerProtocolIncompatible
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell
	cfg := testPolicySchedulerApplyConfig()

	if err := d.applyConfigLocked(context.Background(), cfg); !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want protocol incompatibility", err)
	}

	if dp.seedCalls != 1 {
		t.Fatalf("SetPolicySchedulerActiveState calls = %d, want 1", dp.seedCalls)
	}
	if dp.compileCalls != 1 {
		t.Fatalf("Compile calls = %d, want 1", dp.compileCalls)
	}
	if got, ok := dp.compileStateSeen["workhours"]; !ok || !got {
		t.Fatalf("compile saw workhours active = %t, present=%t; want active true", got, ok)
	}
	if dp.compileCfgPolicy != "scheduled-allow" || dp.compileCfgSchedule != "workhours" {
		t.Fatalf("compile cfg policy=%q scheduler=%q, want scheduled-allow/workhours",
			dp.compileCfgPolicy, dp.compileCfgSchedule)
	}
	if dp.updateCalls != 0 {
		t.Fatalf("UpdatePolicyScheduleState calls = %d, want 0 before aborted apply publishes", dp.updateCalls)
	}
}

func TestPolicySchedulerInitialPublishSkipsUserspaceLegacyMapUpdate(t *testing.T) {
	dp := &userspacePolicySchedulerApplyTestDP{}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell
	cfg := testPolicySchedulerApplyConfig()
	activeState := d.policySchedulerActiveStateForApplyLocked(cfg, testPolicySchedulerApplyNow())

	d.publishInitialPolicySchedulerStateLocked(cfg, activeState, &dataplane.ApplyResult{})

	if dp.updateCalls != 0 {
		t.Fatalf("UpdatePolicyScheduleState calls = %d, want 0 for userspace initial apply", dp.updateCalls)
	}
}

func testPolicySchedulerApplyConfig() *config.Config {
	return &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			// AllDay = always active (`daily all-day`). Post-#3849 an empty
			// scheduler fails CLOSED, so this test — which asserts the seeded
			// active state reaches compile as active=true — pins an
			// explicitly always-on window.
			"workhours": {Name: "workhours", AllDay: true},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{{
					Name:          "scheduled-allow",
					SchedulerName: "workhours",
					Action:        config.PolicyPermit,
				}},
			}},
		},
	}
}

func testPolicySchedulerApplyNow() time.Time {
	return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
}
