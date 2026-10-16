package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
)

// #12885: an active wall-clock recovery hold on the previous scheduler
// must seed a changed-config apply fail-closed (nothing active), even
// though the republish latch is not set. The hold is induced through the
// exported carry path with a stepped-wall previous scheduler.
func TestApplySeedingHonorsRecoveryHold12885(t *testing.T) {
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	noop := func(context.Context, map[string]bool) error { return nil }
	oldCfg := &config.Config{Schedulers: map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", AllDay: true},
	}}
	newCfg := &config.Config{Schedulers: map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", AllDay: true},
		"night":     {Name: "night", AllDay: true},
	}}
	stepped, _ := scheduler.NewPrimed(oldCfg.Schedulers, noop, now.Add(time.Hour))
	old, _ := scheduler.NewPrimed(oldCfg.Schedulers, noop, now)
	old.CarryRecoveryStateFrom(stepped, now)
	if !old.InRecoveryHold(now) {
		t.Fatal("precondition: previous scheduler not in recovery hold")
	}
	oldHash, _ := policySchedulerConfigHash(oldCfg)
	d := &Daemon{policySchedulerConfigHash: oldHash}
	d.scheduler.Store(old)

	staged, failClosed := d.policySchedulerActiveStateAndFailClosedForApplyLocked(newCfg, now)
	if !failClosed {
		t.Fatal("apply seeding ignored the previous recovery hold")
	}
	for name, active := range staged {
		if active {
			t.Fatalf("apply staged %q active during recovery hold", name)
		}
	}

	// Control: no hold — primed actives are staged.
	steady, _ := scheduler.NewPrimed(oldCfg.Schedulers, noop, now)
	d2 := &Daemon{policySchedulerConfigHash: oldHash}
	d2.scheduler.Store(steady)
	staged2, failClosed2 := d2.policySchedulerActiveStateAndFailClosedForApplyLocked(newCfg, now)
	if failClosed2 || !staged2["workhours"] {
		t.Fatalf("steady control staged = %v failClosed=%v, want active workhours", staged2, failClosed2)
	}
}

// #13919: syntactically valid but unloadable zone names must seed the
// action-aware deny-first disposition, not just an all-false scheduler map.
func TestApplySeedingFailsClosedForUnavailableZone13919(t *testing.T) {
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		System: config.SystemConfig{TimeZone: "America/Los_Angels"},
		Schedulers: map[string]*config.SchedulerConfig{
			"workhours": {Name: "workhours", AllDay: true},
		},
	}
	staged, failClosed := (&Daemon{}).policySchedulerActiveStateAndFailClosedForApplyLocked(cfg, now)
	if !failClosed || staged["workhours"] {
		t.Fatalf("unavailable zone staged = %v failClosed=%t, want inactive plus deny-eligible disposition", staged, failClosed)
	}
}
