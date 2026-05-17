package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
)

type policySchedulerActiveStateSetter interface {
	SetPolicySchedulerActiveState(map[string]bool)
}

// reconcilePolicySchedulerLocked runs under applySem. It makes the scheduler
// lifecycle follow committed config instead of only daemon startup, and returns
// the active-state map that must be used for the same apply transaction.
func (d *Daemon) reconcilePolicySchedulerLocked(cfg *config.Config) map[string]bool {
	if d.schedulerCancel != nil {
		d.schedulerCancel()
		d.schedulerCancel = nil
	}
	d.scheduler = nil
	epoch := d.policySchedulerEpoch.Add(1)

	if cfg == nil || len(cfg.Schedulers) == 0 {
		return nil
	}

	sched, activeState := scheduler.NewPrimed(cfg.Schedulers, func(activeState map[string]bool) {
		d.publishPolicyScheduleState(epoch, activeState)
	}, time.Now())
	d.scheduler = sched

	if d.daemonCtx != nil {
		ctx, cancel := context.WithCancel(d.daemonCtx)
		d.schedulerCancel = cancel
		go sched.Run(ctx)
	}
	return activeState
}

func (d *Daemon) publishPolicyScheduleState(epoch uint64, activeState map[string]bool) {
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		slog.Warn("scheduler: failed to acquire apply semaphore", "err", err)
		return
	}
	defer d.applySem.Release(1)

	if epoch != d.policySchedulerEpoch.Load() {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || d.dp == nil {
		return
	}
	d.seedPolicySchedulerActiveStateLocked(activeState)
	d.dp.UpdatePolicyScheduleState(cfg, activeState)
}

func (d *Daemon) seedPolicySchedulerActiveStateLocked(activeState map[string]bool) {
	if d.dp == nil {
		return
	}
	if setter, ok := d.dp.(policySchedulerActiveStateSetter); ok {
		setter.SetPolicySchedulerActiveState(activeState)
	}
}
