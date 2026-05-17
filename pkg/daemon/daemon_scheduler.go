package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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
	hash, hasSchedulers := policySchedulerConfigHash(cfg)
	if hasSchedulers && d.scheduler != nil && hash == d.policySchedulerConfigHash {
		d.startPolicySchedulerLoopLocked()
		return d.scheduler.ActiveState()
	}

	if d.schedulerCancel != nil {
		d.schedulerCancel()
		d.schedulerCancel = nil
	}
	d.scheduler = nil
	epoch := d.policySchedulerEpoch.Add(1)

	if !hasSchedulers {
		d.policySchedulerConfigHash = [32]byte{}
		return nil
	}

	sched, activeState := scheduler.NewPrimed(cfg.Schedulers, func(activeState map[string]bool) {
		d.publishPolicyScheduleState(epoch, activeState)
	}, time.Now())
	d.scheduler = sched
	d.policySchedulerConfigHash = hash
	d.startPolicySchedulerLoopLocked()
	return activeState
}

func policySchedulerConfigHash(cfg *config.Config) ([32]byte, bool) {
	if cfg == nil || len(cfg.Schedulers) == 0 {
		return [32]byte{}, false
	}
	b, err := json.Marshal(cfg.Schedulers)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(b), true
}

func (d *Daemon) startPolicySchedulerLoopLocked() {
	if d.daemonCtx == nil || d.scheduler == nil || d.schedulerCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(d.daemonCtx)
	d.schedulerCancel = cancel
	go d.scheduler.Run(ctx)
}

func (d *Daemon) publishPolicyScheduleState(epoch uint64, activeState map[string]bool) {
	ctx := d.daemonCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
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
