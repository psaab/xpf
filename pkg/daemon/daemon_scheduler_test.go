package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
	"golang.org/x/sync/semaphore"
)

func TestStartPolicySchedulerLoopLockedWaitsForDaemonContext(t *testing.T) {
	sched, _ := scheduler.NewPrimed(map[string]*config.SchedulerConfig{
		"always": {Name: "always"},
	}, func(map[string]bool) {}, time.Now())

	d := &Daemon{scheduler: sched}
	d.startPolicySchedulerLoopLocked()
	if d.schedulerCancel != nil {
		t.Fatal("scheduler loop started before daemon context was available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.daemonCtx = ctx
	d.startPolicySchedulerLoopLocked()
	if d.schedulerCancel == nil {
		t.Fatal("scheduler loop did not start after daemon context became available")
	}
	d.schedulerCancel()
}

func TestReconcilePolicySchedulerLockedKeepsByteIdenticalScheduler(t *testing.T) {
	cfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"always": {Name: "always"},
		},
	}
	d := &Daemon{}

	first := d.reconcilePolicySchedulerLocked(cfg)
	if d.scheduler == nil {
		t.Fatal("scheduler was not created")
	}
	sched := d.scheduler
	epoch := d.policySchedulerEpoch.Load()

	second := d.reconcilePolicySchedulerLocked(&config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"always": {Name: "always"},
		},
	})
	if d.scheduler != sched {
		t.Fatal("byte-identical scheduler config recreated the scheduler")
	}
	if got := d.policySchedulerEpoch.Load(); got != epoch {
		t.Fatalf("epoch = %d, want unchanged %d", got, epoch)
	}
	if first["always"] != second["always"] {
		t.Fatalf("active state changed across identical reconcile: first=%v second=%v", first, second)
	}
}

func TestPublishPolicyScheduleStateUsesDaemonContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &Daemon{
		daemonCtx: ctx,
		applySem:  semaphore.NewWeighted(1),
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire semaphore: %v", err)
	}
	defer d.applySem.Release(1)

	done := make(chan struct{})
	go func() {
		d.publishPolicyScheduleState(0, map[string]bool{"always": true})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("publishPolicyScheduleState blocked on apply semaphore after daemon context cancellation")
	}
}
