package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
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
