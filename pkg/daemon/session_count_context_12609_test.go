package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// This exercises the production liveDataPlane -> LegacyDataPlaneAdapter ->
// Manager.SessionCountContext chain without creating eBPF maps. Removing the
// adapter forwarder makes the chain return the unsupported-surface error.
func TestLiveSessionCountContextReachesUserspaceManager12609(t *testing.T) {
	adapter := dpuserspace.NewLegacyDataPlaneAdapter(dpuserspace.New())
	var d Daemon
	d.dpCell.Store(&dpSlot{v: adapter})
	live := liveDataPlane{daemon: &d}

	v4, v6, err := live.SessionCountContext(context.Background())
	if err != nil || v4 != 0 || v6 != 0 {
		t.Fatalf("live session count = (%d, %d, %v), want (0, 0, nil)", v4, v6, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v4, v6, err = live.SessionCountContext(ctx)
	if !errors.Is(err, context.Canceled) || v4 != 0 || v6 != 0 {
		t.Fatalf("canceled live session count = (%d, %d, %v), want (0, 0, context.Canceled)", v4, v6, err)
	}

	var empty Daemon
	_, _, err = (liveDataPlane{daemon: &empty}).SessionCountContext(context.Background())
	if !errors.Is(err, dataplane.ErrNotPublished) {
		t.Fatalf("unpublished live session count error = %v, want ErrNotPublished", err)
	}
}
