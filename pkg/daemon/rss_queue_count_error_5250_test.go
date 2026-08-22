// #5250 (A7-b2 F2): readQueueCount returned a bare int and yielded 0 on a
// sysfs enumeration error, so an ERROR was indistinguishable from "this NIC
// has no RX queues". computeWeightVector(workers, 0) returns nil, which walks
// the "no weight vector applied" branch — whose restore guard requires
// queues > 1. So on a read error a previously written concentrated
// `[1,..,1,0,..,0]` indirection table stayed live, starving queues no worker
// consumes, with nothing logged above Info. readQueueCount now returns an
// error and the error path restores the kernel default unconditionally.
//
// FAIL-ON-REVERT: swallow the error (return 0, nil) and no `-X ... default`
// call is recorded — the "want a restore" assertion goes RED.
package daemon

import (
	"errors"
	"testing"
)

func TestRSSQueueCountErrorRestoresDefault_5250(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:   map[string]string{"eth0": mlx5Driver},
		queues:    map[string]int{"eth0": 6},
		queueErrs: map[string]error{"eth0": errors.New("permission denied")},
	}

	applyRSSIndirectionOne("eth0", 4, f)

	if len(f.calls) != 1 {
		t.Fatalf("want exactly 1 ethtool call (the unconditional default restore), got %d: %v", len(f.calls), f.calls)
	}
	c := f.calls[0]
	if len(c) != 3 || c[0] != "-X" || c[1] != "eth0" || c[2] != "default" {
		t.Fatalf("call = %v, want [-X eth0 default] — an unreadable queue count must not leave a stale concentrated table live", c)
	}
}

// A successful read of zero queues is NOT the error case: it must keep the
// pre-existing behavior (no weight vector, no restore — there is nothing to
// concentrate on a queueless netdev).
func TestRSSQueueCountZeroIsNotAnError_5250(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{"eth0": mlx5Driver},
		queues:  map[string]int{"eth0": 0},
	}

	applyRSSIndirectionOne("eth0", 4, f)

	if len(f.calls) != 0 {
		t.Fatalf("queues=0 (read OK) must issue no ethtool call, got %v", f.calls)
	}
}
