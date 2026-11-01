package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #18415: the HA rolling upgrade's default rejoin deadline is derived from
// this package's bulk-prime retry schedule. The schedule bounds how long a
// rolled node can wait for its peer to re-push the inbound bulk. If someone
// lengthens the schedule, a roll would start timing out just before its prime
// lands again (the #18415 shape), so this test fails until the rolling default
// is re-derived.
func TestSyncPrimeRetryWindowBoundsRollingRejoin18415(t *testing.T) {
	var window time.Duration
	for _, d := range syncPrimeRetryIntervals {
		window += d
	}
	if window != upgrade.PeerBulkPrimeRetryWindow {
		t.Fatalf("bulk-prime retry schedule totals %s, but upgrade.PeerBulkPrimeRetryWindow mirrors %s; "+
			"re-derive upgrade.DefaultRejoinDeadline", window, upgrade.PeerBulkPrimeRetryWindow)
	}
	// The last attempt's late ack is re-driven after BulkAckPendingRetryAfter;
	// the deadline must cover that and leave time for the bulk itself.
	if need := window + cluster.BulkAckPendingRetryAfter; upgrade.DefaultRejoinDeadline <= need {
		t.Fatalf("upgrade.DefaultRejoinDeadline %s does not exceed the last re-driven prime at +%s",
			upgrade.DefaultRejoinDeadline, need)
	}
}
