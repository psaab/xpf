// #8000, daemon half: a superseded member must not leave its fence barrier
// armed.
//
// #9036 CHANGED THE MECHANISM AND KEPT THE GOAL. #8000 achieved "no misleading
// fence timeout" by DISARMING the barrier, which makes waitFailoverActuated
// take its `b == nil` arm and return nil — indistinguishable from a real
// fence, so a request that demoted NOTHING was ACKed `applied` and the peer
// promoted into the two-owner window #5640 exists to prevent. The barrier is
// now RESOLVED with cluster.ErrFailoverSuperseded instead: it still returns
// immediately (the assertion #8000 actually bought), and it now carries the
// reason, so the ack downgrades to failed and the operator is told the truth
// rather than a fence timeout.
//
// The cells below therefore assert PROMPT + SUPERSEDED, not PROMPT + nil. The
// timing assertion is #8000's and is kept verbatim; dropping it would hand back
// what #8000 bought while claiming to fix something else.
//
// The two halves of #8000 are one fix. Reporting the partial outcome (the
// pkg/cluster half) still leaves the applied-ack burning the full fence timeout
// on whichever member a concurrent reset claimed, and then reporting
// "timed out waiting for local fence actuation of redundancy group N" — a real
// error, naming the right RG, blaming the wrong subsystem. Nothing will ever
// actuate that barrier: a supersede enqueues NO demotion event, so there is no
// edge for watchClusterEvents to fence.
//
// These cells drive the INSTALLED closure (ss.OnRemoteFailoverBatch /
// ss.OnRemoteFailover), not disarmFailoverActuation directly. Calling the
// primitive would pass against a build where the wiring never calls it, which
// is the whole defect.
package daemon

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// barrier8000Timeout is deliberately short: one cell below asserts that an
// APPLIED member still burns it, so the production 3s default would make the
// suite pay for the control.
const barrier8000Timeout = 300 * time.Millisecond

// newBarrier8000Daemon builds the minimum Daemon the failover callbacks touch:
// a cluster manager holding every named RG as primary, plus the actuation-barrier
// map. The batch closure reads d.cluster and the two barrier helpers and nothing
// else, so no store/VRRP/dataplane is needed.
func newBarrier8000Daemon(t *testing.T, rgIDs ...int) *Daemon {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	rgs := make([]*config.RedundancyGroup, 0, len(rgIDs))
	for _, id := range rgIDs {
		rgs = append(rgs, &config.RedundancyGroup{ID: id, NodePriorities: map[int]int{0: 200}})
	}
	cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: rgs})
	// UpdateConfig elects this solo node primary for every RG. Drain those
	// promotions so the demotions below are the only events in flight.
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	for _, id := range rgIDs {
		if !cm.IsLocalPrimary(id) {
			t.Fatalf("setup: node must be cluster-primary for RG%d before a transfer-out", id)
		}
	}
	return &Daemon{
		cluster:            cm,
		failoverActuations: failoverActuationRegistry{timeout: barrier8000Timeout},
	}
}

// resetDuringFailoverHook runs fn with a ResetFailover(rgID) landing inside the
// unlocked pre-hook window, reproducing the #5246 supersede deterministically
// rather than by timing.
//
// The BATCH calls the pre-hook once per member, so the signal fires exactly once
// (closing per call panics with "close of closed channel"). The reset therefore
// lands during the FIRST member's hook, making that member superseded while the
// rest commit — a genuinely partial batch.
func resetDuringFailoverHook(t *testing.T, cm *cluster.Manager, rgID int, fn func()) {
	t.Helper()
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	var once sync.Once
	cm.SetPreManualFailoverHook(func(int) error {
		once.Do(func() { close(hookStarted) })
		<-hookRelease
		return nil
	})
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	<-hookStarted
	if err := cm.ResetFailover(rgID); err != nil {
		t.Fatalf("ResetFailover(%d): %v", rgID, err)
	}
	close(hookRelease)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the failover call never returned")
	}
}

// FAIL-ON-REVERT, two directions:
//   - delete the `for _, rgID := range res.Superseded` loop in
//     wireSessionSyncFailoverCallbacks and RG0's wait burns barrier8000Timeout
//     and returns the fence-timeout error — the misdiagnosis #8000 names.
//   - swap failFailoverActuation back to disarmFailoverActuation and RG0's wait
//     returns nil promptly, which is #9036: a member that demoted nothing
//     reports the same verdict as one that fenced.
func TestRemoteBatchFailoverDisarmsSupersededBarrier8000(t *testing.T) {
	d := newBarrier8000Daemon(t, 0, 1)
	ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	d.wireSessionSyncFailoverCallbacks(ss)

	const reqID = uint64(8000)
	var batchErr error
	resetDuringFailoverHook(t, d.cluster, 0, func() {
		batchErr = ss.OnRemoteFailoverBatch([]int{0, 1}, reqID)
	})
	if batchErr != nil {
		t.Fatalf("OnRemoteFailoverBatch: %v — a supersede is a correct outcome, not a "+
			"transport failure, and turning it into an error would reverse #5246", batchErr)
	}

	// The superseded member: no demotion event was ever enqueued for RG0, so a
	// barrier left armed here can only expire. It must already be gone.
	start := time.Now()
	if err := d.waitFailoverActuated(0, reqID); !errors.Is(err, cluster.ErrFailoverSuperseded) {
		t.Errorf("waitFailoverActuated(RG0) = %v, want ErrFailoverSuperseded. RG0 was "+
			"superseded by a concurrent reset, so no fence actuation is owed — but nil "+
			"would ACK the member `applied` when it never demoted, which is #5640's "+
			"two-owner window (#9036). A fence TIMEOUT is equally wrong: it tells the "+
			"operator the fencing path broke when it did not (#8000)", err)
	}
	if elapsed := time.Since(start); elapsed > barrier8000Timeout/2 {
		t.Errorf("waitFailoverActuated(RG0) took %v (fence timeout is %v): the barrier was "+
			"still armed and the wait expired. Returning nil AFTER burning the timeout is "+
			"not the fix — the applied-ack must not stall on a member that was never "+
			"going to actuate", elapsed, barrier8000Timeout)
	}

	// CONTROL: the APPLIED member's barrier must still be armed. Without this a
	// fix that dropped every barrier — defeating the #5640 fence and reopening
	// the two-owner window — passes the assertions above.
	if err := d.waitFailoverActuated(1, reqID); err == nil {
		t.Error("waitFailoverActuated(RG1) = nil, but RG1 actually failed over and nothing " +
			"actuated its fence. The disarm must be scoped to superseded members; " +
			"dropping it for applied ones would let the peer promote into a two-owner " +
			"window (#5640)")
	} else if !strings.Contains(err.Error(), "redundancy group 1") {
		t.Errorf("waitFailoverActuated(RG1) = %v, want the fence timeout naming RG1", err)
	}
}

// The singular path carries the same defect and the same fix. It is not reachable
// through the batch closure: a one-member ManualFailoverBatch delegates to
// ManualFailover inside pkg/cluster, but ss.OnRemoteFailover is a SEPARATE
// closure with its own arm/disarm, so deleting its disarm arm leaves the batch
// cell above green.
//
// FAIL-ON-REVERT, two directions: delete the
// `if outcome == cluster.FailoverSuperseded` arm in ss.OnRemoteFailover and this
// cell burns the timeout and reds; swap failFailoverActuation back to
// disarmFailoverActuation and it reds on the verdict instead (#9036).
func TestRemoteFailoverDisarmsSupersededBarrier8000(t *testing.T) {
	d := newBarrier8000Daemon(t, 0)
	ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	d.wireSessionSyncFailoverCallbacks(ss)

	const reqID = uint64(8001)
	var callErr error
	resetDuringFailoverHook(t, d.cluster, 0, func() {
		callErr = ss.OnRemoteFailover(0, reqID)
	})
	if callErr != nil {
		t.Fatalf("OnRemoteFailover: %v — #5246 makes a reset winning a non-error", callErr)
	}

	start := time.Now()
	if err := d.waitFailoverActuated(0, reqID); !errors.Is(err, cluster.ErrFailoverSuperseded) {
		t.Errorf("waitFailoverActuated(RG0) = %v, want ErrFailoverSuperseded after a "+
			"supersede: nil would ACK `applied` for a request that demoted nothing "+
			"(#9036)", err)
	}
	if elapsed := time.Since(start); elapsed > barrier8000Timeout/2 {
		t.Errorf("waitFailoverActuated(RG0) took %v: the singular path left the barrier "+
			"armed on a supersede", elapsed)
	}

	// CONTROL: an UNCONTESTED remote failover must still arm and hold the fence.
	// Without it, a build that never arms a barrier at all passes.
	d2 := newBarrier8000Daemon(t, 0)
	ss2 := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	d2.wireSessionSyncFailoverCallbacks(ss2)
	if err := ss2.OnRemoteFailover(0, reqID); err != nil {
		t.Fatalf("uncontested OnRemoteFailover: %v", err)
	}
	if err := d2.waitFailoverActuated(0, reqID); err == nil {
		t.Error("uncontested remote failover left no armed barrier: the applied-ack would " +
			"return before the local demotion actuated, which is the #5640 two-owner window")
	}
}
