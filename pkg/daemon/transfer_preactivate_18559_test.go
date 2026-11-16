package daemon

import (
	"context"
	"errors"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #18559: the daemon half of the make-before-break transfer. The route
// republish must run BETWEEN the mark and the helper publish — the #16270
// order the promotion path keeps — or the first fabric-redirected packet on the
// newly opened RG resolves to the cluster terminal and is discarded.

type fakePreActivateDP struct {
	*fakeOverlayDP
	publishErr     error
	reverted       bool
	marked         []int
	published      []int  // the RGs the publish marked routes-ready (#19167)
	epoch          uint64 // what Begin returns (#19167 fold 1)
	publishedEpoch uint64 // what Publish was handed
	until          time.Time
}

func (f *fakePreActivateDP) BeginTransferPreActivation(rgIDs []int, until time.Time) uint64 {
	f.marked = append([]int(nil), rgIDs...)
	f.until = until
	f.recordCall("mark")
	if time.Until(until) <= 0 || time.Until(until) > transferPreActivateTTL {
		f.recordCall("bad-deadline")
	}
	return f.epoch
}

func (f *fakePreActivateDP) PublishTransferPreActivation(rgIDs []int, epoch uint64) error {
	f.publishedEpoch = epoch
	f.published = append([]int(nil), rgIDs...)
	f.recordCall("ha-publish")
	return f.publishErr
}

func (f *fakePreActivateDP) EndTransferPreActivation(rgIDs []int) (bool, error) {
	f.recordCall("end")
	return f.reverted, nil
}

func newPreActivateDaemon18559(t *testing.T) (*Daemon, *fakePreActivateDP) {
	t.Helper()
	dp := &fakePreActivateDP{fakeOverlayDP: &fakeOverlayDP{callsChanged: make(chan struct{}, 8)}}
	d := routeListenerBumpDaemon11565(t, dp.fakeOverlayDP)
	d.setDataplane(dp)
	return d, dp
}

func TestBeginTransferPreActivationRoutesBeforeHelper18559(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	if err := d.beginTransferPreActivation([]int{1, 2}); err != nil {
		t.Fatalf("beginTransferPreActivation: %v", err)
	}
	want := []string{"mark", "publish", "bump", "ha-publish"}
	if got := dp.callsSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %v, want %v: the connected-RG routes must reach the helper before its forwarding opens (#16270)", got, want)
	}
	if !reflect.DeepEqual(dp.marked, []int{1, 2}) {
		t.Fatalf("marked %v, want [1 2]", dp.marked)
	}
	// #19167: the helper publish is what makes the RGs routes-ready, so it
	// must name exactly the RGs whose routes the republish above carried.
	if !reflect.DeepEqual(dp.published, []int{1, 2}) {
		t.Fatalf("published %v, want [1 2]: the helper publish must mark the republished RGs routes-ready", dp.published)
	}
}

// Strict VIP ownership (#104) exists to forbid a dual-active window; such an
// RG keeps the old sequence.
func TestBeginTransferPreActivationSkipsStrictVIPOwnership18559(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	d.getOrCreateRGState(2).SetStrictVIPOwnership(true)
	if err := d.beginTransferPreActivation([]int{1, 2}); err != nil {
		t.Fatalf("beginTransferPreActivation: %v", err)
	}
	if !reflect.DeepEqual(dp.marked, []int{1}) {
		t.Fatalf("marked %v, want [1]: a strict-VIP-ownership RG was pre-activated", dp.marked)
	}
}

func TestBeginTransferPreActivationReportsPublishFailure18559(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	dp.publishErr = errors.New("helper busy")
	if err := d.beginTransferPreActivation([]int{1}); err == nil {
		t.Fatal("a failed helper publish was reported as an open pre-activation")
	}
}

// The release withdraws what the pre-activation published only when it
// actually reverted an RG; after a successful transfer it must not schedule a
// republish (every publish is a generation change on the helper).
func TestEndTransferPreActivationWithdrawsOnlyOnRevert18559(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	d.endTransferPreActivation([]int{1})
	time.Sleep(50 * time.Millisecond)
	if got := dp.callsSnapshot(); !reflect.DeepEqual(got, []string{"end"}) {
		t.Fatalf("calls = %v after a no-revert release, want [end]", got)
	}

	d2, dp2 := newPreActivateDaemon18559(t)
	dp2.reverted = true
	d2.endTransferPreActivation([]int{1})
	deadline := time.After(2 * time.Second)
	for len(dp2.callsSnapshot()) < 3 {
		select {
		case <-dp2.callsChanged:
		case <-deadline:
			t.Fatalf("calls = %v: a reverted release did not withdraw the connected routes", dp2.callsSnapshot())
		}
	}
	if got := dp2.callsSnapshot(); !reflect.DeepEqual(got, []string{"end", "publish", "bump"}) {
		t.Fatalf("calls = %v, want [end publish bump]", got)
	}
}

// A dataplane without the surface (eBPF-era adapters, tests) is not an error
// the cluster layer must treat as fatal; it gets a typed refusal.
func TestBeginTransferPreActivationUnsupportedDataplane18559(t *testing.T) {
	d := routeListenerBumpDaemon11565(t, &fakeOverlayDP{})
	if err := d.beginTransferPreActivation([]int{1}); !errors.Is(err, errTransferPreActivationUnsupported) {
		t.Fatalf("err = %v, want errTransferPreActivationUnsupported", err)
	}
}

// #18569: the pre-activation waits for applySem at most
// transferPreActivateLockWait. A busy semaphore (a commit in flight, or a
// stuck apply) makes the transfer fall back to break-before-make instead of
// hanging the failover request, and nothing is marked or published. RED on
// revert (the wait was unbounded under the daemon-lifetime context).
func TestBeginTransferPreActivationBoundsApplySemWait18569(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	logs, restore := captureSlog(t)
	defer restore()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- d.beginTransferPreActivation([]int{1}) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(transferPreActivateLockWait + 2*time.Second):
		d.applySem.Release(1)
		<-done
		t.Fatal("the pre-activation waited unbounded for applySem")
	}
	d.applySem.Release(1)
	if !errors.Is(err, errTransferPreActivationLockBusy) {
		t.Fatalf("busy applySem returned %v, want errTransferPreActivationLockBusy", err)
	}
	if waited := time.Since(start); waited < transferPreActivateLockWait/2 {
		t.Fatalf("gave up after %v; it must wait up to %v for an apply to finish", waited, transferPreActivateLockWait)
	}
	if got := dp.callsSnapshot(); len(got) != 0 {
		t.Fatalf("calls = %v after a busy-semaphore fallback, want none", got)
	}
	if !strings.Contains(logs.String(), "transfer pre-activation skipped, apply semaphore busy") {
		t.Fatalf("the break-before-make fallback was not logged:\n%s", logs.String())
	}
}

// panickingOverlayDP18569 panics inside the route republish that runs while
// the pre-activation holds applySem.
type panickingOverlayDP18569 struct{ *fakePreActivateDP }

func (p *panickingOverlayDP18569) PublishRouteOverlaySnapshotWithLatch(*config.Config, []config.RouteOverlayEntry, map[string]bool, bool) (bool, error) {
	panic("route publisher failed")
}

// The pre-activation's applySem hold is released on every exit, including
// a panic in the republish: otherwise every later apply deadlocks. RED if
// the release is not deferred.
func TestPreActivationReleasesApplySemOnPanic18569(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	d.setDataplane(&panickingOverlayDP18569{dp})
	func() {
		defer func() { _ = recover() }()
		_ = d.beginTransferPreActivation([]int{1})
	}()
	if !d.applySem.TryAcquire(1) {
		t.Fatal("applySem leaked after a panic inside the pre-activation's republish")
	}
	d.applySem.Release(1)
}

// The TTL starts once applySem is held, so a wait that eats into it cannot
// publish an already-shortened overlay. RED if the deadline is computed
// before the acquire.
func TestTransferPreActivationTTLStartsAfterLock18569(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	hold := transferPreActivateLockWait / 2
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(hold, func() { d.applySem.Release(1) })
	start := time.Now()
	if err := d.beginTransferPreActivation([]int{1}); err != nil {
		t.Fatalf("beginTransferPreActivation after a short wait: %v", err)
	}
	if dp.until.Before(start.Add(hold).Add(transferPreActivateTTL)) {
		t.Fatalf("overlay deadline %v is less than the TTL after the lock was taken (start %v + wait %v + TTL %v)",
			dp.until, start, hold, transferPreActivateTTL)
	}
}

// #19167 review (r23 P3-3): a FAILED route republish never opens forwarding.
// The pre-activation errors out with no helper publish, and the cluster's
// release (preActivateTransfer calls it on any activation error) reverts the
// entry and schedules the withdrawal of what the pre-activation published.
func TestFailedRepublishNeverOpensForwarding19167(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	// The ROUTE republish fails: the embedded overlay fake's error. The
	// outer dp.publishErr is the helper HA publish, a different call.
	dp.fakeOverlayDP.publishErr = errors.New("injected route publish failure")
	dp.reverted = true
	if err := d.beginTransferPreActivation([]int{1}); err == nil {
		t.Fatal("a failed route republish still reported the pre-activation opened")
	}
	if got := dp.callsSnapshot(); !slices.Contains(got, "publish") || slices.Contains(got, "ha-publish") {
		t.Fatalf("calls %v: want the failed route republish and no helper publish after it", got)
	}
	dp.fakeOverlayDP.publishErr = nil
	d.endTransferPreActivation([]int{1}) // what the cluster's release does
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := dp.callsSnapshot()
		end := slices.Index(got, "end")
		if end >= 0 && slices.Contains(got[end:], "publish") {
			return // released, then the withdrawal republish ran
		}
		if time.Now().After(deadline) {
			t.Fatalf("calls %v: want the release and then a scheduled withdrawal republish", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// #19167 review (r23 P3-2): a SKIPPED republish (here: the daemon is
// resetting) published nothing, so it must not open forwarding either.
func TestSkippedRepublishNeverOpensForwarding19167(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	d.resetting.Store(true)
	if err := d.beginTransferPreActivation([]int{1}); err == nil {
		t.Fatal("a republish that published nothing still reported the pre-activation opened")
	}
	if got := dp.callsSnapshot(); slices.Contains(got, "ha-publish") {
		t.Fatalf("calls %v: the helper was told to open forwarding with no route republish", got)
	}
}

// #19167 fold 1: the epoch Begin returned is the one handed to Publish.
func TestPreActivationPublishCarriesTheBeginEpoch19167(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	dp.epoch = 42
	if err := d.beginTransferPreActivation([]int{1}); err != nil {
		t.Fatalf("beginTransferPreActivation: %v", err)
	}
	if dp.publishedEpoch != 42 {
		t.Fatalf("Publish got epoch %d, want the Begin epoch 42", dp.publishedEpoch)
	}
}

// retainedRoutesDP19167 is a pre-activation dataplane whose route publisher
// reports a retained-only fold: the helper is down or has no published
// snapshot, so no running helper holds the routes.
type retainedRoutesDP19167 struct {
	*fakePreActivateDP
}

func (f retainedRoutesDP19167) PublishRouteOverlaySnapshotOutcome(*config.Config, []config.RouteOverlayEntry, map[string]bool, bool) (dpuserspace.RouteOverlayOutcome, error) {
	f.recordCall("publish")
	return dpuserspace.RouteOverlayRetained, nil
}

// #19167 fold 2 (codex-d P2-1): a retained-only route publish is no evidence
// that a running helper holds the routes. The pre-activation must abort with
// no helper publish, not read it as "unchanged".
func TestRetainedRoutePublishNeverOpensForwarding19167(t *testing.T) {
	d, dp := newPreActivateDaemon18559(t)
	d.setDataplane(retainedRoutesDP19167{dp})
	if err := d.beginTransferPreActivation([]int{1}); err == nil {
		t.Fatal("a route publish that reached no helper still reported the pre-activation opened")
	}
	got := dp.callsSnapshot()
	if !slices.Contains(got, "publish") {
		t.Fatalf("setup: calls %v: the route publish never ran", got)
	}
	if slices.Contains(got, "ha-publish") {
		t.Fatalf("calls %v: the helper was told to open forwarding on routes no helper holds", got)
	}
}
