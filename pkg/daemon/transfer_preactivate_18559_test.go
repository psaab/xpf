package daemon

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// #18559: the daemon half of the make-before-break transfer. The route
// republish must run BETWEEN the mark and the helper publish — the #16270
// order the promotion path keeps — or the first fabric-redirected packet on the
// newly opened RG resolves to the cluster terminal and is discarded.

type fakePreActivateDP struct {
	*fakeOverlayDP
	publishErr error
	reverted   bool
	marked     []int
}

func (f *fakePreActivateDP) BeginTransferPreActivation(rgIDs []int, until time.Time) {
	f.marked = append([]int(nil), rgIDs...)
	f.recordCall("mark")
	if time.Until(until) <= 0 || time.Until(until) > transferPreActivateTTL {
		f.recordCall("bad-deadline")
	}
}

func (f *fakePreActivateDP) PublishTransferPreActivation() error {
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
