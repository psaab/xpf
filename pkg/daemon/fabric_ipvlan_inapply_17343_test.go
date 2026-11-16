package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #17343: the fabric overlay's "deferral until the XSK bind" has not deferred
// since dcc59c67df commented out its `continue`. With the userspace dataplane
// active and the bind not yet notified, applyFabricIPVLAN removes any existing
// overlay and then creates it IN THE APPLY through fabricEnsureFn, so its
// failure is joined into the commit; the OnXSKBound callback only re-ensures it
// afterwards. These cells pin that behaviour, which the docs now describe.

// fakeXSKBindingDP17343 is a userspace dataplane whose XSK bind has not been
// notified. The embedded interface is nil: applyFabricIPVLAN only type-asserts
// the dataplane to userspaceXSKBindingController, so no other method is called.
type fakeXSKBindingDP17343 struct {
	dataplane.RuntimeDataPlane
	onBound func()
}

func (f *fakeXSKBindingDP17343) XSKBoundNotified() bool  { return false }
func (f *fakeXSKBindingDP17343) SetOnXSKBound(fn func()) { f.onBound = fn }

// daemonBeforeXSKBind17343 publishes the fake directly into the dataplane cell:
// setDataplane would also register runtime observers, which type-assert the
// dataplane and would call methods on the nil embedded interface.
func daemonBeforeXSKBind17343() (*Daemon, *fakeXSKBindingDP17343) {
	dp := &fakeXSKBindingDP17343{}
	d := &Daemon{}
	d.dpCell.Store(&dpSlot{v: dp})
	return d, dp
}

func TestApplyFabricIPVLANCreatesInApplyBeforeXSKBind_17343(t *testing.T) {
	var calls []string
	withFabricEnsure(t, func(parent, name string, addrs []string) error {
		calls = append(calls, parent+"/"+name)
		return nil
	})
	d, dp := daemonBeforeXSKBind17343()
	if _, ok := d.dataplane().(userspaceXSKBindingController); !ok {
		t.Fatal("the fake is not a userspaceXSKBindingController; this cell would not reach the pre-bind branch")
	}

	if err := d.applyFabricIPVLAN(fabricCfg6791()); err != nil {
		t.Fatalf("applyFabricIPVLAN returned %v on a healthy pre-bind apply", err)
	}
	if len(calls) != 1 {
		t.Fatalf("fabricEnsureFn ran %d times in the pre-bind apply (%v), want exactly 1: "+
			"the overlay is created in the apply, not deferred to OnXSKBound", len(calls), calls)
	}
	if dp.onBound == nil {
		t.Fatal("no OnXSKBound callback registered: the post-bind re-ensure is gone")
	}
}

func TestApplyFabricIPVLANReportsPreBindFailureToTheCommit_17343(t *testing.T) {
	prev := fabricIPVLANRetryDelay
	fabricIPVLANRetryDelay = time.Millisecond
	t.Cleanup(func() { fabricIPVLANRetryDelay = prev })
	boom := errors.New("no such device")
	withFabricEnsure(t, func(parent, name string, addrs []string) error { return boom })
	d, _ := daemonBeforeXSKBind17343()

	err := d.applyFabricIPVLAN(fabricCfg6791())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "fab0") {
		t.Fatalf("applyFabricIPVLAN returned %v before the XSK bind; a failed in-apply "+
			"creation must reach the commit, naming fab0", err)
	}
}
