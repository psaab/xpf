package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// obsDP9725 records the observer the daemon registers on it.
type obsDP9725 struct {
	dataplane.RuntimeDataPlane

	observer func(int)
	sets     int
}

func (d *obsDP9725) SetAttachedLinksObserver(fn func(int)) {
	d.observer = fn
	d.sets++
}

// #9725: the observer follows the PUBLISHED runtime, and its lifetime is that
// runtime's. The first version of this was a package-level callback, which is
// wrong in a way that only shows with two daemons in one process: whichever
// registered last owned the single global, so one daemon's detach drove the
// other's gate and either shutdown cleared the other's hook. Registration now
// happens in setDataplane, the publish point.
func TestTheAttachedLinksObserverFollowsThePublishedRuntime9725(t *testing.T) {
	t.Run("publishing arms it and unpublishing disarms it", func(t *testing.T) {
		v4, v6, fake := seamTransitClose9686(t)
		d := &Daemon{}
		dp := &obsDP9725{}

		d.setDataplane(dp)
		if dp.observer == nil {
			t.Fatal("publishing a runtime did not register the attached-link observer, so no link change " +
				"reaches the gate and every window this issue closes is open again")
		}

		// A report of zero closes the gate on THIS daemon.
		d.dataplaneArmed.Store(true)
		d.transitWasOpen = true
		dp.observer(0)
		for i, fam := range []string{"IPv4 ip_forward", "IPv6 conf.all.forwarding"} {
			if got := readKnob9725(t, []string{v4, v6}[i]); got != "0" {
				t.Errorf("%s = %q after a report of zero attached links, want \"0\"", fam, got)
			}
		}
		if len(fake.barrierCalls) == 0 || fake.barrierCalls[len(fake.barrierCalls)-1] != "install" {
			t.Errorf("a report of zero did not install the #7191 barrier: %v", fake.barrierCalls)
		}

		d.setDataplane(nil)
		if dp.observer != nil {
			t.Errorf("unpublishing the runtime left the observer registered, so a runtime this daemon no " +
				"longer publishes can still drive its transit gate")
		}
	})

	t.Run("two daemons do not drive each other's gate", func(t *testing.T) {
		seamTransitClose9686(t)
		dA, dB := &Daemon{}, &Daemon{}
		pA, pB := &obsDP9725{}, &obsDP9725{}
		dA.setDataplane(pA)
		dB.setDataplane(pB)
		if pA.observer == nil || pB.observer == nil {
			t.Fatal("premise: both daemons must have registered on their own runtime")
		}
		dA.dataplaneArmed.Store(true)
		dB.dataplaneArmed.Store(true)
		dA.transitWasOpen, dB.transitWasOpen = true, true

		// A's runtime reports that nothing is attached.
		pA.observer(0)

		if dA.transitWasOpen {
			t.Errorf("daemon A's own report did not close A's gate")
		}
		if !dB.transitWasOpen {
			t.Errorf("#9725: daemon A's report closed daemon B's gate. The observer must belong to the runtime " +
				"the daemon PUBLISHED; a package-level callback lets the last registration win and drives the " +
				"wrong daemon's gate")
		}
	})
}
