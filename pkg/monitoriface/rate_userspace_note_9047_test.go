package monitoriface

import (
	"testing"
	"time"
)

func snap9047(withUserspace bool, rxB, rxP uint64) *Snapshot {
	s := &Snapshot{RxBytes: rxB, RxPkts: rxP, Timestamp: time.Now()}
	if withUserspace {
		s.Userspace = &UserspaceSnapshot{
			Bindings: 1, RxBytes: rxB, RxPackets: rxP, TxBytes: rxB, TxPackets: rxP,
		}
	} else {
		// The shape the failed-status path produces: a struct carrying only a
		// note, with no bindings and no counters, so the gate declines.
		s.Userspace = &UserspaceSnapshot{StatusNote: "status read failed"}
	}
	return s
}

// #9047: when the previous sample has no userspace source, the userspace
// component is correctly dropped from the RATE — cumulative counters mean
// treating it as zero would render a spike that never happened — but the drop
// must be REPORTED, because the same render's TOTAL includes it.
func TestRateReportsDroppedUserspaceComponent9047(t *testing.T) {
	prev := snap9047(false, 100, 10)
	curr := snap9047(true, 500, 50)

	deltas := snapshotTrafficDeltas(curr, prev)
	if !deltas.userspaceDropped {
		t.Error("#9047: the userspace component was dropped from the rate and NOT reported. " +
			"The total beside it includes userspace, so the operator sees a rate that " +
			"under-reports forwarding with no indication — the 'silently render 0' shape " +
			"#7422 row 10 fixed for this group's siblings.")
	}
}

// The rate is still CORRECT to exclude it: the counters are cumulative, so
// folding a missing side in as zero attributes the whole cumulative to one
// window. This pins that the fix did NOT do that.
func TestDroppedComponentIsNotFoldedInAsZero9047(t *testing.T) {
	prev := snap9047(false, 100, 10)
	curr := snap9047(true, 500, 50)
	deltas := snapshotTrafficDeltas(curr, prev)
	if deltas.rxBytes != 400 {
		t.Errorf("#9047: rx byte delta = %d, want 400 (kernel only). Including the userspace "+
			"cumulative would attribute the helper's entire lifetime to this one window and "+
			"render a spike that never happened.", deltas.rxBytes)
	}
}

// NO NOTE when both samples have a source: the note must mark a real gap, not
// appear on every window.
func TestNoNoteWhenBothSamplesHaveUserspace9047(t *testing.T) {
	prev := snap9047(true, 100, 10)
	curr := snap9047(true, 500, 50)
	deltas := snapshotTrafficDeltas(curr, prev)
	if deltas.userspaceDropped {
		t.Error("#9047: reported a dropped component when both samples had one")
	}
	if deltas.rxBytes != 800 {
		t.Errorf("#9047: rx byte delta = %d, want 800 (400 kernel + 400 userspace)", deltas.rxBytes)
	}
}

// AND NO NOTE ON A KERNEL-ONLY INTERFACE. Reporting whenever the gate declines
// would put a permanent note on every interface that has no userspace source at
// all — a note that fires always is a note operators learn to skip, which
// disarms it for the window that matters.
func TestNoNoteWhenTheInterfaceHasNoUserspaceAtAll9047(t *testing.T) {
	prev := snap9047(false, 100, 10)
	curr := snap9047(false, 500, 50)
	if snapshotTrafficDeltas(curr, prev).userspaceDropped {
		t.Error("#9047: a kernel-only interface reported a dropped userspace component. " +
			"It never had one to drop, and a note on every window is one nobody reads.")
	}
}
