package monitoriface

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// #10839 follow-up: a reset inside the prev→snap window poisons the
// baseline→snap window even when snap still exceeds the baseline value.
// baseline=5, prev=100, snap=10 must render the baseline delta n/a (not 5),
// rebaseline to 10, and measure honestly on the next tick.
func TestWindowResetPoisonsBaselineDelta10839(t *testing.T) {
	baseline := &Snapshot{RxBytes: 5, Timestamp: time.Now().Add(-20 * time.Second)}
	prev := &Snapshot{RxBytes: 100, Timestamp: time.Now().Add(-10 * time.Second)}
	snap := &Snapshot{RxBytes: 10, Timestamp: time.Now()}

	deltas := snapshotTrafficDeltas(snap, baseline)
	if deltas.rxBytesReset {
		t.Fatal("baseline delta unexpectedly flagged 10 vs baseline 5 without propagation")
	}
	rebaselineInterfaceTrafficCounters(snap, prev, baseline, &deltas)
	if !deltas.rxBytesReset {
		t.Fatal("window reset did not propagate to the baseline delta")
	}
	if baseline.RxBytes != 10 {
		t.Fatalf("baseline RxBytes = %d, want 10 (rebaselined to the new series)", baseline.RxBytes)
	}

	// Next tick measures from the new series: no reset, honest delta.
	next := &Snapshot{RxBytes: 25, Timestamp: time.Now().Add(10 * time.Second)}
	nextDeltas := snapshotTrafficDeltas(next, baseline)
	rebaselineInterfaceTrafficCounters(next, snap, baseline, &nextDeltas)
	if nextDeltas.rxBytesReset || nextDeltas.rxBytes != 15 {
		t.Fatalf("post-reset baseline delta = (%d, reset=%v), want (15, false)",
			nextDeltas.rxBytes, nextDeltas.rxBytesReset)
	}

	var frame bytes.Buffer
	RenderSingleInterface(&frame, "host", "eth0", "eth0", snap, prev,
		&Snapshot{RxBytes: 5, Timestamp: baseline.Timestamp}, time.Now(), "")
	if !strings.Contains(frame.String(), "n/a") {
		t.Fatalf("rendered frame hid the poisoned baseline delta:\n%s", frame.String())
	}
}

// The traffic rebaseline must not touch the userspace baseline: the detail
// rows own it via deltaU64Rebase and must still see the pre-reset values when
// they run later in the same render. A kernel reset especially must not erase
// userspace history.
func TestTrafficRebaselineLeavesUserspaceBaselineAlone10839(t *testing.T) {
	userspace := &UserspaceSnapshot{RxBytes: 1000, TxBytes: 2000}
	baseline := &Snapshot{RxBytes: 5, Userspace: userspace}
	prev := &Snapshot{RxBytes: 100}
	snap := &Snapshot{RxBytes: 10, Userspace: &UserspaceSnapshot{RxBytes: 1010, TxBytes: 2010}}

	deltas := snapshotTrafficDeltas(snap, baseline)
	rebaselineInterfaceTrafficCounters(snap, prev, baseline, &deltas)
	if !deltas.rxBytesReset {
		t.Fatal("kernel window reset did not propagate")
	}
	if baseline.Userspace != userspace {
		t.Fatal("traffic rebaseline replaced the userspace baseline pointer")
	}
	if userspace.RxBytes != 1000 || userspace.TxBytes != 2000 {
		t.Fatalf("traffic rebaseline mutated userspace history: %+v", userspace)
	}
}
