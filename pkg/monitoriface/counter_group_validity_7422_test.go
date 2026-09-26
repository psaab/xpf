package monitoriface

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// #7422 row 10: a counter group whose read FAILED must not render as zeros an
// operator reads as a measurement.
//
// THE DEFECT was an asymmetry inside one function. `snapshotInterface` reads
// three groups; the userspace one already set `StatusNote` on failure, while
// the dataplane counters and the kernel link statistics were each
// `if err == nil { ... }` with NO else. A failed read left the fields at their
// zero value, and the renderer printed 0 — indistinguishable from a genuinely
// idle, error-free interface. On the Error statistics block that is the worse
// direction: it reads as a healthy link.
//
// TWO NOTES, NOT ONE, and that is the row's actual point. The two groups come
// from different sources — the dataplane's own counters and the kernel's link
// stats. A single validity signal spanning both would report "counters
// unavailable" when only one source failed, which is the epoch-mixing this row
// exists to flag, reproduced inside the fix.
func TestCounterGroupValidityIsPerGroup7422(t *testing.T) {
	base := func() *Snapshot {
		return &Snapshot{Timestamp: time.Now()}
	}

	t.Run("dataplane note annotates traffic only", func(t *testing.T) {
		snap := base()
		snap.DataplaneCountersNote = "map read failed"
		out := render7422(t, snap)
		if !strings.Contains(out, "dataplane counters unavailable") {
			t.Error("the traffic block must say its source failed; a rendered 0 is " +
				"otherwise read as an idle interface")
		}
		if strings.Contains(out, "kernel link statistics unavailable") {
			t.Error("the KERNEL group read fine — annotating it too is the " +
				"epoch-mixing this row exists to flag")
		}
	})

	t.Run("kernel note annotates errors only", func(t *testing.T) {
		snap := base()
		snap.KernelStatsNote = "Link not found"
		out := render7422(t, snap)
		if !strings.Contains(out, "kernel link statistics unavailable") {
			t.Error("the error block must say its source failed; zeros there read " +
				"as a healthy link")
		}
		if strings.Contains(out, "dataplane counters unavailable") {
			t.Error("the DATAPLANE group read fine — one note for both misreports it")
		}
	})

	t.Run("both notes render independently", func(t *testing.T) {
		snap := base()
		snap.DataplaneCountersNote = "map read failed"
		snap.KernelStatsNote = "Link not found"
		out := render7422(t, snap)
		if !strings.Contains(out, "dataplane counters unavailable") ||
			!strings.Contains(out, "kernel link statistics unavailable") {
			t.Error("both groups failed; both must say so")
		}
	})

	// THE CONTROL, and it is the row that keeps the fix from being "always
	// print a warning". A healthy snapshot must render no note at all — an
	// unconditional annotation would satisfy every assertion above while making
	// every normal `show interfaces` output claim a failure.
	t.Run("healthy snapshot renders no note", func(t *testing.T) {
		out := render7422(t, base())
		if strings.Contains(out, "unavailable") {
			t.Errorf("a snapshot with both reads OK must carry no validity note; got:\n%s", out)
		}
	})
}

func render7422(t *testing.T, snap *Snapshot) string {
	t.Helper()
	var buf bytes.Buffer
	RenderSingleInterface(&buf, "host", "ge-0/0/0", "ge-0-0-0", snap, nil, nil, time.Now(), "")
	return buf.String()
}
