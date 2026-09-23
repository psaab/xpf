package cli

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #8597 (muse-004 K05) — `show security flow session sort-by ...` built one
// formatted row per SESSION in the daemon process before printing twenty.
//
// The console runs in xpfd with no recover, so a busy box turned a routine
// diagnostic into a control-plane OOM. The REST side has treated a full
// conntrack walk as an admission decision since #5318 (`sessionCountCap`); the
// console path had no equivalent.

// synthSessionDP yields n synthetic v4 sessions with strictly increasing byte
// and packet counters, so the expected top-20 is exactly the last 20 offered
// and the ordering is unambiguous. Session i carries (i+1)*1000 forward bytes.
type synthSessionDP struct {
	*dataplane.Manager
	n int
}

func (d *synthSessionDP) IsLoaded() bool { return true }

func (d *synthSessionDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{}
}

func (d *synthSessionDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.n; i++ {
		key := dataplane.SessionKey{Protocol: 6}
		key.SrcIP = [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
		key.DstIP = [4]byte{10, 1, 1, 1}
		val := dataplane.SessionValue{
			FwdBytes:   uint64(i+1) * 1000,
			FwdPackets: uint64(i+1) * 10,
		}
		if !fn(key, val) {
			return nil
		}
	}
	return nil
}

func (d *synthSessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func newTopTalkerCLI(t *testing.T, n int) *CLI {
	t.Helper()
	return &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    &synthSessionDP{Manager: dataplane.New(), n: n},
	}
}

// TestTopTalkersOutputIsUnchangedByTheBound_8597 is the OVER-BROAD control, and
// the one that has to come first: a bound is worthless if it changed what the
// operator reads.
//
// It pins all three parts of the contract the old full-sort implementation had:
// the header's total counts every ADMITTED session (not the rows kept), exactly
// twenty rows print, and they are the twenty largest in descending order.
func TestTopTalkersOutputIsUnchangedByTheBound_8597(t *testing.T) {
	const n = 500
	c := newTopTalkerCLI(t, n)
	out := captureStdout(t, func() {
		if err := c.showTopTalkers(sessionFilter{sortBy: "bytes"}); err != nil {
			t.Fatalf("showTopTalkers: %v", err)
		}
	})

	if !strings.Contains(out, fmt.Sprintf("Top %d sessions by bytes (of %d total):", topTalkerLimit, n)) {
		t.Errorf("header must report the row count AND the full admitted total; got:\n%s",
			firstLine(out))
	}

	// The largest session is (n)*1000 bytes; the 20th largest is (n-19)*1000.
	// Both must appear, and the one below the cut must not.
	for _, want := range []string{
		fmt.Sprintf("%5d/", n*1000),
		fmt.Sprintf("%5d/", (n-topTalkerLimit+1)*1000),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected a row with bytes %q in:\n%s", want, out)
		}
	}
	if notWant := fmt.Sprintf("%5d/", (n-topTalkerLimit)*1000); strings.Contains(out, notWant) {
		t.Errorf("row below the cut (bytes %q) was printed; the bound must keep the LARGEST "+
			"entries, not the first or last seen", notWant)
	}

	rows := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, strings.TrimSpace(line)) && len(strings.Fields(line)) > 3 &&
			strings.Contains(line, "->") {
			rows++
		}
	}
	if rows != topTalkerLimit {
		t.Errorf("printed %d session rows, want %d", rows, topTalkerLimit)
	}
}

// TestTopTalkersSortByPacketsSelectsOnPackets_8597 covers the second sort mode.
// A single metric function now serves both, so a fix that hard-coded bytes
// would silently make `sort-by packets` a bytes sort.
func TestTopTalkersSortByPacketsSelectsOnPackets_8597(t *testing.T) {
	const n = 100
	c := newTopTalkerCLI(t, n)
	out := captureStdout(t, func() {
		if err := c.showTopTalkers(sessionFilter{sortBy: "packets"}); err != nil {
			t.Fatalf("showTopTalkers: %v", err)
		}
	})
	if !strings.Contains(out, fmt.Sprintf("Top %d sessions by packets (of %d total):", topTalkerLimit, n)) {
		t.Errorf("header wrong for sort-by packets:\n%s", firstLine(out))
	}
	if !strings.Contains(out, fmt.Sprintf("%5d/", n*10)) {
		t.Errorf("largest packet count (%d) missing from:\n%s", n*10, out)
	}
}

// TestTopTalkersAllocationDoesNotScaleWithTheTable_8597 is the RED-on-revert
// core, and it measures the property rather than describing it.
//
// Reverting to `entries = append(entries, ...)` over every session makes the
// 20k-session scan allocate roughly 200x the 100-session scan. With the bound
// the two are within a small constant of each other, because only the survivors
// are ever materialised.
//
// The assertion is a RATIO between two runs of the same code, not an absolute
// byte count, so it does not encode the current formatting cost and will not
// drift when a field is added to topTalkerEntry.
func TestTopTalkersAllocationDoesNotScaleWithTheTable_8597(t *testing.T) {
	measure := func(n int) uint64 {
		c := newTopTalkerCLI(t, n)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_ = captureStdout(t, func() {
			if err := c.showTopTalkers(sessionFilter{sortBy: "bytes"}); err != nil {
				t.Fatalf("showTopTalkers: %v", err)
			}
		})
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	small := measure(100)
	large := measure(20000)

	// A 200x larger table. Unbounded collection tracks that ratio; a bounded
	// collector's growth is the scan itself (no per-session heap allocation at
	// all beyond the closure), which is far below it. 20x leaves a wide margin
	// for the closure allocations and the measurement's own noise while still
	// being an order of magnitude below the 200x an unbounded append produces.
	if large > small*20 {
		t.Fatalf("scanning 200x more sessions allocated %d bytes vs %d (%.1fx): the "+
			"collection is still proportional to the session table, so a busy box can "+
			"OOM the control plane with a show command (#8597/K05)",
			large, small, float64(large)/float64(small))
	}
}

// TestTopTalkersAllocationProbeCanSeeUnboundedGrowth_8597 is the POSITIVE
// CONTROL for the cell above. A ratio under 20x is also what a probe that
// measures nothing returns — a mis-set fixture, an iterator that yields no
// sessions, a MemStats read on the wrong side. This builds the SAME rows the
// unbounded implementation built, at the same two sizes, and asserts the probe
// reports the growth.
func TestTopTalkersAllocationProbeCanSeeUnboundedGrowth_8597(t *testing.T) {
	measureUnbounded := func(n int) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		var entries []topTalkerEntry
		for i := 0; i < n; i++ {
			entries = append(entries, topTalkerEntry{
				src:      fmt.Sprintf("10.0.0.%d:%d", i%256, 1024+i%1000),
				dst:      fmt.Sprintf("10.1.1.1:%d", 443),
				proto:    "tcp",
				zone:     "trust->untrust",
				state:    "established",
				app:      "junos-https",
				fwdBytes: uint64(i) * 1000,
			})
		}
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(entries)
		return after.TotalAlloc - before.TotalAlloc
	}
	small := measureUnbounded(100)
	large := measureUnbounded(20000)
	if large <= small*20 {
		t.Fatalf("the allocation probe reports %d vs %d (%.1fx) for a deliberately "+
			"unbounded build at 200x the size: it cannot see the growth the cell above "+
			"asserts is absent, so that cell proves nothing",
			large, small, float64(large)/float64(small))
	}
}

// TestTopTalkerCollectorKeepsTheLargest_8597 exercises the collector directly
// over the orders that break a naive bound: ascending (every candidate evicts),
// descending (none do), and a value equal to the incumbent minimum.
func TestTopTalkerCollectorKeepsTheLargest_8597(t *testing.T) {
	offer := func(c *topTalkerCollector, v uint64) {
		c.offerV4(v, dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{FwdBytes: v})
	}
	for _, tc := range []struct {
		name  string
		order []uint64
	}{
		{"ascending", []uint64{1, 2, 3, 4, 5, 6}},
		{"descending", []uint64{6, 5, 4, 3, 2, 1}},
		{"interleaved", []uint64{3, 6, 1, 5, 2, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTopTalkerCollector(3)
			for _, v := range tc.order {
				offer(c, v)
			}
			got := c.top(sessionFilter{}, map[uint16]string{}, 0)
			if len(got) != 3 {
				t.Fatalf("kept %d entries, want 3", len(got))
			}
			for i, want := range []uint64{6, 5, 4} {
				if got[i].fwdBytes != want {
					t.Errorf("entry %d = %d, want %d (descending by metric)",
						i, got[i].fwdBytes, want)
				}
			}
			if c.total != len(tc.order) {
				t.Errorf("total = %d, want %d — the header's count is the admitted "+
					"session count, not the rows kept", c.total, len(tc.order))
			}
		})
	}
}

// TestTopTalkerScanDoesNotAllocatePerSession_8597 pins the property directly,
// at the unit level, so a regression names itself instead of showing up as a
// ratio.
//
// testing.AllocsPerRun over offerV4 must report ZERO: the candidate is a
// fixed-size value copied into an already-allocated heap slot. The first
// version of this fix deferred formatting behind a closure per candidate, which
// looks bounded and allocates the closure on every session — this cell is what
// that shape fails.
func TestTopTalkerScanDoesNotAllocatePerSession_8597(t *testing.T) {
	c := newTopTalkerCollector(topTalkerLimit)
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{FwdBytes: 1000}
	// Prime the heap to capacity so the steady-state path (compare, maybe
	// overwrite) is what is measured rather than the initial fill.
	for i := 0; i < topTalkerLimit; i++ {
		c.offerV4(uint64(i+1)*1000, key, val)
	}
	var n uint64
	allocs := testing.AllocsPerRun(200, func() {
		n++
		c.offerV4(n*1000, key, val)
	})
	if allocs != 0 {
		t.Fatalf("offerV4 allocates %.1f times per session; the scan must allocate "+
			"NOTHING per session, or the bound is only on the print (#8597/K05)", allocs)
	}
}

// TestTopTalkerMetricPicksTheRightCounters_8597: one definition of "top" serves
// both sort modes, so it has to be right for both.
func TestTopTalkerMetricPicksTheRightCounters_8597(t *testing.T) {
	if got := topTalkerMetric("bytes", 10, 5, 300, 400); got != 15 {
		t.Errorf("bytes metric = %d, want 15 (fwd+rev BYTES)", got)
	}
	if got := topTalkerMetric("packets", 10, 5, 300, 400); got != 700 {
		t.Errorf("packets metric = %d, want 700 (fwd+rev PACKETS)", got)
	}
	// Anything that is not "bytes" is the packets sort, matching the old
	// if/else. A metric that defaulted to bytes would silently change what an
	// unrecognised sort-by prints.
	if got := topTalkerMetric("", 10, 5, 300, 400); got != 700 {
		t.Errorf("default metric = %d, want the packets sum 700", got)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func TestTopTalkerZoneLabelQuarantine10530(t *testing.T) {
	id := config.StableZoneID("z174")
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {Name: "z174"},
		"z214": {Name: "z214"},
	}}}
	filter := sessionFilter{cfg: cfg, zoneName: "z214", zoneID: id}
	zoneNames := map[uint16]string{id: "z174"}
	if got := zoneLabel(filter, zoneNames, id, id); got !=
		"z174 "+config.ZoneQuarantineReferenceQualifier+"->z174 "+config.ZoneQuarantineReferenceQualifier {
		t.Fatalf("quarantined top-talker zone label = %q, want qualified survivor pair", got)
	}
	ordinary := sessionFilter{cfg: cfg, zoneName: "z174", zoneID: id}
	if got := zoneLabel(ordinary, zoneNames, id, id); got != "z174->z174" {
		t.Fatalf("ordinary top-talker zone label = %q, want unqualified pair", got)
	}
}
