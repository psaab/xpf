package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// notPopulatedCLIDP is a loaded DP whose per-zone traffic + flood reads report
// dataplane.ErrCounterNotPopulated -- the #3643 HIDE state (the userspace
// dataplane does not source per-zone/flood counters).
type notPopulatedCLIDP struct {
	dataplane.DataPlane
	apply *dataplane.ApplyResult
}

func (d *notPopulatedCLIDP) IsLoaded() bool                          { return true }
func (d *notPopulatedCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *notPopulatedCLIDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, dataplane.ErrCounterNotPopulated
}
func (d *notPopulatedCLIDP) ReadFloodCounters(uint32) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, dataplane.ErrCounterNotPopulated
}

// TestShowZonesDisplayZoneCountersNotAvailable is the #3643 CLI HIDE pin for
// `show security zones`: an unpopulated per-zone read renders an explicit "not
// available" line, NOT a "0 packets, 0 bytes" block and NOT a read-error
// warning.
//
// FAIL-ON-REVERT: dropping the ErrCounterNotPopulated branch makes the display
// print "Traffic statistics:" with a 0/0 block (the sentinel falls into the
// value path) or a counter-read warning, so the "not available" assertion goes
// RED.
func TestShowZonesDisplayZoneCountersNotAvailable(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // trust + untrust zones
	c := &CLI{store: store, dp: &notPopulatedCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000}},
	}}

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(store.ActiveConfig(), false, ""); err != nil {
			t.Fatalf("showZonesDisplay() error = %v", err)
		}
	})
	if !strings.Contains(out, "Traffic statistics: not available") {
		t.Fatalf("show security zones lacks the per-zone 'not available' marker; got:\n%s", out)
	}

	// #6843 M3: bind the CAUSE clause, not just the invariant prefix. Reverting
	// the parenthetical to the pre-#6843 "(per-zone accounting not implemented
	// in the userspace dataplane)" left both packages green, because the only
	// assertion matched "Traffic statistics: not available". That wording is now
	// actively wrong -- #3651 shipped per-zone accounting -- and with 64+ zones
	// one command prints real byte counts for slotted zones and "not
	// implemented" for overflowed ones, sending the operator after a feature gap
	// that does not exist. Assert the reason, and assert the retracted claim is
	// absent.
	if !strings.Contains(out, "no per-zone volume published for this zone") {
		t.Errorf("the unavailable line must name the CAUSE (nothing published "+
			"for this zone), not just report unavailability:\n%s", out)
	}
	if strings.Contains(out, "not implemented") {
		t.Errorf("the unavailable line still claims per-zone accounting is not "+
			"implemented; #3651 shipped it, so this names the wrong cause:\n%s", out)
	}
	if strings.Contains(out, "0 packets, 0 bytes") {
		t.Fatalf("show security zones printed a misleading 0/0 per-zone block; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("show security zones raised a false counter-read warning for an unpopulated counter; got:\n%s", out)
	}
}

// TestShowScreenStatisticsAllFloodNotAvailable is the #3643 CLI HIDE pin for
// `show security screen ids-option statistics`: an unpopulated per-zone flood
// read renders "not available", NOT "SYN flood events 0" and NOT the #3408
// aggregate read-error warning.
func TestShowScreenStatisticsAllFloodNotAvailable(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true)
	c := &CLI{store: store, dp: &notPopulatedCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000}},
	}}

	out := captureStdout(t, func() {
		if err := c.showScreenStatisticsAll(); err != nil {
			t.Fatalf("showScreenStatisticsAll() error = %v", err)
		}
	})
	if !strings.Contains(out, "Per-zone flood counters: not available") {
		t.Fatalf("screen statistics lacks the per-zone flood 'not available' marker; got:\n%s", out)
	}

	// #3651 (the #6843 M3 lesson, applied to the flood half): bind the CAUSE
	// clause, not just the invariant prefix. "not implemented in the userspace
	// dataplane" was accurate under the #3643 HIDE and is now actively wrong --
	// #3651 shipped per-zone flood accounting -- and with 64+ zones one command
	// prints real flood counts for slotted zones and "not implemented" for
	// overflowed ones, sending the operator after a feature gap that does not
	// exist. Assert the reason, and assert the retracted claim is absent.
	if !strings.Contains(out, "no per-zone flood counts published for this zone") {
		t.Errorf("the unavailable line must name the CAUSE (nothing published for "+
			"this zone), not just report unavailability:\n%s", out)
	}
	if strings.Contains(out, "not implemented") {
		t.Errorf("the unavailable line still claims per-zone flood accounting is not "+
			"implemented; #3651 shipped it, so this names the wrong cause:\n%s", out)
	}
	if strings.Contains(out, "SYN flood events") {
		t.Fatalf("screen statistics printed a misleading flood-event 0 block; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("screen statistics raised a false flood counter-read warning; got:\n%s", out)
	}
}

// populatedFloodCLIDP is a loaded DP whose per-zone flood read reports live
// counts -- the #3651 POPULATE state.
type populatedFloodCLIDP struct {
	dataplane.DataPlane
	apply *dataplane.ApplyResult
	rows  map[uint32]dataplane.FloodState
}

func (d *populatedFloodCLIDP) IsLoaded() bool                          { return true }
func (d *populatedFloodCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *populatedFloodCLIDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, dataplane.ErrCounterNotPopulated
}
func (d *populatedFloodCLIDP) ReadFloodCounters(id uint32) (dataplane.FloodState, error) {
	fs, ok := d.rows[id]
	if !ok {
		return dataplane.FloodState{}, dataplane.ErrCounterNotPopulated
	}
	return fs, nil
}

// TestShowScreenStatisticsAllFloodPopulatedRendersLiveCounts is the #3651
// consumer-surface pin: once the dataplane publishes per-zone flood counts, the
// SAME command that renders "not available" above must render the real numbers
// for a published zone -- and must STILL degrade to "not available" for a zone
// the dataplane did not publish, in the very same output.
//
// The mixed fixture is the point: a single-state fixture could not distinguish
// "renders live counts" from "renders whatever it was given".
func TestShowScreenStatisticsAllFloodPopulatedRendersLiveCounts(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // trust + untrust zones
	c := &CLI{store: store, dp: &populatedFloodCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000}},
		// trust publishes; untrust does NOT (it lost its hot-path slot, or has
		// never tripped a flood check).
		rows: map[uint32]dataplane.FloodState{
			40000: {SynCount: 11, ICMPCount: 22, UDPCount: 33},
		},
	}}

	out := captureStdout(t, func() {
		if err := c.showScreenStatisticsAll(); err != nil {
			t.Fatalf("showScreenStatisticsAll() error = %v", err)
		}
	})

	// Three DISTINCT values so a renderer that crossed two families cannot pass.
	for _, want := range []string{
		"SYN flood events",
		"11",
		"ICMP flood events",
		"22",
		"UDP flood events",
		"33",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("a published zone must render live flood counts; missing %q in:\n%s", want, out)
		}
	}
	// And the unpublished zone still degrades honestly in the same output.
	if !strings.Contains(out, "Per-zone flood counters: not available") {
		t.Fatalf("a zone the dataplane did not publish must still render "+
			"'not available' alongside the populated one; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("a mix of populated and unpopulated zones must not raise a "+
			"counter-read warning; got:\n%s", out)
	}
}

// TestShowScreenStatisticsSingleZoneFlood covers the SINGLE-ZONE CLI path,
// which has its own ErrCounterNotPopulated branch and its own render distinct
// from the all-zones loop. Both arms: the unavailable line names the CAUSE, and
// a published zone renders live counts.
func TestShowScreenStatisticsSingleZoneFlood(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // trust + untrust zones
	apply := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000}}

	t.Run("unpopulated", func(t *testing.T) {
		c := &CLI{store: store, dp: &notPopulatedCLIDP{apply: apply}}
		out := captureStdout(t, func() {
			if err := c.showScreenStatistics("trust"); err != nil {
				t.Fatalf("showScreenStatistics() error = %v", err)
			}
		})
		if !strings.Contains(out, "no per-zone flood counts published for this zone") {
			t.Errorf("the single-zone unavailable line must name the CAUSE:\n%s", out)
		}
		if strings.Contains(out, "not implemented") {
			t.Errorf("the single-zone unavailable line names the wrong cause:\n%s", out)
		}
		if strings.Contains(out, "SYN flood events") {
			t.Errorf("single-zone printed a misleading flood-event 0 block:\n%s", out)
		}
	})

	t.Run("populated", func(t *testing.T) {
		c := &CLI{store: store, dp: &populatedFloodCLIDP{
			apply: apply,
			rows:  map[uint32]dataplane.FloodState{40000: {SynCount: 11, ICMPCount: 22, UDPCount: 33}},
		}}
		out := captureStdout(t, func() {
			if err := c.showScreenStatistics("trust"); err != nil {
				t.Fatalf("showScreenStatistics() error = %v", err)
			}
		})
		// Three DISTINCT values so a renderer that crossed two families fails.
		for _, want := range []string{"SYN flood events", "11", "ICMP flood events", "22", "UDP flood events", "33"} {
			if !strings.Contains(out, want) {
				t.Fatalf("a published zone must render live flood counts; missing %q in:\n%s", want, out)
			}
		}
		if strings.Contains(out, "not available") {
			t.Errorf("a published zone must not also render 'not available':\n%s", out)
		}
	})
}
