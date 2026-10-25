// #3643: the gRPC TEXT surfaces (show security zones detail, show security
// screen statistics all-zones) must render an explicit "not available" for the
// HIDE'd per-zone traffic / flood counters -- distinct from a "0" block and
// distinct from a genuine read-error warning.
//
// FAIL-ON-REVERT: dropping the dataplane.ErrCounterNotPopulated branch makes
// the sentinel fall into the value path (0-count block) or the genuine-error
// warning path, so the "not available" assertions go RED.
package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// notPopulatedGRPCDP is a loaded DP whose per-zone traffic + flood reads report
// dataplane.ErrCounterNotPopulated (the #3643 HIDE state).
type notPopulatedGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *notPopulatedGRPCDP) IsLoaded() bool                          { return true }
func (d *notPopulatedGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *notPopulatedGRPCDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, dataplane.ErrCounterNotPopulated
}
func (d *notPopulatedGRPCDP) ReadFloodCounters(uint32) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, dataplane.ErrCounterNotPopulated
}

func TestShowZonesDetailTextZoneCountersNotAvailable(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &notPopulatedGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000, "dmz": 42000}},
		},
	}
	var buf strings.Builder
	s.showZonesDetail(store.ActiveConfig(), "", &buf)
	out := buf.String()
	if !strings.Contains(out, "Traffic statistics: not available") {
		t.Fatalf("zone text lacks the per-zone 'not available' marker; got:\n%s", out)
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
	if strings.Contains(out, "warning") {
		t.Fatalf("zone text raised a false counter-read warning for an unpopulated counter; got:\n%s", out)
	}
}

func TestShowScreenStatisticsAllTextFloodNotAvailable(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &notPopulatedGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000, "dmz": 42000}},
		},
	}
	var buf strings.Builder
	if _, err := s.showScreenStatisticsAll(store.ActiveConfig(), &buf); err != nil {
		t.Fatalf("showScreenStatisticsAll() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Per-zone flood counters: not available") {
		t.Fatalf("screen text lacks the per-zone flood 'not available' marker; got:\n%s", out)
	}
	// #3651 (the #6843 M3 lesson, applied to the flood half on the gRPC text
	// surface too): bind the CAUSE clause, not just the invariant prefix.
	// "not implemented in the userspace dataplane" was accurate under the #3643
	// HIDE and is now actively wrong -- #3651 shipped per-zone flood accounting.
	if !strings.Contains(out, "no per-zone flood counts published for this zone") {
		t.Errorf("the unavailable line must name the CAUSE (nothing published for "+
			"this zone), not just report unavailability:\n%s", out)
	}
	if strings.Contains(out, "not implemented") {
		t.Errorf("the unavailable line still claims per-zone flood accounting is not "+
			"implemented; #3651 shipped it, so this names the wrong cause:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("screen text raised a false flood counter-read warning; got:\n%s", out)
	}
}

// populatedFloodGRPCDP is a loaded DP whose per-zone flood read reports live
// counts -- the #3651 POPULATE state.
type populatedFloodGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
	rows  map[uint32]dataplane.FloodState
}

func (d *populatedFloodGRPCDP) IsLoaded() bool                          { return true }
func (d *populatedFloodGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *populatedFloodGRPCDP) ReadFloodCounters(id uint32) (dataplane.FloodState, error) {
	fs, ok := d.rows[id]
	if !ok {
		return dataplane.FloodState{}, dataplane.ErrCounterNotPopulated
	}
	return fs, nil
}

// #3651: the SINGLE-ZONE gRPC screen-statistics path has its own
// ErrCounterNotPopulated branch and its own render, distinct from the all-zones
// loop above. Cover both of its arms: the unavailable line names the CAUSE, and
// a published zone renders live counts.
func TestShowScreenStatisticsSingleZoneTextFlood(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	apply := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000, "dmz": 42000}}

	t.Run("unpopulated", func(t *testing.T) {
		s := &Server{store: store, dp: &notPopulatedGRPCDP{Manager: dataplane.New(), apply: apply}}
		var buf strings.Builder
		if _, err := s.showScreenStatistics(
			&pb.ShowTextRequest{Topic: "screen-statistics:trust"}, store.ActiveConfig(), &buf,
		); err != nil {
			t.Fatalf("showScreenStatistics() error = %v", err)
		}
		out := buf.String()
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
		s := &Server{store: store, dp: &populatedFloodGRPCDP{
			Manager: dataplane.New(),
			apply:   apply,
			rows:    map[uint32]dataplane.FloodState{40000: {SynCount: 11, ICMPCount: 22, UDPCount: 33}},
		}}
		var buf strings.Builder
		if _, err := s.showScreenStatistics(
			&pb.ShowTextRequest{Topic: "screen-statistics:trust"}, store.ActiveConfig(), &buf,
		); err != nil {
			t.Fatalf("showScreenStatistics() error = %v", err)
		}
		out := buf.String()
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
