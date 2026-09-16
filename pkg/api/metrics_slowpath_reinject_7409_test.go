package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7409 — the slow-path reinject counters must be exported, and must be
// exported UNCONDITIONALLY.
//
// All four have been on the BindingStatus wire since the helper gained them
// and are already delta-tracked in pkg/monitoriface, but nothing exported them
// to Prometheus. That is what made the bypass unobservable in production: the
// affected traffic is forwarded by the kernel with no zone policy, session,
// NAT or screen, and the only counter that moved was one nobody could alert on.

func slowPathTestCollector() *xpfCollector {
	c := &xpfCollector{}
	c.initBindingDescriptors()
	return c
}

func collectSlowPathSeries(t *testing.T, c *xpfCollector, status dpuserspace.ProcessStatus) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingSlowPathReinjectCounters(ch, status)
		close(ch)
	}()
	out := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		name := m.Desc().String()
		for _, want := range []string{
			"slow_path_no_route_packets_total",
			"slow_path_next_table_packets_total",
			"slow_path_local_delivery_packets_total",
			"slow_path_missing_neighbor_packets_total",
			// #6664. Note this one makes the quoted-fqName anchoring below
			// load-bearing rather than merely careful: the RETIRED
			// slow_path_next_table_packets HELP now names
			// xpf_userspace_binding_next_table_unsupported_drops_total in
			// prose, to point operators at its replacement. A bare
			// strings.Contains on the metric name would match that HELP and
			// attribute the retired series' value to this one.
			"next_table_unsupported_drops_total",
			// #9752: the installing-table-unresolvable fail-closed drop.
			"table_unavailable_drops_total",
			// #9752 round 5: the fast-path observation count.
			"table_unavailable_packets_total",
		} {
			// Desc.String() embeds the HELP text as well as the fqName, and
			// several of these help strings cross-reference the other
			// reasons — so a bare Contains would misattribute a series.
			// Anchor on the quoted fqName the Desc renders.
			if strings.Contains(name, `fqName: "xpf_userspace_binding_`+want+`"`) {
				out[want] = pb.GetCounter().GetValue()
			}
		}
	}
	return out
}

// A ZERO MUST BE A REAL DATAPOINT. An absent series cannot be alerted on, and
// alerting on this is the entire point of exporting it — a reinject rate that
// rises from nothing is exactly the signal an operator needs, and it is
// invisible if the series only appears once it is already non-zero.
//
// RED on revert: guard the emission behind `if b.SlowPath...Packets > 0`.
func TestSlowPathReinjectCountersAreEmittedEvenWhenZero(t *testing.T) {
	c := slowPathTestCollector()
	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{{
			Slot: 2, QueueID: 5, WorkerID: 7, Interface: "ge-0-0-1",
			// every counter deliberately left at its zero value
		}},
	}

	got := collectSlowPathSeries(t, c, status)
	// #6664: five now — the four #7409 reinject series plus the next_table
	// fail-closed drop. #9752: six — plus the installing-table-unresolvable
	// fail-closed drop. The zero-datapoint property matters MORE for the drops
	// than for the reinjects: both drops' steady state is legitimately 0 and
	// the series would otherwise never appear until the defect already existed.
	if len(got) != 7 {
		t.Fatalf("want all 7 slow-path allow-list series present at zero, got %d: %v", len(got), got)
	}
	for name, v := range got {
		if v != 0 {
			t.Errorf("%s = %v, want 0", name, v)
		}
	}
}

// The values must reach the right series. A transposition here would point an
// operator at the wrong disposition — and only `no_route` is the policy-bypass
// signal, so confusing it with `local_delivery` (which IS gated, by the
// host-inbound plane) would invert the conclusion.
func TestSlowPathReinjectCountersMapToTheCorrectSeries(t *testing.T) {
	c := slowPathTestCollector()
	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{{
			Slot: 1, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-2",
			SlowPathNoRoutePackets:         11,
			SlowPathNextTablePackets:       22,
			SlowPathLocalDeliveryPackets:   33,
			SlowPathMissingNeighborPackets: 44,
			NextTableUnsupportedDrops:      55,
			TableUnavailableDrops:          66,
			TableUnavailablePackets:        77,
		}},
	}

	got := collectSlowPathSeries(t, c, status)
	for name, want := range map[string]float64{
		"slow_path_no_route_packets_total":         11,
		"slow_path_next_table_packets_total":       22,
		"slow_path_local_delivery_packets_total":   33,
		"slow_path_missing_neighbor_packets_total": 44,
		// #6664: the fail-closed drop that replaced the next_table reinject.
		// Asserted by VALUE, not just present in the series count below, so a
		// wiring that emitted the wrong field cannot pass.
		"next_table_unsupported_drops_total": 55,
		// #9752: the installing-table-unresolvable fail-closed drop.
		// Asserted by VALUE for the same reason as #6664 above.
		"table_unavailable_drops_total": 66,
		// #9752 round 5: the fast-path observation count (superset of the
		// drops above). Asserted by VALUE for the same reason.
		"table_unavailable_packets_total": 77,
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
}

// Every binding reports independently: a single hot worker reinjecting must
// not be averaged away by quiet siblings.
func TestSlowPathReinjectCountersAreEmittedPerBinding(t *testing.T) {
	c := slowPathTestCollector()
	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-1", SlowPathNoRoutePackets: 5},
			{Slot: 1, QueueID: 1, WorkerID: 1, Interface: "ge-0-0-2", SlowPathNoRoutePackets: 7},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingSlowPathReinjectCounters(ch, status)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	// #6664 made this five: the four #7409 reinject counters plus the
	// next_table fail-closed drop that replaced one of them. #9752 makes it
	// six: plus the installing-table-unresolvable fail-closed drop.
	if n != 14 {
		t.Fatalf("want 7 series x 2 bindings = 14 metrics, got %d", n)
	}
}
