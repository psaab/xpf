package api

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Slow-path reinject telemetry (#7409).
//
// Split out of metrics_userspace.go rather than appended to it: that file was
// at 1964 LOC and this emitter would have carried it across the 2000-LOC
// modularity floor (docs/engineering-style.md). The emitter is self-contained
// — one status field group, one label set — so it is a clean seam rather than
// an arbitrary cut.
// emitBindingSlowPathReinjectCounters exports the per-binding slow-path
// reinject counters, split by the disposition that sent the frame to the
// kernel (#7409).
//
// #6664 added a FIFTH series that is not a reinject: NextTableUnsupported left
// the slow-path allow-list, so it is now dropped fail-closed and counted as
// `next_table_unsupported_drops`. It is emitted here, beside the four, because
// it is the same question — what did the slow-path allow-list do with this
// frame — on the same label set, and because it is the REPLACEMENT signal for
// `slow_path_next_table_packets`, which is frozen from #6664 onward. Splitting
// it into its own emitter would put the before and after of one migration in
// two places. The function keeps its historical `Reinject` name; that name is
// now a slight over-narrowing rather than a description, and is left alone only
// because renaming it ripples into a #7409-named test file for no behavioural
// gain. Naming it here so the drift is recorded rather than silent.
//
// The four reinject counters have been on the BindingStatus wire since the helper gained them
// and are already aggregated with deltas in pkg/monitoriface, but nothing
// exported them to Prometheus — so a rising reinject rate was visible only in
// `show`-style status output and reached no alerting. That is what made the
// #7409 policy bypass unobservable in production even once you knew to look
// for it: the affected traffic is forwarded by the kernel with no policy,
// session, NAT or screen, and the only counter that moves is one nobody can
// alert on.
//
// Emitted UNCONDITIONALLY per binding, matching emitBindingVMinThrottleCounters:
// a 0 must be a real "nothing was reinjected for this reason" datapoint, not an
// absent series. An absent series cannot be alerted on, and alerting on this is
// the entire point.
func (c *xpfCollector) emitBindingSlowPathReinjectCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		for _, m := range []struct {
			desc  *prometheus.Desc
			value uint64
		}{
			{c.bindingSlowPathNoRoutePackets, b.SlowPathNoRoutePackets},
			{c.bindingSlowPathNextTablePackets, b.SlowPathNextTablePackets},
			{c.bindingNextTableUnsupportedDrops, b.NextTableUnsupportedDrops},
			{c.bindingTableUnavailableDrops, b.TableUnavailableDrops},
			{c.bindingTableUnavailablePackets, b.TableUnavailablePackets},
			{c.bindingSlowPathLocalDeliveryPackets, b.SlowPathLocalDeliveryPackets},
			{c.bindingSlowPathMissingNeighborPackets, b.SlowPathMissingNeighborPackets},
		} {
			ch <- prometheus.MustNewConstMetric(
				m.desc,
				prometheus.CounterValue,
				float64(m.value),
				slot, queueID, workerID, b.Interface,
			)
		}
	}
}
