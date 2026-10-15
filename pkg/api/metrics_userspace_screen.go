package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitUserspaceScreenStateMetrics publishes worker-local ScreenState counters
// carried on BindingStatus. Rust assigns each worker's counters to one binding
// as a transport slot; summing all bindings therefore emits process-wide
// counters without implying per-binding attribution.
func (c *xpfCollector) emitUserspaceScreenStateMetrics(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	var substitutedDefaultDrops, synFloodDstDrops, synFloodSrcDrops uint64
	var synFloodAlarmEvents, alarmWithoutDropEvents uint64
	var missingProfileWarns, inertProfileWarns uint64
	var scanSweepSkippedPressure, scanSweepEvictedPressure uint64
	for _, b := range status.Bindings {
		substitutedDefaultDrops += b.ScreenSubstitutedDefaultDrops
		synFloodDstDrops += b.ScreenSYNFloodDstDrops
		synFloodSrcDrops += b.ScreenSYNFloodSrcDrops
		synFloodAlarmEvents += b.ScreenSYNFloodAlarmEvents
		alarmWithoutDropEvents += b.ScreenAlarmWithoutDropEvents
		missingProfileWarns += b.ScreenMissingProfileWarns
		inertProfileWarns += b.ScreenInertProfileWarns
		scanSweepSkippedPressure += b.ScreenScanSweepSkippedPressure
		scanSweepEvictedPressure += b.ScreenScanSweepEvictedPressure
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenSubstitutedDefaultDrops, prometheus.CounterValue, float64(substitutedDefaultDrops))
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenSYNFloodDstDrops, prometheus.CounterValue, float64(synFloodDstDrops))
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenSYNFloodSrcDrops, prometheus.CounterValue, float64(synFloodSrcDrops))
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenSYNFloodAlarmEvents, prometheus.CounterValue, float64(synFloodAlarmEvents))
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenAlarmWithoutDropEvents, prometheus.CounterValue, float64(alarmWithoutDropEvents))
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenProfileWarns, prometheus.CounterValue, float64(missingProfileWarns), "missing")
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenProfileWarns, prometheus.CounterValue, float64(inertProfileWarns), "inert")
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenTrackerPressureEvents, prometheus.CounterValue, float64(scanSweepSkippedPressure), "skipped")
	ch <- prometheus.MustNewConstMetric(c.userspaceScreenTrackerPressureEvents, prometheus.CounterValue, float64(scanSweepEvictedPressure), "evicted")
}
