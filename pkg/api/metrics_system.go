package api

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *xpfCollector) collectDHCPMetrics(ch chan<- prometheus.Metric) {
	if c.srv.dhcp == nil {
		return
	}
	leases := c.srv.dhcp.Leases()
	var inet, inet6 int
	for _, l := range leases {
		if l.Family == 6 {
			inet6++
		} else {
			inet++
		}
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpLeasesActive, prometheus.GaugeValue,
		float64(inet), "inet")
	ch <- prometheus.MustNewConstMetric(c.dhcpLeasesActive, prometheus.GaugeValue,
		float64(inet6), "inet6")
}

// collectDDNSMetrics emits the xpf_dhcp_ddns_* family from the DDNS
// manager's counter snapshot (#1387 inc-2). The family is omitted entirely
// when no DDNSStatsFn is wired or it returns nil (NoDataplane). Label
// cardinality is CLOSED: result in {ok,fail}; reason in
// {no-name,no-backend,conflict,ptr-notauth}.
func (c *xpfCollector) collectDDNSMetrics(ch chan<- prometheus.Metric) {
	if c.srv.ddnsStatsFn == nil {
		return
	}
	st := c.srv.ddnsStatsFn()
	if st == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSReconcileRunsTotal, prometheus.CounterValue,
		float64(st.ReconcileOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSReconcileRunsTotal, prometheus.CounterValue,
		float64(st.ReconcileFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedNoName), "no-name")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedNoBackend), "no-backend")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedConflict), "conflict")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedPTRNotAuth), "ptr-notauth")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.PTRDeferred), "ptr-deferred")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.DeleteCoowned), "coowned")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSOwnedRecords, prometheus.GaugeValue,
		float64(st.OwnedRecords))
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSPTRPending, prometheus.GaugeValue,
		float64(st.PTRPendingNow))
	var degraded float64
	if st.Degraded {
		degraded = 1
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSDegraded, prometheus.GaugeValue, degraded)
	var lastTs float64
	if !st.LastReconcile.IsZero() {
		lastTs = float64(st.LastReconcile.Unix())
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSLastReconcileTs, prometheus.GaugeValue, lastTs)
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSLastReconcileN, prometheus.GaugeValue,
		float64(st.LastReconcileN))
}

// collectSurfaceADDNSMetrics emits the xpf_ddns_surface_a_* family from the
// Surface A (router/interface-address) DDNS manager snapshot (#2691 P2). The
// family is omitted entirely when no SurfaceAStatsFn is wired or it returns nil
// (NoDataplane). Label cardinality is CLOSED: result in {ok,fail}; reason in
// {unchanged,backoff,no-backend}.
func (c *xpfCollector) collectSurfaceADDNSMetrics(ch chan<- prometheus.Metric) {
	if c.srv.surfaceAStatsFn == nil {
		return
	}
	st := c.srv.surfaceAStatsFn()
	if st == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSSkippedTotal, prometheus.CounterValue,
		float64(st.Skipped), "unchanged")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSSkippedTotal, prometheus.CounterValue,
		float64(st.BackedOff), "backoff")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedNoBackend), "no-backend")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSScopes, prometheus.GaugeValue,
		float64(st.Scopes))
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSOrphaned, prometheus.GaugeValue,
		float64(st.Orphaned))
	var degraded float64
	if st.Degraded {
		degraded = 1
	}
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSDegraded, prometheus.GaugeValue, degraded)
}

// collectFlowExportMetrics emits the xpf_flow_export_collector_* family
// from the per-collector NetFlow v9 / IPFIX write-health snapshot
// (#2464). The family is omitted entirely when no FlowCollectorHealthFn
// is wired or when no flow export is configured (empty slice). Labels:
// protocol {netflow-v9,ipfix}, instance, template, the collector address,
// and source — all bounded (one series per configured flow-server group).
// These counters make a silently-unreachable collector observable:
// write_failures climbs while write_attempts climbs, healthy drops to 0,
// and last_success ages. The source label carries the per-collector local
// bind address (#3745), so two same-family collectors that bind distinct
// sources are distinct series and a source-bound failure is attributable;
// it is "" when the OS selected the source. The instance + template
// labels (#3741) disambiguate MULTIPLE health rows that share one
// (protocol, collector) pair — one per template group, per family-disjoint
// instance — which the daemon legitimately returns; without them the two
// rows collide on an identical labelset, and Prometheus either rejects the
// duplicate series (scrape error) or silently collapses the failing group.
func (c *xpfCollector) collectFlowExportMetrics(ch chan<- prometheus.Metric) {
	if c.srv.flowCollectorHealthFn == nil {
		return
	}
	for _, h := range c.srv.flowCollectorHealthFn() {
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorWriteAttemptsTotal,
			prometheus.CounterValue, float64(h.WriteAttempts), h.Protocol, h.Instance, h.Template, h.Address, h.SourceAddress)
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorWriteFailuresTotal,
			prometheus.CounterValue, float64(h.WriteFailures), h.Protocol, h.Instance, h.Template, h.Address, h.SourceAddress)
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorWriteSkippedTotal,
			prometheus.CounterValue, float64(h.WriteSkipped), h.Protocol, h.Instance, h.Template, h.Address, h.SourceAddress)
		healthy := 0.0
		if h.Healthy {
			healthy = 1
		}
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorHealthy,
			prometheus.GaugeValue, healthy, h.Protocol, h.Instance, h.Template, h.Address, h.SourceAddress)
		var lastSuccess float64
		if !h.LastSuccessTime.IsZero() {
			lastSuccess = float64(h.LastSuccessTime.Unix())
		}
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorLastSuccessSeconds,
			prometheus.GaugeValue, lastSuccess, h.Protocol, h.Instance, h.Template, h.Address, h.SourceAddress)
		var lastFailure float64
		if !h.LastFailureTime.IsZero() {
			lastFailure = float64(h.LastFailureTime.Unix())
		}
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorLastFailureSeconds,
			prometheus.GaugeValue, lastFailure, h.Protocol, h.Instance, h.Template, h.Address, h.SourceAddress)
	}
	c.collectFlowExportBatchMetrics(ch)
}

// collectFlowExportBatchMetrics emits the xpf_flow_export_batch_* family from
// the per-exporter pending-batch queue stats (#3747). The family is omitted
// entirely when no FlowExportBatchStatsFn is wired or when no flow export is
// configured (empty slice). Labels: protocol {netflow-v9,ipfix}, instance,
// template — one series per configured flow-server group (bounded). The
// export batch used to be unbounded: a stalled/overrun drain grew memory
// without bound and silently. depth / max_depth expose the backlog and
// dropped_total exposes the bounded drops that now replace that growth.
func (c *xpfCollector) collectFlowExportBatchMetrics(ch chan<- prometheus.Metric) {
	if c.srv.flowExportBatchStatsFn == nil {
		return
	}
	for _, s := range c.srv.flowExportBatchStatsFn() {
		ch <- prometheus.MustNewConstMetric(c.flowExportBatchDepth,
			prometheus.GaugeValue, float64(s.Depth), s.Protocol, s.Instance, s.Template)
		ch <- prometheus.MustNewConstMetric(c.flowExportBatchMaxDepth,
			prometheus.GaugeValue, float64(s.MaxDepth), s.Protocol, s.Instance, s.Template)
		ch <- prometheus.MustNewConstMetric(c.flowExportBatchDroppedTotal,
			prometheus.CounterValue, float64(s.Dropped), s.Protocol, s.Instance, s.Template)
	}
}

func (c *xpfCollector) collectSystemMetrics(ch chan<- prometheus.Metric) {
	// Daemon uptime
	ch <- prometheus.MustNewConstMetric(c.daemonUptime, prometheus.GaugeValue,
		time.Since(c.srv.startTime).Seconds())

	// #1780: per-phase age of the Go periodic neighbor-maintenance loop.
	// A monotonically climbing age for any phase is the watchdog signal
	// that the phase's guarded goroutine is wedged on a stuck
	// netlink/probe syscall (the idle/overnight cold-connect hang).
	if c.srv.neighborPhaseAgeFn != nil {
		for phase, age := range c.srv.neighborPhaseAgeFn() {
			ch <- prometheus.MustNewConstMetric(c.neighborPeriodicAge,
				prometheus.GaugeValue, age, phase)
		}
	}

	// #1827: services ip-monitoring policy state.
	if c.srv.ipmonStatusFn != nil {
		routesApplied := 0
		routesDesired := 0
		unresolved := 0
		for _, ps := range c.srv.ipmonStatusFn() {
			failed := 0.0
			if ps.Failed {
				failed = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.ipmonPolicyFailed,
				prometheus.GaugeValue, failed, ps.Name)
			ch <- prometheus.MustNewConstMetric(c.ipmonPolicyTransitions,
				prometheus.CounterValue, float64(ps.Transitions), ps.Name)
			// #3761 H8: routes_applied must reflect what is ACTUALLY live
			// in the FIBs (the last converged actuation), not the desired
			// overlay — a failed FRR/snapshot/FIB actuation must not read
			// as applied. routes_desired exposes the winner-resolved
			// intent separately.
			routesApplied += len(ps.AppliedRoutes)
			routesDesired += len(ps.Routes)
			// #1844: Status() recomputes the overlay (including the
			// resolver skips), so the gauge is current on every scrape
			// without requiring an actuation.
			unresolved += len(ps.UnresolvedRoutes)
		}
		ch <- prometheus.MustNewConstMetric(c.ipmonRoutesApplied,
			prometheus.GaugeValue, float64(routesApplied))
		ch <- prometheus.MustNewConstMetric(c.ipmonRoutesDesired,
			prometheus.GaugeValue, float64(routesDesired))
		ch <- prometheus.MustNewConstMetric(c.ipmonUnresolvedNextHops,
			prometheus.GaugeValue, float64(unresolved))
	}
	// #4423 L: ip-monitoring actuation-failure counter — surfaces the
	// otherwise-silent #3757 self-heal retry loop so a stuck overlay
	// actuation (degraded failover) is observable. Independent of
	// ipmonStatusFn: it is meaningful even with zero FAILED policies.
	// #7437: the route-listener pair. Emitted independently so a nil fn on
	// one does not suppress the other -- they are read together and a missing
	// half is worse than an absent pair.
	if c.srv.routeListenerMarksFn != nil {
		ch <- prometheus.MustNewConstMetric(c.routeListenerMarks,
			prometheus.CounterValue, float64(c.srv.routeListenerMarksFn()))
	}
	if c.srv.routeListenerRepublishesFn != nil {
		ch <- prometheus.MustNewConstMetric(c.routeListenerRepublishes,
			prometheus.CounterValue, float64(c.srv.routeListenerRepublishesFn()))
	}
	if c.srv.ipmonActuationFailuresFn != nil {
		ch <- prometheus.MustNewConstMetric(c.ipmonActuationFailures,
			prometheus.CounterValue, float64(c.srv.ipmonActuationFailuresFn()))
	}

	// #2157: event-options remediation action observability. Makes the
	// previously-silent loss (drop on held config lock) visible.
	if c.srv.eventActionStatsFn != nil {
		st := c.srv.eventActionStatsFn()
		ch <- prometheus.MustNewConstMetric(c.eventActionsCommitted,
			prometheus.CounterValue, float64(st.Committed))
		ch <- prometheus.MustNewConstMetric(c.eventActionsCommittedWithDebt,
			prometheus.CounterValue, float64(st.CommittedWithDebt))
		ch <- prometheus.MustNewConstMetric(c.eventActionsRejected,
			prometheus.CounterValue, float64(st.Rejected))
		ch <- prometheus.MustNewConstMetric(c.eventActionsRetried,
			prometheus.CounterValue, float64(st.Retried))
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedLockHeld), "lock_held")
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedQueueFull), "queue_full")
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedStale), "stale")
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedGlobalBudget), "global_budget")
		ch <- prometheus.MustNewConstMetric(c.eventActionsSuperseded,
			prometheus.CounterValue, float64(st.Superseded))
		ch <- prometheus.MustNewConstMetric(c.eventAttributesInvalid,
			prometheus.CounterValue, float64(st.AttributesInvalid))
		ch <- prometheus.MustNewConstMetric(c.eventPlantClassInvalid,
			prometheus.CounterValue, float64(st.PlantClassInvalid))
		ch <- prometheus.MustNewConstMetric(c.eventActionQueueDepth,
			prometheus.GaugeValue, float64(st.QueueDepth))
	}

	// #5064: aggregate EventBuffer fan-out drops. The security/audit event
	// stream sheds records non-blocking when a subscriber's channel is full;
	// this counter makes that otherwise-silent loss visible so a gapped
	// forensic stream is not mistaken for a complete one.
	if c.srv.eventBuf != nil {
		ch <- prometheus.MustNewConstMetric(c.eventStreamSubscriberDropped,
			prometheus.CounterValue, float64(c.srv.eventBuf.DroppedTotal()))
		ch <- prometheus.MustNewConstMetric(c.eventStreamSubscriberRefusals,
			prometheus.CounterValue, float64(c.srv.eventBuf.SubscriberRefusals()))
	}

	// #1895: currently-failed RPM probe-pin installs. Nonzero means
	// next-hop-pinned tests are holding state (their uplinks are not
	// being health-checked) until a pin retry succeeds.
	if c.srv.rpmPinFailedFn != nil {
		ch <- prometheus.MustNewConstMetric(c.rpmPinInstallFailures,
			prometheus.GaugeValue, c.srv.rpmPinFailedFn())
	}

	// Daemon RSS from /proc/self/statm (field 1 = RSS in pages)
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			if rssPages, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				ch <- prometheus.MustNewConstMetric(c.daemonMemRSS, prometheus.GaugeValue,
					float64(rssPages)*float64(os.Getpagesize()))
			}
		}
	}

	// System memory from /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				if v := parseMemInfoKB(line); v > 0 {
					ch <- prometheus.MustNewConstMetric(c.sysMemTotal, prometheus.GaugeValue, float64(v)*1024)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				if v := parseMemInfoKB(line); v > 0 {
					ch <- prometheus.MustNewConstMetric(c.sysMemAvail, prometheus.GaugeValue, float64(v)*1024)
				}
			}
		}
	}

	// CPU usage from /proc/stat: report the inter-scrape delta, NOT the
	// since-boot cumulative average (#4707). The counters in /proc/stat are
	// monotonic-since-boot, so dividing them directly yields a lifetime
	// average that barely moves once uptime is high. c.updateCPUUtilization
	// folds this sample into the collector's running state and returns the
	// (busyΔ/totalΔ) utilization to emit; it reports emit=false on the first
	// scrape (no predecessor) so no bogus value is published.
	if f, err := os.Open("/proc/stat"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			if cur, ok := parseProcStatCPU(scanner.Text()); ok {
				if userPct, systemPct, emit := c.updateCPUUtilization(cur, float64(runtime.NumCPU())); emit {
					ch <- prometheus.MustNewConstMetric(c.sysCPUUser, prometheus.GaugeValue, userPct)
					ch <- prometheus.MustNewConstMetric(c.sysCPUSystem, prometheus.GaugeValue, systemPct)
				}
			}
		}
	}
}

// cpuSample holds the cumulative /proc/stat CPU tick counters needed to
// compute inter-scrape utilization deltas (#4707). userNice and system are the
// busy components exported as separate gauges; total is the sum of all tick
// fields (busy + idle + iowait + irq/softirq/steal).
type cpuSample struct {
	userNice float64
	system   float64
	total    float64
}

// parseProcStatCPU parses the aggregate "cpu " line from /proc/stat into a
// cpuSample. It returns ok=false when the line is not a valid aggregate cpu
// line. Field order: cpu user nice system idle iowait irq softirq steal ...
// iowait/irq/softirq/steal may be absent on older kernels and default to 0.
func parseProcStatCPU(line string) (cpuSample, bool) {
	if !strings.HasPrefix(line, "cpu ") {
		return cpuSample{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return cpuSample{}, false
	}
	user, _ := strconv.ParseFloat(fields[1], 64)
	nice, _ := strconv.ParseFloat(fields[2], 64)
	system, _ := strconv.ParseFloat(fields[3], 64)
	idle, _ := strconv.ParseFloat(fields[4], 64)
	total := user + nice + system + idle
	if len(fields) >= 6 {
		iowait, _ := strconv.ParseFloat(fields[5], 64)
		total += iowait
	}
	if len(fields) >= 9 {
		irq, _ := strconv.ParseFloat(fields[6], 64)
		softirq, _ := strconv.ParseFloat(fields[7], 64)
		steal, _ := strconv.ParseFloat(fields[8], 64)
		total += irq + softirq + steal
	}
	return cpuSample{userNice: user + nice, system: system, total: total}, true
}

// cpuUtilization computes the per-mode utilization percentages between two
// cumulative samples, scaled by the number of CPUs (matching the historical
// "percent of one CPU summed across cores" gauge scale). It returns ok=false
// when the totals did not advance (no elapsed ticks) or any busy counter went
// backwards (counter reset after suspend/hotplug), so the caller skips a bogus
// sample. This is the #4707 delta — NOT cur.userNice/cur.total (the reverted
// cumulative form yields a stale since-boot average).
func cpuUtilization(prev, cur cpuSample, cpus float64) (userPct, systemPct float64, ok bool) {
	dTotal := cur.total - prev.total
	dUserNice := cur.userNice - prev.userNice
	dSystem := cur.system - prev.system
	if dTotal <= 0 || cpus <= 0 || dUserNice < 0 || dSystem < 0 {
		return 0, 0, false
	}
	return dUserNice / dTotal * 100 * cpus, dSystem / dTotal * 100 * cpus, true
}

// updateCPUUtilization folds a fresh /proc/stat cpu sample into the collector's
// running state and returns the inter-scrape utilization to emit (#4707). emit
// is false on the first sample (no predecessor) or when the counters did not
// advance, so the caller emits nothing rather than a bogus since-boot average.
// Guarded by c.mu because Collect can run concurrently for parallel scrapers.
func (c *xpfCollector) updateCPUUtilization(cur cpuSample, cpus float64) (userPct, systemPct float64, emit bool) {
	c.mu.Lock()
	prev := c.cpuSamplePrev
	havePrev := c.cpuSampleValid
	c.cpuSamplePrev = cur
	c.cpuSampleValid = true
	c.mu.Unlock()

	if !havePrev {
		return 0, 0, false
	}
	return cpuUtilization(prev, cur, cpus)
}

// parseMemInfoKB extracts the numeric kB value from a /proc/meminfo line.
func parseMemInfoKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}
