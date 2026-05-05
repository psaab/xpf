package userspace

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/psaab/xpf/pkg/config"
)

type cosInterfaceView struct {
	name           string
	unit           int
	cosUnit        *config.CoSInterfaceUnit
	interfaceUnit  *config.InterfaceUnit
	interfaceState *CoSInterfaceStatus
}

type cosQueueView struct {
	queueID         int
	ownerWorker     *uint32
	forwardingClass string
	priority        string
	exact           bool
	surplusSharing  bool // #915: only meaningful when exact == true
	transmitRate    uint64
	bufferBytes     uint64
	queuedPackets   uint64
	queuedBytes     uint64
	runnable        int
	parked          int
	nextWakeupTick  uint64
	surplusDeficit  uint64
	// #710/#718: admission-path counters sourced from runtime. Zero values
	// are still rendered — operators need to see the counter exists.
	admissionFlowShareDrops uint64
	admissionBufferDrops    uint64
	admissionEcnMarked      uint64
	// #709: owner-profile telemetry for exact queues with single
	// owner binding. When ownerWorker is set AND these fields are
	// non-default, the formatter renders a second indented line under
	// the Drops row. See docs/cos-validation-notes.md "Reading the
	// owner-profile counters".
	drainLatencyHist     []uint64
	drainInvocations     uint64
	drainNoopInvocations uint64
	redirectAcquireHist  []uint64
	ownerPPS             uint64
	peerPPS              uint64
	// #760 overshoot-hunt instrumentation. drainSentBytes /
	// drainParkRootTokens / drainParkQueueTokens are queue-scoped.
	// postDrainBackupBytes is binding-scoped (one-per-binding Rust
	// attribution; summed across queues here for rendering).
	drainSentBytes        uint64
	drainParkRootTokens   uint64
	drainParkQueueTokens  uint64
	postDrainBackupBytes  uint64
}

func FormatCoSInterfaceSummary(cfg *config.Config, status *ProcessStatus, selector string) string {
	if cfg == nil {
		return "No active configuration\n"
	}
	if cfg.ClassOfService == nil || len(cfg.ClassOfService.Interfaces) == 0 {
		return "No class-of-service interfaces configured\n"
	}

	views := configuredCoSInterfaceViews(cfg, status, selector)
	if len(views) == 0 {
		if selector == "" {
			return "No class-of-service interfaces configured\n"
		}
		return fmt.Sprintf("No class-of-service interface matches %s\n", selector)
	}

	var b strings.Builder
	for idx, view := range views {
		if idx > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Interface: %s\n", view.name)
		if view.cosUnit != nil {
			fmt.Fprintf(&b, "  Scheduler map:            %s\n", emptyDash(view.cosUnit.SchedulerMap))
			fmt.Fprintf(&b, "  DSCP classifier:          %s\n", emptyDash(view.cosUnit.DSCPClassifier))
			fmt.Fprintf(&b, "  IEEE 802.1 classifier:    %s\n", emptyDash(view.cosUnit.IEEE8021Classifier))
			fmt.Fprintf(&b, "  DSCP rewrite-rule:        %s\n", emptyDash(view.cosUnit.DSCPRewriteRule))
			fmt.Fprintf(&b, "  Shaping rate:             %s\n", formatCoSRate(view.cosUnit.ShapingRateBytes))
			fmt.Fprintf(&b, "  Burst size:               %s\n", formatCoSBytes(view.cosUnit.BurstSizeBytes))
		}
		if view.interfaceUnit != nil {
			if view.interfaceUnit.FilterInputV4 != "" {
				fmt.Fprintf(&b, "  Input filter (inet):      %s\n", view.interfaceUnit.FilterInputV4)
			}
			if view.interfaceUnit.FilterOutputV4 != "" {
				fmt.Fprintf(&b, "  Output filter (inet):     %s\n", view.interfaceUnit.FilterOutputV4)
			}
			if view.interfaceUnit.FilterInputV6 != "" {
				fmt.Fprintf(&b, "  Input filter (inet6):     %s\n", view.interfaceUnit.FilterInputV6)
			}
			if view.interfaceUnit.FilterOutputV6 != "" {
				fmt.Fprintf(&b, "  Output filter (inet6):    %s\n", view.interfaceUnit.FilterOutputV6)
			}
		}
		if view.interfaceState == nil {
			b.WriteString("  Runtime:                  unavailable\n")
		} else {
			fmt.Fprintf(&b, "  Owner worker:             %s\n", formatOptionalWorkerID(view.interfaceState.OwnerWorkerID))
			fmt.Fprintf(&b, "  Runtime workers:          %d\n", view.interfaceState.WorkerInstances)
			fmt.Fprintf(&b, "  Runtime queues:           nonempty=%d runnable=%d\n",
				view.interfaceState.NonemptyQueues,
				view.interfaceState.RunnableQueues)
			fmt.Fprintf(&b, "  Timer wheel sleepers:     level0=%d level1=%d\n",
				view.interfaceState.TimerLevel0Sleepers,
				view.interfaceState.TimerLevel1Sleepers)
		}
		// Build queue views once per interface and share the slice
		// between the binding-scoped telemetry render and the main
		// queue table below. Copilot flagged that the first rev of
		// this PR invoked buildCoSQueueViews twice — once inside
		// renderBindingScopedTelemetry, again here — which doubled
		// work and risked drift if buildCoSQueueViews filter/order
		// ever changed.
		queues := buildCoSQueueViews(cfg, view)
		// #732 / #751: binding-scoped telemetry rendered once per
		// interface instead of under every queue row. owner_pps /
		// peer_pps / redirect_p99 describe binding-wide arrivals
		// and redirects; producers don't know a target queue at
		// redirect time so these values are inherently per-binding.
		// Pre-#751 each queue row reported the same values, which
		// was the #732 symptom.
		renderBindingScopedTelemetry(&b, view, queues)
		if len(queues) == 0 {
			b.WriteString("  Queues:                   none\n")
			continue
		}
		b.WriteString("  Queues:\n")
		// Render queue rows via tabwriter into a local buffer so columns
		// align across ALL queues. Then walk the rendered lines and
		// interleave the per-queue Drops line. Emitting Drops directly
		// into the tabwriter breaks column alignment — a line without
		// tabs restarts tabwriter's contiguous-column grouping — so we
		// keep the Drops line outside the aligned grid (#710, #718).
		var tableBuf strings.Builder
		tw := tabwriter.NewWriter(&tableBuf, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "    Queue\tOwner\tClass\tPriority\tExact\tTransmit rate\tBuffer\tQueued pkts\tQueued bytes\tRunnable\tParked\tNext wake\tSurplus deficit")
		for _, queue := range queues {
			fmt.Fprintf(tw, "    %d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%s\t%s\n",
				queue.queueID,
				formatOptionalWorkerID(queue.ownerWorker),
				emptyDash(queue.forwardingClass),
				queue.priority,
				yesNo(queue.exact),
				formatCoSRate(queue.transmitRate),
				formatCoSBytes(queue.bufferBytes),
				queue.queuedPackets,
				formatCoSBytes(queue.queuedBytes),
				queue.runnable,
				queue.parked,
				formatWakeTick(queue.nextWakeupTick),
				formatCoSBytes(queue.surplusDeficit),
			)
		}
		_ = tw.Flush()
		// First rendered line is the header; subsequent lines map 1:1 to
		// queues in order. Re-emit into the main builder, appending a
		// Drops line under each queue data row.
		//
		// The Drops line is gated on **interface** runtime (not per-queue
		// runtime): once an interface reports runtime state, every
		// configured queue on it emits a Drops line with whatever counts
		// are exported, defaulting to zero for queues not yet materialised
		// in the runtime snapshot. This avoids the "wired-but-silent vs
		// missing-from-export" ambiguity — an operator seeing `flow_share=0
		// buffer=0 ecn_marked=0` now unambiguously means the counter path
		// is live and nothing is tripping, whereas a missing Drops line
		// means the interface itself is not yet exported (see
		// cos-validation-notes.md "Reading the counters live").
		interfaceHasRuntime := view.interfaceState != nil
		tableLines := strings.Split(strings.TrimRight(tableBuf.String(), "\n"), "\n")
		for i, line := range tableLines {
			b.WriteString(line)
			b.WriteByte('\n')
			if i == 0 {
				// header — no drops line
				continue
			}
			queueIdx := i - 1
			if queueIdx >= len(queues) {
				continue
			}
			if !interfaceHasRuntime {
				continue
			}
			queue := queues[queueIdx]
			fmt.Fprintf(&b, "           Drops: flow_share=%d  buffer=%d  ecn_marked=%d\n",
				queue.admissionFlowShareDrops,
				queue.admissionBufferDrops,
				queue.admissionEcnMarked,
			)
			// #915: surplus-sharing visibility. Rendered only on exact
			// queues so non-exact queues (which already participate in
			// surplus by default) stay clean. Operators debugging an
			// exact queue that exceeds its configured rate need this
			// line — without it the bursting looks like a bug.
			if queue.exact {
				fmt.Fprintf(&b, "           Surplus sharing: %s\n",
					yesNo(queue.surplusSharing))
			}
			// #709 / #751: per-queue OwnerProfile line renders only
			// the queue-scoped drain percentiles. The binding-scoped
			// fields (redirect_p99 / owner_pps / peer_pps) moved to
			// the interface header via renderBindingScopedTelemetry
			// so they are no longer repeated under every queue row
			// (#732). Non-exact / shared_exact queues keep an empty
			// per-queue hist post-#751 because the drain path only
			// writes the atomics when it services them, so
			// drainInvocations==0 correctly suppresses the row.
			if queue.ownerWorker != nil && queue.drainInvocations > 0 {
				fmt.Fprintf(
					&b,
					"           OwnerProfile: drain_p50=%s  drain_p99=%s  drain_invocations=%d\n",
					formatHistPercentileMicros(queue.drainLatencyHist, queue.drainInvocations, 50),
					formatHistPercentileMicros(queue.drainLatencyHist, queue.drainInvocations, 99),
					queue.drainInvocations,
				)
				// #760 overshoot-hunt row. Sibling of the OwnerProfile
				// line so operators can correlate drain-latency with
				// the rate the queue actually shaped out and the two
				// gate-park counters. Only rendered when the queue has
				// been drained at least once — a never-drained queue's
				// zeros carry no signal.
				fmt.Fprintf(
					&b,
					"           DrainShape:   sent_bytes=%d  park_root=%d  park_queue=%d\n",
					queue.drainSentBytes,
					queue.drainParkRootTokens,
					queue.drainParkQueueTokens,
				)
			}
		}
	}
	return b.String()
}

// #709: render a histogram percentile as microseconds. The Rust side
// fills the histogram with `DRAIN_HIST_BUCKETS` powers-of-two buckets;
// we approximate the percentile as the lower bound of the bucket
// containing the Nth-percentile sample. This is intentionally lossy —
// operators want ballpark µs figures to make the decision tree in
// docs/709-owner-hotspot-plan.md actionable, not exact stats.
//
// `total` is the authoritative sample count (drain_invocations). When
// `total == 0`, emit "0µs" rather than "nan" or "-" so the field
// aligns visually across queues and the zero value is obvious.
func formatHistPercentileMicros(hist []uint64, total uint64, percentile int) string {
	if len(hist) == 0 || total == 0 {
		return "0us"
	}
	// Target = ceil(total * percentile / 100). We want the smallest
	// bucket index whose cumulative sum reaches the target.
	target := (total*uint64(percentile) + 99) / 100
	if target == 0 {
		target = 1
	}
	var cumulative uint64
	for i, count := range hist {
		cumulative += count
		if cumulative >= target {
			return bucketLowerBoundMicros(i)
		}
	}
	// Reaching the end means cumulative < target (hist is sparse or
	// `total` is larger than the sum of hist buckets). Saturate at the
	// top bucket's lower bound.
	return bucketLowerBoundMicros(len(hist) - 1)
}

// #709: redirect-acquire has no dedicated "invocations" counter
// (sampling is 1-in-256, so the total is implicit in the bucket sum).
// Derive `total` from the buckets and delegate.
func formatHistPercentileMicrosFromBuckets(hist []uint64, percentile int) string {
	var total uint64
	for _, count := range hist {
		total += count
	}
	return formatHistPercentileMicros(hist, total, percentile)
}

// #732 / #751: render a single "Binding telemetry" line per interface
// carrying the values that are inherently binding-scoped (producers
// do not know the target queue at redirect time). Rust's snapshot
// path attributes these to the sole unambiguous owner-local exact
// queue row, or leaves them at zero when the shape is ambiguous.
//
// Copilot-review-driven design notes:
//   - We SUM across queues instead of MAX. Rust populates the fields
//     on at most one queue per binding in the normal case, so sum and
//     max are equivalent — except if a bug or mixed-version mismatch
//     ever puts non-zero values on multiple queue rows, the sum makes
//     that divergence visible (inflated value in the output) instead
//     of silently hiding it like max would.
//   - The redirect-acquire histogram gate checks for at least one
//     non-zero bucket, not just a non-empty slice. Rust resizes the
//     vector to DRAIN_HIST_BUCKETS on the eligible row even when
//     every sample is 0, so a length-only gate would render a noisy
//     "redirect_p99=0us" line on ambiguous bindings.
//   - The `queues` slice is built once by the caller so the binding-
//     scoped line and the per-queue table see exactly the same data.
//
// Zero-in-all-fields is suppressed so interfaces with no exact queue
// or ambiguous shape don't get a noise line.
func renderBindingScopedTelemetry(b *strings.Builder, view cosInterfaceView, queues []cosQueueView) {
	if view.interfaceState == nil {
		return
	}
	var (
		ownerPPS      uint64
		peerPPS       uint64
		redirectHist  []uint64
		backupBytes   uint64
	)
	for _, q := range queues {
		ownerPPS = saturatingAddU64(ownerPPS, q.ownerPPS)
		peerPPS = saturatingAddU64(peerPPS, q.peerPPS)
		backupBytes = saturatingAddU64(backupBytes, q.postDrainBackupBytes)
		// Fold histograms element-wise; unset-slice queues are
		// skipped so we don't allocate for queues that reported
		// no samples.
		for i, count := range q.redirectAcquireHist {
			if count == 0 {
				continue
			}
			if len(redirectHist) < len(q.redirectAcquireHist) {
				resized := make([]uint64, len(q.redirectAcquireHist))
				copy(resized, redirectHist)
				redirectHist = resized
			}
			redirectHist[i] = saturatingAddU64(redirectHist[i], count)
		}
	}
	if ownerPPS == 0 && peerPPS == 0 && !histHasSample(redirectHist) && backupBytes == 0 {
		return
	}
	fmt.Fprintf(
		b,
		"  Binding telemetry:        redirect_p99=%s  owner_pps=%d  peer_pps=%d  post_drain_backup_bytes=%d\n",
		formatHistPercentileMicrosFromBuckets(redirectHist, 99),
		ownerPPS,
		peerPPS,
		backupBytes,
	)
}

// saturatingAddU64 avoids silent wraparound in the telemetry render.
// Hot-path this is not (called once per interface at scrape cadence)
// but honesty-of-summation matters more here than the cycle cost —
// an overflow under adversarial input is a visible ceiling, not a
// reset to zero.
func saturatingAddU64(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}

func histHasSample(hist []uint64) bool {
	for _, count := range hist {
		if count > 0 {
			return true
		}
	}
	return false
}

// #709: map a bucket index to its lower bound, formatted as µs. The
// bucket layout (see `DRAIN_HIST_BUCKETS` comment in umem.rs):
//   - bucket 0: [0, 1024) ns — render as "0us" (sub-1µs)
//   - bucket N (N >= 1): [2^(N+9), 2^(N+10)) ns — lower bound in µs
//     is `(1 << (N+9)) / 1000`.
func bucketLowerBoundMicros(bucket int) string {
	if bucket <= 0 {
		return "0us"
	}
	ns := uint64(1) << uint(bucket+9)
	us := ns / 1000
	return fmt.Sprintf("%dus", us)
}

func configuredCoSInterfaceViews(cfg *config.Config, status *ProcessStatus, selector string) []cosInterfaceView {
	runtimeByName := make(map[string]*CoSInterfaceStatus)
	if status != nil {
		for i := range status.CoSInterfaces {
			iface := &status.CoSInterfaces[i]
			runtimeByName[iface.InterfaceName] = iface
		}
	}
	selector = strings.TrimSpace(selector)
	views := make([]cosInterfaceView, 0)
	for ifName, iface := range cfg.ClassOfService.Interfaces {
		for unitNum, cosUnit := range iface.Units {
			logicalName := fmt.Sprintf("%s.%d", ifName, unitNum)
			if selector != "" && selector != ifName && selector != logicalName {
				continue
			}
			var interfaceUnit *config.InterfaceUnit
			if cfg.Interfaces.Interfaces != nil {
				if intf := cfg.Interfaces.Interfaces[ifName]; intf != nil && intf.Units != nil {
					interfaceUnit = intf.Units[unitNum]
				}
			}
			views = append(views, cosInterfaceView{
				name:           logicalName,
				unit:           unitNum,
				cosUnit:        cosUnit,
				interfaceUnit:  interfaceUnit,
				interfaceState: runtimeByName[logicalName],
			})
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].name < views[j].name })
	return views
}

func buildCoSQueueViews(cfg *config.Config, view cosInterfaceView) []cosQueueView {
	queueViews := make(map[int]cosQueueView)
	if cfg.ClassOfService != nil && view.cosUnit != nil {
		schedulerMap := cfg.ClassOfService.SchedulerMaps[view.cosUnit.SchedulerMap]
		if schedulerMap != nil {
			for className, entry := range schedulerMap.Entries {
				class := cfg.ClassOfService.ForwardingClasses[className]
				if class == nil {
					continue
				}
				qv := queueViews[class.Queue]
				qv.queueID = class.Queue
				qv.forwardingClass = className
				if sched := cfg.ClassOfService.Schedulers[entry.Scheduler]; sched != nil {
					qv.exact = sched.TransmitRateExact
					qv.surplusSharing = sched.SurplusSharing
					qv.transmitRate = sched.TransmitRateBytes
					qv.bufferBytes = sched.BufferSizeBytes
					if sched.Priority != "" {
						qv.priority = sched.Priority
					}
				}
				queueViews[class.Queue] = qv
			}
		}
	}
	if view.interfaceState != nil {
		for _, runtimeQueue := range view.interfaceState.Queues {
			qv := queueViews[int(runtimeQueue.QueueID)]
			qv.queueID = int(runtimeQueue.QueueID)
			qv.ownerWorker = runtimeQueue.OwnerWorkerID
			if runtimeQueue.ForwardingClass != "" {
				qv.forwardingClass = runtimeQueue.ForwardingClass
			}
			qv.priority = fmt.Sprintf("%d", runtimeQueue.Priority)
			qv.exact = runtimeQueue.Exact
			if runtimeQueue.TransmitRateBytes > 0 {
				qv.transmitRate = runtimeQueue.TransmitRateBytes
			}
			if runtimeQueue.BufferBytes > 0 {
				qv.bufferBytes = runtimeQueue.BufferBytes
			}
			qv.queuedPackets = runtimeQueue.QueuedPackets
			qv.queuedBytes = runtimeQueue.QueuedBytes
			qv.runnable = runtimeQueue.RunnableInstances
			qv.parked = runtimeQueue.ParkedInstances
			qv.nextWakeupTick = runtimeQueue.NextWakeupTick
			qv.surplusDeficit = runtimeQueue.SurplusDeficitBytes
			qv.admissionFlowShareDrops = runtimeQueue.AdmissionFlowShareDrops
			qv.admissionBufferDrops = runtimeQueue.AdmissionBufferDrops
			qv.admissionEcnMarked = runtimeQueue.AdmissionEcnMarked
			// #709: owner-profile telemetry copied from the runtime
			// snapshot. The Rust side populates these only when the
			// queue has a single owner binding (exact && !shared_exact);
			// otherwise the histograms are empty and the pps counters
			// are 0, which the formatter skips.
			qv.drainLatencyHist = runtimeQueue.DrainLatencyHist
			qv.drainInvocations = runtimeQueue.DrainInvocations
			qv.drainNoopInvocations = runtimeQueue.DrainNoopInvocations
			qv.redirectAcquireHist = runtimeQueue.RedirectAcquireHist
			qv.ownerPPS = runtimeQueue.OwnerPPS
			qv.peerPPS = runtimeQueue.PeerPPS
			// #760 copy-through. See field comments on cosQueueView
			// and on the Rust CoSQueueStatus. A queue that never got
			// drained leaves these at zero; the renderer gates on
			// drainInvocations > 0 so a silent queue stays silent.
			qv.drainSentBytes = runtimeQueue.DrainSentBytes
			qv.drainParkRootTokens = runtimeQueue.DrainParkRootTokens
			qv.drainParkQueueTokens = runtimeQueue.DrainParkQueueTokens
			qv.postDrainBackupBytes = runtimeQueue.PostDrainBackupBytes
			queueViews[qv.queueID] = qv
		}
	}
	out := make([]cosQueueView, 0, len(queueViews))
	for _, queue := range queueViews {
		if queue.priority == "" {
			queue.priority = "-"
		}
		out = append(out, queue)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].queueID < out[j].queueID })
	return out
}

func formatCoSRate(bytesPerSecond uint64) string {
	if bytesPerSecond == 0 {
		return "-"
	}
	bitsPerSecond := float64(bytesPerSecond) * 8
	units := []string{"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"}
	unitIdx := 0
	for bitsPerSecond >= 1000 && unitIdx < len(units)-1 {
		bitsPerSecond /= 1000
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", bitsPerSecond, units[unitIdx])
}

func formatOptionalWorkerID(workerID *uint32) string {
	if workerID == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *workerID)
}

func formatCoSBytes(bytes uint64) string {
	if bytes == 0 {
		return "-"
	}
	value := float64(bytes)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	unitIdx := 0
	for value >= 1024 && unitIdx < len(units)-1 {
		value /= 1024
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", value, units[unitIdx])
}

func formatWakeTick(tick uint64) string {
	if tick == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", tick)
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
