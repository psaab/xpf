package format

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/psaab/xpf/pkg/config"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// This file holds the view-model construction and the per-section render
// helpers for FormatCoSInterfaceSummary (cos.go). The split mirrors the
// #4656 status.go aggregate-then-render pattern: configuredCoSInterfaceViews
// + buildCoSRuntimeIndex + buildCoSQueueViews are the ONLY places that join
// the config stanzas with the runtime snapshot, and the writeCoSXxx helpers
// render from those view structs without re-iterating. The queue view slice
// is built once per interface by the caller and passed to both the
// binding-scoped telemetry line and the queue table.

// -----------------------------------------------------------------------
// Section render helpers
// -----------------------------------------------------------------------

// writeCoSInterfaceHeader renders the per-interface config + runtime header:
// the scheduler map / classifiers / shaping / burst lines from the CoS
// stanza, the input/output filter lines from the interface stanza, and the
// runtime worker/queue/timer/waterfill lines from the snapshot. When the
// interface has no runtime state it emits the single "unavailable" line.
func writeCoSInterfaceHeader(b *strings.Builder, view cosInterfaceView) {
	// #7065: a `class-of-service interfaces` stanza whose interface/unit has no
	// counterpart under `interfaces` commits clean, and buildInterfaceSnapshots
	// walks cfg.Interfaces.Interfaces — so NOTHING below reaches the dataplane.
	// Rendered as a fully-fledged block it was indistinguishable from a live
	// one, which is the #6858 failure class (an unanswered question turned into
	// a confidently wrong answer) inside a second command.
	//
	// The row is annotated rather than DROPPED. Hiding it would make the
	// operator's own committed stanza invisible from the command that exists to
	// show it — the likeliest cause here is a typo in the interface name, and an
	// empty output sends them looking for the wrong thing. The reference is
	// quoted for the reason cosRewriteRuleEnforcement quotes its own: a bare
	// "not applied" reads as "you forgot to configure it" to an operator who did
	// configure it, just under a name with a typo in it.
	//
	// Placed FIRST so it qualifies the bindings printed beneath it. A reader who
	// stops after the first line has still been told the block is inert.
	if view.interfaceUnit == nil {
		fmt.Fprintf(b, "  %-26s%s\n", "Dataplane:",
			fmt.Sprintf("not applied (interfaces %s unit %d is not configured, so none of "+
				"the bindings below reach the dataplane)", view.ifName, view.unit))
	}
	if view.cosUnit != nil {
		fmt.Fprintf(b, "  Scheduler map:            %s\n", emptyDash(view.cosUnit.SchedulerMap))
		fmt.Fprintf(b, "  DSCP classifier:          %s\n", emptyDash(view.cosUnit.DSCPClassifier))
		fmt.Fprintf(b, "  IEEE 802.1 classifier:    %s\n", emptyDash(view.cosUnit.IEEE8021Classifier))
		// #7080: the inet-precedence binding sits between the two above it in
		// the config and was the only one of the three missing here — so the
		// binding actually steering the traffic did not appear next to the two
		// that were not.
		fmt.Fprintf(b, "  IP precedence classifier: %s\n", emptyDash(view.cosUnit.INetPrecedenceClassifier))
		fmt.Fprintf(b, "  DSCP rewrite-rule:        %s\n", emptyDash(view.cosUnit.DSCPRewriteRule))
		fmt.Fprintf(b, "  Shaping rate:             %s\n", formatCoSRate(view.cosUnit.ShapingRateBytes))
		fmt.Fprintf(b, "  Burst size:               %s\n", formatCoSBytes(view.cosUnit.BurstSizeBytes))
	}
	if view.interfaceUnit != nil {
		if view.interfaceUnit.FilterInputV4 != "" {
			fmt.Fprintf(b, "  Input filter (inet):      %s\n", view.interfaceUnit.FilterInputV4)
		}
		if view.interfaceUnit.FilterOutputV4 != "" {
			fmt.Fprintf(b, "  Output filter (inet):     %s\n", view.interfaceUnit.FilterOutputV4)
		}
		if view.interfaceUnit.FilterInputV6 != "" {
			fmt.Fprintf(b, "  Input filter (inet6):     %s\n", view.interfaceUnit.FilterInputV6)
		}
		if view.interfaceUnit.FilterOutputV6 != "" {
			fmt.Fprintf(b, "  Output filter (inet6):    %s\n", view.interfaceUnit.FilterOutputV6)
		}
	}
	if view.interfaceState == nil {
		b.WriteString("  Runtime:                  unavailable\n")
		return
	}
	fmt.Fprintf(b, "  Owner worker:             %s\n", formatOptionalWorkerID(view.interfaceState.OwnerWorkerID))
	fmt.Fprintf(b, "  Runtime workers:          %d\n", view.interfaceState.WorkerInstances)
	fmt.Fprintf(b, "  Runtime queues:           nonempty=%d runnable=%d\n",
		view.interfaceState.NonemptyQueues,
		view.interfaceState.RunnableQueues)
	fmt.Fprintf(b, "  Timer wheel sleepers:     level0=%d level1=%d\n",
		view.interfaceState.TimerLevel0Sleepers,
		view.interfaceState.TimerLevel1Sleepers)
	// #1628: per-interface guarantee-rate waterfill counters.
	// Rendered only when the interface ran the waterfill selector
	// (guarantee-rate mode) — zero on Proportional mode. epochs +
	// breaks are summed across workers; min_epochs_per_worker is
	// the MIN over bindings with active exact backlog (a frozen
	// MIN well below the SUM flags a single Phase-2-locked
	// selector). The u64::MAX sentinel = "no active-backlog
	// candidate"; render it as "none" so it is not confused with a
	// real 0-epoch hard lock-in.
	minEpochs := view.interfaceState.WaterfillMinEpochsPerWorker
	minHasCandidate := minEpochs != math.MaxUint64
	if view.interfaceState.WaterfillEpochs != 0 ||
		view.interfaceState.WaterfillPhase1BudgetBreaks != 0 ||
		minHasCandidate {
		minStr := "none"
		if minHasCandidate {
			minStr = strconv.FormatUint(minEpochs, 10)
		}
		fmt.Fprintf(b, "  Waterfill:                epochs=%d phase1_budget_breaks=%d min_epochs_per_worker=%s\n",
			view.interfaceState.WaterfillEpochs,
			view.interfaceState.WaterfillPhase1BudgetBreaks,
			minStr)
	}
}

// writeCoSQueueTable renders the aligned per-queue table plus the
// interleaved per-queue detail rows. The table rows go through a local
// tabwriter so columns align across ALL queues; the detail lines
// (Drops/Sojourn/Surplus/etc.) are emitted OUTSIDE the aligned grid because
// a line without tabs restarts tabwriter's contiguous-column grouping
// (#710, #718).
//
// interfaceHasRuntime gates the detail rows on **interface** runtime (not
// per-queue): once an interface reports runtime state, every configured
// queue emits a Drops line with whatever counts are exported, defaulting to
// zero. This avoids the "wired-but-silent vs missing-from-export" ambiguity
// (see cos-validation-notes.md "Reading the counters live").
func writeCoSQueueTable(b *strings.Builder, queues []cosQueueView, interfaceHasRuntime bool) {
	var tableBuf strings.Builder
	tw := tabwriter.NewWriter(&tableBuf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "    Queue\tOwner\tClass\tPriority\tExact\tGuarantee\tTransmit rate\tBuffer\tQueued pkts\tQueued bytes\tRunnable\tParked\tNext wake\tSurplus deficit")
	for _, queue := range queues {
		fmt.Fprintf(tw, "    %d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%s\t%s\n",
			queue.queueID,
			formatOptionalWorkerID(queue.ownerWorker),
			emptyDash(queue.forwardingClass),
			queue.priority,
			yesNo(queue.exact),
			yesNo(queue.guaranteeEnabled),
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
	// queues in order. Re-emit into the main builder, appending the
	// detail rows under each queue data row.
	tableLines := strings.Split(strings.TrimRight(tableBuf.String(), "\n"), "\n")
	for i, line := range tableLines {
		b.WriteString(line)
		b.WriteByte('\n')
		if i == 0 {
			// header — no detail rows
			continue
		}
		queueIdx := i - 1
		if queueIdx >= len(queues) {
			continue
		}
		if !interfaceHasRuntime {
			continue
		}
		writeCoSQueueDetail(b, queues[queueIdx])
	}
}

// writeCoSQueueDetail renders the interleaved detail rows for a single
// queue: the always-present Drops line, then the conditionally-rendered
// Sojourn / Surplus sharing / Equal-flow / OwnerProfile / DrainShape /
// Waterfill lines. Each row's gate is preserved from the pre-split render
// loop so the output is byte-identical.
func writeCoSQueueDetail(b *strings.Builder, queue cosQueueView) {
	fmt.Fprintf(b, "           Drops: flow_share=%d  buffer=%d  ecn_marked=%d\n",
		queue.admissionFlowShareDrops,
		queue.admissionBufferDrops,
		queue.admissionEcnMarked,
	)
	// #1829 Phase 1: dequeue-time sojourn line, shown once
	// the queue has recorded at least one sample. win_min is
	// the windowed (100 ms two-bucket) MINIMUM — the
	// standing-queue gate metric; 0 means "no standing queue
	// in the last ~2 windows". ewma/peak are supporting
	// context (biased high by scheduler service gaps).
	if queue.sojournPeakNS > 0 {
		fmt.Fprintf(b, "           Sojourn: win_min=%s  ewma=%s  peak=%s\n",
			formatSojournNS(queue.sojournWindowedMinNS),
			formatSojournNS(queue.sojournEwmaNS),
			formatSojournNS(queue.sojournPeakNS),
		)
	}
	// #915: surplus-sharing visibility. Rendered only on exact
	// queues so non-exact queues (which already participate in
	// surplus by default) stay clean. Operators debugging an
	// exact queue that exceeds its configured rate need this
	// line — without it the bursting looks like a bug.
	if queue.exact {
		fmt.Fprintf(b, "           Surplus sharing: %s\n",
			yesNo(queue.surplusSharing))
		if queue.equalFlowEnforcement {
			policy := queue.equalFlowTargetPolicy
			if policy == "" {
				policy = "slowest"
			}
			fmt.Fprintf(
				b,
				"           Equal-flow:     enforced=%s  policy=%s  target=%s  max_worker_cap=%s  cap_hits=%d  suppressed_bytes=%d  fail_open=%s\n",
				yesNo(queue.equalFlowEnforced),
				policy,
				formatBitsPerSecond(queue.equalFlowTargetPerFlowBPS),
				formatCoSBytes(queue.equalFlowMaxWorkerCapBytes),
				queue.equalFlowCapHitEvents,
				queue.equalFlowSuppressedGrantBytes,
				emptyDash(queue.equalFlowFailOpenReason),
			)
		}
	}
	// #709 / #751: per-queue OwnerProfile line renders only
	// the queue-scoped drain percentiles. The binding-scoped
	// fields (redirect_p99 / owner_pps / peer_pps) moved to
	// the interface header via renderBindingScopedTelemetry
	// so they are no longer repeated under every queue row
	// (#732). Non-exact / shared_exact queues keep an empty
	// per-queue histogram, so drainInvocations==0 correctly
	// suppresses the latency row.
	if queue.ownerWorker != nil && queue.drainInvocations > 0 {
		fmt.Fprintf(
			b,
			"           OwnerProfile: drain_p50=%s  drain_p99=%s  drain_invocations=%d\n",
			formatHistPercentileMicros(queue.drainLatencyHist, queue.drainInvocations, 50),
			formatHistPercentileMicros(queue.drainLatencyHist, queue.drainInvocations, 99),
			queue.drainInvocations,
		)
	}
	if queue.hasDrainShapeTelemetry() {
		// #760/#1369 overshoot-hunt row. This is queue-
		// scoped, so render it independently of the exact-only
		// OwnerProfile latency row. Non-exact rows need this
		// line to expose best-effort/uncapped bytes sent while
		// exact queues were still backlogged.
		fmt.Fprintf(
			b,
			"           DrainShape:   sent_bytes=%d  guarantee=%d  surplus=%d  nonexact_while_exact_backlogged=%d  park_root=%d  park_queue=%d\n",
			queue.drainSentBytes,
			queue.drainGuaranteeSentBytes,
			queue.drainSurplusSentBytes,
			queue.drainNonExactWhileExactBytes,
			queue.drainParkRootTokens,
			queue.drainParkQueueTokens,
		)
	}
	if queue.hasWaterfillTelemetry() {
		// #1628 guarantee-rate waterfill trace row. Phase-1 vs
		// Phase-2 admissions + eligible visits. Read WITH the
		// DrainShape park counters and QueuedBytes above to
		// diagnose Phase-2 lock-in (small class: phase1=0,
		// phase2>0, backlog+parks) vs healthy residual (large
		// above-cutoff class, or idle: no backlog/parks).
		fmt.Fprintf(
			b,
			"           Waterfill:    phase1_admit=%d  phase2_admit=%d  eligible_visits=%d  phase1_no_progress=%d\n",
			queue.waterfillPhase1Admissions,
			queue.waterfillPhase2Admissions,
			queue.waterfillEligibleVisits,
			queue.waterfillPhase1SelectedNoProgress,
		)
	}
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
		ownerPPS     uint64
		peerPPS      uint64
		redirectHist []uint64
		backupBytes  uint64
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

func histHasSample(hist []uint64) bool {
	for _, count := range hist {
		if count > 0 {
			return true
		}
	}
	return false
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

// -----------------------------------------------------------------------
// View-model construction (config + runtime join)
// -----------------------------------------------------------------------

func configuredCoSInterfaceViews(cfg *config.Config, status *userspace.ProcessStatus, selector string) []cosInterfaceView {
	runtimeIndex := buildCoSRuntimeIndex(status)
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
				ifName:         ifName,
				unit:           unitNum,
				cosUnit:        cosUnit,
				interfaceUnit:  interfaceUnit,
				interfaceState: runtimeIndex.lookup(ifName, logicalName, unitNum, interfaceUnit),
			})
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].name < views[j].name })
	return views
}

type cosRuntimeIndex struct {
	byName               map[string]*userspace.CoSInterfaceStatus
	byIfindex            map[int]*userspace.CoSInterfaceStatus
	bindingIfindexByName map[string]int
}

func buildCoSRuntimeIndex(status *userspace.ProcessStatus) cosRuntimeIndex {
	idx := cosRuntimeIndex{
		byName:               make(map[string]*userspace.CoSInterfaceStatus),
		byIfindex:            make(map[int]*userspace.CoSInterfaceStatus),
		bindingIfindexByName: make(map[string]int),
	}
	if status == nil {
		return idx
	}
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		if iface.InterfaceName != "" {
			idx.byName[iface.InterfaceName] = iface
			idx.byName[config.LinuxIfName(iface.InterfaceName)] = iface
		}
		if iface.Ifindex > 0 {
			idx.byIfindex[iface.Ifindex] = iface
		}
	}
	for _, binding := range status.Bindings {
		if binding.Interface == "" || binding.Ifindex <= 0 {
			continue
		}
		idx.bindingIfindexByName[binding.Interface] = binding.Ifindex
		idx.bindingIfindexByName[config.LinuxIfName(binding.Interface)] = binding.Ifindex
	}
	return idx
}

func (idx cosRuntimeIndex) lookup(ifName, logicalName string, unitNum int, unit *config.InterfaceUnit) *userspace.CoSInterfaceStatus {
	candidates := cosRuntimeCandidateNames(ifName, logicalName, unitNum, unit)
	for _, name := range candidates {
		if runtime := idx.byName[name]; runtime != nil {
			return runtime
		}
	}
	// #1278: Rust CoS runtime and metrics are keyed by egress ifindex. A
	// logical unit-zero CoS config can display as ge-0-0-1.0 while runtime
	// labels the same ifindex with another snapshot alias, hiding the row
	// from a name-only join.
	for _, name := range candidates {
		if ifindex := idx.bindingIfindexByName[name]; ifindex > 0 {
			if runtime := idx.byIfindex[ifindex]; runtime != nil {
				return runtime
			}
		}
	}
	return nil
}

func cosRuntimeCandidateNames(ifName, logicalName string, unitNum int, unit *config.InterfaceUnit) []string {
	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		for _, existing := range names {
			if existing == name {
				return
			}
		}
		names = append(names, name)
	}
	add(logicalName)
	add(config.LinuxIfName(logicalName))
	hasVLANBindingName := unit != nil && unit.VlanID > 0
	if unitNum == 0 {
		if hasVLANBindingName {
			vlanName := fmt.Sprintf("%s.%d", ifName, unit.VlanID)
			add(vlanName)
			add(config.LinuxIfName(vlanName))
		}
		add(ifName)
		add(config.LinuxIfName(ifName))
	}
	if unitNum != 0 && hasVLANBindingName {
		vlanName := fmt.Sprintf("%s.%d", ifName, unit.VlanID)
		add(vlanName)
		add(config.LinuxIfName(vlanName))
	}
	return names
}

func buildCoSQueueViews(cfg *config.Config, view cosInterfaceView) []cosQueueView {
	queueViews := make(map[int]cosQueueView)
	if cfg.ClassOfService != nil && view.cosUnit != nil {
		schedulerMap := cfg.ClassOfService.SchedulerMaps[view.cosUnit.SchedulerMap]
		if schedulerMap != nil {
			// #13088 (D7-09): Entries is a map, so ranging it directly
			// visited classes in randomized order. Two forwarding classes
			// sharing one queue ID (a committable shape — the strict
			// validator rejects only duplicate CLASS names, not shared
			// queue ids) then non-deterministically overwrote each other
			// in queueViews below, flipping the rendered Class / Priority
			// / Transmit rate / Buffer of the shared queue across
			// consecutive `show class-of-service interface` runs. Iterate
			// in ascending class order — the same order
			// buildClassOfServiceSnapshot (userspace/cos.go) emits the
			// entries onto the wire — so the shared-queue collapse is
			// stable: the lexicographically last class sharing a queue
			// owns the row, run after run.
			entryNames := make([]string, 0, len(schedulerMap.Entries))
			for className := range schedulerMap.Entries {
				entryNames = append(entryNames, className)
			}
			sort.Strings(entryNames)
			for _, className := range entryNames {
				entry := schedulerMap.Entries[className]
				class := cfg.ClassOfService.ForwardingClasses[className]
				if class == nil {
					continue
				}
				qv := queueViews[class.Queue]
				qv.queueID = class.Queue
				qv.forwardingClass = className
				if sched := cfg.ClassOfService.Schedulers[entry.Scheduler]; sched != nil {
					qv.exact = sched.TransmitRateExact
					// #6565 row 4 / #7422: ANY of the three transmit-rate
					// forms is a guarantee. Keying on TransmitRateBytes alone
					// made a `percent`/`remainder` scheduler read as
					// unguaranteed, and the gate at the runtime merge below
					// then DISCARDED the dataplane's resolved rate for it --
					// throwing away the true value while it was in hand.
					qv.guaranteeEnabled = sched.TransmitRateBytes > 0 ||
						sched.TransmitRatePercent > 0 || sched.TransmitRateRemainder
					qv.surplusSharing = sched.SurplusSharing
					qv.equalFlowEnforcement = sched.EqualFlowEnforcement
					qv.equalFlowTargetPolicy = sched.EqualFlowTargetPolicy
					qv.transmitRate = sched.TransmitRateBytes
					if sched.BufferSizeBytes > 0 {
						qv.bufferBytes = sched.BufferSizeBytes
					} else if sched.BufferSizePercent > 0 {
						qv.bufferBytes = cosPercentBufferBytes(cosUnitBurstPoolBytes(view.cosUnit), sched.BufferSizePercent)
					}
					if sched.Priority != "" {
						qv.priority = sched.Priority
					}
				}
				queueViews[class.Queue] = qv
			}
		}
	}
	configuredQueueCount := len(queueViews)
	// #13088 (D7-09): the dataplane admits any unit with a shaping rate or
	// a resolved scheduler map and then ALWAYS materializes a synthetic
	// best-effort fallback queue for unclassified traffic
	// (build_cos_iface_config, userspace-dp/src/afxdp/forwarding_build/
	// cos.rs: lowest unused queue id — preferring 0 —, priority "low",
	// guaranteed at the interface shaping rate, sized from the interface
	// burst pool). The formatter modeled only the configured scheduler-map
	// entries, so an admitted unit whose map omitted best-effort — or a
	// shaped unit with no scheduler-map at all — rendered fewer queues
	// than the dataplane actually shapes, down to "Queues: none" for the
	// shaped-no-map case with runtime status unavailable. Mirror the
	// dataplane fallback here so the config-only view matches what the
	// runtime merge below overlays when a snapshot exists.
	//
	// Placed AFTER configuredQueueCount so isOldJSONSyntheticDefaultQueue
	// still sees the pre-synthesis "nothing configured" signal it keys on;
	// the runtime merge overwrites these defaults with live values.
	if view.cosUnit != nil &&
		(view.cosUnit.ShapingRateBytes > 0 || configuredQueueCount > 0) {
		hasBestEffort := false
		for _, qv := range queueViews {
			if qv.forwardingClass == "best-effort" {
				hasBestEffort = true
				break
			}
		}
		if !hasBestEffort {
			queueID := 0
			for {
				if _, taken := queueViews[queueID]; !taken {
					break
				}
				queueID++
			}
			queueViews[queueID] = cosQueueView{
				queueID:          queueID,
				forwardingClass:  "best-effort",
				priority:         "low",
				transmitRate:     view.cosUnit.ShapingRateBytes,
				guaranteeEnabled: true,
				bufferBytes:      cosUnitBurstPoolBytes(view.cosUnit),
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
			if runtimeQueue.GuaranteeEnabled != nil {
				qv.guaranteeEnabled = *runtimeQueue.GuaranteeEnabled
			} else if isOldJSONSyntheticDefaultQueue(view, runtimeQueue, configuredQueueCount) {
				qv.guaranteeEnabled = true
			}
			qv.equalFlowEnforcement = runtimeQueue.EqualFlowEnforcement
			qv.equalFlowEnforced = runtimeQueue.EqualFlowEnforced
			if runtimeQueue.TransmitRateBytes > 0 && qv.guaranteeEnabled {
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
			// and on the Rust userspace.CoSQueueStatus. A queue that never got
			// drained leaves these at zero; the renderer gates on
			// drainInvocations > 0 so a silent queue stays silent.
			qv.drainSentBytes = runtimeQueue.DrainSentBytes
			qv.drainGuaranteeSentBytes = runtimeQueue.DrainGuaranteeSentBytes
			qv.drainSurplusSentBytes = runtimeQueue.DrainSurplusSentBytes
			qv.drainNonExactWhileExactBytes = runtimeQueue.DrainNonExactSentBytesWhileExactBacklogged
			qv.drainParkRootTokens = runtimeQueue.DrainParkRootTokens
			qv.drainParkQueueTokens = runtimeQueue.DrainParkQueueTokens
			qv.postDrainBackupBytes = runtimeQueue.PostDrainBackupBytes
			qv.equalFlowTargetPerFlowBPS = runtimeQueue.EqualFlowTargetPerFlowBPS
			qv.equalFlowMaxWorkerCapBytes = runtimeQueue.EqualFlowMaxWorkerCapBytes
			qv.equalFlowCapHitEvents = runtimeQueue.EqualFlowCapHitEvents
			qv.equalFlowSuppressedGrantBytes = runtimeQueue.EqualFlowSuppressedGrantBytes
			qv.equalFlowFailOpenReason = runtimeQueue.EqualFlowFailOpenReason
			if runtimeQueue.EqualFlowTargetPolicy != "" {
				qv.equalFlowTargetPolicy = runtimeQueue.EqualFlowTargetPolicy
			}
			// #1628 copy-through; rendered only when non-zero.
			// #1829 copy-through; rendered only when peak > 0.
			qv.sojournEwmaNS = runtimeQueue.SojournEwmaNS
			qv.sojournPeakNS = runtimeQueue.SojournPeakNS
			qv.sojournWindowedMinNS = runtimeQueue.SojournWindowedMinNS
			qv.waterfillPhase1Admissions = runtimeQueue.WaterfillPhase1Admissions
			qv.waterfillPhase2Admissions = runtimeQueue.WaterfillPhase2Admissions
			qv.waterfillEligibleVisits = runtimeQueue.WaterfillEligibleVisits
			qv.waterfillPhase1SelectedNoProgress = runtimeQueue.WaterfillPhase1SelectedNoProgress
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

func isOldJSONSyntheticDefaultQueue(view cosInterfaceView, runtimeQueue userspace.CoSQueueStatus, configuredQueueCount int) bool {
	return configuredQueueCount == 0 &&
		view.cosUnit != nil &&
		view.cosUnit.ShapingRateBytes > 0 &&
		runtimeQueue.QueueID == 0 &&
		!runtimeQueue.Exact &&
		runtimeQueue.TransmitRateBytes > 0
}
