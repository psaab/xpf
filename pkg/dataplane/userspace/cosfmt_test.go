package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func testCoSConfig() *config.Config {
	return &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort":    {Name: "best-effort", Queue: 0},
				"bandwidth-10mb": {Name: "bandwidth-10mb", Queue: 4},
			},
			Schedulers: map[string]*config.CoSScheduler{
				"be":   {Name: "be", TransmitRateBytes: 1_875_000},
				"10mb": {Name: "10mb", TransmitRateBytes: 1_250_000, TransmitRateExact: true},
			},
			SchedulerMaps: map[string]*config.CoSSchedulerMap{
				"bandwidth-limit": {
					Name: "bandwidth-limit",
					Entries: map[string]*config.CoSSchedulerMapEntry{
						"best-effort":    {ForwardingClass: "best-effort", Scheduler: "be"},
						"bandwidth-10mb": {ForwardingClass: "bandwidth-10mb", Scheduler: "10mb"},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {
							Unit:               80,
							ShapingRateBytes:   1_875_000,
							BurstSizeBytes:     65_536,
							SchedulerMap:       "bandwidth-limit",
							DSCPClassifier:     "wan-classifier",
							IEEE8021Classifier: "wan-pcp",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						80: {
							Number:         80,
							FilterOutputV4: "bandwidth-output",
						},
					},
				},
			},
		},
	}
}

func TestFormatCoSInterfaceSummaryShowsConfigOnlyInterface(t *testing.T) {
	out := FormatCoSInterfaceSummary(testCoSConfig(), nil, "reth0.80")
	for _, want := range []string{
		"Interface: reth0.80",
		"Scheduler map:            bandwidth-limit",
		"DSCP classifier:          wan-classifier",
		"IEEE 802.1 classifier:    wan-pcp",
		"DSCP rewrite-rule:        -",
		"Output filter (inet):     bandwidth-output",
		"Runtime:                  unavailable",
		"best-effort",
		"bandwidth-10mb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestFormatCoSInterfaceSummaryIncludesRuntimeQueueState(t *testing.T) {
	owner := uint32(7)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:       "reth0.80",
				OwnerWorkerID:       &owner,
				WorkerInstances:     2,
				NonemptyQueues:      1,
				RunnableQueues:      1,
				TimerLevel0Sleepers: 1,
				TimerLevel1Sleepers: 0,
				Queues: []CoSQueueStatus{
					{
						QueueID:             4,
						OwnerWorkerID:       &owner,
						ForwardingClass:     "bandwidth-10mb",
						Priority:            1,
						Exact:               true,
						TransmitRateBytes:   1_250_000,
						BufferBytes:         32 * 1024,
						QueuedPackets:       3,
						QueuedBytes:         4096,
						RunnableInstances:   1,
						ParkedInstances:     1,
						NextWakeupTick:      77,
						SurplusDeficitBytes: 2048,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "")
	for _, want := range []string{
		"Owner worker:             7",
		"Runtime workers:          2",
		"Runtime queues:           nonempty=1 runnable=1",
		"Timer wheel sleepers:     level0=1 level1=0",
		"Queue  Owner  Class",
		"bandwidth-10mb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "77") || !strings.Contains(out, "4.00 KiB") {
		t.Fatalf("expected runtime queue metrics in output:\n%s", out)
	}
}

// #915 (Copilot code-review #4): the per-queue formatter exposes
// a new `Surplus sharing: yes/no` line under exact queues so
// operators can see which exact queues have opted in. Pin both
// the "yes" and "no" cases. Non-exact queues never render this
// line (the formatter gates on `queue.exact`).
func TestFormatCoSInterfaceSummaryRendersSurplusSharingLineOnExactQueues(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"iperf-a": {Name: "iperf-a", Queue: 4},
				"iperf-b": {Name: "iperf-b", Queue: 5},
				"be":      {Name: "be", Queue: 0}, // non-exact, must NOT render line
			},
			Schedulers: map[string]*config.CoSScheduler{
				"sa":   {Name: "sa", TransmitRateBytes: 125_000_000, TransmitRateExact: true, SurplusSharing: true},
				"sb":   {Name: "sb", TransmitRateBytes: 1_250_000_000, TransmitRateExact: true, SurplusSharing: false},
				"sbe":  {Name: "sbe", TransmitRateBytes: 12_500_000, TransmitRateExact: false, SurplusSharing: false},
			},
			SchedulerMaps: map[string]*config.CoSSchedulerMap{
				"m": {
					Name: "m",
					Entries: map[string]*config.CoSSchedulerMapEntry{
						"iperf-a": {ForwardingClass: "iperf-a", Scheduler: "sa"},
						"iperf-b": {ForwardingClass: "iperf-b", Scheduler: "sb"},
						"be":      {ForwardingClass: "be", Scheduler: "sbe"},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {Unit: 80, ShapingRateBytes: 12_500_000_000, SchedulerMap: "m"},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{80: {Number: 80}}},
		}},
	}
	owner := uint32(0)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{{
			InterfaceName:   "reth0.80",
			OwnerWorkerID:   &owner,
			WorkerInstances: 1,
			Queues: []CoSQueueStatus{
				{QueueID: 4, OwnerWorkerID: &owner, ForwardingClass: "iperf-a", Priority: 5, Exact: true, TransmitRateBytes: 125_000_000, BufferBytes: 65536},
				{QueueID: 5, OwnerWorkerID: &owner, ForwardingClass: "iperf-b", Priority: 5, Exact: true, TransmitRateBytes: 1_250_000_000, BufferBytes: 65536},
				{QueueID: 0, OwnerWorkerID: &owner, ForwardingClass: "be", Priority: 5, Exact: false, TransmitRateBytes: 12_500_000, BufferBytes: 65536},
			},
		}},
	}
	out := FormatCoSInterfaceSummary(cfg, status, "reth0.80")
	if !strings.Contains(out, "Surplus sharing: yes") {
		t.Fatalf("expected `Surplus sharing: yes` line for opted-in iperf-a queue:\n%s", out)
	}
	if !strings.Contains(out, "Surplus sharing: no") {
		t.Fatalf("expected `Surplus sharing: no` line for hard-cap iperf-b queue:\n%s", out)
	}
	// Non-exact `be` queue must NOT render the line. Easiest check: count
	// occurrences of the literal "Surplus sharing:" prefix and verify it's
	// exactly two (one per exact queue), not three.
	count := strings.Count(out, "Surplus sharing:")
	if count != 2 {
		t.Fatalf("expected exactly 2 `Surplus sharing:` lines (one per exact queue, none on non-exact be); got %d:\n%s", count, out)
	}
}

func TestFormatCoSInterfaceSummaryShowsUnknownOwnerAsDash(t *testing.T) {
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				WorkerInstances: 1,
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	if !strings.Contains(out, "Owner worker:             -") {
		t.Fatalf("expected unknown owner to render as dash:\n%s", out)
	}
}

func TestFormatCoSInterfaceSummaryFiltersByBaseInterface(t *testing.T) {
	out := FormatCoSInterfaceSummary(testCoSConfig(), nil, "reth0")
	if !strings.Contains(out, "Interface: reth0.80") {
		t.Fatalf("expected base selector to include logical unit:\n%s", out)
	}
}

// #710/#718: admission-drop counters must render under each queue row
// with real values. Without this line, operators debugging the
// admission path (SFQ flow-share cap, buffer cap, ECN threshold) have
// no way to tell which admission decision is firing on the live system.
func TestFormatCoSInterfaceSummaryRendersAdmissionDropCounters(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:                 4,
						OwnerWorkerID:           &owner,
						ForwardingClass:         "bandwidth-10mb",
						Priority:                5,
						Exact:                   true,
						TransmitRateBytes:       1_250_000,
						BufferBytes:             32 * 1024,
						AdmissionFlowShareDrops: 12345,
						AdmissionBufferDrops:    0,
						AdmissionEcnMarked:      4567,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	want := "Drops: flow_share=12345  buffer=0  ecn_marked=4567"
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q in output:\n%s", want, out)
	}
}

// The formatter renders queues via tabwriter into a scratch buffer and
// interleaves the per-queue Drops line on a second pass. That second
// pass relies on a strict 1:1 mapping between the i-th table data line
// and the i-th element of `queues` (sorted by queue_id ascending).
// This test pins that invariant — a future refactor that, say, adds a
// blank separator line, re-orders queues, or attaches one queue's
// Drops row under another's data row would break this assertion while
// the single-queue tests above would still pass.
func TestFormatCoSInterfaceSummaryInterleavesPerQueueDropsInOrder(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:                 0,
						OwnerWorkerID:           &owner,
						ForwardingClass:         "best-effort",
						Priority:                5,
						Exact:                   true,
						TransmitRateBytes:       1_875_000,
						BufferBytes:             16 * 1024,
						AdmissionFlowShareDrops: 11,
						AdmissionBufferDrops:    22,
						AdmissionEcnMarked:      33,
					},
					{
						QueueID:                 4,
						OwnerWorkerID:           &owner,
						ForwardingClass:         "bandwidth-10mb",
						Priority:                5,
						Exact:                   true,
						TransmitRateBytes:       1_250_000,
						BufferBytes:             32 * 1024,
						AdmissionFlowShareDrops: 44,
						AdmissionBufferDrops:    55,
						AdmissionEcnMarked:      66,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")

	// Use content-unique markers rather than full row-text substrings
	// because tabwriter's column widths depend on cell content across
	// all rows — a new queue with a longer forwarding-class name in
	// the fixture would shift spacing and break a literal-row match
	// without actually breaking the invariant this test pins.
	//
	// The invariant: queue rows emit in queue_id ascending order, and
	// each queue's Drops line sits directly under its own data row
	// (not under the next queue's). We pin that with unique counter
	// values per queue (33 vs 66) so a misaligned interleave would be
	// detectable.
	q0Drops := "Drops: flow_share=11  buffer=22  ecn_marked=33"
	q4Drops := "Drops: flow_share=44  buffer=55  ecn_marked=66"
	// The word "best-effort" anchors queue 0's row. "bandwidth-10mb"
	// anchors queue 4's. Both strings appear exactly once in the
	// output (once in the data row).
	q0RowIdx := strings.Index(out, "best-effort")
	q0DropsIdx := strings.Index(out, q0Drops)
	q4RowIdx := strings.Index(out, "bandwidth-10mb")
	q4DropsIdx := strings.Index(out, q4Drops)

	if q0RowIdx < 0 || q0DropsIdx < 0 || q4RowIdx < 0 || q4DropsIdx < 0 {
		t.Fatalf("missing queue row anchor or drops line:\n%s", out)
	}
	// Strict order: q0 row, q0 drops, q4 row, q4 drops. A swap would
	// mean queue 0's row is followed by queue 4's Drops line (or
	// similar) — exactly the pathology this test guards against.
	if !(q0RowIdx < q0DropsIdx && q0DropsIdx < q4RowIdx && q4RowIdx < q4DropsIdx) {
		t.Fatalf(
			"drops-line interleave broken: q0Row=%d q0Drops=%d q4Row=%d q4Drops=%d\n%s",
			q0RowIdx, q0DropsIdx, q4RowIdx, q4DropsIdx, out,
		)
	}
}

// #709: The OwnerProfile line renders below the Drops line for exact
// queues with a single named owner worker. Fields: drain_p50 µs,
// drain_p99 µs, redirect_p99 µs, owner_pps, peer_pps. Anchor on
// non-zero values so a regression that swaps the ordering of the
// percentile calls fails loudly.
func TestFormatCoSInterfaceSummaryRendersOwnerProfileLineForExactQueues(t *testing.T) {
	owner := uint32(1)
	// Histogram layout (see umem.rs DRAIN_HIST_BUCKETS): bucket 0
	// = [0, 1024) ns ("0us"), bucket 1 = [1024, 2048) ns ("1us"),
	// ... bucket 5 = [2^14, 2^15) ns → lower bound 16384 ns = 16us.
	// We want p50 in bucket 1 and p99 in bucket 5:
	//   target50 = ceil(100 * 50 / 100) = 50; cumulative reaches 50 at
	//     bucket 1 (50 samples there).
	//   target99 = ceil(100 * 99 / 100) = 99; cumulative reaches 99 at
	//     bucket 5 (50 + 48 + 0 + 0 + 0 + 2 = 100 >= 99, and 98 < 99
	//     at bucket 4).
	hist := make([]uint64, 16)
	hist[1] = 50
	hist[2] = 48
	hist[5] = 2
	redirectHist := make([]uint64, 16)
	redirectHist[2] = 10 // p99 of redirect-acquire → bucket 2 = ~2us

	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:              4,
						OwnerWorkerID:        &owner,
						ForwardingClass:      "bandwidth-10mb",
						Priority:             1,
						Exact:                true,
						TransmitRateBytes:    1_250_000,
						BufferBytes:          32 * 1024,
						DrainLatencyHist:     hist,
						DrainInvocations:     100,
						DrainNoopInvocations: 30,
						RedirectAcquireHist:  redirectHist,
						OwnerPPS:             12345,
						PeerPPS:              6789,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	// #751: per-queue OwnerProfile line now renders only the
	// queue-scoped fields (drain_p50, drain_p99, drain_invocations).
	// p50 is "1us" (bucket 1 lower bound), p99 is "16us" (bucket 5 =
	// 2^14 ns = 16384 ns → 16µs).
	wantQueue := "OwnerProfile: drain_p50=1us  drain_p99=16us  drain_invocations=100"
	if !strings.Contains(out, wantQueue) {
		t.Fatalf("missing queue-scoped OwnerProfile line %q in output:\n%s", wantQueue, out)
	}
	// #732: binding-scoped fields now render once at the interface
	// level instead of being repeated under every queue row. p99 of
	// redirect-acquire is "2us" (bucket 2 = 2^11 ns = 2048 ns → 2µs).
	wantBinding := "Binding telemetry:        redirect_p99=2us  owner_pps=12345  peer_pps=6789"
	if !strings.Contains(out, wantBinding) {
		t.Fatalf("missing binding-scoped telemetry line %q in output:\n%s", wantBinding, out)
	}
	// Positional invariant: per-queue OwnerProfile must follow Drops
	// on the same queue row. Binding telemetry must appear ABOVE
	// the Queues table (it's an interface-level summary).
	dropsIdx := strings.Index(out, "Drops: flow_share=")
	ownerIdx := strings.Index(out, "OwnerProfile:")
	queuesIdx := strings.Index(out, "Queues:")
	bindingIdx := strings.Index(out, "Binding telemetry:")
	if dropsIdx < 0 || ownerIdx < 0 || ownerIdx <= dropsIdx {
		t.Fatalf("OwnerProfile line must render AFTER Drops line: drops=%d owner=%d\n%s",
			dropsIdx, ownerIdx, out)
	}
	if bindingIdx < 0 || queuesIdx < 0 || bindingIdx >= queuesIdx {
		t.Fatalf("Binding telemetry must render ABOVE the Queues table: binding=%d queues=%d\n%s",
			bindingIdx, queuesIdx, out)
	}
}

// #751 / #732: pin that two exact queues on the same interface with
// distinct drain profiles render distinct per-queue OwnerProfile
// lines. Pre-#751 the hist was sourced from a binding-wide rollup and
// both queues carried identical values (#732 symptom).
//
// Counter-factual: the two queues are seeded with DISJOINT bucket
// sets (q4 at bucket 1 = "1us", q6 at bucket 5 = "16us"). If the
// render collapsed them to a single distribution — the pre-#751
// behaviour — the formatted line for each queue would show the
// same p50/p99 and the distinct-percentile assertion would fail.
func TestFormatCoSInterfaceSummaryRendersDistinctPerQueueOwnerProfiles(t *testing.T) {
	owner := uint32(1)
	q4Hist := make([]uint64, 16)
	q4Hist[1] = 100 // p50 & p99 in bucket 1 → "1us"
	q6Hist := make([]uint64, 16)
	q6Hist[5] = 200 // p50 & p99 in bucket 5 → "16us"

	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:           4,
						OwnerWorkerID:     &owner,
						ForwardingClass:   "bandwidth-10mb",
						Priority:          1,
						Exact:             true,
						TransmitRateBytes: 1_250_000,
						BufferBytes:       32 * 1024,
						DrainLatencyHist:  q4Hist,
						DrainInvocations:  100,
					},
					{
						QueueID:           6,
						OwnerWorkerID:     &owner,
						ForwardingClass:   "bandwidth-iperf-c",
						Priority:          1,
						Exact:             true,
						TransmitRateBytes: 625_000,
						BufferBytes:       32 * 1024,
						DrainLatencyHist:  q6Hist,
						DrainInvocations:  200,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	wantQ4 := "OwnerProfile: drain_p50=1us  drain_p99=1us  drain_invocations=100"
	wantQ6 := "OwnerProfile: drain_p50=16us  drain_p99=16us  drain_invocations=200"
	if !strings.Contains(out, wantQ4) {
		t.Fatalf("missing q4 per-queue OwnerProfile %q:\n%s", wantQ4, out)
	}
	if !strings.Contains(out, wantQ6) {
		t.Fatalf("missing q6 per-queue OwnerProfile %q:\n%s", wantQ6, out)
	}
	// Counter-factual: the pre-#751 regression would produce identical
	// lines for both queues (both showing the same p50/p99). Pin that
	// the two OwnerProfile strings are actually distinct in the output.
	if strings.Count(out, wantQ4) != 1 || strings.Count(out, wantQ6) != 1 {
		t.Fatalf("expected exactly one per-queue OwnerProfile per queue; got:\n%s", out)
	}
}

// #709: Non-exact / no-owner queues do not get an OwnerProfile line.
// The plan's telemetry is only meaningful on single-owner exact queues
// (see docs/709-owner-hotspot-plan.md §4). Counter-factual: render a
// queue without OwnerWorkerID set and assert the line is absent while
// the Drops line still renders.
func TestFormatCoSInterfaceSummaryOmitsOwnerProfileForQueuesWithoutOwner(t *testing.T) {
	owner := uint32(2)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID: 4,
						// OwnerWorkerID intentionally nil: shared_exact
						// or non-exact queue has no single owner binding.
						ForwardingClass:      "bandwidth-10mb",
						Priority:             1,
						Exact:                true,
						TransmitRateBytes:    1_250_000,
						BufferBytes:          32 * 1024,
						DrainLatencyHist:     []uint64{0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						DrainInvocations:     5,
						DrainNoopInvocations: 0,
						OwnerPPS:             999,
						PeerPPS:              0,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	if !strings.Contains(out, "Drops: flow_share=0") {
		t.Fatalf("expected Drops line to still render for no-owner queue:\n%s", out)
	}
	if strings.Contains(out, "OwnerProfile:") {
		t.Fatalf("OwnerProfile line should NOT render for queue without owner_worker_id:\n%s", out)
	}
}

// #751: zeroed owner-profile telemetry now SUPPRESSES the per-queue
// OwnerProfile line entirely (drainInvocations == 0 ⇒ nothing to
// report). Same for the interface-level Binding telemetry line:
// when all three fields are zero there's nothing meaningful to show.
// This keeps "show class-of-service interface" tight on a freshly-
// deployed firewall with no traffic instead of surfacing rows of
// "0us 0us 0us 0 0" noise that operators learn to skip over and
// that dilute the signal when a real non-zero does appear.
//
// Counter-factual pin: if a future change started emitting the
// OwnerProfile line on zero-invocation queues, it would produce
// "drain_p50=0us" somewhere in the output and this test would
// catch it.
func TestFormatCoSInterfaceSummarySuppressesZeroedOwnerProfile(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:           4,
						OwnerWorkerID:     &owner,
						ForwardingClass:   "bandwidth-10mb",
						Priority:          1,
						Exact:             true,
						TransmitRateBytes: 1_250_000,
						BufferBytes:       32 * 1024,
						// All telemetry fields zero / empty.
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	if strings.Contains(out, "OwnerProfile:") {
		t.Fatalf("OwnerProfile line must not render for zeroed queue:\n%s", out)
	}
	if strings.Contains(out, "Binding telemetry:") {
		t.Fatalf("Binding telemetry line must not render when all fields are zero:\n%s", out)
	}
	// The Drops line MUST still render — zero-valued admission
	// counters are the signal that the counter path is wired; see
	// TestFormatCoSInterfaceSummaryRendersZeroAdmissionCounters
	// below for the same invariant documented there.
	if !strings.Contains(out, "Drops: flow_share=0") {
		t.Fatalf("Drops line must still render even with zeroed telemetry:\n%s", out)
	}
}

// Zero-valued counters MUST still render — operators need to see the
// counter is wired, otherwise "no output" is indistinguishable from
// "counter missing from the pipeline" when chasing #718 / #722.
func TestFormatCoSInterfaceSummaryRendersZeroAdmissionCounters(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:         4,
						OwnerWorkerID:   &owner,
						ForwardingClass: "bandwidth-10mb",
						// all admission counters default to 0
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	want := "Drops: flow_share=0  buffer=0  ecn_marked=0"
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q in output (zero-valued drops must still render):\n%s", want, out)
	}
}
