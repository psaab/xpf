package api

import (
	"math"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #925 Phase 2: emitWorkerRuntime must surface the per-worker
// `xpf_userspace_worker_dead` gauge driven by ProcessStatus.WorkerRuntime[i].Dead.
// This test pins the wire shape so a future refactor can't silently drop it
// (the regression Phase 2 was created to prevent: a panic going unnoticed
// because no metric exposes the supervisor's mark-dead atomic).
//
// Test strategy: construct an xpfCollector with just the worker descriptors
// initialized (the rest are nil — emitWorkerRuntime only touches the worker
// fields). Drive a hand-built ProcessStatus through emitWorkerRuntime and
// collect the resulting metrics off the channel. Inspect each metric's
// protobuf representation to find the worker_dead series and assert value.
func TestEmitWorkerRuntime_DeadGaugeReflectsDeadFlag(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()

	// Mixed fixture: 3 workers, only the middle one dead.
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID: 0, CoSQueueLeaseAcquireV8Calls: 7,
				CoSQueueLeaseAcquireV8GrantedBytes: 4096,
				// #1782 Step-1 cold-start CoS instruments.
				CoSWheelTicksAdvancedTotal:            12_000_000,
				CoSWheelTicksAdvancedMax:              11_000_000,
				CoSQueueLeaseUndergrantSeqlockGiveUp:  1,
				CoSQueueLeaseUndergrantCapZero:        2,
				CoSQueueLeaseUndergrantEpochRotated:   3,
				CoSQueueLeaseUndergrantShareExhausted: 4,
				CoSQueueLeaseUndergrantClassCap:       5,
				CoSQueueLeaseUndergrantOutstandingCap: 6,
				SessionTableEntries:                   17,
				MaxSessions:                           100,
				// #4800: distinct per worker, and distinct from every other
				// field on the same worker, so a collector wired to the wrong
				// quantity cannot pass by coincidence.
				NewFlowInstalls: 149,
				Dead:            false,
			},
			{
				WorkerID: 1, CoSQueueLeaseAcquireV8Calls: 11,
				CoSQueueLeaseAcquireV8GrantedBytes: 0,
				SessionTableEntries:                19,
				MaxSessions:                        100,
				NewFlowInstalls:                    151,
				Dead:                               true,
			},
			{
				WorkerID: 2, CoSQueueLeaseAcquireV8Calls: 13,
				CoSQueueLeaseAcquireV8GrantedBytes: 8192,
				SessionTableEntries:                23,
				MaxSessions:                        100,
				NewFlowInstalls:                    157,
				Dead:                               false,
			},
		},
	}

	got := collectFromEmitWorkerRuntime(t, c, status)

	// Each worker emits 9 counters + 1 dead gauge + 1 last-60s gauge,
	// 1 window-width gauge, 2 session-table gauges +
	// 1 NAT reverse-key collision counter (#1760) = 15 metrics +
	// #1621 cold-path always-emitted metrics (4 per-worker scalars
	// + clock_source gauge + snapshot_failed counter = 6) = 21 +
	// #1782 Step-1 cold-start CoS instruments (wheel sum counter +
	// wheel max gauge + 6 per-cause under-grant counters = 8) = 29 +
	// #1861 install-refusal trio (create drops + admission refused +
	// install partial counters) = 32 +
	// #4800 per-worker transit new-flow install counter = 33.
	// #6751 distinct-source subset of the reverse-key collision counter = 34.
	// #7919 by-key lookup misses, split by cause (no-handle + stale-handle +
	// key-mismatch = 3) = 37. Three metrics rather than one `cause`-labelled
	// family: the discriminator that matters is PER WORKER, and the measured
	// symptom is non-uniform across concurrent flows, so a collapsed form
	// would destroy exactly what they were added to show.
	// Per-slot/per-bucket metrics need non-empty Vec fields which
	// these test fixtures don't populate, so they're zero here.
	if len(got) != 3*37 {
		t.Fatalf("emitWorkerRuntime: want %d metrics for 3 workers, got %d", 3*37, len(got))
	}

	// Gather just the dead-gauge entries, keyed by worker_id label.
	// Filter by descriptor pointer (not Desc().String() which is not a
	// stable public API and could shift with prometheus/client_golang
	// updates). Copilot review on PR #1186 caught the previous
	// substring approach as brittle.
	deadByWorker := make(map[string]float64)
	for _, m := range got {
		if m.Desc() != c.workerDead {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		if pb.Gauge == nil {
			t.Fatalf("xpf_userspace_worker_dead must be a Gauge, got %+v", &pb)
		}
		var workerID string
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "worker_id" {
				workerID = lp.GetValue()
			}
		}
		if workerID == "" {
			t.Fatalf("xpf_userspace_worker_dead emission missing worker_id label: %+v", &pb)
		}
		deadByWorker[workerID] = pb.Gauge.GetValue()
	}

	if len(deadByWorker) != 3 {
		t.Fatalf("expected one xpf_userspace_worker_dead emission per worker (3), got %d", len(deadByWorker))
	}
	for wid, want := range map[string]float64{
		"0": 0,
		"1": 1,
		"2": 0,
	} {
		if got := deadByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_dead{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}

	leaseCallsByWorker := metricValuesByWorker(t, got, c.workerCoSQueueLeaseAcquireV8Calls, true)
	if len(leaseCallsByWorker) != 3 {
		t.Fatalf("expected one lease-acquire-calls emission per worker (3), got %d", len(leaseCallsByWorker))
	}
	for wid, want := range map[string]float64{"0": 7, "1": 11, "2": 13} {
		if got := leaseCallsByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
	leaseBytesByWorker := metricValuesByWorker(t, got, c.workerCoSQueueLeaseAcquireV8GrantedBytes, true)
	if len(leaseBytesByWorker) != 3 {
		t.Fatalf("expected one lease-acquire-bytes emission per worker (3), got %d", len(leaseBytesByWorker))
	}
	for wid, want := range map[string]float64{"0": 4096, "1": 0, "2": 8192} {
		if got := leaseBytesByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
	// #1782 Step-1: wheel tick-advance sum (counter) + single-call max
	// (gauge) per worker; zero for workers that never primed a CoS root.
	wheelTotalByWorker := metricValuesByWorker(t, got, c.workerCoSWheelTicksAdvancedTotal, true)
	for wid, want := range map[string]float64{"0": 12_000_000, "1": 0, "2": 0} {
		if got := wheelTotalByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_cos_wheel_ticks_advanced_total{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
	wheelMaxByWorker := metricValuesByWorker(t, got, c.workerCoSWheelTicksAdvancedMax, false)
	for wid, want := range map[string]float64{"0": 11_000_000, "1": 0, "2": 0} {
		if got := wheelMaxByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_cos_wheel_ticks_advanced_max{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
	// #1782 Step-1: per-cause under-grant family — all six causes emit
	// for every worker (zero baseline included), keyed (worker, cause).
	undergrant := make(map[string]map[string]float64)
	for _, m := range got {
		if m.Desc() != c.workerCoSQueueLeaseUndergrant {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		if pb.Counter == nil {
			t.Fatalf("undergrant family must be a Counter: %+v", &pb)
		}
		var workerID, cause string
		for _, lp := range pb.GetLabel() {
			switch lp.GetName() {
			case "worker_id":
				workerID = lp.GetValue()
			case "cause":
				cause = lp.GetValue()
			}
		}
		if workerID == "" || cause == "" {
			t.Fatalf("undergrant emission missing worker_id/cause label: %+v", &pb)
		}
		if undergrant[workerID] == nil {
			undergrant[workerID] = make(map[string]float64)
		}
		undergrant[workerID][cause] = pb.Counter.GetValue()
	}
	for wid, byCause := range undergrant {
		if len(byCause) != 6 {
			t.Errorf("worker %s: want 6 under-grant cause series, got %d (%v)", wid, len(byCause), byCause)
		}
	}
	for cause, want := range map[string]float64{
		"seqlock_give_up": 1, "cap_zero": 2, "epoch_rotated": 3,
		"share_exhausted": 4, "class_cap": 5, "outstanding_cap": 6,
	} {
		if got := undergrant["0"][cause]; got != want {
			t.Errorf("xpf_userspace_worker_cos_queue_lease_undergrant_total{worker_id=\"0\",cause=%q} = %v, want %v", cause, got, want)
		}
	}
	entriesByWorker := metricValuesByWorker(t, got, c.workerSessionTableEntries, false)
	for wid, want := range map[string]float64{"0": 17, "1": 19, "2": 23} {
		if got := entriesByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_session_table_entries{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
	capacityByWorker := metricValuesByWorker(t, got, c.workerSessionTableCapacity, false)
	for wid, want := range map[string]float64{"0": 100, "1": 100, "2": 100} {
		if got := capacityByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_session_table_capacity{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
	// #4800: per-worker transit new-flow installs. Asserted per worker_id with
	// a distinct value each, exactly like the sibling per-worker series above,
	// because this is the ONLY input to both cross-worker gates the ceiling
	// analyzer runs (`active_workers < 3`, `max_worker_share > 0.60`) — a
	// collector emitting the right descriptor, label and type while carrying a
	// different worker's number, or a different field's number, would leave
	// both gates quietly reading the wrong distribution.
	//
	// RED on revert: changing the emit to `float64(w.SessionInstallPartial)`
	// (or any other WorkerRuntimeStatus field) in metrics_userspace.go fails
	// these on their messages; a per-worker count assertion alone would not
	// have noticed, which is what the pre-#6927 `len(got) != 3*33` check was.
	newFlowsByWorker := metricValuesByWorker(t, got, c.workerNewFlowInstalls, true)
	if len(newFlowsByWorker) != 3 {
		t.Fatalf("expected one new-flow-installs emission per worker (3), got %d", len(newFlowsByWorker))
	}
	for wid, want := range map[string]float64{"0": 149, "1": 151, "2": 157} {
		if got := newFlowsByWorker[wid]; got != want {
			t.Errorf("xpf_userspace_worker_new_flow_installs_total{worker_id=%q} = %v, want %v", wid, got, want)
		}
	}
}

// All-healthy fixture: dead gauge must be 0 for every worker, never absent.
// The metric being always-present (instead of absent until first panic) is a
// deliberate choice from #925 Phase 2 plan §10/Q2 — Prometheus alerts that
// fire on metric absence vs. value=1 are notoriously fragile.
func TestEmitWorkerRuntime_DeadGaugeZeroForHealthyWorkers(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()

	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{WorkerID: 0, Dead: false},
			{WorkerID: 5, Dead: false},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)

	deads := 0
	for _, m := range got {
		if m.Desc() != c.workerDead {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		deads++
		if v := pb.Gauge.GetValue(); v != 0 {
			t.Errorf("healthy worker should emit dead=0, got %v: %+v", v, &pb)
		}
	}
	if deads != 2 {
		t.Fatalf("expected 2 dead-gauge emissions for 2 healthy workers, got %d", deads)
	}
}

func newCollectorWithWorkerDescsOnly() *xpfCollector {
	// Only the worker counter descriptors plus the dead gauge
	// are needed by emitWorkerRuntime; the rest stay nil and are not
	// exercised by this test.
	mk := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, []string{"worker_id"}, nil)
	}
	// #1621: cold-path emission requires per-(worker, slot[, le])
	// descriptors with different label sets.
	mkSlot := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "zone_pair_slot"}, nil)
	}
	mkBucket := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "zone_pair_slot", "le"}, nil)
	}
	mkSource := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "source"}, nil)
	}
	// #1782 Step-1: per-cause under-grant family.
	mkCause := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "cause"}, nil)
	}
	// #1635 v3 per-zone-pair descriptors.
	mkZonePair := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "from_zone", "to_zone"}, nil)
	}
	mkZonePairBucket := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "from_zone", "to_zone", "le"}, nil)
	}
	mkVersion := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name,
			[]string{"worker_id", "version"}, nil)
	}
	return &xpfCollector{
		workerWallSecs:                           mk("xpf_userspace_worker_wall_seconds_total"),
		workerActiveSecs:                         mk("xpf_userspace_worker_active_seconds_total"),
		workerIdleSpinSecs:                       mk("xpf_userspace_worker_idle_spin_seconds_total"),
		workerIdleBlockSecs:                      mk("xpf_userspace_worker_idle_block_seconds_total"),
		workerThreadCPUSecs:                      mk("xpf_userspace_worker_thread_cpu_seconds_total"),
		workerThreadCPUSecsLast60s:               mk("xpf_userspace_worker_thread_cpu_seconds_last_60s"),
		workerThreadCPUWindowSecs:                mk("xpf_userspace_worker_thread_cpu_window_seconds"),
		workerWorkLoops:                          mk("xpf_userspace_worker_work_loops_total"),
		workerIdleLoops:                          mk("xpf_userspace_worker_idle_loops_total"),
		workerSessionVolumeHighWater:             mk("xpf_userspace_worker_session_volume_high_water"),
		workerCoSQueueLeaseAcquireV8Calls:        mk("xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total"),
		workerCoSQueueLeaseAcquireV8GrantedBytes: mk("xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total"),
		// #1782 Step-1 cold-start CoS instruments.
		workerCoSWheelTicksAdvancedTotal: mk("xpf_userspace_worker_cos_wheel_ticks_advanced_total"),
		workerCoSWheelTicksAdvancedMax:   mk("xpf_userspace_worker_cos_wheel_ticks_advanced_max"),
		workerCoSQueueLeaseUndergrant:    mkCause("xpf_userspace_worker_cos_queue_lease_undergrant_total"),
		workerSessionTableEntries:        mk("xpf_userspace_worker_session_table_entries"),
		workerSessionTableCapacity:       mk("xpf_userspace_worker_session_table_capacity"),
		workerNatReverseKeyCollisions:    mk("xpf_userspace_worker_session_nat_reverse_key_collisions_total"),
		// #6751: the DIFFERENT-SOURCE subset of the collision counter above.
		workerNatReverseKeyCollisionsDistinctSrc: mk(
			"xpf_userspace_worker_session_nat_reverse_key_collisions_distinct_src_total"),
		// #7919 by-key lookup misses, split by cause. Three separate metrics
		// rather than one `cause`-labelled family: the split that matters is
		// PER WORKER, and collapsing these would destroy the discriminator.
		workerSessionLookupMissNoHandle:    mk("xpf_userspace_worker_session_lookup_miss_no_handle_total"),
		workerSessionLookupMissStaleHandle: mk("xpf_userspace_worker_session_lookup_miss_stale_handle_total"),
		workerSessionLookupMissKeyMismatch: mk("xpf_userspace_worker_session_lookup_miss_key_mismatch_total"),
		// #1861 install-refusal trio.
		workerSessionCreateDrops:             mk("xpf_userspace_worker_session_create_drops_total"),
		workerSessionInstallAdmissionRefused: mk("xpf_userspace_worker_session_install_admission_refused_total"),
		workerSessionInstallPartial:          mk("xpf_userspace_worker_session_install_partial_total"),
		// #4800 per-worker transit new-flow installs.
		workerNewFlowInstalls: mk("xpf_userspace_worker_new_flow_installs_total"),
		workerDead:            mk("xpf_userspace_worker_dead"),
		// #1621 cold-path descriptors.
		workerColdPathBucket:              mkBucket("xpf_userspace_worker_cold_path_ns_bucket"),
		workerColdPathSamples:             mkSlot("xpf_userspace_worker_cold_path_samples_total"),
		workerColdPathSumNS:               mkSlot("xpf_userspace_worker_cold_path_sum_ns_total"),
		workerColdPathAliasSeen:           mkSlot("xpf_userspace_worker_cold_path_alias_seen"),
		workerColdPathSamplePhase:         mk("xpf_userspace_worker_cold_path_sample_phase_total"),
		workerColdPathWrapperUnderflow:    mk("xpf_userspace_worker_cold_path_wrapper_underflow_count_total"),
		workerColdPathWrapperNSBaseline:   mk("xpf_userspace_worker_cold_path_wrapper_ns_baseline"),
		workerColdPathNSPerTSCQ32:         mk("xpf_userspace_worker_cold_path_ns_per_tsc_q32"),
		workerColdPathClockSource:         mkSource("xpf_userspace_worker_cold_path_clock_source"),
		workerColdPathSnapshotFailedTotal: mk("xpf_userspace_worker_cold_path_snapshot_failed_total"),
		workerColdPathBucketV3:            mkZonePairBucket("xpf_userspace_worker_cold_path_ns_bucket_v3"),
		workerColdPathSamplesV3:           mkZonePair("xpf_userspace_worker_cold_path_samples_v3_total"),
		workerColdPathSumNSV3:             mkZonePair("xpf_userspace_worker_cold_path_sum_ns_v3_total"),
		workerColdPathBuilderCollisionV3:  mkZonePair("xpf_userspace_worker_cold_path_builder_collision_v3"),
		workerColdPathOverflowActive:      mk("xpf_userspace_worker_cold_path_overflow_active"),
		workerColdPathLayoutVersion:       mkVersion("xpf_userspace_worker_cold_path_layout_version"),
		workerColdPathLayoutUnknownTotal:  mkVersion("xpf_userspace_worker_cold_path_layout_version_unknown"),
	}
}

// collectFromEmitWorkerRuntime drives emitWorkerRuntime into an
// unbuffered channel from a goroutine, then drains. Running the
// producer in a goroutine (rather than synchronously into a fixed-size
// buffer) means a future engineer adding a 9th per-worker metric
// can't deadlock this helper — the test would still complete
// correctly, just with more metrics in the returned slice.
// (Gemini Pro 3 round-2 review of #1186 caught the previous
// hardcoded `*8` buffer as a latent deadlock trap.)
func collectFromEmitWorkerRuntime(
	t *testing.T,
	c *xpfCollector,
	status dpuserspace.ProcessStatus,
) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitWorkerRuntime(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	// Sanity: every returned metric should be one of the worker
	// descriptors we initialized. Pointer-equality is stable across
	// prometheus/client_golang versions.
	expected := map[*prometheus.Desc]struct{}{
		c.workerWallSecs:                           {},
		c.workerActiveSecs:                         {},
		c.workerIdleSpinSecs:                       {},
		c.workerIdleBlockSecs:                      {},
		c.workerThreadCPUSecs:                      {},
		c.workerThreadCPUSecsLast60s:               {},
		c.workerThreadCPUWindowSecs:                {},
		c.workerWorkLoops:                          {},
		c.workerIdleLoops:                          {},
		c.workerSessionVolumeHighWater:             {},
		c.workerCoSQueueLeaseAcquireV8Calls:        {},
		c.workerCoSQueueLeaseAcquireV8GrantedBytes: {},
		// #1782 Step-1 cold-start CoS instruments.
		c.workerCoSWheelTicksAdvancedTotal:         {},
		c.workerCoSWheelTicksAdvancedMax:           {},
		c.workerCoSQueueLeaseUndergrant:            {},
		c.workerSessionTableEntries:                {},
		c.workerSessionTableCapacity:               {},
		c.workerNatReverseKeyCollisions:            {},
		c.workerNatReverseKeyCollisionsDistinctSrc: {},
		// #7919 by-key lookup misses, split by cause.
		c.workerSessionLookupMissNoHandle:    {},
		c.workerSessionLookupMissStaleHandle: {},
		c.workerSessionLookupMissKeyMismatch: {},
		// #1861 install-refusal trio.
		c.workerSessionCreateDrops:             {},
		c.workerSessionInstallAdmissionRefused: {},
		c.workerSessionInstallPartial:          {},
		// #4800 per-worker transit new-flow installs.
		c.workerNewFlowInstalls: {},
		c.workerDead:            {},
		// #1621 cold-path descriptors.
		c.workerColdPathBucket:              {},
		c.workerColdPathSamples:             {},
		c.workerColdPathSumNS:               {},
		c.workerColdPathAliasSeen:           {},
		c.workerColdPathSamplePhase:         {},
		c.workerColdPathWrapperUnderflow:    {},
		c.workerColdPathWrapperNSBaseline:   {},
		c.workerColdPathNSPerTSCQ32:         {},
		c.workerColdPathClockSource:         {},
		c.workerColdPathSnapshotFailedTotal: {},
		// #1635 v3 cold-path descriptors.
		c.workerColdPathBucketV3:           {},
		c.workerColdPathSamplesV3:          {},
		c.workerColdPathSumNSV3:            {},
		c.workerColdPathBuilderCollisionV3: {},
		c.workerColdPathOverflowActive:     {},
		c.workerColdPathLayoutVersion:      {},
		c.workerColdPathLayoutUnknownTotal: {},
	}
	for _, m := range got {
		if _, ok := expected[m.Desc()]; !ok {
			t.Fatalf("unexpected metric leaked from emitWorkerRuntime: %s", m.Desc())
		}
	}
	return got
}

func TestEmitUserspaceEventStreamMetrics(t *testing.T) {
	mkNoLabel := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, nil, nil)
	}
	mkOneLabel := func(name, label string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, []string{label}, nil)
	}
	c := &xpfCollector{
		userspaceEventStreamFramesTotal:          mkOneLabel("xpf_userspace_event_stream_frames_total", "direction"),
		userspaceEventStreamProducerFramesTotal:  mkOneLabel("xpf_userspace_event_stream_producer_frames_total", "outcome"),
		userspaceEventStreamDecodeErrorsTotal:    mkNoLabel("xpf_userspace_event_stream_decode_errors_total"),
		userspaceEventStreamSequenceGapsTotal:    mkNoLabel("xpf_userspace_event_stream_sequence_gaps_total"),
		userspaceEventStreamDataplaneEventsTotal: mkOneLabel("xpf_userspace_event_stream_dataplane_events_total", "type"),
		userspaceEventStreamDataplaneDropsTotal:  mkOneLabel("xpf_userspace_event_stream_dataplane_event_drops_total", "type"),
		userspaceEventStreamUnknownDropsTotal:    mkNoLabel("xpf_userspace_event_stream_unknown_frame_drops_total"),
	}
	status := dpuserspace.ProcessStatus{
		EventStreamSent:                 101,
		EventStreamDropped:              7,
		EventStreamWriteStalls:          13,
		EventStreamReplayEvictions:      4,
		EventStreamSessionCloseSent:     90,
		EventStreamSessionCloseDropped:  3,
		EventStreamSessionCreateSent:    12,
		EventStreamSessionCreateDropped: 1,
		EventStream: &dpuserspace.EventStreamStatus{
			FramesRead:          11,
			FramesWritten:       7,
			DecodeErrors:        2,
			SeqGaps:             3,
			PolicyDenyEvents:    5,
			ScreenDropEvents:    6,
			FilterLogEvents:     8,
			SessionCloseEvents:  14,
			SessionCreateEvents: 15,
			PolicyDenyDrops:     1,
			ScreenDropDrops:     4,
			FilterLogDrops:      9,
			SessionCloseDrops:   2,
			SessionCreateDrops:  3,
			UnknownFrameDrops:   10,
		},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceEventStream(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	assertCounterClose(t, got, c.userspaceEventStreamFramesTotal, map[string]string{"direction": "read"}, 11)
	assertCounterClose(t, got, c.userspaceEventStreamFramesTotal, map[string]string{"direction": "written"}, 7)
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "sent"}, 101)
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "dropped"}, 7)
	// #2381 / #2382: the stalled-consumer and replay-eviction telemetry-loss
	// counters surface under distinct outcome labels on the same metric.
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "write_stalled"}, 13)
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "replay_evicted"}, 4)
	// #2512: per-kind RT_FLOW close/create producer accounting.
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "session_close_sent"}, 90)
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "session_close_dropped"}, 3)
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "session_create_sent"}, 12)
	assertCounterClose(t, got, c.userspaceEventStreamProducerFramesTotal, map[string]string{"outcome": "session_create_dropped"}, 1)
	assertCounterClose(t, got, c.userspaceEventStreamDecodeErrorsTotal, nil, 2)
	assertCounterClose(t, got, c.userspaceEventStreamSequenceGapsTotal, nil, 3)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneEventsTotal, map[string]string{"type": "policy_deny"}, 5)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneEventsTotal, map[string]string{"type": "screen_drop"}, 6)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneEventsTotal, map[string]string{"type": "filter_log"}, 8)
	// #2510: session-close / session-create RT_FLOW volume must be observable.
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneEventsTotal, map[string]string{"type": "session_close"}, 14)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneEventsTotal, map[string]string{"type": "session_create"}, 15)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneDropsTotal, map[string]string{"type": "policy_deny"}, 1)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneDropsTotal, map[string]string{"type": "screen_drop"}, 4)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneDropsTotal, map[string]string{"type": "filter_log"}, 9)
	// #2510: close-frame LOSS must be observable.
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneDropsTotal, map[string]string{"type": "session_close"}, 2)
	assertCounterClose(t, got, c.userspaceEventStreamDataplaneDropsTotal, map[string]string{"type": "session_create"}, 3)
	assertCounterClose(t, got, c.userspaceEventStreamUnknownDropsTotal, nil, 10)
}

func newSchedulerCounterMetricsStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone dmz;
        security-zone trust;
        security-zone untrust;
    }
    policy-stats {
        system-wide enable;
    }
    policies {
        from-zone trust to-zone dmz {
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone trust to-zone untrust {
            policy scheduled-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
        global {
            policy global-scheduled {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func globalCounterPolicyID(t *testing.T, store *configstore.Store, ruleName string) uint32 {
	t.Helper()
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	for i, rule := range cfg.Security.GlobalPolicies {
		if rule != nil && rule.Name == ruleName {
			// Global policy IDs start after all zone-pair policy sets.
			return policyCounterID(uint32(len(cfg.Security.Policies)), i)
		}
	}
	t.Fatalf("global policy %q not found", ruleName)
	return 0
}

func TestCollectPolicyCountersExposesSparseAndGlobalPolicyIDs(t *testing.T) {
	store := newSchedulerCounterMetricsStore(t)
	scheduledID := scheduledCounterPolicyID(t, store)
	globalID := globalCounterPolicyID(t, store, "global-scheduled")
	// #7016: see TestCollectPolicyCountersNilSlotsNoPanic -- initialize the
	// real descriptor set, then override the asserted one.
	c := &xpfCollector{srv: &Server{store: store}}
	c.initPolicyDescriptors()
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total",
		"policy hits",
		[]string{"from_zone", "to_zone", "policy_name"},
		nil,
	)
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			1:           {Packets: 99, Bytes: 9900},
			scheduledID: {Packets: 17, Bytes: 1700},
			globalID:    {Packets: 31, Bytes: 3100},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.collectPolicyCounters(ch, dp)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}

	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone":   "trust",
		"to_zone":     "untrust",
		"policy_name": "scheduled-allow",
	}, 17)
	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone":   "*",
		"to_zone":     "*",
		"policy_name": "global-scheduled",
	}, 31)
}

// TestCollectPolicyCountersGatedOnPolicyStats verifies the #2008 M4 gate
// AND the #3074 per-policy `then count` override on the Prometheus
// collector. With `security policy-stats system-wide enable` absent (the
// Junos default): a policy WITHOUT `then count` (plain-allow) emits no
// per-policy hit counter (the M4 gate), while a policy WITH `then count`
// (scheduled-allow) DOES emit its counter — `then count` opts that policy
// into per-policy counting independent of the global knob (Junos
// per-policy `count`). Before #3074 `then count` was inert and this
// collector emitted nothing with the knob off.
func TestCollectPolicyCountersGatedOnPolicyStats(t *testing.T) {
	store := newSchedulerCounterAPIStore(t) // no policy-stats enabled
	if store.ActiveConfig().Security.PolicyStatsEnabled {
		t.Fatal("test precondition: policy-stats must be disabled in this store")
	}
	scheduledID := scheduledCounterPolicyID(t, store)
	// #7016: see TestCollectPolicyCountersNilSlotsNoPanic -- initialize the
	// real descriptor set, then override the asserted one.
	c := &xpfCollector{srv: &Server{store: store}}
	c.initPolicyDescriptors()
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total",
		"policy hits",
		[]string{"from_zone", "to_zone", "policy_name"},
		nil,
	)
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			// plain-allow occupies a zone-pair slot; give it a nonzero
			// value to prove the M4 gate still suppresses a no-`then count`
			// policy with the knob off.
			0:           {Packets: 99, Bytes: 9900},
			scheduledID: {Packets: 17, Bytes: 1700},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.collectPolicyCounters(ch, dp)
		close(ch)
	}()
	var got []prometheus.Metric
	var hits int
	for m := range ch {
		got = append(got, m)
		// #7016: count only xpf_policy_hits_total. collectPolicyCounters also
		// emits the xpf_policy_counters_unpublished_rules gauge on EVERY path,
		// so a bare len(got) no longer measures the M4 gate. The fqName is
		// EXTRACTED, not substring-matched: Desc.String() embeds the HELP text,
		// and that gauge's HELP cross-references xpf_policy_hits_total.
		if descFQName(m.Desc().String()) == "xpf_policy_hits_total" {
			hits++
		}
	}
	// #3074: scheduled-allow (then count) is emitted even with the knob off.
	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone":   "trust",
		"to_zone":     "untrust",
		"policy_name": "scheduled-allow",
	}, 17)
	// M4 gate: plain-allow (no then count) must NOT be emitted with the
	// knob off, so scheduled-allow is the ONLY policy-hit sample.
	if hits != 1 {
		t.Fatalf("policy-stats off: want exactly 1 xpf_policy_hits_total sample (scheduled-allow, then count), got %d", hits)
	}
}

func TestEmitThreeColorPolicerCounters(t *testing.T) {
	c := &xpfCollector{
		threeColorPolicerPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_packets_total",
			"packets",
			[]string{"policer", "color"},
			nil,
		),
		threeColorPolicerBytesTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_bytes_total",
			"bytes",
			[]string{"policer", "color"},
			nil,
		),
		threeColorPolicerDropsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drops_total",
			"drops",
			[]string{"policer"},
			nil,
		),
		threeColorPolicerDropBytes: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drop_bytes_total",
			"drop bytes",
			[]string{"policer"},
			nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		ThreeColorPolicerCounters: []dpuserspace.ThreeColorPolicerStatus{
			{
				Name:          "wan-egress",
				GreenPackets:  10,
				GreenBytes:    1000,
				YellowPackets: 3,
				YellowBytes:   300,
				RedPackets:    2,
				RedBytes:      200,
				DropPackets:   2,
				DropBytes:     200,
			},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitThreeColorPolicerCounters(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	if len(got) != 8 {
		t.Fatalf("emitThreeColorPolicerCounters: want 8 metrics, got %d", len(got))
	}

	assertCounterClose(t, got, c.threeColorPolicerPacketsTotal, map[string]string{"policer": "wan-egress", "color": "green"}, 10)
	assertCounterClose(t, got, c.threeColorPolicerBytesTotal, map[string]string{"policer": "wan-egress", "color": "green"}, 1000)
	assertCounterClose(t, got, c.threeColorPolicerPacketsTotal, map[string]string{"policer": "wan-egress", "color": "yellow"}, 3)
	assertCounterClose(t, got, c.threeColorPolicerBytesTotal, map[string]string{"policer": "wan-egress", "color": "yellow"}, 300)
	assertCounterClose(t, got, c.threeColorPolicerPacketsTotal, map[string]string{"policer": "wan-egress", "color": "red"}, 2)
	assertCounterClose(t, got, c.threeColorPolicerBytesTotal, map[string]string{"policer": "wan-egress", "color": "red"}, 200)
	assertCounterClose(t, got, c.threeColorPolicerDropsTotal, map[string]string{"policer": "wan-egress"}, 2)
	assertCounterClose(t, got, c.threeColorPolicerDropBytes, map[string]string{"policer": "wan-egress"}, 200)
}

func TestEmitUserspaceSourceNATPoolMetrics(t *testing.T) {
	c := &xpfCollector{
		userspaceSNATPoolLiveFlows: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_live_flows",
			"live flows",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolUsedPorts: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_used_ports",
			"used ports",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolPersistentLeases: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_persistent_leases",
			"persistent leases",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolAllocationsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_allocations_total",
			"allocations",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolReusesTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_reuses_total",
			"reuses",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolExhaustionsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_exhaustions_total",
			"exhaustions",
			[]string{"pool", "rule"},
			nil,
		),
		// #8447: the persistent-NAT admission pair.
		userspaceSNATPoolPersistentAdmittedTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_persistent_admitted_total",
			"persistent admitted",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolPersistentDeclinedTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_persistent_declined_total",
			"persistent declined",
			[]string{"pool", "rule"},
			nil,
		),
		// #4800: the residual live-state mutex (denominator, contended) pair.
		userspaceSNATPoolLiveLockAcquisitionsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_live_lock_acquisitions_total",
			"live lock acquisitions",
			[]string{"pool", "rule"},
			nil,
		),
		userspaceSNATPoolLiveLockContendedTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_live_lock_contended_total",
			"live lock contended",
			[]string{"pool", "rule"},
			nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		SourceNATPools: []dpuserspace.SourceNATPoolStatus{{
			PoolName:         "pool-a",
			RuleName:         "snat-a",
			LiveFlows:        2,
			UsedPorts:        1,
			PersistentLeases: 1,
			AllocationsTotal: 3,
			ReusesTotal:      5,
			ExhaustionTotal:  7,
			// #4800: distinct from each other and from every other field
			// above, so a mis-wired collector cannot pass by coincidence.
			LiveLockAcquisitionsTotal: 11,
			LiveLockContendedTotal:    4,
			// #8447: distinct values, for the reason the #4800 pair below
			// records — a collector that emitted one of the pair into the
			// other's series would pass on equal fixtures.
			PersistentAdmittedTotal: 13,
			PersistentDeclinedTotal: 6,
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceSourceNATPoolMetrics(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	// 6 pre-#4800 series + the live-lock (denominator, contended) pair
	// + the #8447 persistent-NAT (admitted, declined) pair.
	if len(got) != 10 {
		t.Fatalf("emitUserspaceSourceNATPoolMetrics: want 10 metrics, got %d", len(got))
	}

	labels := map[string]string{"pool": "pool-a", "rule": "snat-a"}
	assertGaugeClose(t, got, c.userspaceSNATPoolLiveFlows, labels, 2)
	assertGaugeClose(t, got, c.userspaceSNATPoolUsedPorts, labels, 1)
	assertGaugeClose(t, got, c.userspaceSNATPoolPersistentLeases, labels, 1)
	assertCounterClose(t, got, c.userspaceSNATPoolAllocationsTotal, labels, 3)
	assertCounterClose(t, got, c.userspaceSNATPoolReusesTotal, labels, 5)
	assertCounterClose(t, got, c.userspaceSNATPoolExhaustionsTotal, labels, 7)
	// #4800: both legs of the pair carry through to Prometheus. Distinct
	// fixture values so a collector that emitted the same field twice
	// (acquisitions into the contended series, or vice versa) fails here
	// rather than passing on a coincidence.
	assertCounterClose(t, got, c.userspaceSNATPoolLiveLockAcquisitionsTotal, labels, 11)
	assertCounterClose(t, got, c.userspaceSNATPoolLiveLockContendedTotal, labels, 4)
	// #8447: same discipline for the persistent-NAT admission pair. Swapping
	// the two emissions fails here rather than passing on equal fixtures —
	// which matters more than usual for this pair, because its whole purpose
	// is telling "declined" apart from "never ran".
	assertCounterClose(t, got, c.userspaceSNATPoolPersistentAdmittedTotal, labels, 13)
	assertCounterClose(t, got, c.userspaceSNATPoolPersistentDeclinedTotal, labels, 6)
}

func TestEmitUserspaceDynamicBufferMetrics(t *testing.T) {
	c := &xpfCollector{
		userspaceSessionTableEntries: prometheus.NewDesc(
			"xpf_userspace_session_table_entries",
			"session entries",
			nil,
			nil,
		),
		userspaceSessionTableCapacity: prometheus.NewDesc(
			"xpf_userspace_session_table_capacity",
			"session capacity",
			nil,
			nil,
		),
		// #8447: source-NAT rule-match outcome quartet.
		userspaceSourceNATMatchConsulted: prometheus.NewDesc(
			"xpf_userspace_source_nat_match_consulted_total", "consulted", nil, nil,
		),
		userspaceSourceNATMatchMatched: prometheus.NewDesc(
			"xpf_userspace_source_nat_match_matched_total", "matched", nil, nil,
		),
		userspaceSourceNATMatchUnavailable: prometheus.NewDesc(
			"xpf_userspace_source_nat_match_unavailable_total", "unavailable", nil, nil,
		),
		userspaceSourceNATMatchNoMatch: prometheus.NewDesc(
			"xpf_userspace_source_nat_match_no_match_total", "no match", nil, nil,
		),
		userspaceNatReverseKeyCollisions: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_collisions_total",
			"nat reverse-key collisions",
			nil,
			nil,
		),
		// #6751: the DIFFERENT-SOURCE subset of the counter above.
		userspaceNatReverseKeyCollisionsDistinctSrc: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_collisions_distinct_src_total",
			"nat reverse-key collisions with a distinct source",
			nil,
			nil,
		),
		// #6751 PR 2/3: the interface-mode SNAT identity registry's three
		// outcomes.
		userspaceInterfaceSNATPATCollisions: prometheus.NewDesc(
			"xpf_userspace_interface_snat_pat_collisions_total",
			"interface snat pat collisions",
			nil,
			nil,
		),
		// #7056: this literal enumerates every Desc
		// emitUserspaceDynamicBufferMetrics touches, so a new emit without a
		// matching entry here nil-derefs inside MustNewConstMetric rather than
		// failing an assertion.
		userspaceNAT64FragCrossDomainMisses: prometheus.NewDesc(
			"xpf_userspace_nat64_frag_cross_domain_misses_total",
			"nat64 frag cross-domain refused-alias misses",
			nil,
			nil,
		),
		userspaceNAT64FragProtocolAliasMisses: prometheus.NewDesc(
			"xpf_userspace_nat64_frag_protocol_alias_misses_total",
			"nat64 frag protocol refused-alias misses",
			nil,
			nil,
		),
		userspaceInterfaceSNATIdentityExhaustion: prometheus.NewDesc(
			"xpf_userspace_interface_snat_identity_exhaustion_total",
			"interface snat identity exhaustion",
			nil,
			nil,
		),
		userspaceInterfaceSNATSyncConflictDrops: prometheus.NewDesc(
			"xpf_userspace_interface_snat_sync_identity_conflict_drops_total",
			"interface snat sync identity conflict drops",
			nil,
			nil,
		),
		userspaceInterfaceSNATRegistryCap: prometheus.NewDesc(
			"xpf_userspace_interface_snat_registry_cap_exhaustion_total",
			"interface snat registry cap exhaustion",
			nil,
			nil,
		),
		userspaceSessionPublishErrors: prometheus.NewDesc(
			"xpf_userspace_session_publish_errors_total",
			"session publish errors",
			nil,
			nil,
		),
		// #4800: publish + replication legs of the new-flow-install
		// contention surface.
		userspaceSharedSessionPublishes: prometheus.NewDesc(
			"xpf_userspace_shared_session_publishes_total",
			"shared session publishes",
			nil,
			nil,
		),
		userspaceSharedSessionPublishLockAcquired: prometheus.NewDesc(
			"xpf_userspace_shared_session_publish_lock_acquisitions_total",
			"shared session publish lock acquisitions",
			nil,
			nil,
		),
		userspaceSharedSessionPublishLockBlocked: prometheus.NewDesc(
			"xpf_userspace_shared_session_publish_lock_contended_total",
			"shared session publish lock contended",
			nil,
			nil,
		),
		userspaceSessionReplicationUpserts: prometheus.NewDesc(
			"xpf_userspace_session_replication_upserts_total",
			"session replication upserts",
			nil,
			nil,
		),
		userspaceSessionReplicationEnqueued: prometheus.NewDesc(
			"xpf_userspace_session_replication_enqueued_total",
			"session replication enqueued",
			nil,
			nil,
		),
		userspaceSessionReplicationLockBlocked: prometheus.NewDesc(
			"xpf_userspace_session_replication_lock_contended_total",
			"session replication lock contended",
			nil,
			nil,
		),
		userspaceSessionReplicationQueueDepthSum: prometheus.NewDesc(
			"xpf_userspace_session_replication_queue_depth_sum",
			"session replication queue depth sum",
			nil,
			nil,
		),
		userspaceSessionReplicationQueueDepthMax: prometheus.NewDesc(
			"xpf_userspace_session_replication_queue_depth_max",
			"session replication queue depth high-water",
			nil,
			nil,
		),
		userspaceDnatPublishErrors: prometheus.NewDesc(
			"xpf_userspace_dnat_publish_errors_total",
			"dnat publish errors",
			nil,
			nil,
		),
		// #5674: synced-import aggregate admission-bound drops.
		userspaceSyncedImportCapDrops: prometheus.NewDesc(
			"xpf_userspace_synced_import_cap_drops_total",
			"synced import cap drops",
			nil,
			nil,
		),
		// #1861 install-refusal trio.
		userspaceSessionCreateDrops: prometheus.NewDesc(
			"xpf_userspace_session_create_drops_total",
			"session create drops",
			nil,
			nil,
		),
		userspaceSessionInstallAdmissionRefused: prometheus.NewDesc(
			"xpf_userspace_session_install_admission_refused_total",
			"session install admission refusals",
			nil,
			nil,
		),
		userspaceSessionInstallPartial: prometheus.NewDesc(
			"xpf_userspace_session_install_partial_total",
			"session install partials",
			nil,
			nil,
		),
		userspaceNatReverseKeySharedDisplacements: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_shared_displacements_total",
			"shared-map nat reverse-key displacements",
			nil,
			nil,
		),
		userspaceWorkerCommandQueuePoisonRecoveries: prometheus.NewDesc(
			"xpf_userspace_worker_command_queue_poison_recoveries_total",
			"worker command-queue poison recoveries",
			nil,
			nil,
		),
		userspaceWorkerCommandQueueDrops: prometheus.NewDesc(
			"xpf_userspace_worker_command_queue_drops_total",
			"worker command-queue capacity drops",
			nil,
			nil,
		),
		userspaceSharedSessionPoisonRecoveries: prometheus.NewDesc(
			"xpf_userspace_shared_session_poison_recoveries_total",
			"shared-session poison recoveries",
			nil,
			nil,
		),
		// #7398: the emit helper dereferences these three, so a literal that
		// omits them segfaults rather than failing an assertion — the reason
		// the issue calls out that a green BUILD proves nothing about a
		// descriptor.
		userspaceSessionInstallStaleIgnored: prometheus.NewDesc(
			"xpf_userspace_session_install_stale_ignored_total",
			"stale-generation session installs ignored",
			nil,
			nil,
		),
		userspaceSessionDeleteStaleIgnored: prometheus.NewDesc(
			"xpf_userspace_session_delete_stale_ignored_total",
			"stale-generation session deletes ignored",
			nil,
			nil,
		),
		userspaceSyncedImportReserveRefused: prometheus.NewDesc(
			"xpf_userspace_synced_import_reserve_refused_total",
			"synced imports refused for want of a NAT reservation",
			nil,
			nil,
		),
		// #7160: this collector is built by struct literal, so a descriptor
		// the emit path uses and this fixture omits is a nil *Desc and
		// `MustNewConstMetric` SEGVs rather than failing an assertion — a
		// panic, not a red, which the package-level FAIL reports with no
		// `--- FAIL` line at all.
		userspaceSyncedImportUnknownRoutingDomain: prometheus.NewDesc(
			"xpf_userspace_synced_import_unknown_routing_domain_total",
			"synced imports refused for an unresolvable routing domain",
			nil,
			nil,
		),
		userspaceSyncedImportZoneUnresolved: prometheus.NewDesc(
			"xpf_userspace_synced_import_zone_unresolved_total",
			"synced imports that skipped the #6211 zone narrowing",
			nil,
			nil,
		),
		userspaceSyncedImportUnpublished: prometheus.NewDesc(
			"xpf_userspace_synced_import_unpublished_total",
			"synced imports admitted with no session map to publish into",
			nil,
			nil,
		),
		userspaceGreDecapEcnIllegalDrops: prometheus.NewDesc(
			"xpf_userspace_gre_decap_ecn_illegal_drops_total",
			"gre decap rfc6040 illegal-combo drops",
			nil,
			nil,
		),
		userspaceWgDecapEcnIllegalDrops: prometheus.NewDesc(
			"xpf_userspace_wg_decap_ecn_illegal_drops_total",
			"wg decap rfc6040 illegal-combo drops",
			nil,
			nil,
		),
		userspaceGreEncapDfOversizeDrops: prometheus.NewDesc(
			"xpf_userspace_gre_encap_df_oversize_drops_total",
			"gre encap df-set oversized-outer drops",
			nil,
			nil,
		),
		userspaceGreDecapChecksumInvalidDrops: prometheus.NewDesc(
			"xpf_userspace_gre_decap_checksum_invalid_drops_total",
			"gre decap checksum-present invalid drops",
			nil,
			nil,
		),
		userspaceGreDecapUnsupportedVersionRefusals: prometheus.NewDesc(
			"xpf_userspace_gre_decap_unsupported_version_refusals_total",
			"gre decap unsupported-version refusals",
			nil,
			nil,
		),
		userspaceTimeExceededRateLimited: prometheus.NewDesc(
			"xpf_userspace_time_exceeded_rate_limited_total",
			"time-exceeded generated-error rate-limit drops",
			nil,
			nil,
		),
		userspacePacketTooBigRateLimited: prometheus.NewDesc(
			"xpf_userspace_packet_too_big_rate_limited_total",
			"ptb generated-error rate-limit drops",
			nil,
			nil,
		),
		userspaceRejectRateLimited: prometheus.NewDesc(
			"xpf_userspace_reject_rate_limited_total",
			"reject generated-error rate-limit drops",
			nil,
			nil,
		),
		userspaceRejectSent: prometheus.NewDesc(
			"xpf_userspace_reject_sent_total",
			"reject replies sent by source",
			[]string{"source"},
			nil,
		),
		userspaceRejectReplyBudgetDrops: prometheus.NewDesc(
			"xpf_userspace_reject_reply_budget_drops_total",
			"reject reply tx-frame budget drops by source",
			[]string{"source"},
			nil,
		),
		userspaceRejectOutputFilterDrops: prometheus.NewDesc(
			"xpf_userspace_reject_output_filter_drops_total",
			"reject reply output-filter drops by source",
			[]string{"source"},
			nil,
		),
		userspaceRejectRateLimitedBySource: prometheus.NewDesc(
			"xpf_userspace_reject_rate_limited_by_source_total",
			"reject reply rate-limit drops by source",
			[]string{"source"},
			nil,
		),
		userspaceFlowCacheActiveFlows: prometheus.NewDesc(
			"xpf_userspace_flow_cache_active_flows",
			"flow-cache active flows",
			nil,
			nil,
		),
		userspaceFlowCacheCapacity: prometheus.NewDesc(
			"xpf_userspace_flow_cache_capacity",
			"flow-cache capacity",
			nil,
			nil,
		),
		bindingFlowCacheCapacity: prometheus.NewDesc(
			"xpf_userspace_binding_flow_cache_capacity",
			"binding flow-cache capacity",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"},
			nil,
		),
		userspaceEventStreamProducerSeqLockAcquired: prometheus.NewDesc(
			"xpf_userspace_event_stream_producer_seq_lock_acquisitions_total",
			"event stream producer seq lock acquisitions",
			nil,
			nil,
		),
		userspaceEventStreamProducerSeqLockBlocked: prometheus.NewDesc(
			"xpf_userspace_event_stream_producer_seq_lock_contended_total",
			"event stream producer seq lock contended",
			nil,
			nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		// #8447: distinct values so a swapped emission fails rather than passing.
		SourceNATMatchConsultedTotal:   41,
		SourceNATMatchMatchedTotal:     23,
		SourceNATMatchUnavailableTotal: 5,
		SourceNATMatchNoMatchTotal:     13,
		SessionTableEntries:            77,
		MaxSessions:                    100,
		// #1789: publish-error counter emitted unconditionally.
		SessionPublishErrorsTotal: 6,
		// #4800: publish + replication contention surface. Seven values,
		// all distinct from one another and from every other field in this
		// fixture, so a collector that crossed two of these wires (emitting
		// acquisitions into the contended series, say) fails an assertion
		// instead of passing on a coincidence.
		SharedSessionPublishesTotal:               101,
		SharedSessionPublishLockAcquisitionsTotal: 103,
		SharedSessionPublishLockContendedTotal:    107,
		SessionReplicationUpsertsTotal:            109,
		SessionReplicationEnqueuedTotal:           113,
		SessionReplicationLockContendedTotal:      127,
		SessionReplicationQueueDepthSum:           137,
		SessionReplicationQueueDepthMax:           131,
		// #9169: the FOURTH #4800 site. Two more distinct primes, for the
		// same reason as the seven above — a collector that crossed the
		// denominator and the contended wire would otherwise pass.
		EventStreamProducerSeqLockAcquisitionsTotal: 139,
		EventStreamProducerSeqLockContendedTotal:    149,
		// #2244: dnat_table reverse-NAT publish-error counter emitted
		// unconditionally.
		DnatPublishErrorsTotal: 7,
		// #5674: synced-import aggregate admission-bound drop counter emitted
		// unconditionally.
		SyncedImportCapDropsTotal: 11,
		// #1760 W3': shared-map displacement counter emitted unconditionally.
		NatReverseKeySharedDisplacementsTotal: 4,
		// #1807: poison-recovery counter emitted unconditionally.
		WorkerCommandQueuePoisonRecoveries: 2,
		// #6929: per-worker command-queue capacity drops, emitted
		// unconditionally. Deliberately a DIFFERENT value from the poison
		// counter above so a collector that wired one Desc to the other
		// field fails here instead of matching by coincidence.
		WorkerCommandQueueDrops: 9,
		// #2402/#6641: shared-session poison-recovery counter emitted
		// unconditionally.
		SharedSessionPoisonRecoveries: 5,
		// #7398: distinct values so an assertion cannot pass by reading the
		// neighbouring field — a mis-wired descriptor emits a series either way.
		SessionInstallStaleIgnored: 21,
		SessionDeleteStaleIgnored:  22,
		SyncedImportReserveRefused: 23,
		SyncedImportZoneUnresolved: 7,
		SyncedImportUnpublished:    31,
		// #2315: GRE-decap RFC 6040 §4.2 illegal-combo drop counter
		// emitted unconditionally.
		GreDecapEcnIllegalDropsTotal: 3,
		// #2317: WG-decap RFC 6040 §4.2 illegal-combo drop counter
		// emitted unconditionally.
		WgDecapEcnIllegalDropsTotal: 5,
		// #2331: GRE-encap DF-set oversized-outer drop counter emitted
		// unconditionally.
		GreEncapDfOversizeDropsTotal: 6,
		// #2782: GRE-decap checksum-present invalid drop counter emitted
		// unconditionally.
		GreDecapChecksumInvalidDropsTotal: 8,
		// #6842: GRE-decap unsupported-version (RFC 2637 / PPTP) refusal
		// counter emitted unconditionally.
		GreDecapUnsupportedVersionRefusalsTotal: 9,
		// #2472: per-reason generated-error rate-limit drop counters emitted
		// unconditionally.
		TimeExceededRateLimitedTotal: 11,
		PacketTooBigRateLimitedTotal: 12,
		RejectRateLimitedTotal:       13,
		// #6751: distinct-source subset. Deliberately NON-ZERO while the
		// aggregate stays 0 in this fixture, so an emit wired to the wrong
		// field cannot satisfy the assertion below.
		NatReverseKeyCollisionsDistinctSrc: 5,
		// #6751 PR 2/3: three DISTINCT non-zero values, so an emit wired to
		// the wrong one of the trio cannot satisfy the assertions below --
		// the two exhaustion counters exist precisely to be read apart.
		InterfaceSNATPATCollisionsTotal: 17,
		// #7056: DISTINCT fixture values, so an emit wired to the wrong field
		// swaps two numbers that differ rather than two that happen to match.
		NAT64FragCrossDomainMissesTotal:             23,
		NAT64FragProtocolAliasMissesTotal:           29,
		InterfaceSNATIdentityExhaustionTotal:        19,
		InterfaceSNATSyncIdentityConflictDropsTotal: 29,
		InterfaceSNATRegistryCapExhaustionTotal:     23,
		// #1861: install-refusal trio emitted unconditionally.
		SessionCreateDrops:             9,
		SessionInstallAdmissionRefused: 8,
		SessionInstallPartial:          1,
		Bindings: []dpuserspace.BindingStatus{
			{
				Slot:              0,
				QueueID:           1,
				WorkerID:          2,
				Interface:         "ge-0-0-1",
				ActiveFlowCount:   9,
				FlowCacheCapacity: 10,
				// #3657: per-source reject reply legs, summed across
				// bindings and emitted with source=policy|filter labels.
				PolicyRejectSent:              5,
				FilterRejectSent:              2,
				PolicyRejectReplyBudgetDrops:  3,
				FilterRejectReplyBudgetDrops:  1,
				PolicyRejectOutputFilterDrops: 7,
				FilterRejectOutputFilterDrops: 4,
				// #3661: per-source reject rate-limit drop leg.
				PolicyRejectRateLimitDrops: 13,
				FilterRejectRateLimitDrops: 15,
			},
			{
				Slot:                          1,
				QueueID:                       1,
				WorkerID:                      3,
				Interface:                     "ge-0-0-2",
				ActiveFlowCount:               3,
				FlowCacheCapacity:             10,
				PolicyRejectSent:              6,
				FilterRejectSent:              8,
				PolicyRejectReplyBudgetDrops:  9,
				FilterRejectReplyBudgetDrops:  10,
				PolicyRejectOutputFilterDrops: 11,
				FilterRejectOutputFilterDrops: 12,
				PolicyRejectRateLimitDrops:    17,
				FilterRejectRateLimitDrops:    19,
			},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceDynamicBufferMetrics(ch, status)
		// #3657: source-split reject reply telemetry is emitted by a
		// dedicated helper off the same status; collect it here so the
		// assertions below cover the sent / reply-budget / output-filter
		// legs alongside the aggregate rate-limit counter.
		c.emitRejectObservability(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	// 10 pre-#1861 metrics + the #1861 install-refusal trio + the #2244
	// dnat_table reverse-NAT publish-error counter (= 14) + the #2315
	// gre_decap_ecn_illegal_drops_total counter (= 15) + the #2317
	// wg_decap_ecn_illegal_drops_total counter (= 16) + the #2331
	// gre_encap_df_oversize_drops_total counter (= 17) + the #2782
	// gre_decap_checksum_invalid_drops_total counter (= 18) + the #2472
	// per-reason generated-error rate-limit trio (time_exceeded /
	// packet_too_big / reject) = 21 + the #3657 source-split reject trio
	// (sent / reply-budget / output-filter) × 2 sources = 27 + the #3661
	// source-split reject rate-limit drop leg × 2 sources = 29 + the #5674
	// synced_import_cap_drops_total counter (= 30) + the #4800 new-flow
	// contention surface (publish call count + publish lock pair +
	// replication upserts/enqueued/contended + replication queue depth
	// high-water = 7, plus the depth SUM added when the lifetime max was
	// demoted to operator context = 8) = 38 + the #2402/#6641
	// shared-session poison-recovery counter = 39, plus the #6751
	// distinct-source subset of the reverse-key collision counter = 40,
	// plus the #6751 PR 2/3 interface-mode SNAT identity registry trio
	// (PAT collisions + identity exhaustion + sync-import identity-conflict
	// drops + registry-cap exhaustion) = 44, plus the #6842
	// gre_decap_unsupported_version_refusals_total counter = 45, plus the
	// #6929 worker_command_queue_drops_total counter = 46, plus the #7056
	// refused-alias PAIR (cross-domain + protocol) = 48. The pair is counted as
	// TWO because they are deliberately distinct series; if a later change folds
	// them into one total this census is the guard that notices. Plus the
	// #7209 synced_import_zone_unresolved_total counter = 49. Plus the #7398
	// TRIO that emptied the status-wiring allowlist —
	// session_install_stale_ignored_total, session_delete_stale_ignored_total
	// and synced_import_reserve_refused_total = 52. Counted as three because
	// they are distinct series; folding any two together is a change this
	// census is here to notice. Plus the #7160 (#2387)
	// synced_import_unknown_routing_domain_total counter = 53 — a peer-synced
	// import refused because this node runs routing instances and the request
	// named no ingress identity to resolve the session's routing domain from.
	// Its own series rather than folded into the reserve-refusal above,
	// because the two say different things to an operator: one means the
	// standby cannot hold a translation, the other means it will not adopt a
	// session under a domain nothing verified.
	// synced_import_unpublished_total counter = 54 (#7209) — a peer-synced
	// import the local-replace guard ADMITTED that had no kernel session map
	// to publish into. Its own series rather than folded into the
	// zone-unresolved counter above, because they report different failures:
	// that one means the import was published with a degraded reservation,
	// this one means it was not published at all while still being answered
	// to Go as installed.
	// +4 for the #8447 source-NAT rule-match quartet.
	// +2 for the #9169 event-stream producer_seq_lock pair (#4800 SITE 4).
	// RE-ANCHORED, not relaxed: this count is a deliberate gate — it catches a
	// series that is emitted but never asserted, which is how a collector grows
	// an unverified metric. The two new series ARE asserted below, so the
	// original claim still holds and the number moves with the population.
	if len(got) != 60 {
		t.Fatalf("emitUserspaceDynamicBufferMetrics: want 60 metrics, got %d", len(got))
	}

	// #8447: DISTINCT values, so a collector that emitted one of the quartet
	// into another's series fails here rather than passing on equal fixtures.
	// That matters most for `consulted`, whose whole job is being readable
	// beside a zero in the other three.
	assertCounterClose(t, got, c.userspaceSourceNATMatchConsulted, nil, 41)
	assertCounterClose(t, got, c.userspaceSourceNATMatchMatched, nil, 23)
	assertCounterClose(t, got, c.userspaceSourceNATMatchUnavailable, nil, 5)
	assertCounterClose(t, got, c.userspaceSourceNATMatchNoMatch, nil, 13)
	assertGaugeClose(t, got, c.userspaceSessionTableEntries, nil, 77)
	assertGaugeClose(t, got, c.userspaceSessionTableCapacity, nil, 100)
	// #1760: collision counter emitted unconditionally (0 with no
	// collisions configured in this fixture).
	assertCounterClose(t, got, c.userspaceNatReverseKeyCollisions, nil, 0)
	// #6751: the distinct-source subset is emitted unconditionally too, and
	// carries its OWN value -- 5 here against an aggregate of 0.
	assertCounterClose(t, got, c.userspaceNatReverseKeyCollisionsDistinctSrc, nil, 5)
	// #6751 PR 2/3: the interface-mode SNAT identity registry trio, each
	// carrying its own value.
	assertCounterClose(t, got, c.userspaceInterfaceSNATPATCollisions, nil, 17)
	// #7056: assert the VALUES, not merely that two more series appeared — a
	// census bump alone would pass against emits wired to the wrong field.
	assertCounterClose(t, got, c.userspaceNAT64FragCrossDomainMisses, nil, 23)
	assertCounterClose(t, got, c.userspaceNAT64FragProtocolAliasMisses, nil, 29)
	assertCounterClose(t, got, c.userspaceInterfaceSNATIdentityExhaustion, nil, 19)
	assertCounterClose(t, got, c.userspaceInterfaceSNATSyncConflictDrops, nil, 29)
	assertCounterClose(t, got, c.userspaceInterfaceSNATRegistryCap, nil, 23)
	// #1789: publish-error counter emitted unconditionally.
	assertCounterClose(t, got, c.userspaceSessionPublishErrors, nil, 6)
	// #4800: every leg of the new-flow-install contention surface reaches
	// Prometheus carrying ITS OWN value. Both halves of each pair are
	// asserted separately — a denominator that silently went missing (or
	// got wired to the contended field) would leave the ratio the
	// connection-rate harness computes quietly wrong rather than absent.
	assertCounterClose(t, got, c.userspaceSharedSessionPublishes, nil, 101)
	assertCounterClose(t, got, c.userspaceSharedSessionPublishLockAcquired, nil, 103)
	assertCounterClose(t, got, c.userspaceSharedSessionPublishLockBlocked, nil, 107)
	assertCounterClose(t, got, c.userspaceSessionReplicationUpserts, nil, 109)
	assertCounterClose(t, got, c.userspaceSessionReplicationEnqueued, nil, 113)
	assertCounterClose(t, got, c.userspaceSessionReplicationLockBlocked, nil, 127)
	// The depth SUM is a COUNTER (differenceable — the analyzer's backlog
	// input); the lifetime max is a GAUGE. Asserted as their distinct types
	// so swapping them is caught here: differencing a high-water gauge is
	// exactly the defect that made every cell after one spike report a
	// replication backlog.
	assertCounterClose(t, got, c.userspaceSessionReplicationQueueDepthSum, nil, 137)
	assertGaugeClose(t, got, c.userspaceSessionReplicationQueueDepthMax, nil, 131)
	// #9169: site 4's pair. Emitted unconditionally and together, like the
	// three above — the connection-rate analyzer refuses a ratio whose
	// denominator is missing, so half a pair is a site that reports "never
	// taken" for a mutex every session delta passes through.
	assertCounterClose(t, got, c.userspaceEventStreamProducerSeqLockAcquired, nil, 139)
	assertCounterClose(t, got, c.userspaceEventStreamProducerSeqLockBlocked, nil, 149)
	// #2244: dnat_table reverse-NAT publish-error counter emitted
	// unconditionally.
	assertCounterClose(t, got, c.userspaceDnatPublishErrors, nil, 7)
	// #5674: synced-import aggregate admission-bound drop counter emitted
	// unconditionally (a 0 is a real "no over-ceiling imports rejected" signal).
	assertCounterClose(t, got, c.userspaceSyncedImportCapDrops, nil, 11)
	// #1760 W3': shared-map displacement counter emitted unconditionally.
	assertCounterClose(t, got, c.userspaceNatReverseKeySharedDisplacements, nil, 4)
	// #1807: poison-recovery counter emitted unconditionally.
	assertCounterClose(t, got, c.userspaceWorkerCommandQueuePoisonRecoveries, nil, 2)
	// #6929: per-worker command-queue capacity drops emitted
	// unconditionally — 0 is the EXPECTED value here (the consumer cannot be
	// outrun), so an absent series would be indistinguishable from a helper
	// that never reports one.
	assertCounterClose(t, got, c.userspaceWorkerCommandQueueDrops, nil, 9)
	// #2402/#6641: shared-session poison-recovery counter emitted
	// unconditionally, so a 0 is a real "no worker panic touched HA session
	// state" signal rather than an absent series.
	assertCounterClose(t, got, c.userspaceSharedSessionPoisonRecoveries, nil, 5)
	// #7398: assert the VALUE, not merely that a series exists — a descriptor
	// wired to the wrong status field emits a series too.
	assertCounterClose(t, got, c.userspaceSessionInstallStaleIgnored, nil, 21)
	assertCounterClose(t, got, c.userspaceSessionDeleteStaleIgnored, nil, 22)
	assertCounterClose(t, got, c.userspaceSyncedImportReserveRefused, nil, 23)
	// #7209: synced imports that skipped the #6211 zone narrowing. Emitted
	// unconditionally like its neighbours, so a 0 is a real "every synced
	// import resolved its zones" signal rather than an absent series. The
	// fixture value is deliberately NOT 0 — a 0 here would pass against a
	// collector that never emitted the series at all.
	assertCounterClose(t, got, c.userspaceSyncedImportZoneUnresolved, nil, 7)
	// #7209: synced imports the local-replace guard ADMITTED that had no
	// kernel session map to publish into. Emitted unconditionally like its
	// neighbours. The fixture value is distinct from every sibling above, so
	// an emit wired to the wrong status field swaps two numbers that DIFFER,
	// and it is non-zero so a collector that never emitted the series fails
	// rather than matching a default.
	assertCounterClose(t, got, c.userspaceSyncedImportUnpublished, nil, 31)
	// #2315: GRE-decap RFC 6040 §4.2 illegal-combo drop counter emitted
	// unconditionally.
	assertCounterClose(t, got, c.userspaceGreDecapEcnIllegalDrops, nil, 3)
	// #2317: WG-decap RFC 6040 §4.2 illegal-combo drop counter emitted
	// unconditionally.
	assertCounterClose(t, got, c.userspaceWgDecapEcnIllegalDrops, nil, 5)
	// #2331: GRE-encap DF-set oversized-outer drop counter emitted
	// unconditionally.
	assertCounterClose(t, got, c.userspaceGreEncapDfOversizeDrops, nil, 6)
	// #2782: GRE-decap checksum-present invalid drop counter emitted
	// unconditionally.
	assertCounterClose(t, got, c.userspaceGreDecapChecksumInvalidDrops, nil, 8)
	// #6842: GRE-decap unsupported-version refusal counter emitted
	// unconditionally, carrying its OWN value -- 9 against the
	// checksum-invalid counter's 8, so a collector wired to the wrong
	// status field is caught here rather than agreeing by coincidence.
	assertCounterClose(t, got, c.userspaceGreDecapUnsupportedVersionRefusals, nil, 9)
	// #2472: per-reason generated-error rate-limit drop counters emitted
	// unconditionally.
	assertCounterClose(t, got, c.userspaceTimeExceededRateLimited, nil, 11)
	assertCounterClose(t, got, c.userspacePacketTooBigRateLimited, nil, 12)
	assertCounterClose(t, got, c.userspaceRejectRateLimited, nil, 13)
	// #3657 (H15/M02): source-split reject reply telemetry, summed across
	// the two bindings above and labeled source=policy|filter. Reverting the
	// emitRejectObservability helper (or dropping the descriptors) turns
	// these RED — the series would be absent entirely. sent: policy=5+6=11,
	// filter=2+8=10; reply-budget: policy=3+9=12, filter=1+10=11;
	// output-filter: policy=7+11=18, filter=4+12=16.
	assertCounterClose(t, got, c.userspaceRejectSent, map[string]string{"source": "policy"}, 11)
	assertCounterClose(t, got, c.userspaceRejectSent, map[string]string{"source": "filter"}, 10)
	assertCounterClose(t, got, c.userspaceRejectReplyBudgetDrops, map[string]string{"source": "policy"}, 12)
	assertCounterClose(t, got, c.userspaceRejectReplyBudgetDrops, map[string]string{"source": "filter"}, 11)
	assertCounterClose(t, got, c.userspaceRejectOutputFilterDrops, map[string]string{"source": "policy"}, 18)
	assertCounterClose(t, got, c.userspaceRejectOutputFilterDrops, map[string]string{"source": "filter"}, 16)
	// #3661: source-split reject rate-limit drop leg, summed across the two
	// bindings. Reverting the source split (rate-limit drop stays
	// source-neutral) or dropping the descriptor turns these RED — the
	// per-source series would be absent. rate-limit: policy=13+17=30,
	// filter=15+19=34.
	assertCounterClose(t, got, c.userspaceRejectRateLimitedBySource, map[string]string{"source": "policy"}, 30)
	assertCounterClose(t, got, c.userspaceRejectRateLimitedBySource, map[string]string{"source": "filter"}, 34)
	// #1861: install-refusal trio emitted unconditionally.
	assertCounterClose(t, got, c.userspaceSessionCreateDrops, nil, 9)
	assertCounterClose(t, got, c.userspaceSessionInstallAdmissionRefused, nil, 8)
	assertCounterClose(t, got, c.userspaceSessionInstallPartial, nil, 1)
	assertGaugeClose(t, got, c.userspaceFlowCacheActiveFlows, nil, 12)
	assertGaugeClose(t, got, c.userspaceFlowCacheCapacity, nil, 20)
	assertGaugeClose(t, got, c.bindingFlowCacheCapacity, map[string]string{
		"binding_slot": "0",
		"queue_id":     "1",
		"worker_id":    "2",
		"iface":        "ge-0-0-1",
	}, 10)
}

func metricValuesByWorker(
	t *testing.T,
	metrics []prometheus.Metric,
	desc *prometheus.Desc,
	counter bool,
) map[string]float64 {
	t.Helper()
	out := make(map[string]float64)
	for _, m := range metrics {
		if m.Desc() != desc {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		var workerID string
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "worker_id" {
				workerID = lp.GetValue()
			}
		}
		if workerID == "" {
			t.Fatalf("worker metric missing worker_id label: %+v", &pb)
		}
		if counter {
			if pb.Counter == nil {
				t.Fatalf("worker metric must be a Counter: %+v", &pb)
			}
			out[workerID] = pb.Counter.GetValue()
		} else {
			if pb.Gauge == nil {
				t.Fatalf("worker metric must be a Gauge: %+v", &pb)
			}
			out[workerID] = pb.Gauge.GetValue()
		}
	}
	return out
}

func TestEmitCoSEqualFlowEnforcement_LabelsAndValues(t *testing.T) {
	c := &xpfCollector{
		cosEqualFlowEnforcementEnabled: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforcement_enabled",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowEnforced: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforced",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_target_per_flow_bps",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowMaxWorkerCapBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_max_worker_cap_bytes",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowCapHitEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_cap_hit_events_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowSuppressedGrantBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowStaleOrTagMismatchEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_stale_or_tag_mismatch_events_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowFailOpen: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_fail_open",
			"test desc",
			[]string{"ifindex", "queue_id", "reason"}, nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{{
			Ifindex: 80,
			Queues: []dpuserspace.CoSQueueStatus{
				{
					QueueID:                           4,
					EqualFlowEnforcement:              true,
					EqualFlowEnforced:                 true,
					EqualFlowTargetPerFlowBPS:         8_000_000,
					EqualFlowMaxWorkerCapBytes:        4096,
					EqualFlowCapHitEvents:             7,
					EqualFlowSuppressedGrantBytes:     8192,
					EqualFlowStaleOrTagMismatchEvents: 3,
					EqualFlowFailOpenReason:           "none",
				},
				{QueueID: 5},
			},
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSEqualFlowEnforcement(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	if len(got) != 8 {
		t.Fatalf("emitCoSEqualFlowEnforcement: want 8 metrics for one enabled queue, got %d", len(got))
	}
	values := map[*prometheus.Desc]float64{
		c.cosEqualFlowEnforcementEnabled:       1,
		c.cosEqualFlowEnforced:                 1,
		c.cosEqualFlowTargetPerFlowBPS:         8_000_000,
		c.cosEqualFlowMaxWorkerCapBytes:        4096,
		c.cosEqualFlowCapHitEvents:             7,
		c.cosEqualFlowSuppressedGrantBytes:     8192,
		c.cosEqualFlowStaleOrTagMismatchEvents: 3,
		c.cosEqualFlowFailOpen:                 1,
	}
	counters := map[*prometheus.Desc]bool{
		c.cosEqualFlowCapHitEvents:             true,
		c.cosEqualFlowSuppressedGrantBytes:     true,
		c.cosEqualFlowStaleOrTagMismatchEvents: true,
	}
	for _, m := range got {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["ifindex"] != "80" || labels["queue_id"] != "4" {
			t.Fatalf("wrong equal-flow metric labels: %v", labels)
		}
		if m.Desc() == c.cosEqualFlowFailOpen && labels["reason"] != "none" {
			t.Fatalf("wrong fail-open reason label: %v", labels)
		}
		want, ok := values[m.Desc()]
		if !ok {
			t.Fatalf("unexpected equal-flow metric descriptor: %s", m.Desc())
		}
		var value float64
		if counters[m.Desc()] {
			if pb.Counter == nil {
				t.Fatalf("equal-flow metric %s must be a counter: %+v", m.Desc(), &pb)
			}
			value = pb.Counter.GetValue()
		} else {
			if pb.Gauge == nil {
				t.Fatalf("equal-flow metric %s must be a gauge: %+v", m.Desc(), &pb)
			}
			value = pb.Gauge.GetValue()
		}
		if value != want {
			t.Fatalf("equal-flow metric %s = %v, want %v", m.Desc(), value, want)
		}
	}
}

func TestEmitCoSDrainPhaseTelemetry_EmitsNonExactExactBacklogCounter(t *testing.T) {
	c := &xpfCollector{
		cosDrainGuaranteeSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_guarantee_sent_bytes_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainSurplusSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_surplus_sent_bytes_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainNonExactSentBytesWhileExactBacklogged: prometheus.NewDesc(
			"xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{{
			Ifindex: 80,
			Queues: []dpuserspace.CoSQueueStatus{{
				QueueID:                 0,
				DrainGuaranteeSentBytes: 1024,
				DrainSurplusSentBytes:   2048,
				DrainNonExactSentBytesWhileExactBacklogged: 512,
			}},
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSDrainPhaseTelemetry(ch, status)
		close(ch)
	}()
	values := map[*prometheus.Desc]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["ifindex"] != "80" || labels["queue_id"] != "0" {
			t.Fatalf("wrong drain phase labels: %v", labels)
		}
		if pb.Counter == nil {
			t.Fatalf("drain phase metric %s must be a counter: %+v", m.Desc(), &pb)
		}
		values[m.Desc()] = pb.Counter.GetValue()
	}

	want := map[*prometheus.Desc]float64{
		c.cosDrainGuaranteeSentBytes:                    1024,
		c.cosDrainSurplusSentBytes:                      2048,
		c.cosDrainNonExactSentBytesWhileExactBacklogged: 512,
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("drain phase metric values: got %+v, want %+v", values, want)
	}
}

// #1359: emitCoSParkReasonTelemetry must surface the four per-queue
// park-reason counters that were carried on the CoS snapshot but never
// exported. The four snapshot fields are given DISTINCT values so the
// assertion fails if any single emit line is dropped or mapped to the
// wrong descriptor (non-tautological: a removed emit drops its series,
// and a swapped field/desc mismatches the expected value). The counter
// typing is asserted explicitly — these are monotonic park totals, not
// gauges.
func TestEmitCoSParkReasonTelemetry_DistinctValuesAndCounterType(t *testing.T) {
	c := &xpfCollector{
		cosRootTokenStarvationParks: prometheus.NewDesc(
			"xpf_userspace_cos_root_token_starvation_parks_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosQueueTokenStarvationParks: prometheus.NewDesc(
			"xpf_userspace_cos_queue_token_starvation_parks_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainParkRootTokens: prometheus.NewDesc(
			"xpf_userspace_cos_drain_park_root_tokens_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainParkQueueTokens: prometheus.NewDesc(
			"xpf_userspace_cos_drain_park_queue_tokens_total",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{{
			Ifindex: 80,
			Queues: []dpuserspace.CoSQueueStatus{{
				QueueID:                   3,
				RootTokenStarvationParks:  111,
				QueueTokenStarvationParks: 222,
				DrainParkRootTokens:       333,
				DrainParkQueueTokens:      444,
			}},
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSParkReasonTelemetry(ch, status)
		close(ch)
	}()
	values := map[*prometheus.Desc]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["ifindex"] != "80" || labels["queue_id"] != "3" {
			t.Fatalf("wrong park-reason labels: %v for %s", labels, m.Desc())
		}
		if pb.Counter == nil {
			t.Fatalf("park-reason metric %s must be a counter: %+v", m.Desc(), &pb)
		}
		values[m.Desc()] = pb.Counter.GetValue()
	}

	want := map[*prometheus.Desc]float64{
		c.cosRootTokenStarvationParks:  111,
		c.cosQueueTokenStarvationParks: 222,
		c.cosDrainParkRootTokens:       333,
		c.cosDrainParkQueueTokens:      444,
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("park-reason metric values: got %+v, want %+v", values, want)
	}
}

// #1830 (g): emitCoSFlowFairOccupancy must surface the bucket-vs-flow
// occupancy pair for EVERY queue row (no flow-fair gating — a 0 is a
// real idle signal), with GAUGE typing and (ifindex, queue_id) labels.
func TestEmitCoSFlowFairOccupancy_LabelsValuesAndGaugeType(t *testing.T) {
	c := &xpfCollector{
		cosFlowFairBucketsOccupied: prometheus.NewDesc(
			"xpf_userspace_cos_flow_fair_buckets_occupied",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosFlowFairFlowsActive: prometheus.NewDesc(
			"xpf_userspace_cos_flow_fair_flows_active",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{{
			Ifindex: 80,
			Queues: []dpuserspace.CoSQueueStatus{
				{
					QueueID:                 4,
					FlowFairBucketsOccupied: 9,
					FlowFairFlowsActive:     12,
				},
				// Idle / non-flow-fair queue: both gauges must still
				// emit, as zeros.
				{QueueID: 5},
			},
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSFlowFairOccupancy(ch, status)
		close(ch)
	}()
	type series struct {
		desc    *prometheus.Desc
		queueID string
	}
	values := map[series]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["ifindex"] != "80" {
			t.Fatalf("wrong flow-fair occupancy labels: %v", labels)
		}
		if pb.Gauge == nil {
			t.Fatalf("flow-fair occupancy metric %s must be a gauge: %+v", m.Desc(), &pb)
		}
		values[series{m.Desc(), labels["queue_id"]}] = pb.Gauge.GetValue()
	}

	want := map[series]float64{
		{c.cosFlowFairBucketsOccupied, "4"}: 9,
		{c.cosFlowFairFlowsActive, "4"}:     12,
		{c.cosFlowFairBucketsOccupied, "5"}: 0,
		{c.cosFlowFairFlowsActive, "5"}:     0,
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("flow-fair occupancy metric values: got %+v, want %+v", values, want)
	}
}

// #1628: emitCoSWaterfillTelemetry must surface the per-queue admission/
// visit counters and the per-interface epochs/breaks/min-epochs metrics
// with the right labels and metric types.
func TestEmitCoSWaterfillTelemetry_EmitsQueueAndInterfaceMetrics(t *testing.T) {
	c := &xpfCollector{
		cosWaterfillPhase1Admissions: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_admissions_total", "t",
			[]string{"ifindex", "queue_id"}, nil),
		cosWaterfillPhase2Admissions: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase2_admissions_total", "t",
			[]string{"ifindex", "queue_id"}, nil),
		cosWaterfillEligibleVisits: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_eligible_visits_total", "t",
			[]string{"ifindex", "queue_id"}, nil),
		cosWaterfillPhase1SelectedNoProgress: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_selected_no_progress_total", "t",
			[]string{"ifindex", "queue_id"}, nil),
		cosWaterfillEpochs: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_epochs_total", "t",
			[]string{"ifindex"}, nil),
		cosWaterfillPhase1BudgetBreaks: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_budget_breaks_total", "t",
			[]string{"ifindex"}, nil),
		cosWaterfillMinEpochsPerWorker: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_min_epochs_per_worker", "t",
			[]string{"ifindex"}, nil),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{{
			Ifindex:                     80,
			WaterfillEpochs:             1000,
			WaterfillPhase1BudgetBreaks: 7,
			WaterfillMinEpochsPerWorker: 3,
			Queues: []dpuserspace.CoSQueueStatus{{
				QueueID:                           5,
				WaterfillPhase1Admissions:         12,
				WaterfillPhase2Admissions:         34,
				WaterfillEligibleVisits:           56,
				WaterfillPhase1SelectedNoProgress: 78,
			}},
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSWaterfillTelemetry(ch, status)
		close(ch)
	}()
	counters := map[*prometheus.Desc]float64{}
	var sawMinGauge bool
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		if m.Desc() == c.cosWaterfillMinEpochsPerWorker {
			if pb.Gauge == nil {
				t.Fatalf("min_epochs_per_worker must be a gauge: %+v", &pb)
			}
			if pb.Gauge.GetValue() != 3 {
				t.Fatalf("min_epochs gauge: got %v want 3", pb.Gauge.GetValue())
			}
			sawMinGauge = true
			continue
		}
		if pb.Counter == nil {
			t.Fatalf("waterfill metric %s must be a counter: %+v", m.Desc(), &pb)
		}
		counters[m.Desc()] = pb.Counter.GetValue()
	}

	want := map[*prometheus.Desc]float64{
		c.cosWaterfillPhase1Admissions:         12,
		c.cosWaterfillPhase2Admissions:         34,
		c.cosWaterfillEligibleVisits:           56,
		c.cosWaterfillPhase1SelectedNoProgress: 78,
		c.cosWaterfillEpochs:                   1000,
		c.cosWaterfillPhase1BudgetBreaks:       7,
	}
	if !reflect.DeepEqual(counters, want) {
		t.Fatalf("waterfill counter values: got %+v, want %+v", counters, want)
	}
	if !sawMinGauge {
		t.Fatalf("min_epochs_per_worker gauge not emitted")
	}
}

// #1628 (code-review r2): the min_epochs_per_worker gauge is SUPPRESSED
// when the interface reports the math.MaxUint64 "no active-backlog
// candidate" sentinel, so an idle interface emits no series and any
// emitted value (including 0) is a real lock-in signal. A genuine 0
// (hard lock-in) MUST still be emitted.
func TestEmitCoSWaterfillTelemetry_SuppressesMaxSentinelButEmitsZeroLockin(t *testing.T) {
	c := &xpfCollector{
		cosWaterfillEpochs: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_epochs_total", "t", []string{"ifindex"}, nil),
		cosWaterfillPhase1BudgetBreaks: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_budget_breaks_total", "t", []string{"ifindex"}, nil),
		cosWaterfillMinEpochsPerWorker: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_min_epochs_per_worker", "t", []string{"ifindex"}, nil),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{
			{ // idle: MAX sentinel → gauge suppressed
				Ifindex:                     80,
				WaterfillEpochs:             10,
				WaterfillMinEpochsPerWorker: math.MaxUint64,
			},
			{ // hard 0-epoch lock-in → gauge emitted with value 0
				Ifindex:                     81,
				WaterfillEpochs:             5,
				WaterfillMinEpochsPerWorker: 0,
			},
		},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSWaterfillTelemetry(ch, status)
		close(ch)
	}()
	minByIfindex := map[string]float64{}
	for m := range ch {
		if m.Desc() != c.cosWaterfillMinEpochsPerWorker {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		var ifx string
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "ifindex" {
				ifx = lp.GetValue()
			}
		}
		minByIfindex[ifx] = pb.Gauge.GetValue()
	}
	if _, ok := minByIfindex["80"]; ok {
		t.Fatalf("idle interface (MAX sentinel) must NOT emit the min gauge; got %v", minByIfindex)
	}
	if v, ok := minByIfindex["81"]; !ok || v != 0 {
		t.Fatalf("hard 0-epoch lock-in must emit min gauge = 0; got %v (present=%v)", v, ok)
	}
}

// #1219: emitBindingActiveFlowCount must surface the per-binding
// xpf_userspace_binding_active_flow_count gauge with labels
// {binding_slot, queue_id, worker_id, iface}. Mirrors the
// emitWorkerRuntime test pattern; pins the wire shape so a
// future refactor can't silently drop the metric the fairness
// harness depends on.
func TestEmitBindingActiveFlowCount_LabelsAndValue(t *testing.T) {
	c := &xpfCollector{
		bindingActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_binding_active_flow_count",
			"test desc",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"},
			nil,
		),
	}

	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-1", ActiveFlowCount: 5},
			{Slot: 1, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-2", ActiveFlowCount: 0},
			{Slot: 2, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-0", ActiveFlowCount: 3},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingActiveFlowCount(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}

	if len(got) != 3 {
		t.Fatalf("emitBindingActiveFlowCount: want 3 metrics for 3 bindings, got %d", len(got))
	}

	// Verify the slot=0 series has value 5 with correct labels.
	var found bool
	for _, m := range got {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.Label {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["binding_slot"] != "0" {
			continue
		}
		found = true
		if labels["queue_id"] != "0" || labels["worker_id"] != "0" || labels["iface"] != "ge-0-0-1" {
			t.Errorf("slot=0 wrong labels: %v", labels)
		}
		if pb.Gauge == nil {
			t.Fatalf("slot=0 metric has no gauge")
		}
		if got := pb.Gauge.GetValue(); got != 5 {
			t.Errorf("slot=0 ActiveFlowCount=5 → want gauge value 5, got %v", got)
		}
	}
	if !found {
		t.Fatalf("slot=0 series missing from emitBindingActiveFlowCount output")
	}
}

func TestEmitBindingTXCompletionTelemetry_LabelsAndValues(t *testing.T) {
	c := &xpfCollector{
		bindingTXCompletions: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completions_total",
			"test desc",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"},
			nil,
		),
		bindingTXCompletionRingAvailable: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available",
			"test desc",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"},
			nil,
		),
		bindingTXCompletionRingAvailableMax: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available_max",
			"test desc",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"},
			nil,
		),
	}

	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{{
			Slot:                         2,
			QueueID:                      5,
			WorkerID:                     7,
			Interface:                    "ge-0-0-1",
			TXCompletions:                1234,
			TXCompletionRingAvailable:    17,
			TXCompletionRingAvailableMax: 29,
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingTXCompletionTelemetry(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	if len(got) != 3 {
		t.Fatalf("emitBindingTXCompletionTelemetry: want 3 metrics, got %d", len(got))
	}

	labels := map[string]string{
		"binding_slot": "2",
		"queue_id":     "5",
		"worker_id":    "7",
		"iface":        "ge-0-0-1",
	}
	assertCounterClose(t, got, c.bindingTXCompletions, labels, 1234)
	assertGaugeClose(t, got, c.bindingTXCompletionRingAvailable, labels, 17)
	assertGaugeClose(t, got, c.bindingTXCompletionRingAvailableMax, labels, 29)
}

// #1831: value + type pin for the per-binding V_min fairness-throttle
// counters (#941 work item D / #943) emitted by
// emitBindingVMinThrottleCounters. assertCounterClose checks the
// concrete dto type, so a Counter→Gauge mixup here fails the test.
// Both series must emit even at 0 (second binding) so "brake never
// fired" is a real 0 rather than an absent series.
func TestEmitBindingVMinThrottleCounters_LabelsAndValues(t *testing.T) {
	bindingLabels := []string{"binding_slot", "queue_id", "worker_id", "iface"}
	c := &xpfCollector{
		bindingVMinThrottles: prometheus.NewDesc(
			"xpf_userspace_binding_v_min_throttles_total",
			"test desc", bindingLabels, nil,
		),
		bindingVMinThrottleHardCapOverrides: prometheus.NewDesc(
			"xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total",
			"test desc", bindingLabels, nil,
		),
	}

	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{
			{
				Slot:                         2,
				QueueID:                      5,
				WorkerID:                     7,
				Interface:                    "ge-0-0-1",
				VMinThrottles:                67,
				VMinThrottleHardCapOverrides: 59,
			},
			{
				Slot:      3,
				QueueID:   0,
				WorkerID:  1,
				Interface: "ge-0-0-2",
				// zero counters must still emit
			},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingVMinThrottleCounters(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	if len(got) != 4 {
		t.Fatalf("emitBindingVMinThrottleCounters: want 4 metrics (2 bindings x 2 counters), got %d", len(got))
	}

	labels := map[string]string{
		"binding_slot": "2",
		"queue_id":     "5",
		"worker_id":    "7",
		"iface":        "ge-0-0-1",
	}
	assertCounterClose(t, got, c.bindingVMinThrottles, labels, 67)
	assertCounterClose(t, got, c.bindingVMinThrottleHardCapOverrides, labels, 59)

	zeroLabels := map[string]string{
		"binding_slot": "3",
		"queue_id":     "0",
		"worker_id":    "1",
		"iface":        "ge-0-0-2",
	}
	assertCounterClose(t, got, c.bindingVMinThrottles, zeroLabels, 0)
	assertCounterClose(t, got, c.bindingVMinThrottleHardCapOverrides, zeroLabels, 0)
}

func TestEmitCoSActiveFlowCount_LabelsAndValue(t *testing.T) {
	c := &xpfCollector{
		cosActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_cos_active_flow_count",
			"test desc",
			[]string{"ifindex", "queue_id", "worker_id"},
			nil,
		),
	}

	status := dpuserspace.ProcessStatus{
		CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 1, ActiveFlowCount: 7},
			{Ifindex: 80, QueueID: 5, WorkerID: 2, ActiveFlowCount: 3},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSActiveFlowCount(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}

	if len(got) != 2 {
		t.Fatalf("emitCoSActiveFlowCount: want 2 metrics, got %d", len(got))
	}

	var found bool
	for _, m := range got {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.Label {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["ifindex"] != "80" || labels["queue_id"] != "4" || labels["worker_id"] != "1" {
			continue
		}
		found = true
		if pb.Gauge == nil {
			t.Fatalf("cos active metric has no gauge")
		}
		if got := pb.Gauge.GetValue(); got != 7 {
			t.Errorf("cos active flow count=7 -> want gauge value 7, got %v", got)
		}
	}
	if !found {
		t.Fatalf("queue 4 worker 1 series missing from emitCoSActiveFlowCount output")
	}
}

func TestEmitFairnessRSSGauges_DerivesStructuralCeiling(t *testing.T) {
	c := &xpfCollector{
		fairnessCstruct: prometheus.NewDesc(
			"xpf_fairness_cstruct",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_active_workers",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessActiveFlows: prometheus.NewDesc(
			"xpf_fairness_active_flows",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessMaxWorkerFlowShare: prometheus.NewDesc(
			"xpf_fairness_max_worker_flow_share",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessCoSCountsTruncated: prometheus.NewDesc(
			"xpf_fairness_cos_active_flow_counts_truncated",
			"test desc",
			nil,
			nil,
		),
	}

	status := dpuserspace.ProcessStatus{
		CoSActiveFlowCountsTruncated: true,
		CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: 1, ActiveFlowCount: 3},
			{Ifindex: 80, QueueID: 4, WorkerID: 2, ActiveFlowCount: 0},
			{Ifindex: 80, QueueID: 5, WorkerID: 0, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 5, WorkerID: 1, ActiveFlowCount: 2},
		},
	}

	got := collectFromEmitFairnessRSSGauges(t, c, status)
	if len(got) != 9 {
		t.Fatalf("emitFairnessRSSGauges: want 9 metrics (truncation + 4 per active queue), got %d", len(got))
	}

	assertGaugeClose(t, got, c.fairnessCoSCountsTruncated, nil, 1)
	labelsQ4 := map[string]string{"ifindex": "80", "queue_id": "4"}
	assertGaugeClose(t, got, c.fairnessCstruct, labelsQ4, 0.577350269)
	assertGaugeClose(t, got, c.fairnessActiveWorkers, labelsQ4, 2)
	assertGaugeClose(t, got, c.fairnessActiveFlows, labelsQ4, 4)
	assertGaugeClose(t, got, c.fairnessMaxWorkerFlowShare, labelsQ4, 0.75)

	labelsQ5 := map[string]string{"ifindex": "80", "queue_id": "5"}
	assertGaugeClose(t, got, c.fairnessCstruct, labelsQ5, 0)
	assertGaugeClose(t, got, c.fairnessActiveWorkers, labelsQ5, 2)
	assertGaugeClose(t, got, c.fairnessActiveFlows, labelsQ5, 4)
	assertGaugeClose(t, got, c.fairnessMaxWorkerFlowShare, labelsQ5, 0.5)
}

func TestEmitFairnessRSSGauges_EmptyDistributionOnlyReportsTruncation(t *testing.T) {
	c := &xpfCollector{
		fairnessCstruct: prometheus.NewDesc(
			"xpf_fairness_cstruct",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_active_workers",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessActiveFlows: prometheus.NewDesc(
			"xpf_fairness_active_flows",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessMaxWorkerFlowShare: prometheus.NewDesc(
			"xpf_fairness_max_worker_flow_share",
			"test desc",
			[]string{"ifindex", "queue_id"},
			nil,
		),
		fairnessCoSCountsTruncated: prometheus.NewDesc(
			"xpf_fairness_cos_active_flow_counts_truncated",
			"test desc",
			nil,
			nil,
		),
	}

	got := collectFromEmitFairnessRSSGauges(t, c, dpuserspace.ProcessStatus{})
	if len(got) != 1 {
		t.Fatalf("empty fairness distribution should emit only truncation gauge, got %d metrics", len(got))
	}
	assertGaugeClose(t, got, c.fairnessCoSCountsTruncated, nil, 0)
}

func TestEmitFairnessRSSExpectationGauges(t *testing.T) {
	c := &xpfCollector{
		fairnessRSSExpectation: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_configured",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
		fairnessRSSExpectationValue: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_value",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
		fairnessRSSSkewViolation: prometheus.NewDesc(
			"xpf_fairness_rss_skew_violation",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
		fairnessRSSIndeterminate: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_indeterminate",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		Workers: 4,
		Bindings: []dpuserspace.BindingStatus{
			{Interface: "reth0", Ifindex: 80},
		},
		CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 3},
			{Ifindex: 80, QueueID: 4, WorkerID: 1, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: 2, ActiveFlowCount: 0},
			{Ifindex: 80, QueueID: 4, WorkerID: 3, ActiveFlowCount: 0},
			{Ifindex: 80, QueueID: 5, WorkerID: 0, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 5, WorkerID: 1, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 5, WorkerID: 2, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 5, WorkerID: 3, ActiveFlowCount: 2},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitFairnessRSSExpectationGauges(ch, status, []dpuserspace.FairnessRSSExpectation{
			{Interface: "reth0", QueueID: 4, RSSExpectation: "balanced"},
			{Interface: "reth0", QueueID: 5, RSSExpectation: "balanced"},
			{Interface: "reth0", QueueID: 6, RSSExpectation: "cstruct-max:0.25"},
		})
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	// 3 configured + 1 value (cstruct-max) + 3 violation + 3 indeterminate (#9369).
	if len(got) != 10 {
		t.Fatalf("expected 10 expectation metrics, got %d", len(got))
	}
	labelsQ4 := map[string]string{"ifindex": "80", "queue_id": "4", "kind": "balanced"}
	assertGaugeClose(t, got, c.fairnessRSSExpectation, labelsQ4, 1)
	assertGaugeClose(t, got, c.fairnessRSSSkewViolation, labelsQ4, 1)

	labelsQ5 := map[string]string{"ifindex": "80", "queue_id": "5", "kind": "balanced"}
	assertGaugeClose(t, got, c.fairnessRSSExpectation, labelsQ5, 1)
	assertGaugeClose(t, got, c.fairnessRSSSkewViolation, labelsQ5, 0)

	labelsQ6 := map[string]string{"ifindex": "80", "queue_id": "6", "kind": "cstruct-max"}
	assertGaugeClose(t, got, c.fairnessRSSExpectation, labelsQ6, 1)
	assertGaugeClose(t, got, c.fairnessRSSExpectationValue, labelsQ6, 0.25)
	assertGaugeClose(t, got, c.fairnessRSSSkewViolation, labelsQ6, 1)
	for _, l := range []map[string]string{labelsQ4, labelsQ5, labelsQ6} {
		assertGaugeClose(t, got, c.fairnessRSSIndeterminate, l, 0)
	}
}

// #9369: on a truncated snapshot a constrained expectation is INDETERMINATE.
// It emits xpf_fairness_rss_expectation_indeterminate=1 and NO violation
// sample: a 0 would read as a clean fairness board, and a 1 as a false alarm.
func TestEmitFairnessRSSExpectationGaugesIndeterminateOnTruncation_9369(t *testing.T) {
	desc := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, "test desc", []string{"ifindex", "queue_id", "kind"}, nil)
	}
	c := &xpfCollector{
		fairnessRSSExpectation:      desc("xpf_fairness_rss_expectation_configured"),
		fairnessRSSExpectationValue: desc("xpf_fairness_rss_expectation_value"),
		fairnessRSSSkewViolation:    desc("xpf_fairness_rss_skew_violation"),
		fairnessRSSIndeterminate:    desc("xpf_fairness_rss_expectation_indeterminate"),
	}
	status := dpuserspace.ProcessStatus{
		Workers:                      4,
		Bindings:                     []dpuserspace.BindingStatus{{Interface: "reth0", Ifindex: 80}},
		CoSActiveFlowCountsTruncated: true,
		CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
		},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitFairnessRSSExpectationGauges(ch, status, []dpuserspace.FairnessRSSExpectation{
			{Interface: "reth0", QueueID: 4, RSSExpectation: "cstruct-max:0.1"},
		})
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	labels := map[string]string{"ifindex": "80", "queue_id": "4", "kind": "cstruct-max"}
	assertGaugeClose(t, got, c.fairnessRSSExpectation, labels, 1)
	assertGaugeClose(t, got, c.fairnessRSSIndeterminate, labels, 1)
	for _, m := range got {
		if m.Desc() == c.fairnessRSSSkewViolation {
			t.Fatalf("#9369: an indeterminate expectation must emit NO violation sample, got %v", m)
		}
	}
	// configured + value + indeterminate; no violation.
	if len(got) != 3 {
		t.Fatalf("expected 3 metrics for an indeterminate expectation, got %d", len(got))
	}
}

// fairnessExpectationCollector adapts emitFairnessRSSExpectationGauges to
// the prometheus.Collector interface so a real registry Gather() runs the
// same duplicate-label detection the live /metrics scrape does.
type fairnessExpectationCollector struct {
	c            *xpfCollector
	status       dpuserspace.ProcessStatus
	expectations []dpuserspace.FairnessRSSExpectation
}

func (fc fairnessExpectationCollector) Describe(chan<- *prometheus.Desc) {}

func (fc fairnessExpectationCollector) Collect(ch chan<- prometheus.Metric) {
	fc.c.emitFairnessRSSExpectationGauges(ch, fc.status, fc.expectations)
}

// #hb166 F2: two rss-expectations for two DISTINCT interface names on the
// same queue+kind are both valid config (the dedup key is
// interface/queue). When BOTH are unresolved (their names are absent from
// the dataplane status snapshot) they resolve to ifindex 0, so emitting
// the Prometheus gauge for both would produce two identical
// (ifindex="0", queue_id, kind) label sets — a duplicate-metric error
// that Gather() turns into an HTTP 500 for the ENTIRE /metrics endpoint.
// The fix skips unresolved rows. RED on revert: without the skip both
// rows emit ifindex=0 and Gather() fails.
func TestEmitFairnessRSSExpectationGaugesUnresolvedNoDuplicateLabels(t *testing.T) {
	c := &xpfCollector{
		fairnessRSSExpectation: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_configured",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
		fairnessRSSExpectationValue: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_value",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
		fairnessRSSSkewViolation: prometheus.NewDesc(
			"xpf_fairness_rss_skew_violation",
			"test desc",
			[]string{"ifindex", "queue_id", "kind"},
			nil,
		),
	}
	// No Bindings / CoSInterfaces: both interface names are unresolved.
	status := dpuserspace.ProcessStatus{Workers: 4}
	reg := prometheus.NewRegistry()
	reg.MustRegister(fairnessExpectationCollector{
		c:      c,
		status: status,
		expectations: []dpuserspace.FairnessRSSExpectation{
			{Interface: "ge-0-0-2", QueueID: 4, RSSExpectation: "balanced"},
			{Interface: "ge-0-0-9", QueueID: 4, RSSExpectation: "balanced"},
		},
	})
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed — unresolved rss-expectations collide on ifindex=0 and 500 the whole /metrics scrape: %v", err)
	}
	for _, fam := range families {
		if len(fam.GetMetric()) != 0 {
			t.Fatalf("unresolved rss-expectations must emit no Prometheus gauge, got %d metric(s) for %s",
				len(fam.GetMetric()), fam.GetName())
		}
	}
}

func TestEmitFairnessEqualFlowEstimateGauges(t *testing.T) {
	c := newCollector(nil)
	row := dpuserspace.FairnessThroughputSummary{
		EqualFlowEstimate: dpuserspace.FairnessEqualFlowEstimate{
			Valid:                  true,
			TargetPerFlowBPS:       3_200,
			ObservedBPS:            16_000,
			CappedBPS:              12_800,
			SuppressedBPS:          3_200,
			ThroughputLossRatio:    0.2,
			ActiveWorkers:          2,
			SampledActiveWorkers:   2,
			UnsampledActiveWorkers: 0,
			Workers: []dpuserspace.FairnessEqualFlowWorkerEstimate{
				{
					WorkerID:        0,
					ActiveFlows:     3,
					ObservedBPS:     9_600,
					ObservedPerFlow: 3_200,
					CapBPS:          9_600,
				},
				{
					WorkerID:        1,
					ActiveFlows:     1,
					ObservedBPS:     6_400,
					ObservedPerFlow: 6_400,
					CapBPS:          3_200,
					SuppressedBPS:   3_200,
				},
			},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitFairnessEqualFlowEstimateGauges(ch, row, "80", "4")
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	if len(got) != 16 {
		t.Fatalf("emitFairnessEqualFlowEstimateGauges: want 16 metrics, got %d", len(got))
	}

	queueLabels := map[string]string{"ifindex": "80", "queue_id": "4"}
	assertGaugeClose(t, got, c.fairnessEqualFlowEstimateValid, queueLabels, 1)
	assertGaugeClose(t, got, c.fairnessEqualFlowSampledActiveWorkers, queueLabels, 2)
	assertGaugeClose(t, got, c.fairnessEqualFlowUnsampledActiveWorkers, queueLabels, 0)
	assertGaugeClose(t, got, c.fairnessEqualFlowTargetPerFlowBPS, queueLabels, 3_200)
	assertGaugeClose(t, got, c.fairnessEqualFlowObservedBPS, queueLabels, 16_000)
	assertGaugeClose(t, got, c.fairnessEqualFlowCappedBPS, queueLabels, 12_800)
	assertGaugeClose(t, got, c.fairnessEqualFlowSuppressedBPS, queueLabels, 3_200)
	assertGaugeClose(t, got, c.fairnessEqualFlowThroughputLossRatio, queueLabels, 0.2)

	workerOneLabels := map[string]string{"ifindex": "80", "queue_id": "4", "worker_id": "1"}
	assertGaugeClose(t, got, c.fairnessEqualFlowWorkerObservedBPS, workerOneLabels, 6_400)
	assertGaugeClose(t, got, c.fairnessEqualFlowWorkerObservedPerFlowBPS, workerOneLabels, 6_400)
	assertGaugeClose(t, got, c.fairnessEqualFlowWorkerCapBPS, workerOneLabels, 3_200)
	assertGaugeClose(t, got, c.fairnessEqualFlowWorkerSuppressedBPS, workerOneLabels, 3_200)
}

func TestCoSFairnessRSSSummaries_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		dist []uint32
		want float64
	}{
		{name: "single one-flow worker", dist: []uint32{1}, want: 0},
		{name: "single multi-flow worker", dist: []uint32{5}, want: 0},
		{name: "uniform multi-worker", dist: []uint32{3, 3, 3}, want: 0},
		{name: "severe skew", dist: []uint32{1, 99}, want: 4.92468529477},
		{
			name: "near-uniform billion-scale counts stay nonzero",
			dist: []uint32{1_000_000_000, 1_000_000_001},
			want: 4.9999999975e-10,
		},
		{
			name: "near-uniform uint32-max counts stay nonzero",
			dist: []uint32{4_294_967_294, 4_294_967_295},
			want: 1.16415321868e-10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := dpuserspace.ProcessStatus{}
			for workerID, active := range tt.dist {
				status.CoSActiveFlowCounts = append(status.CoSActiveFlowCounts, dpuserspace.CoSActiveFlowCountStatus{
					Ifindex:         80,
					QueueID:         4,
					WorkerID:        uint32(workerID),
					ActiveFlowCount: active,
				})
			}
			rows := dpuserspace.CoSFairnessRSSSummaries(status)
			if len(rows) != 1 {
				t.Fatalf("CoSFairnessRSSSummaries(%v) returned %d rows, want 1", tt.dist, len(rows))
			}
			if got := rows[0].Cstruct; math.Abs(got-tt.want) > 1e-12 {
				t.Fatalf("cstruct(%v) = %.15g, want %.15g", tt.dist, got, tt.want)
			}
		})
	}
}

func collectFromEmitFairnessRSSGauges(
	t *testing.T,
	c *xpfCollector,
	status dpuserspace.ProcessStatus,
) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitFairnessRSSGauges(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	expected := map[*prometheus.Desc]struct{}{
		c.fairnessCstruct:             {},
		c.fairnessActiveWorkers:       {},
		c.fairnessActiveFlows:         {},
		c.fairnessMaxWorkerFlowShare:  {},
		c.fairnessCoSCountsTruncated:  {},
		c.fairnessRSSExpectation:      {},
		c.fairnessRSSExpectationValue: {},
		c.fairnessRSSSkewViolation:    {},
	}
	for _, m := range got {
		if _, ok := expected[m.Desc()]; !ok {
			t.Fatalf("unexpected metric leaked from emitFairnessRSSGauges: %s", m.Desc())
		}
	}
	return got
}

func assertGaugeClose(
	t *testing.T,
	metrics []prometheus.Metric,
	desc *prometheus.Desc,
	wantLabels map[string]string,
	want float64,
) {
	t.Helper()
	for _, m := range metrics {
		if m.Desc() != desc {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if !metricHasLabels(&pb, wantLabels) {
			continue
		}
		if pb.Gauge == nil {
			t.Fatalf("metric %s has no gauge", desc)
		}
		if got := pb.Gauge.GetValue(); math.Abs(got-want) > 0.000001 {
			t.Fatalf("metric %s labels=%v got %v, want %v", desc, wantLabels, got, want)
		}
		return
	}
	t.Fatalf("metric %s labels=%v not found", desc, wantLabels)
}

func assertCounterClose(
	t *testing.T,
	metrics []prometheus.Metric,
	desc *prometheus.Desc,
	wantLabels map[string]string,
	want float64,
) {
	t.Helper()
	for _, m := range metrics {
		if m.Desc() != desc {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if !metricHasLabels(&pb, wantLabels) {
			continue
		}
		if pb.Counter == nil {
			t.Fatalf("metric %s has no counter", desc)
		}
		if got := pb.Counter.GetValue(); math.Abs(got-want) > 0.000001 {
			t.Fatalf("metric %s labels=%v got %v, want %v", desc, wantLabels, got, want)
		}
		return
	}
	t.Fatalf("metric %s labels=%v not found", desc, wantLabels)
}

func metricHasLabels(pb *dto.Metric, want map[string]string) bool {
	if len(want) == 0 {
		return len(pb.GetLabel()) == 0
	}
	got := map[string]string{}
	for _, label := range pb.GetLabel() {
		got[label.GetName()] = label.GetValue()
	}
	for name, value := range want {
		if got[name] != value {
			return false
		}
	}
	return true
}

// #1829 Phase 1: emitCoSSojourn must surface the sojourn trio for
// EVERY queue row (no gating — a windowed-min 0 is a real "no
// standing queue" signal, the gate evidence's strongest negative
// result), with GAUGE typing and (ifindex, queue_id) labels.
func TestEmitCoSSojourn_LabelsValuesAndGaugeType(t *testing.T) {
	c := &xpfCollector{
		cosSojournEwmaNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_ewma_ns",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosSojournPeakNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_peak_ns",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosSojournWindowedMinNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_windowed_min_ns",
			"test desc",
			[]string{"ifindex", "queue_id"}, nil,
		),
	}
	status := dpuserspace.ProcessStatus{
		CoSInterfaces: []dpuserspace.CoSInterfaceStatus{{
			Ifindex: 80,
			Queues: []dpuserspace.CoSQueueStatus{
				{
					QueueID:              4,
					SojournEwmaNS:        2500000,
					SojournPeakNS:        9000000,
					SojournWindowedMinNS: 1750000,
				},
				// Idle queue: all three gauges must still emit, as
				// zeros (windowed-min 0 = no standing queue).
				{QueueID: 5},
			},
		}},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitCoSSojourn(ch, status)
		close(ch)
	}()
	type series struct {
		desc    *prometheus.Desc
		queueID string
	}
	values := map[series]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["ifindex"] != "80" {
			t.Fatalf("wrong sojourn labels: %v", labels)
		}
		if pb.Gauge == nil {
			t.Fatalf("sojourn metric %s must be a gauge: %+v", m.Desc(), &pb)
		}
		values[series{m.Desc(), labels["queue_id"]}] = pb.Gauge.GetValue()
	}

	want := map[series]float64{
		{c.cosSojournEwmaNS, "4"}:        2500000,
		{c.cosSojournPeakNS, "4"}:        9000000,
		{c.cosSojournWindowedMinNS, "4"}: 1750000,
		{c.cosSojournEwmaNS, "5"}:        0,
		{c.cosSojournPeakNS, "5"}:        0,
		{c.cosSojournWindowedMinNS, "5"}: 0,
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("sojourn metric values: got %+v, want %+v", values, want)
	}
}

// TestEmitWorkerSessionLookupMisses7919 pins the VALUES, not just that the
// three metrics are emitted. The descriptor-set check above proves a metric
// exists; it cannot tell a correctly-wired counter from one reading a
// neighbouring field, and #7919 is an investigation where that distinction
// decides which code path gets blamed.
//
// Distinct primes per cause so a copy-paste that emits the same field three
// times, or swaps two, fails rather than passing on equal values.
func TestEmitWorkerSessionLookupMisses7919(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
			WorkerID:                     2,
			SessionLookupMissNoHandle:    7,
			SessionLookupMissStaleHandle: 11,
			SessionLookupMissKeyMismatch: 13,
		}},
	}
	want := map[string]float64{
		"xpf_userspace_worker_session_lookup_miss_no_handle_total":    7,
		"xpf_userspace_worker_session_lookup_miss_stale_handle_total": 11,
		"xpf_userspace_worker_session_lookup_miss_key_mismatch_total": 13,
	}
	seen := map[string]bool{}
	for _, m := range collectFromEmitWorkerRuntime(t, c, status) {
		name := descName(m.Desc())
		exp, ok := want[name]
		if !ok {
			continue
		}
		seen[name] = true
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		if got := pb.GetCounter().GetValue(); got != exp {
			t.Errorf("%s = %v, want %v — the metric is emitted but carries the "+
				"wrong field; a per-cause counter reading its neighbour would "+
				"send whoever reads it to the wrong code path", name, got, exp)
		}
		if len(pb.GetLabel()) != 1 || pb.GetLabel()[0].GetValue() != "2" {
			t.Errorf("%s: want a single worker_id=2 label, got %v — the per-worker "+
				"split IS the discriminator here (the measured symptom is "+
				"non-uniform across concurrent flows), so an unlabelled or summed "+
				"form would destroy what these were added to show",
				name, pb.GetLabel())
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s was never emitted", name)
		}
	}
}
