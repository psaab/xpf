package api

import (
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #1621: Prometheus emission test for the cold-path histogram surface.
//
// Per plan v2 (§4.5 + claude-smr-plan-r1.md F2/F4/F5 + agy-r1.md F3/F5/F6 +
// codex-r1.md F3/F4/F5):
//
//   - Bucket counter uses `le` label (PromQL histogram_quantile-
//     compatible).
//   - clock_source gauge ALWAYS emitted, even when uncalibrated
//     (source="unset"), so dashboards distinguish "tsc active" from
//     "no data this scrape".
//   - snapshot_failed counter ALWAYS emitted so operators can detect
//     publish-contention starvation.
//   - ns_per_tsc_q32 gauge emitted so operators can validate
//     calibration sanity.
//   - All scalars (sample_phase, wrapper_underflow_count,
//     wrapper_ns_baseline) emitted.

func TestEmitWorkerColdPath_EmptyStatus_AlwaysEmittedMetrics(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{WorkerID: 0}, // empty cold-path fields
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)

	want := map[string]bool{
		"xpf_userspace_worker_cold_path_sample_phase_total":            false,
		"xpf_userspace_worker_cold_path_wrapper_underflow_count_total": false,
		"xpf_userspace_worker_cold_path_wrapper_ns_baseline":           false,
		"xpf_userspace_worker_cold_path_ns_per_tsc_q32":                false,
		"xpf_userspace_worker_cold_path_clock_source":                  false,
		"xpf_userspace_worker_cold_path_snapshot_failed_total":         false,
	}
	for _, m := range got {
		name := descName(m.Desc())
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("cold-path metric not emitted on empty status: %s", name)
		}
	}
}

func TestEmitWorkerColdPath_ClockSourceGaugeAlwaysOne(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	cases := []struct {
		name        string
		source      string
		labelExpect string
	}{
		{"unset", "", "unset"},
		{"tsc", "tsc", "tsc"},
		{"clock_gettime", "clock_gettime", "clock_gettime"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := dpuserspace.ProcessStatus{
				WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
					{WorkerID: 0, ColdPathClockSource: tc.source},
				},
			}
			got := collectFromEmitWorkerRuntime(t, c, status)
			var foundClockSource bool
			for _, m := range got {
				if m.Desc() != c.workerColdPathClockSource {
					continue
				}
				foundClockSource = true
				var pb dto.Metric
				if err := m.Write(&pb); err != nil {
					t.Fatalf("metric.Write: %v", err)
				}
				if v := pb.Gauge.GetValue(); v != 1.0 {
					t.Errorf("clock_source gauge value: want 1.0 got %v", v)
				}
				var srcLabel string
				for _, l := range pb.Label {
					if l.GetName() == "source" {
						srcLabel = l.GetValue()
					}
				}
				if srcLabel != tc.labelExpect {
					t.Errorf("clock_source label: want %q got %q",
						tc.labelExpect, srcLabel)
				}
			}
			if !foundClockSource {
				t.Errorf("clock_source gauge missing for %s", tc.name)
			}
		})
	}
}

func TestEmitWorkerColdPath_BucketLabelIsLE(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	// Build a synthetic histogram with 1 bucket entry in slot 3.
	hist := make([][]uint64, 16)
	for i := range hist {
		hist[i] = make([]uint64, 24)
	}
	hist[3][5] = 42 // slot 3, bucket 5 (le = 2^(10+5)-1 = 32767)

	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:        0,
				ColdPathHist:    hist,
				ColdPathSamples: make([]uint64, 16),
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)
	var foundBucket bool
	for _, m := range got {
		if m.Desc() != c.workerColdPathBucket {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, l := range pb.Label {
			labels[l.GetName()] = l.GetValue()
		}
		// Verify the bucket metric has the `le` label (NOT
		// `bucket_hi_ns`) per Prometheus histogram_quantile()
		// convention.
		if _, ok := labels["le"]; !ok {
			t.Errorf("bucket metric missing `le` label: labels=%v", labels)
		}
		if _, ok := labels["bucket_hi_ns"]; ok {
			t.Errorf("bucket metric must not use legacy `bucket_hi_ns` label: labels=%v", labels)
		}
		// Sanity: slot 3 + bucket 5 + value 42.
		if labels["zone_pair_slot"] == "3" && labels["le"] == "32767" {
			if pb.Counter.GetValue() == 42 {
				foundBucket = true
			}
		}
	}
	if !foundBucket {
		t.Errorf("expected bucket {worker=0,slot=3,le=32767}=42 not found in emission")
	}
}

func TestEmitWorkerColdPath_PopulatedSlot(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	samples := make([]uint64, 16)
	sumNS := make([]uint64, 16)
	aliasSeen := make([]bool, 16)
	samples[7] = 100
	sumNS[7] = 12345
	aliasSeen[7] = true

	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:                      2,
				ColdPathSamples:               samples,
				ColdPathSumNS:                 sumNS,
				ColdPathAliasSeen:             aliasSeen,
				ColdPathSamplePhase:           50000,
				ColdPathWrapperUnderflowCount: 3,
				ColdPathWrapperNSBaseline:     45,
				ColdPathNSPerTSCQ32:           1871674289,
				ColdPathClockSource:           "tsc",
				ColdPathSnapshotFailed:        2,
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)

	type key struct {
		desc *prometheus.Desc
		slot string
	}
	seen := map[key]float64{}
	for _, m := range got {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		var slot string
		for _, l := range pb.Label {
			if l.GetName() == "zone_pair_slot" {
				slot = l.GetValue()
			}
		}
		v := 0.0
		if pb.Counter != nil {
			v = pb.Counter.GetValue()
		} else if pb.Gauge != nil {
			v = pb.Gauge.GetValue()
		}
		seen[key{m.Desc(), slot}] = v
	}
	if seen[key{c.workerColdPathSamples, "7"}] != 100 {
		t.Errorf("samples slot 7: want 100 got %v",
			seen[key{c.workerColdPathSamples, "7"}])
	}
	if seen[key{c.workerColdPathSumNS, "7"}] != 12345 {
		t.Errorf("sum_ns slot 7: want 12345 got %v",
			seen[key{c.workerColdPathSumNS, "7"}])
	}
	if seen[key{c.workerColdPathAliasSeen, "7"}] != 1 {
		t.Errorf("alias_seen slot 7: want 1.0 got %v",
			seen[key{c.workerColdPathAliasSeen, "7"}])
	}
	if seen[key{c.workerColdPathSamplePhase, ""}] != 50000 {
		t.Errorf("sample_phase: want 50000 got %v",
			seen[key{c.workerColdPathSamplePhase, ""}])
	}
	if seen[key{c.workerColdPathWrapperUnderflow, ""}] != 3 {
		t.Errorf("wrapper_underflow: want 3 got %v",
			seen[key{c.workerColdPathWrapperUnderflow, ""}])
	}
	if seen[key{c.workerColdPathWrapperNSBaseline, ""}] != 45 {
		t.Errorf("wrapper_ns_baseline: want 45 got %v",
			seen[key{c.workerColdPathWrapperNSBaseline, ""}])
	}
	if seen[key{c.workerColdPathNSPerTSCQ32, ""}] != 1871674289 {
		t.Errorf("ns_per_tsc_q32: want 1871674289 got %v",
			seen[key{c.workerColdPathNSPerTSCQ32, ""}])
	}
	if seen[key{c.workerColdPathSnapshotFailedTotal, ""}] != 2 {
		t.Errorf("snapshot_failed: want 2 got %v",
			seen[key{c.workerColdPathSnapshotFailedTotal, ""}])
	}
}

// descName extracts the metric name from a *prometheus.Desc by parsing
// the Desc's `String()` representation. Prometheus client_golang
// stores the name internally but doesn't expose an accessor; the
// String() form is "Desc{fqName: \"<NAME>\", ...}".
func descName(d *prometheus.Desc) string {
	s := d.String()
	const prefix = `fqName: "`
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// === #1635 sparse v3 cold-path emission tests ===

// labelsOf reads a metric's labels into a map.
func labelsOf(t *testing.T, m prometheus.Metric) map[string]string {
	t.Helper()
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("metric.Write: %v", err)
	}
	out := map[string]string{}
	for _, l := range pb.Label {
		out[l.GetName()] = l.GetValue()
	}
	return out
}

func valueOf(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("metric.Write: %v", err)
	}
	if pb.Counter != nil {
		return pb.Counter.GetValue()
	}
	if pb.Gauge != nil {
		return pb.Gauge.GetValue()
	}
	return 0
}

// #1635: layout version 1 (or 0) routes to the v1 dense emit path; the
// v3 per-zone-pair families must NOT appear.
func TestEmitWorkerColdPath_LayoutVersion1_EmitsV1(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	hist := make([][]uint64, 16)
	for i := range hist {
		hist[i] = make([]uint64, 24)
	}
	hist[3][5] = 7
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:              0,
				ColdPathLayoutVersion: 1,
				ColdPathHist:          hist,
				ColdPathSamples:       make([]uint64, 16),
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)
	var sawV1Bucket, sawV3Bucket bool
	for _, m := range got {
		switch descName(m.Desc()) {
		case "xpf_userspace_worker_cold_path_ns_bucket":
			sawV1Bucket = true
		case "xpf_userspace_worker_cold_path_ns_bucket_v3":
			sawV3Bucket = true
		}
	}
	if !sawV1Bucket {
		t.Error("version 1 must emit the v1 bucket family")
	}
	if sawV3Bucket {
		t.Error("version 1 must NOT emit the v3 bucket family")
	}
}

// #1635: layout version 3 routes to the sparse per-zone-pair path with
// from_zone/to_zone labels and the 48-bucket log-linear `le` boundaries.
func TestEmitWorkerColdPath_LayoutVersion3_EmitsV3WithZoneLabels(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	buckets := make([]uint64, 48)
	buckets[6] = 5 // 100 ns lands in linear bucket 6 (le=111)
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:                       0,
				ColdPathLayoutVersion:          3,
				ColdPathActiveSlotIDs:          []uint32{0},
				ColdPathActiveZoneFrom:         []uint32{2},
				ColdPathActiveZoneTo:           []uint32{5},
				ColdPathActiveSamples:          []uint64{5},
				ColdPathActiveSumNS:            []uint64{500},
				ColdPathActiveBuckets:          [][]uint64{buckets},
				ColdPathActiveBuilderCollision: []bool{false},
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)
	var sawSamplesV3, sawBucketLE111, sawVersionGauge bool
	for _, m := range got {
		switch descName(m.Desc()) {
		case "xpf_userspace_worker_cold_path_samples_v3_total":
			lbl := labelsOf(t, m)
			if lbl["from_zone"] == "2" && lbl["to_zone"] == "5" &&
				valueOf(t, m) == 5 {
				sawSamplesV3 = true
			}
		case "xpf_userspace_worker_cold_path_ns_bucket_v3":
			lbl := labelsOf(t, m)
			if lbl["le"] == "111" && valueOf(t, m) == 5 {
				sawBucketLE111 = true
			}
		case "xpf_userspace_worker_cold_path_layout_version":
			if labelsOf(t, m)["version"] == "3" {
				sawVersionGauge = true
			}
		}
	}
	if !sawSamplesV3 {
		t.Error("v3 samples metric with from_zone=2/to_zone=5/value=5 not emitted")
	}
	if !sawBucketLE111 {
		t.Error("v3 cumulative bucket le=111 (100 ns) not emitted — log-linear le mismatch")
	}
	if !sawVersionGauge {
		t.Error("layout_version gauge {version=3} not emitted")
	}
}

// #1635: an unknown layout version emits no v1/v3 metrics, only the
// forward-compat unknown gauge.
func TestEmitWorkerColdPath_LayoutVersionUnknown_EmitsWarning(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{WorkerID: 0, ColdPathLayoutVersion: 99},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)
	var sawUnknown, sawV1, sawV3 bool
	for _, m := range got {
		switch descName(m.Desc()) {
		case "xpf_userspace_worker_cold_path_layout_version_unknown":
			if labelsOf(t, m)["version"] == "99" {
				sawUnknown = true
			}
		case "xpf_userspace_worker_cold_path_ns_bucket":
			sawV1 = true
		case "xpf_userspace_worker_cold_path_ns_bucket_v3":
			sawV3 = true
		}
	}
	if !sawUnknown {
		t.Error("unknown version must emit the unknown-version gauge")
	}
	if sawV1 || sawV3 {
		t.Error("unknown version must NOT emit v1/v3 histogram families")
	}
}

// #1635 CONSUMER CRITERION (per-zone-pair separability): a 20-zone-pair
// workload must report 20 DISTINCT latency distributions with no
// collision-exclusion artifact. With the direct slot map every active
// pair publishes its own (from_zone, to_zone) series; none is excluded.
func TestEmitWorkerColdPath_V3_TwentyZonePairsSeparable(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	const n = 20
	w := dpuserspace.WorkerRuntimeStatus{
		WorkerID:              0,
		ColdPathLayoutVersion: 3,
	}
	for i := 0; i < n; i++ {
		buckets := make([]uint64, 48)
		buckets[i%48] = uint64(i + 1)
		w.ColdPathActiveSlotIDs = append(w.ColdPathActiveSlotIDs, uint32(i))
		w.ColdPathActiveZoneFrom = append(w.ColdPathActiveZoneFrom, uint32(i))
		w.ColdPathActiveZoneTo = append(w.ColdPathActiveZoneTo, uint32(i+1))
		w.ColdPathActiveSamples = append(w.ColdPathActiveSamples, uint64(i+1))
		w.ColdPathActiveSumNS = append(w.ColdPathActiveSumNS, uint64((i+1)*100))
		w.ColdPathActiveBuckets = append(w.ColdPathActiveBuckets, buckets)
		w.ColdPathActiveBuilderCollision = append(w.ColdPathActiveBuilderCollision, false)
	}
	status := dpuserspace.ProcessStatus{WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{w}}
	got := collectFromEmitWorkerRuntime(t, c, status)

	distinctPairs := map[string]float64{}
	for _, m := range got {
		if descName(m.Desc()) != "xpf_userspace_worker_cold_path_samples_v3_total" {
			continue
		}
		lbl := labelsOf(t, m)
		distinctPairs[lbl["from_zone"]+"->"+lbl["to_zone"]] = valueOf(t, m)
	}
	if len(distinctPairs) != n {
		t.Fatalf("expected %d separable zone-pair series, got %d (collision exclusion?)",
			n, len(distinctPairs))
	}
	for i := 0; i < n; i++ {
		key := strconv.Itoa(i) + "->" + strconv.Itoa(i+1)
		if distinctPairs[key] != float64(i+1) {
			t.Errorf("pair %s: want samples %d got %v", key, i+1, distinctPairs[key])
		}
	}
}

// #1635: the sparse encoding emits exactly one series per ACTIVE slot,
// not POLICY_COLD_PATH_ZONE_PAIR_SLOTS (256) series. 12 active slots ⇒
// 12 samples_v3 series.
func TestEmitWorkerColdPath_V3_SparseEmitsOnlyActiveSlots(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	const n = 12
	w := dpuserspace.WorkerRuntimeStatus{WorkerID: 0, ColdPathLayoutVersion: 3}
	for i := 0; i < n; i++ {
		w.ColdPathActiveSlotIDs = append(w.ColdPathActiveSlotIDs, uint32(i))
		w.ColdPathActiveZoneFrom = append(w.ColdPathActiveZoneFrom, uint32(i))
		w.ColdPathActiveZoneTo = append(w.ColdPathActiveZoneTo, uint32(31-i))
		w.ColdPathActiveSamples = append(w.ColdPathActiveSamples, uint64(i+1))
		w.ColdPathActiveSumNS = append(w.ColdPathActiveSumNS, 1)
		w.ColdPathActiveBuckets = append(w.ColdPathActiveBuckets, make([]uint64, 48))
		w.ColdPathActiveBuilderCollision = append(w.ColdPathActiveBuilderCollision, false)
	}
	status := dpuserspace.ProcessStatus{WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{w}}
	got := collectFromEmitWorkerRuntime(t, c, status)
	count := 0
	for _, m := range got {
		if descName(m.Desc()) == "xpf_userspace_worker_cold_path_samples_v3_total" {
			count++
		}
	}
	if count != n {
		t.Fatalf("sparse encoding must emit %d samples_v3 series, got %d", n, count)
	}
}

// #1635 (Copilot code-r2): a v3 payload with overflow_active=true but
// no sampled slots must still emit the overflow gauge (version stamped
// v3 even with empty active arrays), and must not panic on the empty
// parallel arrays.
func TestEmitWorkerColdPath_V3_OverflowNoSamples(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:               0,
				ColdPathLayoutVersion:  3,
				ColdPathOverflowActive: true,
				// All active arrays empty.
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)
	var sawOverflow1, sawV3Bucket bool
	for _, m := range got {
		switch descName(m.Desc()) {
		case "xpf_userspace_worker_cold_path_overflow_active":
			if valueOf(t, m) == 1.0 {
				sawOverflow1 = true
			}
		case "xpf_userspace_worker_cold_path_ns_bucket_v3",
			"xpf_userspace_worker_cold_path_samples_v3_total":
			sawV3Bucket = true
		}
	}
	if !sawOverflow1 {
		t.Error("overflow gauge=1 must emit even with no sampled slots")
	}
	if sawV3Bucket {
		t.Error("no active slots ⇒ no per-zone-pair v3 series")
	}
}

// #1635 (Copilot code-r7 finding 1): xpfCollector is a CHECKED
// collector — every Desc emitted by Collect()/emitWorkerColdPath MUST
// be declared in Describe(), or promhttp logs a Gather error on every
// scrape and a HTTPErrorOnError registry returns 500. This test builds
// the REAL collector (newCollector(nil) — Describe and emitWorkerColdPath
// don't touch srv), captures the Describe() desc set, then drives
// emitWorkerColdPath over a fully-populated v3 worker and asserts every
// emitted Desc is declared. It FAILS if any cold-path desc (v1, scalar,
// or v3) is emitted but undeclared — the registration-contract bug.
func TestColdPathDescriptorsAreDescribed(t *testing.T) {
	c := newCollector(nil)

	// Capture the full Describe() desc set.
	// Buffer must hold the FULL Describe() set (Describe sends synchronously
	// before the drain below); size comfortably above the descriptor count
	// so adding a descriptor does not silently deadlock this capture.
	descCh := make(chan *prometheus.Desc, 1024)
	c.Describe(descCh)
	close(descCh)
	declared := map[*prometheus.Desc]struct{}{}
	for d := range descCh {
		declared[d] = struct{}{}
	}

	// Drive emitWorkerColdPath over a worker that exercises BOTH a
	// populated v3 sparse slot AND the overflow/version/unknown paths,
	// so every cold-path desc family is emitted at least once. Two
	// workers: one v3-with-data, one unknown-version.
	buckets := make([]uint64, 48)
	buckets[6] = 3
	workers := []dpuserspace.WorkerRuntimeStatus{
		{
			WorkerID:                       0,
			ColdPathLayoutVersion:          3,
			ColdPathActiveSlotIDs:          []uint32{0},
			ColdPathActiveZoneFrom:         []uint32{1},
			ColdPathActiveZoneTo:           []uint32{2},
			ColdPathActiveSamples:          []uint64{3},
			ColdPathActiveSumNS:            []uint64{300},
			ColdPathActiveBuckets:          [][]uint64{buckets},
			ColdPathActiveBuilderCollision: []bool{false},
			ColdPathOverflowActive:         true,
			ColdPathClockSource:            "tsc",
		},
		{WorkerID: 1, ColdPathLayoutVersion: 99}, // unknown-version path
	}
	// Also emit a v1 worker so the legacy dense families are exercised.
	hist := make([][]uint64, 16)
	for i := range hist {
		hist[i] = make([]uint64, 24)
	}
	hist[3][5] = 1
	// Populate ALL v1 per-slot families so workerColdPathSumNS and
	// workerColdPathAliasSeen are actually emitted (Codex code-r7: the
	// earlier fixture left these empty, so the test would not catch
	// their removal from Describe()).
	v1Samples := make([]uint64, 16)
	v1Samples[3] = 1
	v1SumNS := make([]uint64, 16)
	v1SumNS[3] = 100
	v1AliasSeen := make([]bool, 16)
	v1AliasSeen[3] = true
	workers = append(workers, dpuserspace.WorkerRuntimeStatus{
		WorkerID:              2,
		ColdPathLayoutVersion: 1,
		ColdPathHist:          hist,
		ColdPathSamples:       v1Samples,
		ColdPathSumNS:         v1SumNS,
		ColdPathAliasSeen:     v1AliasSeen,
	})

	metricCh := make(chan prometheus.Metric, 1024)
	go func() {
		for _, w := range workers {
			label := strconv.FormatUint(uint64(w.WorkerID), 10)
			c.emitWorkerColdPath(metricCh, label, w)
		}
		close(metricCh)
	}()

	var undeclared []string
	emitted := map[*prometheus.Desc]struct{}{}
	for m := range metricCh {
		d := m.Desc()
		emitted[d] = struct{}{}
		if _, ok := declared[d]; !ok {
			undeclared = append(undeclared, descName(d))
		}
	}
	if len(undeclared) > 0 {
		t.Fatalf("emitWorkerColdPath emitted %d undeclared descriptors (checked-collector "+
			"contract violation — add them to Describe()): %v", len(undeclared), undeclared)
	}
	// Sanity (Codex code-r7): the fixtures above exercise EVERY cold-path
	// descriptor exactly once across the family — 4 v1 (bucket, samples,
	// sum_ns, alias_seen) + 6 scalars (sample_phase, wrapper_underflow,
	// wrapper_ns_baseline, ns_per_tsc_q32, clock_source, snapshot_failed)
	// + 4 v3 (bucket, samples, sum_ns, builder_collision) + overflow +
	// layout_version + layout_version_unknown = 17. Asserting the exact
	// count means removing ANY cold-path desc from Describe() is caught
	// here (the undeclared check above catches additions; this catches
	// the test silently under-exercising the family).
	const wantColdPathDescs = 17
	coldPathEmitted := 0
	for d := range emitted {
		if strings.Contains(descName(d), "cold_path") {
			coldPathEmitted++
		}
	}
	if coldPathEmitted != wantColdPathDescs {
		t.Fatalf("test exercised %d distinct cold-path descriptors, want exactly %d "+
			"(fixtures must emit every family so removal of any desc is caught)",
			coldPathEmitted, wantColdPathDescs)
	}
}
