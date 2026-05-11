package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

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
			{WorkerID: 0, Dead: false},
			{WorkerID: 1, Dead: true},
			{WorkerID: 2, Dead: false},
		},
	}

	got := collectFromEmitWorkerRuntime(t, c, status)

	// Each worker emits 7 counters + 1 dead gauge = 8 metrics. 3 workers = 24.
	if len(got) != 3*8 {
		t.Fatalf("emitWorkerRuntime: want 24 metrics for 3 workers (7 counters + 1 dead gauge), got %d", len(got))
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
	// Only the seven worker counter descriptors plus the new dead gauge
	// are needed by emitWorkerRuntime; the rest stay nil and are not
	// exercised by this test.
	mk := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, []string{"worker_id"}, nil)
	}
	return &xpfCollector{
		workerWallSecs:      mk("xpf_userspace_worker_wall_seconds_total"),
		workerActiveSecs:    mk("xpf_userspace_worker_active_seconds_total"),
		workerIdleSpinSecs:  mk("xpf_userspace_worker_idle_spin_seconds_total"),
		workerIdleBlockSecs: mk("xpf_userspace_worker_idle_block_seconds_total"),
		workerThreadCPUSecs: mk("xpf_userspace_worker_thread_cpu_seconds_total"),
		workerWorkLoops:     mk("xpf_userspace_worker_work_loops_total"),
		workerIdleLoops:     mk("xpf_userspace_worker_idle_loops_total"),
		workerDead:          mk("xpf_userspace_worker_dead"),
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
		c.workerWallSecs:      {},
		c.workerActiveSecs:    {},
		c.workerIdleSpinSecs:  {},
		c.workerIdleBlockSecs: {},
		c.workerThreadCPUSecs: {},
		c.workerWorkLoops:     {},
		c.workerIdleLoops:     {},
		c.workerDead:          {},
	}
	for _, m := range got {
		if _, ok := expected[m.Desc()]; !ok {
			t.Fatalf("unexpected metric leaked from emitWorkerRuntime: %s", m.Desc())
		}
	}
	return got
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
