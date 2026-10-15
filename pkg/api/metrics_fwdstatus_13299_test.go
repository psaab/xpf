package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dp "github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

type fwdStatusMetricsTestDP struct {
	apiRuntimeDataPlane
	statusCalls int
	mapReads    int
	status      userspace.ProcessStatus
}

func (d *fwdStatusMetricsTestDP) IsLoaded() bool { return true }
func (d *fwdStatusMetricsTestDP) GetMapStats() []dp.MapStats {
	d.mapReads++
	return nil
}
func (d *fwdStatusMetricsTestDP) Status() (userspace.ProcessStatus, error) {
	d.statusCalls++
	return d.status, nil
}

func TestCollectFwdStatusUsesSharedUserspaceSnapshot13299(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sampler := fwdstatus.NewSampler(nil, fwdstatus.OSProcReader{})
	sampler.Start(ctx)
	now := time.Now()
	dp := &fwdStatusMetricsTestDP{status: userspace.ProcessStatus{
		WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
		Bindings: []userspace.BindingStatus{{
			UmemTotalFrames: 100, UmemInflightFrames: 50,
			DebugPendingFillFrames: 80, TxRingCapacity: 100,
		}},
	}}
	c := &xpfCollector{srv: &Server{dp: dp, fwdSampler: sampler, startTime: now}}
	c.initFwdStatusDescriptors()
	c.initBindingDescriptors()

	shared := fetchUserspaceStatus(dp)
	if shared == nil {
		t.Fatal("fetchUserspaceStatus returned nil")
	}
	if dp.statusCalls != 1 {
		t.Fatalf("status calls after shared fetch = %d, want 1", dp.statusCalls)
	}
	ch := make(chan prometheus.Metric, 32)
	c.collectFwdStatus(ch, dp, shared)
	c.emitBindingUMEMFrames(ch, *shared)
	close(ch)
	var gotBuffer float64
	foundPendingFill := false
	for m := range ch {
		if m.Desc() == c.forwardingBufferUtilization {
			gotBuffer = metricValue(t, m)
		}
		if m.Desc() == c.bindingPendingFillFrames {
			foundPendingFill = metricValue(t, m) == 80
		}
	}
	if gotBuffer != 0.5 {
		t.Errorf("buffer utilization ratio = %v, want 0.5; idle pending fill must not inflate saturation", gotBuffer)
	}
	if !foundPendingFill {
		t.Error("idle pending-fill frames were not separately exported as a gauge")
	}
	if dp.statusCalls != 1 {
		t.Errorf("status calls after forwarding collection = %d, want 1 (reuse the shared snapshot)", dp.statusCalls)
	}
	if dp.mapReads != 0 {
		t.Errorf("userspace map-stat reads = %d, want 0", dp.mapReads)
	}
}

func TestCollectFwdStatusExportsSamplerErrors13299(t *testing.T) {
	proc := fwdstatus.NewSampler(nil, fwdstatus.OSProcReader{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc.Start(ctx)
	c := &xpfCollector{srv: &Server{fwdSampler: proc}}
	c.initFwdStatusDescriptors()
	ch := make(chan prometheus.Metric, 32)
	c.collectFwdStatus(ch, nil, nil)
	close(ch)
	found := map[*prometheus.Desc]bool{}
	for m := range ch {
		found[m.Desc()] = true
	}
	for name, desc := range map[string]*prometheus.Desc{
		"xpf_forwarding_state":                c.forwardingState,
		"xpf_forwarding_cpu_data_stale":       c.forwardingCPUDataStale,
		"xpf_forwarding_sampler_errors_total": c.forwardingSamplerErrors,
	} {
		if !found[desc] {
			t.Errorf("%s was not exported", name)
		}
	}
}

func TestPendingFillFramesAreExportedSeparately13299(t *testing.T) {
	c := newCollector(nil)
	status := userspace.ProcessStatus{Bindings: []userspace.BindingStatus{{
		Slot: 1, QueueID: 2, WorkerID: 3, Interface: "eth0",
		UmemTotalFrames: 100, UmemInflightFrames: 50,
		DebugPendingFillFrames: 80,
	}}}
	ch := make(chan prometheus.Metric)
	go func() {
		c.collectUserspaceStatus(ch, &status)
		close(ch)
	}()
	found := false
	for m := range ch {
		if !strings.Contains(m.Desc().String(), `fqName: "xpf_userspace_binding_pending_fill_frames"`) {
			continue
		}
		if got := metricValue(t, m); got != 80 {
			t.Errorf("pending-fill frames = %v, want 80", got)
		}
		found = true
	}
	if !found {
		t.Fatal("idle pending-fill inventory was not exported as its own gauge")
	}
}

func metricValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var sample dto.Metric
	if err := m.Write(&sample); err != nil {
		t.Fatal(err)
	}
	if sample.Gauge == nil {
		t.Fatal("expected gauge metric, got metric without gauge")
	}
	return sample.Gauge.GetValue()
}
