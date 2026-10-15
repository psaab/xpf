package api

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

func TestCollectFwdStatusExportsSamplerAndHealthSignals13299(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sampler := fwdstatus.NewSampler(nil, fwdstatus.OSProcReader{})
	sampler.Start(ctx)
	c := &xpfCollector{srv: &Server{fwdSampler: sampler}}
	c.initFwdStatusDescriptors()
	ch := make(chan prometheus.Metric, 32)
	c.collectFwdStatus(ch)
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
