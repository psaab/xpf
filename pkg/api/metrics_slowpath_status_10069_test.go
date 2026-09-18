package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #10069 Gap 2: delegated outlet status is observable in Prometheus with the
// same metric families as the trusted outlet and an explicit outlet label.
func TestSlowPathDelegatedStatusMetrics10069(t *testing.T) {
	c := &xpfCollector{}
	c.initSlowPathDescriptors()
	status := dpuserspace.ProcessStatus{
		SlowPath: dpuserspace.SlowPathStatus{Active: true, LiveMTU: 9000},
		SlowPathDelegated: dpuserspace.SlowPathStatus{
			Active: true, Degraded: true, LiveMTU: 1500,
			InjectedPackets: 7, MTUDroppedPackets: 3,
		},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceSlowPathStatus(ch, status)
		close(ch)
	}()
	delegatedMTU := false
	delegatedDegraded := false
	delegatedInjected := false
	for metric := range ch {
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		desc := metric.Desc().String()
		if !strings.Contains(desc, `fqName: "xpf_userspace_slow_path_live_mtu"`) {
			continue
		}
		if pb.GetGauge().GetValue() != 1500 && pb.GetGauge().GetValue() != 9000 {
			t.Fatalf("unexpected live MTU metric value: %v", pb.GetGauge().GetValue())
		}
		for _, label := range pb.GetLabel() {
			if label.GetName() != "outlet" {
				continue
			}
			if label.GetValue() == "delegated" {
				delegatedMTU = pb.GetGauge().GetValue() == 1500
			}
		}
	}
	if !delegatedMTU {
		t.Fatal("delegated live MTU metric was not emitted")
	}

	// Re-collect the health/counter families with a focused value check. This
	// catches a metric wiring that emits the outlet label but reads trusted data.
	ch = make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceSlowPathStatus(ch, status)
		close(ch)
	}()
	for metric := range ch {
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		desc := metric.Desc().String()
		isDelegated := false
		for _, label := range pb.GetLabel() {
			if label.GetName() == "outlet" && label.GetValue() == "delegated" {
				isDelegated = true
			}
		}
		if !isDelegated {
			continue
		}
		switch {
		case strings.Contains(desc, `fqName: "xpf_userspace_slow_path_degraded"`):
			delegatedDegraded = pb.GetGauge().GetValue() == 1
		case strings.Contains(desc, `fqName: "xpf_userspace_slow_path_injected_packets_total"`):
			delegatedInjected = pb.GetCounter().GetValue() == 7
		}
	}
	if !delegatedDegraded || !delegatedInjected {
		t.Fatalf("delegated status metrics missing values: degraded=%t injected=%t", delegatedDegraded, delegatedInjected)
	}
}
