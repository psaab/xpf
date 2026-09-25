package api

import (
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestIPsecInnerStatusExportEndToEnd10695(t *testing.T) {
	const payload = `{"zone_gate_unzoned_total":11,"zone_gate_ambiguous_total":12,"zone_gate_stale_total":13,"zone_gate_no_generation_total":14,"ipsec_inner_parse_drops_total":15,"ipsec_inner_ecn_illegal_drops":16,"ipsec_inner_worker_queue_full_total":17,"ipsec_inner_verdict_queue_full_total":18,"ipsec_inner_slab_exhausted_total":19,"ipsec_inner_worker_retired_total":20,"ipsec_inner_worker_orphan_reaped_total":21,"ipsec_inner_orphan_provisional_total":22}`
	var status dpuserspace.ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode helper status: %v", err)
	}

	collector := newCollector(nil)
	ch := make(chan prometheus.Metric)
	go func() {
		collector.emitUserspaceDynamicBufferMetrics(ch, status)
		close(ch)
	}()
	var metrics []prometheus.Metric
	for metric := range ch {
		metrics = append(metrics, metric)
	}

	assertCounterClose(t, metrics, collector.userspaceZoneGateUnzoned, nil, 11)
	assertCounterClose(t, metrics, collector.userspaceZoneGateAmbiguous, nil, 12)
	assertCounterClose(t, metrics, collector.userspaceZoneGateStale, nil, 13)
	assertCounterClose(t, metrics, collector.userspaceZoneGateNoGeneration, nil, 14)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerParseDrops, nil, 15)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerEcnIllegalDrops, nil, 16)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerWorkerQueueFull, nil, 17)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerVerdictQueueFull, nil, 18)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerSlabExhausted, nil, 19)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerWorkerRetired, nil, 20)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerWorkerOrphanReaped, nil, 21)
	assertCounterClose(t, metrics, collector.userspaceIpsecInnerOrphanProvisional, nil, 22)
}
