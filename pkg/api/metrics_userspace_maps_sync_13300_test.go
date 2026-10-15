package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestUserspaceMapsSyncTelemetryEmit13300(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{
		RSTSuppressionDegraded:  true,
		RSTSuppressionFailures:  3,
		BindingsWatchdogRepairs: 5,
		BindingsWatchdogErrors:  2,
		LocalAddrPruneSkipped:   7,
	}
	ch := make(chan prometheus.Metric)
	go func() { c.emitUserspaceMapsSyncTelemetry(ch, status); close(ch) }()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	assertCounterClose(t, got, c.userspaceRSTSuppressionFailures, nil, 3)
	assertCounterClose(t, got, c.userspaceBindingsWatchdogRepairs, nil, 5)
	assertCounterClose(t, got, c.userspaceBindingsWatchdogErrors, nil, 2)
	assertCounterClose(t, got, c.userspaceLocalAddrPruneSkipped, nil, 7)
	assertGaugeClose(t, got, c.userspaceRSTSuppressionDegraded, nil, 1)
}
