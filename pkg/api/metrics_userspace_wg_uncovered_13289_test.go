package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestWGUncoveredCountersEmit13289(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{
		WgUncoveredEnqueuedTotal:         11,
		WgUncoveredStaleTotal:            12,
		WgUncoveredMalformedTotal:        13,
		WgUncoveredNonlocalTotal:         14,
		WgUncoveredQueueFullTotal:        15,
		WgUncoveredQueueShedTotal:        16,
		WgUncoveredQueueOrphanTotal:      17,
		WgUncoveredQueuePoisonRecoveries: 18,
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceStatus13280(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for metric := range ch {
		got = append(got, metric)
	}
	for _, outcome := range []struct {
		name  string
		value float64
	}{
		{"enqueued", 11}, {"stale", 12}, {"malformed", 13}, {"nonlocal", 14},
		{"queue_full", 15}, {"queue_shed", 16}, {"queue_orphan", 17},
	} {
		assertCounterClose(t, got, c.userspaceWGUncoveredPacketsTotal,
			map[string]string{"outcome": outcome.name}, outcome.value)
	}
	assertCounterClose(t, got, c.userspaceWGUncoveredQueuePoison, nil, 18)
}
