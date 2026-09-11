package api

import (
	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9654: xpf_learned_route_import_capped says whether the box is capped NOW.
//
// xpf_learned_route_cap_hits_total (#9019) counts capped snapshot BUILDS, so it
// cannot answer that question. It stays non-zero after the import comes back
// under the cap, and it does not move while one capped snapshot stays in force.
// The helper reports the flag from the runtime view its live workers serve, and
// omits it when no worker is live.
//
// EMITTED ONLY WHEN KNOWN, deliberately unlike the always-emitted #9019
// counters. A 0 here claims that live workers are forwarding uncapped. Emitting
// 0 for a helper that did not say would be a confident wrong answer: it may have
// no live worker, or it may predate the field and enforce capped forwarding all
// the same. Absent is the honest reading, and absent() is how to alert on it.
func (c *xpfCollector) describeLearnedRouteImportCapped(ch chan<- *prometheus.Desc) {
	ch <- c.learnedRouteImportCapped
}

func (c *xpfCollector) emitLearnedRouteImportCapped(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	if status.LearnedRouteImportCapped == nil {
		return
	}
	v := 0.0
	if *status.LearnedRouteImportCapped {
		v = 1
	}
	ch <- prometheus.MustNewConstMetric(c.learnedRouteImportCapped, prometheus.GaugeValue, v)
}
