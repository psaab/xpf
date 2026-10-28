package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
)

func (c *xpfCollector) initDataplaneSafetyDescriptors() {
	c.dataplaneObsoleteRegistryAccesses = prometheus.NewDesc("xpf_dataplane_obsolete_registry_accesses_total", "Cumulative dataplane registry accesses refused because the registry generation is obsolete.", nil, nil)
	c.dataplaneXDPDetachDebtInterfaces = prometheus.NewDesc("xpf_dataplane_xdp_detach_debt_interfaces", "Interfaces with outstanding fail-closed XDP detach debt.", nil, nil)
	c.dataplaneHostDivergenceMutations = prometheus.NewDesc("xpf_dataplane_host_divergence_mutations", "Sticky host mutation classes retained after an aborted dataplane apply.", nil, nil)
	c.dataplaneArmUncoveredSurfaces = prometheus.NewDesc("xpf_dataplane_arm_uncovered_surfaces", "Surfaces not covered by the most recent arm proof; emitted only after a completed proof.", nil, nil)
	c.dataplaneArmTotalSurfaces = prometheus.NewDesc("xpf_dataplane_arm_total_surfaces", "Surfaces enumerated by the most recent arm proof; emitted only after a completed proof.", nil, nil)
	c.dataplaneXDPAttachModeSurfaces = prometheus.NewDesc("xpf_dataplane_xdp_attach_mode_surfaces", "Surfaces by XDP attach mode (driver, generic, or skipped) in the most recent completed arm proof.", []string{"mode"}, nil)
}

func (c *xpfCollector) emitDataplaneSafety(ch chan<- prometheus.Metric) {
	// A literal-constructed collector never ran newCollector, so its
	// descriptors are nil. emitConstMetric would panic on a nil Desc
	// (client_golang NewConstMetric dereferences desc.err), so the
	// emit helper below skips each nil-Desc series and counts it.
	emit := func(desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labelValues ...string) {
		if desc == nil {
			c.counterReadErrors.Add(1)
			return
		}
		c.emitConstMetric(ch, desc, valueType, value, labelValues...)
	}
	m, ok := mgmtview.Probe(c.deps.dp).(interface {
		ObsoleteRegistryAccesses() uint64
		DetachDebt() []int
		HostDivergence() []string
		ArmCoverageSnapshot() (dataplane.ArmCoverageReport, bool)
	})
	if !ok {
		return
	}
	emit(c.dataplaneObsoleteRegistryAccesses, prometheus.CounterValue, float64(m.ObsoleteRegistryAccesses()))
	emit(c.dataplaneXDPDetachDebtInterfaces, prometheus.GaugeValue, float64(len(m.DetachDebt())))
	emit(c.dataplaneHostDivergenceMutations, prometheus.GaugeValue, float64(len(m.HostDivergence())))
	report, seen := m.ArmCoverageSnapshot()
	if !seen || !report.Ran {
		return
	}
	emit(c.dataplaneArmUncoveredSurfaces, prometheus.GaugeValue, float64(report.Uncovered))
	emit(c.dataplaneArmTotalSurfaces, prometheus.GaugeValue, float64(len(report.Surfaces)))
	var driver, generic, skipped float64
	for _, surface := range report.Surfaces {
		switch surface.Kind {
		case dataplane.CoverageSkipped:
			skipped++
		case dataplane.CoverageDirect, dataplane.CoverageDelegated:
			if surface.Generic {
				generic++
			} else {
				driver++
			}
		}
	}
	for _, sample := range []struct {
		mode  string
		value float64
	}{{"driver", driver}, {"generic", generic}, {"skipped", skipped}} {
		emit(c.dataplaneXDPAttachModeSurfaces, prometheus.GaugeValue, sample.value, sample.mode)
	}
}
