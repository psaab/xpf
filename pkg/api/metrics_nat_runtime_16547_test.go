package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16547: Prometheus must export the overlap scans/addresses pair and the
// per-pool quarantine gauge, and a runtime-quarantined pool's capacity
// must read 0 (it installs nothing).

type natMetricsVerdictsDP struct {
	*dataplane.Manager
	verdicts dpuserspace.AppliedNATSnapshotVerdicts
}

func (d *natMetricsVerdictsDP) IsLoaded() bool { return true }
func (d *natMetricsVerdictsDP) AppliedNATSnapshotVerdicts() dpuserspace.AppliedNATSnapshotVerdicts {
	return d.verdicts
}

func (d *natMetricsVerdictsDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{}
}

func natMetricsCollector16547(t *testing.T) (*xpfCollector, *natMetricsVerdictsDP) {
	t.Helper()
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := "set security zones security-zone trust\n" +
		"set security zones security-zone untrust\n" +
		"set security nat source pool p1 address 203.0.113.10/32\n" +
		"set security nat source rule-set rs1 from zone trust\n" +
		"set security nat source rule-set rs1 to zone untrust\n" +
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8\n" +
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1"
	if _, err := store.LoadSet(lines); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := newCollector(&Server{store: store})
	dp := &natMetricsVerdictsDP{Manager: dataplane.New(), verdicts: dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{"r1": "iface_snat_egress_overlap"},
		SourceNATPools: map[string]string{"p1": "iface_snat_egress_overlap"},
		NAT64Rules:     map[string]string{},
	}}
	return c, dp
}

func collect16547(t *testing.T, c *xpfCollector, dp apiRuntimeDataPlane) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 256)
	go func() {
		c.collectNATPoolMetrics(ch, dp, &dpuserspace.ProcessStatus{})
		close(ch)
	}()
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

func findMetric16547(t *testing.T, ms []prometheus.Metric, desc *prometheus.Desc, pool string) (float64, bool) {
	t.Helper()
	for _, m := range ms {
		if m.Desc() != desc {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write: %v", err)
		}
		if pool != "" {
			ok := false
			for _, lp := range pb.GetLabel() {
				if lp.GetName() == "pool" && lp.GetValue() == pool {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		if pb.GetGauge() != nil {
			return pb.GetGauge().GetValue(), true
		}
		if pb.GetCounter() != nil {
			return pb.GetCounter().GetValue(), true
		}
	}
	return 0, false
}

func TestCollectNATPoolMetricsRuntimeQuarantine16547(t *testing.T) {
	c, dp := natMetricsCollector16547(t)
	ms := collect16547(t, c, dp)

	if _, ok := findMetric16547(t, ms, c.ifaceSNATOverlapScansTotal, ""); !ok {
		t.Error("xpf_iface_snat_overlap_scans_total not emitted (#16547)")
	}
	if _, ok := findMetric16547(t, ms, c.ifaceSNATOverlapAddresses, ""); !ok {
		t.Error("xpf_iface_snat_overlap_addresses not emitted (#16547)")
	}
	if v, ok := findMetric16547(t, ms, c.ifaceSNATOverlapQuarantined, "p1"); !ok || v != 1 {
		t.Errorf("quarantined{p1} = %v,%v want 1,true", v, ok)
	}
	if v, ok := findMetric16547(t, ms, c.natPoolTotalPorts, "p1"); !ok || v != 0 {
		t.Errorf("total_ports{p1} = %v,%v want 0,true for a runtime-quarantined pool", v, ok)
	}
	if _, ok := findMetric16547(t, ms, c.natPoolUsedPorts, "p1"); ok {
		t.Error("used_ports emitted for a runtime-quarantined pool; want omitted like a config-refused pool")
	}
}

func TestCollectNATPoolMetricsRuntimeControl16547(t *testing.T) {
	c, dp := natMetricsCollector16547(t)
	dp.verdicts = dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{},
		SourceNATPools: map[string]string{},
		NAT64Rules:     map[string]string{},
	}
	ms := collect16547(t, c, dp)
	if v, ok := findMetric16547(t, ms, c.ifaceSNATOverlapQuarantined, "p1"); !ok || v != 0 {
		t.Errorf("quarantined{p1} control = %v,%v want 0,true", v, ok)
	}
	if v, ok := findMetric16547(t, ms, c.natPoolTotalPorts, "p1"); !ok || v == 0 {
		t.Errorf("total_ports{p1} control = %v,%v want >0,true", v, ok)
	}
	if !strings.Contains("x", "x") {
		t.Fatal("unreachable")
	}
}
