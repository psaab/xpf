package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type metricsNilSlotDP13275 struct {
	*dataplane.Manager
	apply  *dataplane.ApplyResult
	status dpuserspace.ProcessStatus
}

func (d *metricsNilSlotDP13275) IsLoaded() bool                          { return true }
func (d *metricsNilSlotDP13275) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *metricsNilSlotDP13275) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}
func (d *metricsNilSlotDP13275) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}
func (d *metricsNilSlotDP13275) ReadFilterCounters(idx uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(idx) + 1}, nil
}

func metricsNoPanic13275(t *testing.T, what string, fn func(chan<- prometheus.Metric)) []prometheus.Metric {
	t.Helper()
	var out []prometheus.Metric
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s panicked on a nil config slot (must skip, not panic): %v", what, r)
			}
		}()
		ch := make(chan prometheus.Metric, 128)
		fn(ch)
		close(ch)
		for m := range ch {
			out = append(out, m)
		}
	}()
	return out
}

func metricsValue13275(t *testing.T, m prometheus.Metric) (map[string]string, float64) {
	t.Helper()
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("metric write: %v", err)
	}
	labels := make(map[string]string, len(pb.GetLabel()))
	for _, l := range pb.GetLabel() {
		labels[l.GetName()] = l.GetValue()
	}
	if pb.Counter != nil {
		return labels, pb.GetCounter().GetValue()
	}
	return labels, pb.GetGauge().GetValue()
}

// #13275/D1-03: tolerant config restore and HA peer-sync may leave nil map
// values or slice entries. All nil variants are tested alongside valid siblings
// so the collector must skip only the bad slot and keep emitting good series.
func TestCollectFilterCountersSkipsNilSlots13275(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		t.Run(family+"-nil-filter", func(t *testing.T) {
			store := newFilterStore(t, []string{"set firewall family " + family + " filter fin term t1 then accept"})
			cfg := store.ActiveConfig()
			if cfg == nil {
				t.Fatal("missing active config")
			}
			if family == "inet" {
				cfg.Firewall.FiltersInet["zz-nil"] = nil
			} else {
				cfg.Firewall.FiltersInet6["zz-nil"] = nil
			}
			c := newCollector(&Server{store: store})
			dp := &metricsNilSlotDP13275{Manager: dataplane.New(), apply: &dataplane.ApplyResult{FilterIDs: map[string]uint32{family + ":fin": 0}}}
			metrics := metricsNoPanic13275(t, "collectFilterCounters nil filter", func(ch chan<- prometheus.Metric) {
				c.collectFilterCounters(ch, dp, nil)
			})
			found := false
			for _, m := range metrics {
				if !strings.Contains(m.Desc().String(), "xpf_filter_hits_total") {
					continue
				}
				labels, value := metricsValue13275(t, m)
				if labels["term"] == "t1" && value == 1 {
					found = true
				}
				if labels["filter"] == "zz-nil" {
					t.Fatal("emitted filter series for nil filter")
				}
			}
			if !found {
				t.Fatal("valid sibling term t1 series missing")
			}
		})
	}

	for _, userspace := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil-term-map", true: "nil-term-userspace"}[userspace], func(t *testing.T) {
			store := newFilterStore(t, []string{
				"set firewall family inet filter fin term t1 then accept",
				"set firewall family inet filter fin term t2 then accept",
			})
			cfg := store.ActiveConfig()
			if cfg == nil {
				t.Fatal("missing active config")
			}
			filter := cfg.Firewall.FiltersInet["fin"]
			if filter == nil || len(filter.Terms) != 2 {
				t.Fatalf("unexpected filter fixture: %+v", filter)
			}
			filter.Terms = append(filter.Terms[:1:1], append([]*config.FirewallFilterTerm{nil}, filter.Terms[1:]...)...)
			c := newCollector(&Server{store: store})
			dp := &metricsNilSlotDP13275{Manager: dataplane.New()}
			var status *dpuserspace.ProcessStatus
			want1, want2 := 1.0, 2.0
			if userspace {
				dp.apply = nil
				dp.status.FilterTermCounters = []dpuserspace.FirewallFilterTermCounterStatus{
					{Family: "inet", FilterName: "fin", TermName: "t1", Packets: 11},
					{Family: "inet", FilterName: "fin", TermName: "t2", Packets: 22},
				}
				status = &dp.status
				want1, want2 = 11, 22
			} else {
				dp.apply = &dataplane.ApplyResult{FilterIDs: map[string]uint32{"inet:fin": 0}}
			}
			metrics := metricsNoPanic13275(t, "collectFilterCounters nil term", func(ch chan<- prometheus.Metric) {
				c.collectFilterCounters(ch, dp, status)
			})
			got := map[string]float64{}
			for _, m := range metrics {
				if strings.Contains(m.Desc().String(), "xpf_filter_hits_total") {
					labels, value := metricsValue13275(t, m)
					got[labels["term"]] = value
				}
			}
			if got["t1"] != want1 || got["t2"] != want2 {
				t.Fatalf("filter hits = %v, want t1=%v t2=%v; nil term must not panic or emit a sample", got, want1, want2)
			}
			if _, ok := got[""]; ok {
				t.Fatal("emitted filter series for nil term")
			}
		})
	}
}

func TestCollectNATPoolMetricsSkipsNilPool13275(t *testing.T) {
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set security nat source pool p1 address 192.0.2.1/32",
		"set security nat source pool p1 port range low 1024 high 2047",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.NAT.SourcePools) == 0 {
		t.Fatal("missing NAT pool fixture")
	}
	cfg.Security.NAT.SourcePools["zz-nil-pool"] = nil
	c := newCollector(&Server{store: store})
	dp := &descriptorCoverageDP{Manager: dataplane.New(), apply: &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 1}}}
	metrics := metricsNoPanic13275(t, "collectNATPoolMetrics nil pool", func(ch chan<- prometheus.Metric) {
		c.collectNATPoolMetrics(ch, dp, &dpuserspace.ProcessStatus{})
	})
	got := map[string]float64{}
	for _, m := range metrics {
		if m.Desc() == c.natPoolTotalPorts {
			labels, value := metricsValue13275(t, m)
			got[labels["pool"]] = value
		}
	}
	if got["p1"] != 1024 {
		t.Fatalf("natPoolTotalPorts = %v, want p1=1024 (valid sibling preserved)", got)
	}
	if _, ok := got["zz-nil-pool"]; ok {
		t.Fatal("emitted NAT pool series for nil pool")
	}
}
