package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestNewServerCopiesSNMPServeBudgetStatsHook13309(t *testing.T) {
	srv := NewServer(Config{SNMPServeBudgetStatsFn: func() (uint64, uint64, uint64) {
		return 4, 2, 7
	}})
	if srv.snmpServeBudgetStatsFn == nil {
		t.Fatal("NewServer dropped SNMPServeBudgetStatsFn")
	}
	if shed, evictions, tracked := srv.snmpServeBudgetStatsFn(); shed != 4 || evictions != 2 || tracked != 7 {
		t.Fatalf("SNMPServeBudgetStatsFn = %d/%d/%d, want 4/2/7", shed, evictions, tracked)
	}
}
func TestSNMPServeBudgetMetrics13309(t *testing.T) {
	c := newCollector(&Server{snmpServeBudgetStatsFn: func() (uint64, uint64, uint64) {
		return 7, 2, 11
	}})
	ch := make(chan prometheus.Metric, 3)
	c.emitSNMPServeBudget(ch)
	close(ch)
	want := map[string]float64{
		"xpf_snmp_requests_shed_total":           7,
		"xpf_snmp_source_bucket_evictions_total": 2,
		"xpf_snmp_tracked_sources":               11,
	}
	for metric := range ch {
		var wire dto.Metric
		if err := metric.Write(&wire); err != nil {
			t.Fatal(err)
		}
		name := ""
		for expected := range want {
			if strings.Contains(metric.Desc().String(), `fqName: "`+expected+`"`) {
				name = expected
				break
			}
		}
		if name == "" {
			t.Errorf("unexpected metric descriptor: %s", metric.Desc())
			continue
		}
		value := wire.GetGauge().GetValue()
		if wire.Counter != nil {
			value = wire.GetCounter().GetValue()
		}
		if value != want[name] {
			t.Errorf("%s = %v, want %v", name, value, want[name])
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Errorf("missing SNMP serve-budget metrics: %v", want)
	}

	described := map[string]bool{}
	descs := make(chan *prometheus.Desc, 1024)
	c.Describe(descs)
	close(descs)
	for desc := range descs {
		for _, name := range []string{
			"xpf_snmp_requests_shed_total",
			"xpf_snmp_source_bucket_evictions_total",
			"xpf_snmp_tracked_sources",
		} {
			if strings.Contains(desc.String(), `fqName: "`+name+`"`) {
				described[name] = true
			}
		}
	}
	for _, name := range []string{
		"xpf_snmp_requests_shed_total",
		"xpf_snmp_source_bucket_evictions_total",
		"xpf_snmp_tracked_sources",
	} {
		if !described[name] {
			t.Errorf("%s descriptor is not declared in Describe()", name)
		}
	}
}
