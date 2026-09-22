package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #4768/#10498: emitDropClassCounters sums each per-binding drop class into
// one process-level, unlabeled CounterValue series and emits every series at
// zero when no bindings exist.
func TestEmitDropClassCounters_4768(t *testing.T) {
	c := &xpfCollector{
		userspaceMartianDropped: prometheus.NewDesc(
			"xpf_userspace_martian_dropped_total", "test", nil, nil),
		userspaceIPv6ExtHeaderDropped: prometheus.NewDesc(
			"xpf_userspace_ipv6_ext_header_dropped_total", "test", nil, nil),
		userspaceUMEMSliceDropped: prometheus.NewDesc(
			"xpf_userspace_umem_slice_dropped_total", "test", nil, nil),
		userspaceUnknownVLANDropped: prometheus.NewDesc(
			"xpf_userspace_unknown_vlan_dropped_total", "test", nil, nil),
		userspaceDstMACDropped: prometheus.NewDesc(
			"xpf_userspace_dst_mac_dropped_total", "test", nil, nil),
	}

	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{
			{
				MartianDropped: 3, IPv6ExtHeaderDropped: 0,
				UMEMSliceDropped: 1, UnknownVLANDropped: 2, DstMACDropped: 3,
			},
			{
				MartianDropped: 4, IPv6ExtHeaderDropped: 10,
				UMEMSliceDropped: 5, UnknownVLANDropped: 7, DstMACDropped: 11,
			},
			{
				MartianDropped: 0, IPv6ExtHeaderDropped: 5,
			},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitDropClassCounters(ch, status)
		close(ch)
	}()
	byName := map[string]float64{}
	count := 0
	for m := range ch {
		count++
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Counter == nil {
			t.Fatalf("metric %s is not a Counter", m.Desc().String())
		}
		byName[m.Desc().String()] = pb.Counter.GetValue()
	}

	if count != 5 {
		t.Fatalf("want exactly 5 aggregate metrics, got %d", count)
	}

	want := map[string]float64{
		"martian_dropped_total":         7,
		"ipv6_ext_header_dropped_total": 15,
		"umem_slice_dropped_total":      6,
		"unknown_vlan_dropped_total":    9,
		"dst_mac_dropped_total":         14,
	}
	for desc, value := range byName {
		matched := false
		for suffix, wantValue := range want {
			if strings.Contains(desc, suffix) {
				matched = true
				if value != wantValue {
					t.Errorf("%s: want %v, got %v", suffix, wantValue, value)
				}
			}
		}
		if !matched {
			t.Errorf("unexpected metric desc: %s", desc)
		}
	}
	if len(byName) != len(want) {
		t.Fatalf("want one series for each of %d reasons, got %d", len(want), len(byName))
	}

	ch2 := make(chan prometheus.Metric)
	go func() {
		c.emitDropClassCounters(ch2, dpuserspace.ProcessStatus{})
		close(ch2)
	}()
	zeros := 0
	for m := range ch2 {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Counter.GetValue() != 0 {
			t.Errorf("empty bindings: want 0, got %v", pb.Counter.GetValue())
		}
		zeros++
	}
	if zeros != 5 {
		t.Errorf("empty bindings: want 5 series emitted at 0, got %d", zeros)
	}
}
