package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// metrics_zone_flood_13293_test.go — #13293 (D4-10).
//
// ProcessStatus.ZoneFloodCounters / FloodCounterOverflowActive were populated
// by the helper (#3651) and decoded in Go, but no Prometheus emitter read them.
// Sibling ZoneCounterOverflowActive was exported (#6845); flood twin was not.

type zoneFloodOnlyCollector13293 struct {
	c      *xpfCollector
	status *dpuserspace.ProcessStatus
	cfg    *config.Config
}

func (z *zoneFloodOnlyCollector13293) Describe(ch chan<- *prometheus.Desc) {
	ch <- z.c.zoneFloodDropsTotal
	ch <- z.c.floodCounterOverflowActive
}

func (z *zoneFloodOnlyCollector13293) Collect(ch chan<- prometheus.Metric) {
	z.c.emitZoneFloodCounters(ch, z.status, z.cfg)
}

func gatherZoneFlood13293(t *testing.T, status *dpuserspace.ProcessStatus, cfg *config.Config) (map[string]float64, float64, bool) {
	t.Helper()
	apply := &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"trust": config.StableZoneID("trust"), "untrust": config.StableZoneID("untrust"),
	}}
	dp := &descriptorCoverageDP{Manager: dataplane.New(), apply: apply}
	c := newCollector(&Server{dp: dp})
	reg := prometheus.NewRegistry()
	reg.MustRegister(&zoneFloodOnlyCollector13293{c: c, status: status, cfg: cfg})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string]float64{}
	overflow := 0.0
	hasOverflow := false
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_userspace_zone_flood_drops_total":
			for _, m := range mf.GetMetric() {
				var zone, kind string
				for _, l := range m.GetLabel() {
					if l.GetName() == "zone" {
						zone = l.GetValue()
					}
					if l.GetName() == "flood_type" {
						kind = l.GetValue()
					}
				}
				out[zone+"/"+kind] = m.GetCounter().GetValue()
			}
		case "xpf_userspace_flood_counter_overflow_active":
			ms := mf.GetMetric()
			if len(ms) != 1 {
				t.Fatalf("overflow metric count = %d, want 1", len(ms))
			}
			overflow = ms[0].GetGauge().GetValue()
			hasOverflow = true
		}
	}
	return out, overflow, hasOverflow
}

func testCfg13293() *config.Config {
	return &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}}}
}

func TestZoneFloodCountersEmitted13293(t *testing.T) {
	cfg := testCfg13293()
	status := &dpuserspace.ProcessStatus{
		FloodCounterOverflowActive: true,
		ZoneFloodCounters: []dpuserspace.ZoneFloodCounterStatus{
			{ZoneID: config.StableZoneID("trust"), SynFloodEvents: 11, ICMPFloodEvents: 22, UDPFloodEvents: 33},
			{ZoneID: config.StableZoneID("untrust"), SynFloodEvents: 44, ICMPFloodEvents: 55, UDPFloodEvents: 66},
		},
	}
	got, overflow, hasOverflow := gatherZoneFlood13293(t, status, cfg)
	want := map[string]float64{
		"trust/syn_flood": 11, "trust/icmp_flood": 22, "trust/udp_flood": 33,
		"untrust/syn_flood": 44, "untrust/icmp_flood": 55, "untrust/udp_flood": 66,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("xpf_userspace_zone_flood_drops_total{%s} = %v, want %v (all=%v)", k, got[k], v, got)
		}
	}
	if !hasOverflow || overflow != 1 {
		t.Errorf("flood overflow gauge = %v present=%v, want 1", overflow, hasOverflow)
	}
}

func TestZoneFloodOverflowHealthyAndAbsent13293(t *testing.T) {
	cfg := testCfg13293()
	_, overflow, has := gatherZoneFlood13293(t, &dpuserspace.ProcessStatus{}, cfg)
	if !has || overflow != 0 {
		t.Errorf("healthy flood overflow = %v present=%v, want 0 present", overflow, has)
	}
	got, _, has := gatherZoneFlood13293(t, nil, cfg)
	if has || len(got) != 0 {
		t.Errorf("nil status must emit nothing, got overflowPresent=%v samples=%v", has, got)
	}
}

func TestZoneFloodUnknownZoneIDOmitted13293(t *testing.T) {
	cfg := testCfg13293()
	status := &dpuserspace.ProcessStatus{ZoneFloodCounters: []dpuserspace.ZoneFloodCounterStatus{
		{ZoneID: 9999, SynFloodEvents: 7},
	}}
	got, _, _ := gatherZoneFlood13293(t, status, cfg)
	if len(got) != 0 {
		t.Errorf("unknown zone ID must be omitted (no fabricated label), got %v", got)
	}
}

// Wiring: Collect must call the emitter after fetching status.
func TestCollectCallsZoneFloodEmitter13293(t *testing.T) {
	src := stripComments6845(readAPISource6845(t, "metrics.go"))
	const call = "c.emitZoneFloodCounters(ch, userspaceStatus"
	if !strings.Contains(src, call) {
		t.Fatalf("Collect does not call emitZoneFloodCounters; flood series emitted by nothing")
	}
	fetch := strings.Index(src, "userspaceStatus := fetchUserspaceStatus(dp)")
	if fetch < 0 || strings.Index(src, call) < fetch {
		t.Error("emitZoneFloodCounters called before status fetch")
	}
}
