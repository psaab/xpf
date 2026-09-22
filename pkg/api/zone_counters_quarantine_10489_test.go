package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestCollectZoneCountersOmitsQuarantinedZone10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
		"trust": {Name: "trust"},
	}
	ids := map[string]uint16{
		"z174":  config.StableZoneID("z174"),
		"z214":  config.StableZoneID("z214"),
		"trust": config.StableZoneID("trust"),
	}
	mgr := dataplane.New()
	mgr.SetZoneCounterOffset(ids["z174"],
		dataplane.CounterValue{Packets: 11, Bytes: 1100},
		dataplane.CounterValue{Packets: 22, Bytes: 2200})
	mgr.SetZoneCounterOffset(ids["trust"],
		dataplane.CounterValue{Packets: 33, Bytes: 3300},
		dataplane.CounterValue{Packets: 44, Bytes: 4400})
	srv := &Server{store: store}
	dp := &zoneRealReadDP{&descriptorCoverageDP{
		Manager: mgr,
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	srv.dp = dp
	c := newCollector(srv)

	got, unpopulated := zoneSamples(t, c, dp)
	for k := range got {
		if strings.Contains(k, "/z214/") {
			t.Fatalf("quarantined zone emitted metric sample %q (survivor volume under loser): %v", k, got)
		}
	}
	for _, k := range []string{
		"xpf_zone_packets_total/z174/ingress",
		"xpf_zone_packets_total/trust/ingress",
	} {
		if _, ok := got[k]; !ok {
			t.Fatalf("survivor/ordinary sample %q absent: %v", k, got)
		}
	}
	if unpopulated != 1 {
		t.Fatalf("unpopulated gauge = %v, want 1 (quarantined z214 only)", unpopulated)
	}
}
