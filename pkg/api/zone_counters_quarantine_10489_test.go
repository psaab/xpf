package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestCollectZoneCountersOmitsQuarantinedZone10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
		"trust":    {Name: "trust"},
	}
	ids := map[string]uint32{
		"zzq17760": config.StableZoneID("zzq17760"),
		"zzq8100":  config.StableZoneID("zzq8100"),
		"trust":    config.StableZoneID("trust"),
	}
	mgr := dataplane.New()
	mgr.SetZoneCounterOffset(ids["zzq17760"],
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
		if strings.Contains(k, "/zzq8100/") {
			t.Fatalf("quarantined zone emitted metric sample %q (survivor volume under loser): %v", k, got)
		}
	}
	for _, k := range []string{
		"xpf_zone_packets_total/zzq17760/ingress",
		"xpf_zone_packets_total/trust/ingress",
	} {
		if _, ok := got[k]; !ok {
			t.Fatalf("survivor/ordinary sample %q absent: %v", k, got)
		}
	}
	if unpopulated != 1 {
		t.Fatalf("unpopulated gauge = %v, want 1 (quarantined zzq8100 only)", unpopulated)
	}
}
