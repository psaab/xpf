package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestRenderSourceRuleDetailQuarantinePairAndSurvivor10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	collidingID := config.StableZoneID("zzq17760")
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
		"untrust":  {Name: "untrust"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-survivor", FromZone: "zzq17760", ToZone: "untrust",
			Rules: []*config.NATRule{{Name: "r-surv", Then: config.NATThen{Interface: true}}},
		},
		{
			Name: "rs-loser", FromZone: "zzq8100", ToZone: "untrust",
			Rules: []*config.NATRule{{Name: "r-lose", Then: config.NATThen{Interface: true}}},
		},
	}
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{Flags: dataplane.SessFlagSNAT, IsReverse: 0, IngressZone: uint16(collidingID), EgressZone: 8},
		},
	}
	cr := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
		"zzq17760": collidingID, "zzq8100": collidingID, "untrust": 8,
	}}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	out := b.String()
	if !strings.Contains(out, "zzq8100 "+config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("quarantined rule-set zones missing reference qualifier:\n%s", out)
	}
	if !strings.Contains(out, "Rule-set rs-loser: sessions for this zone pair: "+config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("quarantined pair did not render UNAVAILABLE sessions:\n%s", out)
	}
	if !strings.Contains(out, "Rule-set rs-survivor: sessions for this zone pair: 1") {
		t.Fatalf("survivor pair lost the colliding-ID session (want 1 via deterministic survivor mapping):\n%s", out)
	}
}
