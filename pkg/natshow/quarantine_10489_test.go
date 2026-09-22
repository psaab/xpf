package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestRenderSourceRuleDetailQuarantinePairAndSurvivor10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	collidingID := config.StableZoneID("z174")
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174":    {Name: "z174"},
		"z214":    {Name: "z214"},
		"untrust": {Name: "untrust"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-survivor", FromZone: "z174", ToZone: "untrust",
			Rules: []*config.NATRule{{Name: "r-surv", Then: config.NATThen{Interface: true}}},
		},
		{
			Name: "rs-loser", FromZone: "z214", ToZone: "untrust",
			Rules: []*config.NATRule{{Name: "r-lose", Then: config.NATThen{Interface: true}}},
		},
	}
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{Flags: dataplane.SessFlagSNAT, IsReverse: 0, IngressZone: collidingID, EgressZone: 8},
		},
	}
	cr := &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"z174": collidingID, "z214": collidingID, "untrust": 8,
	}}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	out := b.String()
	if !strings.Contains(out, "z214 "+config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("quarantined rule-set zones missing reference qualifier:\n%s", out)
	}
	if !strings.Contains(out, "Rule-set rs-loser: sessions for this zone pair: "+config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("quarantined pair did not render UNAVAILABLE sessions:\n%s", out)
	}
	if !strings.Contains(out, "Rule-set rs-survivor: sessions for this zone pair: 1") {
		t.Fatalf("survivor pair lost the colliding-ID session (want 1 via deterministic survivor mapping):\n%s", out)
	}
}
