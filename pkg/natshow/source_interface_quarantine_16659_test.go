package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #16659/#16556: RenderSourceRuleDetail must consult the duplicate-
// membership interface quarantine verdict. A rule-set whose zone pair
// claims a quarantined interface (bound to NEITHER claimant) has no
// measured zone-pair sessions; rendering the armed tally (here 1,
// seeded under the pair's zone IDs) would present an unmeasured pair
// as measured. It must render UNAVAILABLE instead. The control pair
// (single claimant) keeps its measured count.
//
// Fail-on-revert: drop the ZoneInterfaceQuarantineReason consultation
// in renderSourceRuleDetail and the contested case renders "1".

func TestRenderSourceRuleDetailInterfaceQuarantinePair16659(t *testing.T) {
	mk := func(interfaces map[string][]string) *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust":   {Name: "trust", Interfaces: interfaces["trust"]},
			"untrust": {Name: "untrust", Interfaces: interfaces["untrust"]},
		}
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{
				Name: "rs-src", FromZone: "trust", ToZone: "untrust",
				Rules: []*config.NATRule{{Name: "r1", Then: config.NATThen{Interface: true}}},
			},
		}
		return cfg
	}
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{Flags: dataplane.SessFlagSNAT, IsReverse: 0, IngressZone: 7, EgressZone: 8},
		},
	}
	cr := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 7, "untrust": 8}}

	// Contested: ge-0/0/0.0 claimed by both zones.
	contested := mk(map[string][]string{
		"trust":   {"ge-0/0/0.0"},
		"untrust": {"ge-0/0/0.0"},
	})
	if got := config.ZoneInterfaceQuarantineReason(contested, "trust", "ge-0/0/0.0"); got == "" {
		t.Fatalf("premise: contested member reason empty, want quarantine verdict")
	}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, contested, dp, func() *dataplane.ApplyResult { return cr })
	out := b.String()
	wantLine := "Rule-set rs-src: sessions for this zone pair: " + config.ZoneQuarantineLiveCountersUnavailable
	if !strings.Contains(out, wantLine) {
		t.Fatalf("contested pair did not render UNAVAILABLE:\n%s\nwant line: %s", out, wantLine)
	}
	if strings.Contains(out, "sessions for this zone pair: 1") {
		t.Fatalf("contested pair rendered measured count:\n%s", out)
	}

	// Control: each interface claimed by exactly one zone.
	control := mk(map[string][]string{
		"trust":   {"ge-0/0/0.0"},
		"untrust": {"ge-0/0/1.0"},
	})
	if got := config.ZoneInterfaceQuarantineReason(control, "trust", "ge-0/0/0.0"); got != "" {
		t.Fatalf("premise: control member reason = %q, want empty", got)
	}
	var c strings.Builder
	RenderSourceRuleDetail(context.Background(), &c, control, dp, func() *dataplane.ApplyResult { return cr })
	if !strings.Contains(c.String(), "Rule-set rs-src: sessions for this zone pair: 1") {
		t.Fatalf("control pair lost measured count:\n%s", c.String())
	}
}
