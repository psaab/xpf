package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #17691: Duplicate-membership interfaces bind to neither claimant.
// Source-NAT sessions are aggregated by zone pair, so a partially quarantined
// pair with surviving members still has a meaningful count. Render UNAVAILABLE
// only if either zone has no surviving interface; fully and one-sidedly
// quarantined pairs remain unavailable, while mixed and single-claimant
// controls keep their seeded count.
//
// Fail-on-revert: dropping the ZoneInterfaceQuarantineReason consultation in
// renderSourceRuleDetail makes the fully contested case render "1".

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

	// Asymmetric: trust has only the contested member, while untrust retains
	// a healthy member. Either fully quarantined zone makes the pair unavailable.
	oneZoneQuarantined := mk(map[string][]string{
		"trust":   {"ge-0/0/0.0"},
		"untrust": {"ge-0/0/0.0", "ge-0/0/1.0"},
	})
	if got := config.ZoneInterfaceQuarantineReason(oneZoneQuarantined, "trust", "ge-0/0/0.0"); got == "" {
		t.Fatalf("premise: trust's only member reason empty, want quarantine verdict")
	}
	if got := config.ZoneInterfaceQuarantineReason(oneZoneQuarantined, "untrust", "ge-0/0/1.0"); got != "" {
		t.Fatalf("premise: untrust's healthy member reason = %q, want empty", got)
	}
	var a strings.Builder
	RenderSourceRuleDetail(context.Background(), &a, oneZoneQuarantined, dp, func() *dataplane.ApplyResult { return cr })
	if !strings.Contains(a.String(), wantLine) {
		t.Fatalf("pair with one fully quarantined zone did not render UNAVAILABLE:\n%s", a.String())
	}
	if strings.Contains(a.String(), "sessions for this zone pair: 1") {
		t.Fatalf("pair with one fully quarantined zone rendered measured count:\n%s", a.String())
	}

	// Mixed: the contested member is unusable, but each zone retains a
	// uniquely claimed interface through which the zone-pair tally is measured.
	mixed := mk(map[string][]string{
		"trust":   {"ge-0/0/0.0", "ge-0/0/2.0"},
		"untrust": {"ge-0/0/0.0", "ge-0/0/1.0"},
	})
	if got := config.ZoneInterfaceQuarantineReason(mixed, "trust", "ge-0/0/0.0"); got == "" {
		t.Fatalf("premise: mixed contested member reason empty, want quarantine verdict")
	}
	var m strings.Builder
	RenderSourceRuleDetail(context.Background(), &m, mixed, dp, func() *dataplane.ApplyResult { return cr })
	if !strings.Contains(m.String(), "Rule-set rs-src: sessions for this zone pair: 1") {
		t.Fatalf("mixed pair lost measured count:\n%s", m.String())
	}
	if strings.Contains(m.String(), config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("mixed pair rendered UNAVAILABLE despite healthy members:\n%s", m.String())
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
