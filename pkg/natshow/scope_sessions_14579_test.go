package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #14579: a NAT rule-set scoped by interface or routing-instance (#3096)
// leaves FromZone/ToZone empty on that side. RenderSourceRuleDetail and
// RenderDestRuleDetail printed the blank zone and a numeric
// "sessions for this zone pair: 0" — the tally is keyed by real zone pair
// {FromZone, ToZone}, so the lookup for {"", ToZone} / {"", ""} misses
// unconditionally and the 0 is not a measurement. It also hid the scope
// itself. The fix renders the actual scope and prints no numeric
// zone-pair count for a non-zone-scoped rule-set, while the zone-scoped
// control still prints its measured 2/1.

func scopedNATFixtureConfig() *config.Config {
	cfg := natFixtureConfig()
	// Source: interface-scoped from, zone-scoped to.
	cfg.Security.NAT.Source[0].FromZone = ""
	cfg.Security.NAT.Source[0].FromInterface = "ge-0/0/1.0"
	// Destination: routing-instance-scoped from, no to clause.
	cfg.Security.NAT.Destination.RuleSets[0].FromZone = ""
	cfg.Security.NAT.Destination.RuleSets[0].FromRoutingInstance = "blue"
	return cfg
}

func TestScopedRuleDetailRendersScopeAndNoNumericZonePair_14579(t *testing.T) {
	cfg := scopedNATFixtureConfig()
	// Same three live sessions as the zone-scoped control below: 2 SNAT
	// (trust->untrust zone ids) + 1 DNAT (untrust->dmz). The scoped
	// rule-sets must NOT claim any of them via a {"",...} lookup.
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
			{IsReverse: 0, Flags: dataplane.SessFlagDNAT, IngressZone: 8, EgressZone: 9},
		},
		counters: map[uint32]dataplane.CounterValue{},
	}
	cr := &dataplane.ApplyResult{
		ZoneIDs: map[string]uint16{"trust": 7, "untrust": 8, "dmz": 9},
	}

	var sb strings.Builder
	RenderSourceRuleDetail(context.Background(), &sb, cfg, dp, func() *dataplane.ApplyResult { return cr })
	src := sb.String()
	if !strings.Contains(src, "From interface: ge-0/0/1.0") {
		t.Errorf("source detail did not render the interface scope:\n%s", src)
	}
	if strings.Contains(src, "sessions for this zone pair: 0") {
		t.Errorf("source detail printed an unconditional numeric 0 for a non-zone-scoped rule-set:\n%s", src)
	}
	if strings.Contains(src, "sessions for this zone pair: 2") {
		t.Errorf("source detail attributed zone-pair sessions to an interface-scoped rule-set:\n%s", src)
	}
	if !strings.Contains(src, "To zone: untrust") {
		t.Errorf("source detail lost its zone-scoped to side:\n%s", src)
	}

	var db strings.Builder
	RenderDestRuleDetail(context.Background(), &db, cfg, dp, func() *dataplane.ApplyResult { return cr })
	dst := db.String()
	if !strings.Contains(dst, "From routing-instance: blue") {
		t.Errorf("dest detail did not render the routing-instance scope:\n%s", dst)
	}
	if strings.Contains(dst, "sessions for this zone pair: 0") {
		t.Errorf("dest detail printed an unconditional numeric 0 for a non-zone-scoped rule-set:\n%s", dst)
	}
	if strings.Contains(dst, "sessions for this zone pair: 1") {
		t.Errorf("dest detail attributed zone-pair sessions to an RI-scoped rule-set:\n%s", dst)
	}
}

func TestZoneScopedControlStillPrintsMeasuredCounts_14579(t *testing.T) {
	cfg := natFixtureConfig()
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
			{IsReverse: 0, Flags: dataplane.SessFlagDNAT, IngressZone: 8, EgressZone: 9},
		},
		counters: map[uint32]dataplane.CounterValue{},
	}
	cr := &dataplane.ApplyResult{
		ZoneIDs: map[string]uint16{"trust": 7, "untrust": 8, "dmz": 9},
	}
	var sb strings.Builder
	RenderSourceRuleDetail(context.Background(), &sb, cfg, dp, func() *dataplane.ApplyResult { return cr })
	if !strings.Contains(sb.String(), "sessions for this zone pair: 2") {
		t.Errorf("zone-scoped source control lost its measured count 2:\n%s", sb.String())
	}
	if !strings.Contains(sb.String(), "From zone: trust") {
		t.Errorf("zone-scoped source control lost its from-zone:\n%s", sb.String())
	}
	var db strings.Builder
	RenderDestRuleDetail(context.Background(), &db, cfg, dp, func() *dataplane.ApplyResult { return cr })
	if !strings.Contains(db.String(), "sessions for this zone pair: 1") {
		t.Errorf("zone-scoped dest control lost its measured count 1:\n%s", db.String())
	}
}

// Global (all-empty scope) rule-sets are match-any, not zone-scoped: they
// must not print a numeric zone-pair count either, and must not render
// blank zone labels.
func TestGlobalRuleDetailNoNumericZonePair_14579(t *testing.T) {
	cfg := natFixtureConfig()
	cfg.Security.NAT.Source[0].FromZone = ""
	cfg.Security.NAT.Source[0].ToZone = ""
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
		},
		counters: map[uint32]dataplane.CounterValue{},
	}
	cr := &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 7, "untrust": 8}}
	var sb strings.Builder
	RenderSourceRuleDetail(context.Background(), &sb, cfg, dp, func() *dataplane.ApplyResult { return cr })
	out := sb.String()
	if strings.Contains(out, "sessions for this zone pair: 0") || strings.Contains(out, "sessions for this zone pair: 1") {
		t.Errorf("global rule-set printed a numeric zone-pair count it cannot measure:\n%s", out)
	}
	if !strings.Contains(out, "From zone: any") {
		t.Errorf("global rule-set did not render its match-any scope:\n%s", out)
	}
}
