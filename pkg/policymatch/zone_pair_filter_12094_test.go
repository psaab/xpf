package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func filterConfig12094() *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{
			"trust":   {Name: "trust"},
			"untrust": {Name: "untrust"},
			"dmz":     {Name: "dmz"},
		},
	}}
}

func TestZonePairPolicyAppliesToFilterPair12094(t *testing.T) {
	cfg := filterConfig12094()
	tests := []struct {
		name                 string
		from, to             string
		filterFrom, filterTo string
		want                 bool
	}{
		{name: "exact", from: "trust", to: "untrust", filterFrom: "trust", filterTo: "untrust", want: true},
		{name: "from-any", from: "any", to: "untrust", filterFrom: "trust", filterTo: "untrust", want: true},
		{name: "to-any", from: "trust", to: "any", filterFrom: "trust", filterTo: "untrust", want: true},
		{name: "both-any", from: "any", to: "any", filterFrom: "trust", filterTo: "untrust", want: true},
		{name: "unrelated-from", from: "dmz", to: "untrust", filterFrom: "trust", filterTo: "untrust", want: false},
		{name: "unrelated-to", from: "trust", to: "dmz", filterFrom: "trust", filterTo: "untrust", want: false},
		{name: "unfiltered-axis", from: "dmz", to: "untrust", filterTo: "untrust", want: true},
		{name: "empty-zone-pair-axis-is-not-wildcard", from: "", to: "untrust", filterFrom: "trust", filterTo: "untrust", want: false},
		{name: "host-exact", from: "trust", to: JunosHostZone, filterFrom: "trust", filterTo: JunosHostZone, want: true},
		{name: "host-from-any", from: "any", to: JunosHostZone, filterFrom: "trust", filterTo: JunosHostZone, want: true},
		{name: "host-to-any-excluded", from: "trust", to: "any", filterFrom: "trust", filterTo: JunosHostZone, want: false},
		{name: "host-both-any-excluded", from: "any", to: "any", filterFrom: "trust", filterTo: JunosHostZone, want: false},
		{name: "host-other-exact", from: "dmz", to: JunosHostZone, filterFrom: "trust", filterTo: JunosHostZone, want: false},
		{name: "literal-any-transit-filter-excludes-wildcards", from: "any", to: "untrust", filterFrom: "any", filterTo: "untrust", want: false},
		{name: "literal-any-to-any-excluded", from: "any", to: "any", filterFrom: "any", filterTo: "untrust", want: false},
		{name: "literal-any-source-only-excludes-transit", from: "any", to: "any", filterFrom: "any", want: false},
		{name: "literal-any-host-from-any-runtime-tier", from: "any", to: JunosHostZone, filterFrom: "any", filterTo: JunosHostZone, want: true},
		{name: "unknown-filter-does-not-expand-wildcards", from: "any", to: "untrust", filterFrom: "ghost", filterTo: "untrust", want: false},
		{name: "unknown-filter-exact-also-ineligible", from: "ghost", to: "untrust", filterFrom: "ghost", filterTo: "untrust", want: false},
		{name: "unknown-host-filter-keeps-runtime-from-any", from: "any", to: JunosHostZone, filterFrom: "ghost", filterTo: JunosHostZone, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewZonePairPolicyFilter(cfg, tt.filterFrom, tt.filterTo)
			if got := ZonePairPolicyAppliesToFilterPair(filter, tt.from, tt.to); got != tt.want {
				t.Fatalf("ZonePairPolicyAppliesToFilterPair(%q, %q, %q, %q) = %t, want %t",
					tt.from, tt.to, tt.filterFrom, tt.filterTo, got, tt.want)
			}
		})
	}
}

func TestZonePairPolicyAppliesToQuarantinedFilter12094(t *testing.T) {
	cfg := zoneQuarantineCfg(t)
	filter := NewZonePairPolicyFilter(cfg, "z214", "trust")
	tests := []struct {
		stanza [2]string
		want   bool
	}{
		{stanza: [2]string{"any", "trust"}, want: false},
		{stanza: [2]string{"z214", "trust"}, want: true},
		{stanza: [2]string{"any", "any"}, want: false},
	}
	for _, tt := range tests {
		if got := ZonePairPolicyAppliesToFilterPair(filter, tt.stanza[0], tt.stanza[1]); got != tt.want {
			t.Errorf("quarantined filter applicability for %s -> %s = %t, want %t",
				tt.stanza[0], tt.stanza[1], got, tt.want)
		}
	}
	hostFilter := NewZonePairPolicyFilter(cfg, "z214", JunosHostZone)
	if !ZonePairPolicyAppliesToFilterPair(hostFilter, "any", JunosHostZone) {
		t.Error("quarantined host filter omitted the runtime from-any exception")
	}
	if !ZonePairPolicyAppliesToFilterPair(hostFilter, "z214", JunosHostZone) {
		t.Error("quarantined host filter hid the exact authored stanza")
	}
}

func TestZonePairPolicyFilterTier12094(t *testing.T) {
	tests := []struct {
		from, to string
		want     int
	}{
		{from: "trust", to: "untrust", want: 0},
		{from: "any", to: "untrust", want: 1},
		{from: "trust", to: "any", want: 1},
		{from: "any", to: "any", want: 2},
	}
	for _, tt := range tests {
		if got := ZonePairPolicyFilterTier(tt.from, tt.to); got != tt.want {
			t.Errorf("ZonePairPolicyFilterTier(%q, %q) = %d, want %d", tt.from, tt.to, got, tt.want)
		}
	}
}
