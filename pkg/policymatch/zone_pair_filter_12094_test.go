package policymatch

import "testing"

func TestZonePairPolicyAppliesToFilterPair12094(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ZonePairPolicyAppliesToFilterPair(tt.from, tt.to, tt.filterFrom, tt.filterTo); got != tt.want {
				t.Fatalf("ZonePairPolicyAppliesToFilterPair(%q, %q, %q, %q) = %t, want %t",
					tt.from, tt.to, tt.filterFrom, tt.filterTo, got, tt.want)
			}
		})
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
