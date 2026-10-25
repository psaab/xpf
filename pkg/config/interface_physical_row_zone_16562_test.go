package config

import "testing"

// #16562: PhysicalRowZoneKey is the shared physical-row attribution
// predicate moved out of pkg/grpcapi (#14364) so the local CLI twins use
// the same rule: only a bare or unit-0 member governs the physical row.
func TestPhysicalRowZoneKey16562(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2"},
		"ge-0/0/3": {Name: "ge-0/0/3"},
	}
	cases := []struct {
		member string
		want   string
		ok     bool
	}{
		{"ge-0/0/2", "ge-0/0/2", true},     // bare governs
		{"ge-0/0/2.0", "ge-0/0/2", true},   // unit 0 governs
		{"ge-0/0/2.00", "ge-0/0/2", true},  // ".00" folds to unit 0 (#5878)
		{"ge-0/0/2.50", "", false},         // non-zero VLAN unit: logical only
		{"ge-0/0/2.80", "", false},         // non-zero VLAN unit: logical only
		{"ge-0/0/3.0", "ge-0/0/3", true},   // unit-0 control
		{"ge-0/0/2.notanumber", "", false}, // malformed never resolves
		{"reth0.50", "", false},            // reth VLAN unit likewise
		{"reth0.0", "reth0", true},         //
		{"reth0", "reth0", true},           //
	}
	for _, tc := range cases {
		got, ok := PhysicalRowZoneKey(cfg, tc.member)
		if ok != tc.ok || got != tc.want {
			t.Errorf("PhysicalRowZoneKey(%q) = (%q, %v), want (%q, %v)",
				tc.member, got, ok, tc.want, tc.ok)
		}
	}
	// Nil config degrades to the legacy split (SplitInterfaceUnitRef is
	// nil-receiver safe): bare/unit-0 still resolve, non-zero does not.
	if got, ok := PhysicalRowZoneKey(nil, "ge-0/0/2.0"); !ok || got != "ge-0/0/2" {
		t.Errorf("PhysicalRowZoneKey(nil, unit0) = (%q, %v), want (ge-0/0/2, true)", got, ok)
	}
	if _, ok := PhysicalRowZoneKey(nil, "ge-0/0/2.50"); ok {
		t.Errorf("PhysicalRowZoneKey(nil, unit50) resolved, want not-ok")
	}
}
