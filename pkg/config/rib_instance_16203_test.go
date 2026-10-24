package config

import "testing"

// TestRibInstanceFromName16203 pins the shared matcher hoisted by #16203:
// .inet.0/.inet6.0 instance ribs resolve, bare main ribs and empty-owner
// forms do not, and malformed/trailing-garbage names are rejected. This is
// the same table pkg/routing's TestRibInstanceFromName exercises via
// config.RibInstanceFromName, so gate and applier cannot drift.
func TestRibInstanceFromName16203(t *testing.T) {
	for _, tt := range []struct {
		ribName, instance string
		ok                bool
	}{
		{"vrf1.inet.0", "vrf1", true},
		{"vrf1.inet6.0", "vrf1", true},
		{"a.b.inet.0", "a.b", true},
		{"inet.0", "", false},
		{"inet6.0", "", false},
		{".inet.0", "", false},
		{".inet6.0", "", false},
		{"vrf1.inetX.0", "", false},
		{"vrf1.inet.0.garbage", "", false},
		{"", "", false},
	} {
		if instance, ok := RibInstanceFromName(tt.ribName); instance != tt.instance || ok != tt.ok {
			t.Errorf("RibInstanceFromName(%q) = (%q, %v), want (%q, %v)", tt.ribName, instance, ok, tt.instance, tt.ok)
		}
	}
}

// TestMaxRibGroupLeakRules16203 pins the shared cap value: N fits, N+1 is
// over. The strict gate and the routing applier both read this constant.
func TestMaxRibGroupLeakRules16203(t *testing.T) {
	if MaxRibGroupLeakRules != 1000 {
		t.Fatalf("MaxRibGroupLeakRules = %d, want 1000", MaxRibGroupLeakRules)
	}
	if err := validateRoutingRuleWindowsStrict(mkLeakingInstance(MaxRibGroupLeakRules, "inet")); err != nil {
		t.Fatalf("%d leaked prefixes must pass, got %v", MaxRibGroupLeakRules, err)
	}
	if err := validateRoutingRuleWindowsStrict(mkLeakingInstance(MaxRibGroupLeakRules+1, "inet")); err == nil {
		t.Fatalf("%d leaked prefixes must be rejected", MaxRibGroupLeakRules+1)
	}
	if err := validateRoutingRuleWindowsStrict(mkLeakingInstance(MaxRibGroupLeakRules+1, "inet6")); err == nil {
		t.Fatalf("%d v6 leaked prefixes must be rejected", MaxRibGroupLeakRules+1)
	}
}
