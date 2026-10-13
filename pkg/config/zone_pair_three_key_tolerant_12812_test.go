package config

import (
	"strings"
	"testing"
)

// #12812 (follow-up #12807): `from-zone A X { to-zone { B { policy } } }`
// parses to Keys=["from-zone","A","X"] (len==3), so it misses both the
// >=4 combined arm and the ==2 nested-to-zone recording arm in
// compilePolicies; tolerant compilation recorded nothing and the dropped
// deny failed open. Separately, one record per to-zone context named
// only the first policy-bearing destination child; later policy-bearing
// children were dropped but unnamed in the diagnostic.

func TestTolerantThreeKeyFromZonePoison12812(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name     string
		fromZone string
	}{
		{"keyless-destination", `from-zone A X { to-zone { B { ` + deny + ` } } }`},
		{"keyed-destination", `from-zone A X { to-zone B { ` + deny + ` } }`},
		{"nested-destination-child", `from-zone A X { to-zone B { C { ` + deny + ` } } }`},
		{"second-to-zone-bearing", `from-zone A X { to-zone { B; } to-zone { C { ` + deny + ` } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := zonePairShape12633(t, tc.fromZone)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict CompileConfig accepted the malformed 3-key zone-pair shape")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable: %v", err)
			}
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatalf("3-key shape recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", cfg.Security.Policies)
			}
			joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
			if !strings.Contains(joined, `from-zone "A"`) {
				t.Fatalf("MalformedZonePairs %q does not name from-zone A", joined)
			}
			// The policy-bearing destination must be named: B except for
			// the policy-bearing second to-zone sibling, which is C.
			wantDest := "to-zone B"
			if tc.name == "second-to-zone-bearing" {
				wantDest = "to-zone C"
			}
			if !strings.Contains(joined, wantDest) {
				t.Fatalf("MalformedZonePairs %q does not name %q", joined, wantDest)
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatal("tolerant compile did not add the snapshot poison carrier")
			}
			if len(cfg.Security.Policies) != 0 {
				t.Fatalf("malformed 3-key shape compiled zone pairs: %+v", cfg.Security.Policies)
			}
		})
	}
}

func TestTolerantToZoneRecordsEveryPolicyBearingChild12812(t *testing.T) {
	deny1 := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	deny2 := `policy p2 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name     string
		fromZone string
	}{
		// Two policy-bearing destination children under ONE keyless to-zone.
		{"two-children-one-to-zone", `from-zone A { to-zone { B { ` + deny1 + ` } C { ` + deny2 + ` } } }`},
		// Policy-bearing children under two sibling to-zone contexts.
		{"two-to-zone-siblings", `from-zone A { to-zone { B { ` + deny1 + ` } } to-zone { C { ` + deny2 + ` } } }`},
		// Same residual on the 3-key arm.
		{"three-key-two-children", `from-zone A X { to-zone { B { ` + deny1 + ` } C { ` + deny2 + ` } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := zonePairShape12633(t, tc.fromZone)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict CompileConfig accepted the malformed zone-pair shape")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable: %v", err)
			}
			if len(cfg.Security.MalformedZonePairs) < 2 {
				t.Fatalf("want one record per policy-bearing destination, got %q", cfg.Security.MalformedZonePairs)
			}
			joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
			for _, want := range []string{"to-zone B", "to-zone C"} {
				if !strings.Contains(joined, want) {
					t.Fatalf("MalformedZonePairs %q does not name %q (later policy-bearing child unnamed)", joined, want)
				}
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatal("tolerant compile did not add the snapshot poison carrier")
			}
		})
	}
}

func TestValidCombinedZonePairNotPoisoned12812(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	tree := zonePairShape12633(t, `from-zone A to-zone B { `+deny+` }`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict CompileConfig rejected valid combined pair: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 0 {
		t.Fatalf("valid combined pair poisoned: %q", cfg.Security.MalformedZonePairs)
	}
	if len(cfg.Security.Policies) != 1 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("valid combined pair did not compile its policy: %+v", cfg.Security.Policies)
	}
}
