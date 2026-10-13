package config

import (
	"strings"
	"testing"
)

// #12807 (follow-up #12633): keyless/nested to-zone variants stay warn-only
// on the tolerant path — only the #7523 lenient downgrade warning surfaces;
// nothing is recorded into MalformedZonePairs, so the snapshot poison
// carrier never engages and the dropped deny fails open under permit-all.
// compilePolicies also inspected only the first to-zone child, so a policy-
// bearing SECOND to-zone records nothing at all.

func TestTolerantKeylessNestedZonePairShapesPoison12807(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name            string
		fromZone        string
		wantRecord      string
		wantDestination string
	}{
		// Keyless to-zone: policy nested under its single child.
		{"keyless-to-zone", `from-zone A { to-zone { B { ` + deny + ` } } }`, `from-zone "A"`, "to-zone B"},
		// Keyed to-zone whose body nests a second to-zone child.
		{"nested-to-zone-child", `from-zone A { to-zone B { C { ` + deny + ` } } }`, `from-zone "A"`, "to-zone B"},
		// Policy-bearing to-zone is the SECOND to-zone sibling; the first
		// carries no policy, so a first-child-only inspection misses it.
		{"second-to-zone-bearing", `from-zone A { to-zone { B; } to-zone { C { ` + deny + ` } } }`, `from-zone "A"`, "to-zone C"},
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
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatalf("shape recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", cfg.Security.Policies)
			}
			joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
			if !strings.Contains(joined, tc.wantRecord) || !strings.Contains(joined, tc.wantDestination) {
				t.Fatalf("MalformedZonePairs %q does not name malformed pair via %q and %q", joined, tc.wantRecord, tc.wantDestination)
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatal("tolerant compile did not add the snapshot poison carrier")
			}
		})
	}
}

func TestTolerantKeylessToZoneNamesPolicyBearingChild12807(t *testing.T) {
	// `to-zone { X; B { policy deny } }`: the diagnostic must name B
	// (the policy-bearing destination), not the first child X.
	cfg, _ := CompileConfigLenient(hierTree(t, `security {
    policies {
        from-zone A {
            to-zone {
                X;
                B { policy p1 { then { deny; } } }
            }
        }
    }
}`))
	found := false
	for _, mp := range cfg.Security.MalformedZonePairs {
		if strings.Contains(mp, "to-zone B ") {
			found = true
		}
		if strings.Contains(mp, "to-zone X ") {
			t.Fatalf("diagnostic named first child instead of policy-bearing B: %q", mp)
		}
	}
	if !found {
		t.Fatalf("MalformedZonePairs = %v, want one naming B", cfg.Security.MalformedZonePairs)
	}
}
