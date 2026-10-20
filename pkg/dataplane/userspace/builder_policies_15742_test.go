package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15742 (regression from #15707/#15890, 670274c712): the full snapshot
// builder computed `policies` via buildPolicySnapshotsWithAddressBookAndFailClosed
// but the ConfigSnapshot literal dropped the `Policies: policies` field
// assignment when NoIPv6RejectZeroHopLimit was added. Every full Compile
// therefore published policies=[] with default_policy=deny, so the helper
// denied all transit (policy_id=4294967295) while Summary.PolicyCount
// still reported len(policies). Partial republishes
// (rebuildScheduledPolicySections) did set next.Policies, masking the
// defect until the next full Compile. This test fails on the pre-fix
// builder (snap.Policies empty) and passes with the field restored.
func TestSnapshotCarriesPolicies15742(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		Policies: []*config.ZonePairPolicies{{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{{
				Name:   "allow-all",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
			}},
		}},
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Policies) != 1 {
		t.Fatalf("snapshot Policies = %d rules, want 1 (full builder must publish the compiled policy set)", len(snap.Policies))
	}
	rule := snap.Policies[0]
	if rule.Name != "allow-all" || rule.FromZone != "lan" || rule.ToZone != "wan" {
		t.Errorf("snapshot policy = %+v, want allow-all lan->wan", rule)
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		t.Errorf("Summary.PolicyCount = %d, want len(Policies) = %d", snap.Summary.PolicyCount, len(snap.Policies))
	}
}
