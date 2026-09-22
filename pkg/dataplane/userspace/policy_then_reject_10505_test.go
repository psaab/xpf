package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNamedPolicyRejectLowersAsReject10505 pins the production wire action for
// a named policy. The default-policy reject path is independent; this assertion
// covers the per-rule arm that emits PolicyRuleSnapshot.Action.
func TestNamedPolicyRejectLowersAsReject10505(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{{
					Name:   "p-reject",
					Action: config.PolicyReject,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
					},
				}},
			}},
		},
	}

	rules, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d policy rule snapshots, want 1", len(rules))
	}
	if got := rules[0].Action; got != "reject" {
		t.Fatalf("named then-reject snapshot action = %q, want reject", got)
	}
}
