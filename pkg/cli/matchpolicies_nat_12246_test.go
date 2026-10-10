package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowMatchPoliciesRequiresPostDNATInput pins #12246 at the advertised
// packet-check surface. The dataplane evaluates policy after DNAT, so the
// simulator's policy-only tuple must be supplied post-DNAT. A VIP query may
// otherwise hit permit-vip even though a real VIP packet is translated to the
// denied server. The output must state the tuple-stage requirement alongside
// the verdict, and usage must name the expected input stage.
func TestShowMatchPoliciesRequiresPostDNATInput(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones: map[string]*config.ZoneConfig{
			"untrust": {Name: "untrust"},
			"trust":   {Name: "trust"},
		},
		NAT: config.NATConfig{Destination: &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{
				"srv-pool": {Name: "srv-pool", Address: "10.0.0.5", Port: 8080},
			},
			RuleSets: []*config.NATRuleSet{{
				Name:     "rs-dnat",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name: "vip-http",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.10",
						DestinationPort:    80,
						Protocol:           "tcp",
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "srv-pool"},
				}},
			}},
		}},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "untrust",
			ToZone:   "trust",
			Policies: []*config.Policy{
				{
					Name:   "permit-vip",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"203.0.113.10/32"},
						Applications:         []string{"any"},
					},
				},
				{
					Name:   "deny-server",
					Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"10.0.0.5/32"},
						Applications:         []string{"any"},
					},
				},
			},
		}},
	}}

	out := captureStdout(t, func() {
		if err := (&CLI{}).showMatchPolicies(cfg, []string{
			"from-zone", "untrust", "to-zone", "trust",
			"source-ip", "198.51.100.7", "destination-ip", "203.0.113.10",
			"protocol", "tcp", "destination-port", "80",
		}); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})
	if !strings.Contains(out, "post-DNAT") || !strings.Contains(out, "post-translation") {
		t.Fatalf("match-policies must state that destination-ip/port are expected post-DNAT; output:\n%s", out)
	}
	if !strings.Contains(out, "permit-vip") {
		t.Fatalf("the VIP-vs-real regression fixture did not exercise the literal VIP verdict; output:\n%s", out)
	}
}
