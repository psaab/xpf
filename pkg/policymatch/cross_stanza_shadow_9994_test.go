package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9994 — analyzePolicyListShadowing historically walked one ZonePairPolicies
// entry at a time. The compiler preserves each same-pair stanza as a distinct
// entry, while runtime policy.rs concatenates every rule index in the same
// zone-pair bucket and evaluates that ordered stream first-match. A rule in a
// later same-pair stanza can therefore be unreachable behind a rule in an
// earlier stanza, but the advisory omitted it.
//
// RED-ON-REVERT: with the old per-entry walk, the two same-pair stanzas below
// produce no finding for block-web. GREEN requires the concatenated same-pair
// stream to report it SHADOWED, while the independent trust->dmz entry stays
// outside that stream and produces no false positive.
func TestAnalyzePolicyShadowingAcrossSamePairStanzas9994(t *testing.T) {
	pol := func(name string, action config.PolicyAction, src, dst, apps []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      src,
				DestinationAddresses: dst,
				Applications:         apps,
			},
		}
	}

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				pol("permit-all-first-stanza", config.PolicyPermit,
					[]string{"any"}, []string{"any"}, []string{"any"}),
			},
		},
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				pol("block-web-second-stanza", config.PolicyDeny,
					[]string{"any"}, []string{"web-srv"}, []string{"http"}),
			},
		},
		{
			FromZone: "trust", ToZone: "dmz",
			Policies: []*config.Policy{
				pol("independent-dmz-rule", config.PolicyDeny,
					[]string{"any"}, []string{"web-srv"}, []string{"http"}),
			},
		},
	}

	joined := strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	if !strings.Contains(joined, "block-web-second-stanza") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("expected cross-stanza block-web-second-stanza SHADOWED, got:\n%s", joined)
	}
	if strings.Contains(joined, "independent-dmz-rule") {
		t.Fatalf("independent trust->dmz rule was falsely reported:\n%s", joined)
	}
}
