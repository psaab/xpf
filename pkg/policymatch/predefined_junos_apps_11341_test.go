package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11341: each term in the issue's version-bounded Junos defaults must match
// through the policy simulator. Current-release vSRX readback remains separate.
func TestPredefinedJunosApplicationPolicyMatchesEveryTerm_11341(t *testing.T) {
	cases := []struct {
		set   string
		terms []struct {
			protocol string
			port     int
		}
	}{
		{
			set: "junos-smb",
			terms: []struct {
				protocol string
				port     int
			}{
				{"tcp", 139},
				{"tcp", 445},
			},
		},
		{
			set: "junos-h323",
			terms: []struct {
				protocol string
				port     int
			}{
				{"tcp", 1720},
				{"udp", 1719},
				{"tcp", 1503},
				{"tcp", 389},
				{"tcp", 522},
				{"tcp", 1731},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.set, func(t *testing.T) {
			cfg := cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("permit-"+tc.set,
						config.PolicyMatch{Applications: []string{tc.set}})),
				},
			}, config.ApplicationsConfig{})

			for _, term := range tc.terms {
				res := Match(cfg, Query{
					FromZone: "trust", ToZone: "untrust",
					Protocol: term.protocol, DstPort: term.port,
				})
				if res.ContentRejected {
					t.Errorf("%s %s/%d rejected: %v", tc.set, term.protocol, term.port, res.ContentRejectionReasons)
					continue
				}
				if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "permit-"+tc.set {
					t.Errorf("%s %s/%d did not match its permit: Matched=%v Action=%v Policy=%q DefaultUsed=%v",
						tc.set, term.protocol, term.port, res.Matched, res.Action, res.PolicyName, res.DefaultUsed)
				}
			}

			for _, nonMember := range []struct {
				protocol string
				port     int
			}{
				{"tcp", 80},
				{"udp", 1720},
			} {
				res := Match(cfg, Query{
					FromZone: "trust", ToZone: "untrust",
					Protocol: nonMember.protocol, DstPort: nonMember.port,
				})
				if res.Matched {
					t.Errorf("%s wrongly matched non-member %s/%d", tc.set, nonMember.protocol, nonMember.port)
				}
			}
		})
	}
}
