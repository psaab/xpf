package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// portConstrainedAppCfg builds a trust->untrust permit policy whose application
// term is a custom app constrained to TCP destination-port 80. Zones are
// defined so the #3355 guard passes and this test isolates the #3330 port
// semantics.
func portConstrainedAppCfg() *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "web-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"web80"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			"web80": {Name: "web80", Protocol: "tcp", DestinationPort: "80"},
		},
	}
	return cfgWith(sec, apps)
}

// TestPortConstrainedAppOmittedQueryPortNoMatch pins #3330: a port-constrained
// application term must NOT match when the query OMITS the port. The runtime
// keys a single-port term in exact_dst_ports (policy.rs
// CompiledApplications.matches); an omitted query port arrives as 0, which the
// real app port (80) never equals, so the term fails closed. The old
// `&& dstPort > 0` gate skipped the port check for an omitted port and reported
// a permit no concrete packet could hit.
//
// FAIL-ON-REVERT: restoring `app.DestinationPort != "" && dstPort > 0 && ...`
// makes the omitted-port query match (Matched=true, permit), failing the
// want-default-deny assertion.
func TestPortConstrainedAppOmittedQueryPortNoMatch(t *testing.T) {
	cfg := portConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp"}) // DstPort omitted (0)
	if res.Matched {
		t.Fatalf("port-constrained app over-matched an omitted query port (#3330); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for an omitted query port, got %+v", res)
	}
}

// TestPortConstrainedAppMatchingPortStillPermits is the positive control: the
// concrete in-range port still matches (the fix narrows, not breaks, matching).
func TestPortConstrainedAppMatchingPortStillPermits(t *testing.T) {
	cfg := portConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("concrete in-range port no longer matches (#3330 over-narrowed); res = %+v", res)
	}
}

// TestPortConstrainedAppWrongPortNoMatch confirms the constraint is live: a
// concrete OUT-of-range port does not match.
func TestPortConstrainedAppWrongPortNoMatch(t *testing.T) {
	cfg := portConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(81)})
	if res.Matched {
		t.Fatalf("out-of-range port matched a port-constrained app; res = %+v", res)
	}
}
