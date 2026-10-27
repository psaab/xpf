package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// srcPortConstrainedAppCfg builds a trust->untrust permit policy whose
// application term is a custom app constrained to TCP source-port 5000 (and
// destination-port 80, so the term is otherwise satisfiable). Zones are defined
// so the #3355 guard passes and this test isolates the #3415 source-port
// semantics.
func srcPortConstrainedAppCfg() *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "src5000-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"src5000"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			"src5000": {Name: "src5000", Protocol: "tcp", SourcePort: "5000", DestinationPort: "80"},
		},
	}
	return cfgWith(sec, apps)
}

// TestSrcPortConstrainedAppOmittedQuerySrcPortNoMatch pins #3415: a
// source-port-constrained application term must NOT match when the query OMITS
// the source port. The runtime always carries a concrete source port and gates
// a source-port-constrained app on it (appid.matchTuple -> portInSpec(srcPort,
// appSrcPort); policy.rs CompiledApplications.matches), so a packet whose
// source port differs from the app's `source-port` never matches. An omitted
// query source port arrives as 0, which the real app source port (5000) never
// equals, so the term fails closed — mirroring the #3323 (protocol) and #3330
// (destination-port) siblings.
//
// FAIL-ON-REVERT: restoring `app.SourcePort != "" && srcPort > 0 && ...` skips
// the source-port check for an omitted port, making this query MATCH
// (Matched=true, permit) and over-certifying a permit no concrete packet could
// hit (the #3107 wildcard stance #3415 supersedes), failing the
// want-default-deny assertion.
func TestSrcPortConstrainedAppOmittedQuerySrcPortNoMatch(t *testing.T) {
	cfg := srcPortConstrainedAppCfg()

	// SrcPort omitted (0); destination port supplied so only the source-port
	// dimension is in question.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if res.Matched {
		t.Fatalf("source-port-constrained app over-matched an omitted query source port (#3415); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for an omitted query source port, got %+v", res)
	}
}

// TestSrcPortConstrainedAppMatchingSrcPortStillPermits is the positive control:
// the concrete in-spec source port still matches (the fix narrows, not breaks,
// matching).
func TestSrcPortConstrainedAppMatchingSrcPortStillPermits(t *testing.T) {
	cfg := srcPortConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", SrcPort: PortPtr(5000), DstPort: PortPtr(80)})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("concrete in-spec source port no longer matches (#3415 over-narrowed); res = %+v", res)
	}
}

// TestSrcPortConstrainedAppWrongSrcPortNoMatch confirms the constraint is live:
// a concrete WRONG source port does not match (this held before #3415 too, via
// the SPECIFIED-port branch; it pins that the fix did not regress it).
func TestSrcPortConstrainedAppWrongSrcPortNoMatch(t *testing.T) {
	cfg := srcPortConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", SrcPort: PortPtr(6000), DstPort: PortPtr(80)})
	if res.Matched {
		t.Fatalf("wrong source port matched a source-port-constrained app; res = %+v", res)
	}
}

// TestUnconstrainedSrcPortAppOmittedQuerySrcPortStillMatches pins that the
// #3415 narrowing is scoped to SOURCE-port-CONSTRAINED apps only: an ordinary
// app with NO source-port constraint still matches a query that omits the
// source port (the common case is unaffected). web80 constrains only the
// destination port, supplied here.
func TestUnconstrainedSrcPortAppOmittedQuerySrcPortStillMatches(t *testing.T) {
	cfg := portConstrainedAppCfg() // web80: tcp, destination-port 80, no source-port

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)}) // SrcPort omitted (0)
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("source-port-UNCONSTRAINED app must still match an omitted query source port (#3415 over-narrowed); res = %+v", res)
	}
}
