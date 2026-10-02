package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func unknownZoneHostConfig(policies []*config.ZonePairPolicies, globals []*config.Policy) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy:  config.PolicyPermit,
			Zones:          zones("trust"),
			Policies:       policies,
			GlobalPolicies: globals,
		},
		Applications: config.ApplicationsConfig{},
	}
}

func unknownZoneHostPolicy(name string, action config.PolicyAction) *config.Policy {
	return &config.Policy{
		Name:   name,
		Action: action,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
	}
}

func TestUndefinedFromZoneJunosHostUsesFromAnyTier11369(t *testing.T) {
	cfg := unknownZoneHostConfig([]*config.ZonePairPolicies{
		{
			FromZone: "any",
			ToZone:   JunosHostZone,
			Policies: []*config.Policy{unknownZoneHostPolicy("block-unzoned", config.PolicyDeny)},
		},
	}, nil)

	res := Match(cfg, Query{FromZone: "bogus", ToZone: JunosHostZone, Protocol: "tcp", DstPort: 22})
	if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "block-unzoned" {
		t.Fatalf("unknown ingress must reach from-any junos-host policy (#11369); got %+v", res)
	}
	if res.HostInboundUnmatched {
		t.Fatalf("explicit from-any deny must override local delivery; got %+v", res)
	}
}

func TestUndefinedFromZoneJunosHostUsesGlobalTier11369(t *testing.T) {
	cfg := unknownZoneHostConfig(nil, []*config.Policy{
		unknownZoneHostPolicy("block-global-unzoned", config.PolicyDeny),
	})
	cfg.Security.GlobalPolicies[0].Match.ToZones = []string{JunosHostZone}

	res := Match(cfg, Query{FromZone: "bogus", ToZone: JunosHostZone, Protocol: "tcp", DstPort: 22})
	if !res.Matched || !res.Global || res.Action != config.PolicyDeny || res.PolicyName != "block-global-unzoned" {
		t.Fatalf("unknown ingress must reach global junos-host policy (#11369); got %+v", res)
	}
	if res.HostInboundUnmatched {
		t.Fatalf("explicit global deny must override local delivery; got %+v", res)
	}
}

func TestUndefinedFromZoneJunosHostNoMatchingTierStillDelivers11369(t *testing.T) {
	cfg := unknownZoneHostConfig([]*config.ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   JunosHostZone,
			Policies: []*config.Policy{unknownZoneHostPolicy("trust-only", config.PolicyDeny)},
		},
	}, []*config.Policy{
		{
			Name:   "global-trust-only",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				FromZones:            []string{"trust"},
				ToZones:              []string{JunosHostZone},
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		},
	})

	res := Match(cfg, Query{FromZone: "bogus", ToZone: JunosHostZone, Protocol: "tcp", DstPort: 22})
	if res.Matched || !res.HostInboundUnmatched {
		t.Fatalf("unknown ingress outside exact/scoped global tiers must keep the local-delivery lifeline; got %+v", res)
	}
}
