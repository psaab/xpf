package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/natshow"
)

// #1687 invariant: the gRPC NAT show wrappers must produce byte-identical
// output to the shared pkg/natshow renderers (which the CLI show path
// also calls). These assert the gRPC *strings.Builder wrapper output
// equals a direct natshow render of the same fixture and Reader.
// Combined with the CLI-side test (pkg/cli/cli_show_nat_shared_test.go),
// this proves both consumers single-source identical bytes.

func sharedGRPCNATFixture() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-src", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{
					Name:  "r1",
					Match: config.NATMatch{SourceAddress: "10.0.1.0/24", Protocol: "tcp"},
					Then:  config.NATThen{PoolName: "p-src"},
				},
			},
		},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p-src": {Name: "p-src", Addresses: []string{"203.0.113.1"}},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p-dst": {Name: "p-dst", Address: "10.0.30.5", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "rs-dst", FromZone: "untrust", ToZone: "dmz",
				Rules: []*config.NATRule{
					{
						Name:  "d1",
						Match: config.NATMatch{DestinationAddress: "198.51.100.7/32", DestinationPort: 443, Protocol: "tcp"},
						Then:  config.NATThen{PoolName: "p-dst"},
					},
				},
			},
		},
	}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-static", FromZone: "trust",
			Rules: []*config.StaticNATRule{
				{Name: "s1", Match: "192.0.2.10", Then: "10.0.1.10"},
				{Name: "n1", Match: "2001:db8:a::/64", Then: "fd00:a::/64", IsNPTv6: true},
			},
		},
	}
	return cfg
}

func TestGRPCNATWrappersMatchSharedRenderers(t *testing.T) {
	cfg := sharedGRPCNATFixture()
	dp := dataplane.New() // IsLoaded() == false -> deterministic, no sessions
	s := &Server{dp: dp}

	cases := []struct {
		name string
		grpc func(*strings.Builder)
		want func(*strings.Builder)
	}{
		{
			"source-rule-detail",
			func(b *strings.Builder) { s.showNATSourceRuleDetail(context.Background(), cfg, b) },
			func(b *strings.Builder) {
				natshow.RenderSourceRuleDetail(context.Background(), b, cfg, s.dp, s.applyResult)
			},
		},
		{
			"dest-rule-detail",
			func(b *strings.Builder) { s.showNATDestRuleDetail(context.Background(), cfg, b) },
			func(b *strings.Builder) {
				natshow.RenderDestRuleDetail(context.Background(), b, cfg, s.dp, s.applyResult)
			},
		},
		{
			"static",
			func(b *strings.Builder) { s.showNATStatic(cfg, b) },
			func(b *strings.Builder) { natshow.RenderStatic(b, cfg) },
		},
		{
			"nptv6",
			func(b *strings.Builder) { s.showNATNPTv6(cfg, b) },
			func(b *strings.Builder) { natshow.RenderNPTv6(b, cfg) },
		},
		{
			"persistent",
			func(b *strings.Builder) { s.showPersistentNAT(context.Background(), b) },
			func(b *strings.Builder) { natshow.RenderPersistent(b, s.dp) },
		},
		{
			"persistent-detail",
			func(b *strings.Builder) { s.showPersistentNATDetail(context.Background(), b) },
			func(b *strings.Builder) { natshow.RenderPersistentDetail(context.Background(), b, s.dp) },
		},
		{
			"nat64",
			func(b *strings.Builder) { s.showNAT64(sharedGRPCNAT64Fixture16681(), b) },
			func(b *strings.Builder) { natshow.RenderNAT64(b, sharedGRPCNAT64Fixture16681(), nil) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got, want strings.Builder
			tc.grpc(&got)
			tc.want(&want)
			if got.String() != want.String() {
				t.Fatalf("%s: gRPC wrapper output not byte-identical to shared renderer:\n grpc =%q\nshared=%q",
					tc.name, got.String(), want.String())
			}
		})
	}
}
