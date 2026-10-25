package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/natshow"
)

// #1687 invariant: the CLI NAT show wrappers must produce byte-identical
// output to the shared pkg/natshow renderers (which the gRPC ShowText
// path also calls). These tests capture the CLI wrapper's stdout and
// assert it equals a direct natshow render of the same fixture, on the
// same Reader. Since the gRPC wrapper is the same one-line delegation,
// equality here proves both consumers single-source the output.

func sharedNATFixture() *config.Config {
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

func TestCLINATWrappersMatchSharedRenderers(t *testing.T) {
	cfg := sharedNATFixture()
	dp := dataplane.New() // IsLoaded() == false -> deterministic, no sessions
	c := &CLI{dp: dp}

	cases := []struct {
		name string
		cli  func() error
		want func(*strings.Builder)
	}{
		{
			"source-rule-detail",
			func() error { return c.showNATSourceRuleDetail(cfg) },
			func(b *strings.Builder) {
				natshow.RenderSourceRuleDetail(context.Background(), b, cfg, dp, c.applyResult)
			},
		},
		{
			"dest-rule-detail",
			func() error { return c.showNATDestinationRuleDetail(cfg) },
			func(b *strings.Builder) {
				natshow.RenderDestRuleDetail(context.Background(), b, cfg, dp, c.applyResult)
			},
		},
		{
			"static",
			func() error { return c.showNATStatic(cfg, nil) },
			func(b *strings.Builder) { natshow.RenderStatic(b, cfg) },
		},
		{
			"static-rule-detail",
			func() error { return c.showNATStatic(cfg, []string{"rule", "detail"}) },
			func(b *strings.Builder) { natshow.RenderStaticRule(b, cfg, true) },
		},
		{
			"nptv6",
			func() error { return c.showNPTv6(cfg) },
			func(b *strings.Builder) { natshow.RenderNPTv6(b, cfg) },
		},
		{
			"persistent",
			func() error { return c.showPersistentNAT() },
			func(b *strings.Builder) { natshow.RenderPersistent(b, dp) },
		},
		{
			"persistent-detail",
			func() error { return c.showPersistentNATDetail() },
			func(b *strings.Builder) { natshow.RenderPersistentDetail(context.Background(), b, dp) },
		},
		{
			"nat64",
			func() error { return c.showNAT64(sharedNAT64Fixture16681()) },
			func(b *strings.Builder) { natshow.RenderNAT64(b, sharedNAT64Fixture16681(), nil) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureStdout(t, func() {
				if err := tc.cli(); err != nil {
					t.Fatalf("%s CLI wrapper error = %v", tc.name, err)
				}
			})
			var want strings.Builder
			tc.want(&want)
			if got != want.String() {
				t.Fatalf("%s: CLI wrapper output not byte-identical to shared renderer:\n cli =%q\nshared=%q",
					tc.name, got, want.String())
			}
		})
	}
}
