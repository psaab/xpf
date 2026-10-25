package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16681 acceptance: remote (gRPC ShowText) text equals local CLI text
// for a fully scoped NAT64 rule-set. Both wrappers delegate to
// natshow.RenderNAT64; this test pins the gRPC side byte-for-byte
// against the golden local bytes (asserted identically on the CLI side
// in pkg/cli/nat64_show_parity_16681_test.go). Pre-fix the gRPC renderer
// printed only Prefix + Source pool, omitting zone, routing-instance
// and source-address scope entirely.

func sharedGRPCNAT64Fixture16681() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"203.0.113.1"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{
			Name:                 "scoped64",
			Prefix:               "64:ff9b::/96",
			SourcePool:           "p64",
			FromZone:             "trust",
			FromZones:            []string{"trust", "dmz"},
			FromRoutingInstance:  "blue",
			FromRoutingInstances: []string{"blue", "red"},
			SourceAddress:        "2001:db8:1::/48",
			SourceAddresses:      []string{"2001:db8:1::/48", "2001:db8:2::/48"},
			SourceAddressName:    "v6-clients",
			SourceAddressNames:   []string{"v6-clients", "v6-partners"},
		},
	}
	return cfg
}

const wantNAT64ScopedGRPC16681 = "NAT64 rule-set: scoped64\n" +
	"  Prefix:      64:ff9b::/96\n" +
	"  From zones:   trust, dmz\n" +
	"  From routing-instances: blue, red\n" +
	"  Source addresses: 2001:db8:1::/48, 2001:db8:2::/48\n" +
	"  Source address-names: v6-clients, v6-partners\n" +
	"  Source pool:  p64\n" +
	"\n"

func TestGRPCNAT64ShowParity16681(t *testing.T) {
	s := &Server{}
	var b strings.Builder
	s.showNAT64(sharedGRPCNAT64Fixture16681(), &b)
	if b.String() != wantNAT64ScopedGRPC16681 {
		t.Fatalf("gRPC NAT64 output != golden local bytes:\n got=%q\nwant=%q", b.String(), wantNAT64ScopedGRPC16681)
	}
}

func TestGRPCNAT64ShowEmpty16681(t *testing.T) {
	s := &Server{}
	var b strings.Builder
	s.showNAT64(&config.Config{}, &b)
	if b.String() != "No NAT64 rule-sets configured\n" {
		t.Errorf("empty gRPC NAT64 = %q", b.String())
	}
}
