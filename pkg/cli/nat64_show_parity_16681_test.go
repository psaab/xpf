package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16681 acceptance: local CLI text equals remote (gRPC ShowText) text
// for a fully scoped NAT64 rule-set. Both wrappers delegate to
// natshow.RenderNAT64; this test pins the CLI side byte-for-byte against
// the golden remote bytes (asserted identically on the gRPC side in
// pkg/grpcapi/nat64_show_parity_16681_test.go) and asserts every scope
// axis is present — the pre-fix defect was that both renderers omitted
// the source restriction and the remote one omitted zone/RI scope too,
// so a scoped rule-set read as match-any.

func sharedNAT64Fixture16681() *config.Config {
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

const wantNAT64Scoped16681 = "NAT64 rule-set: scoped64\n" +
	"  Prefix:      64:ff9b::/96\n" +
	"  From zones:   trust, dmz\n" +
	"  From routing-instances: blue, red\n" +
	"  Source addresses: 2001:db8:1::/48, 2001:db8:2::/48\n" +
	"  Source address-names: v6-clients, v6-partners\n" +
	"  Source pool:  p64\n" +
	"\n"

func TestCLINAT64ShowParity16681(t *testing.T) {
	c := &CLI{}
	got := captureStdout(t, func() {
		if err := c.showNAT64(sharedNAT64Fixture16681()); err != nil {
			t.Fatalf("showNAT64: %v", err)
		}
	})
	if got != wantNAT64Scoped16681 {
		t.Fatalf("CLI NAT64 output != golden remote bytes:\n got=%q\nwant=%q", got, wantNAT64Scoped16681)
	}
	for _, axis := range []string{"From zones:", "From routing-instances:", "Source addresses:", "Source address-names:"} {
		if !strings.Contains(got, axis) {
			t.Errorf("CLI NAT64 output missing scope axis %q:\n%s", axis, got)
		}
	}
}

func TestCLINAT64ShowEmpty16681(t *testing.T) {
	c := &CLI{}
	got := captureStdout(t, func() {
		if err := c.showNAT64(&config.Config{}); err != nil {
			t.Fatalf("showNAT64 empty: %v", err)
		}
	})
	if got != "No NAT64 rule-sets configured\n" {
		t.Errorf("empty CLI NAT64 = %q, want shared gRPC-canonical message", got)
	}
}
