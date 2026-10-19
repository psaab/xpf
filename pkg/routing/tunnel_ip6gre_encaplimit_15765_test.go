package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNeedsIP6GREEncapLimitNone15765 pins #15765: an explicit `mode ip6gre`
// IPv6 GRE tunnel must get the same `type ip6gre encaplimit none` treatment
// as `mode gre`/"" on the legacy kernel-tunnel create path.
func TestNeedsIP6GREEncapLimitNone15765(t *testing.T) {
	cases := []struct {
		mode   string
		isIPv6 bool
		want   bool
	}{
		{"gre", true, true},
		{"ip6gre", true, true},
		{"", true, true},
		{"gre", false, false},
		{"ip6gre", false, false},
		{"ipip", true, false},
		{"wireguard", true, false},
	}
	for _, tc := range cases {
		if got := needsIP6GREEncapLimitNone(tc.mode, tc.isIPv6); got != tc.want {
			t.Errorf("needsIP6GREEncapLimitNone(%q,%v)=%v want %v", tc.mode, tc.isIPv6, got, tc.want)
		}
	}
	// The desired link for ip6gre is a Gretun rendering as ip6gre.
	link := buildKernelTunnelLink(&config.TunnelConfig{Name: "gr0", Mode: "ip6gre"}, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 64, true)
	if link.Type() != "ip6gre" {
		t.Errorf("buildKernelTunnelLink(ip6gre).Type()=%q want ip6gre", link.Type())
	}
}
