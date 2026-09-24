package config_test

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// C179-049 (codex-179): SNMPCommunity.AllowsSource resolved an EQUAL-LENGTH
// prefix tie between a plain allow and a `restrict` by INSERTION ORDER — the
// first-listed of two same-length prefixes won, so `10.0.0.0/24` before
// `10.0.0.0/24 restrict` leaked the allow while the reverse order denied. A
// deny must win a same-length tie regardless of authoring order.
//
// FAIL-ON-REVERT: dropping the `cn.ones == bestBits && cn.restrict` deny-wins
// branch makes the allow-then-restrict ordering ALLOW the source again.
func TestSNMPAllowsSource_EqualLengthTie_DenyWins_5523(t *testing.T) {
	src := net.ParseIP("10.0.0.5").To4()
	allow := config.SNMPClient{Prefix: "10.0.0.0/24"}
	deny := config.SNMPClient{Prefix: "10.0.0.0/24", Restrict: true}

	// A deny must win in BOTH authoring orders.
	for _, tc := range []struct {
		name    string
		clients []config.SNMPClient
	}{
		{"allow-then-restrict", []config.SNMPClient{allow, deny}},
		{"restrict-then-allow", []config.SNMPClient{deny, allow}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &config.SNMPCommunity{Clients: tc.clients}
			if c.AllowsSource(src) {
				t.Fatalf("equal-length tie (%s): a same-length `restrict` must DENY %s (deny-wins)", tc.name, src)
			}
		})
	}
}

// The tie-break must not disturb the longest-prefix ordering: a more-specific
// allow still beats a broader restrict, and a source matched only by the
// broader restrict is still denied.
func TestSNMPAllowsSource_LongestPrefixIntact_5523(t *testing.T) {
	c := &config.SNMPCommunity{Clients: []config.SNMPClient{
		{Prefix: "10.0.0.0/8", Restrict: true}, // deny 10/8 ...
		{Prefix: "10.0.0.0/24"},                // ... except the more-specific /24 (allow)
	}}
	if !c.AllowsSource(net.ParseIP("10.0.0.5").To4()) {
		t.Fatal("more-specific /24 allow must beat the broader /8 restrict (longest-prefix)")
	}
	if c.AllowsSource(net.ParseIP("10.9.9.9").To4()) {
		t.Fatal("10.9.9.9 matched only by the /8 restrict must be DENIED")
	}
}
