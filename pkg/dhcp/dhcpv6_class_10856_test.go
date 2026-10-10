package dhcp

import (
	"net/netip"
	"testing"
	"time"
)

// Fail-on-revert: each unsafe IA_PD class must be skipped individually. A
// legitimate global-unicast delegation remains usable in the same IA_PD.
func TestExtractDelegatedPrefixesRejectsNonGUAClasses10856(t *testing.T) {
	bad := []struct {
		name string
		cidr string
	}{
		{"link-local", "fe80::/64"},
		{"multicast", "ff02::1/128"},
		{"loopback", "::1/128"},
		{"unspecified", "::/128"},
		{"documentation", "2001:db8::/32"},
		{"documentation-RFC-9637", "3fff::/20"},
		{"ULA", "fc00::/48"},
	}
	good := netip.MustParsePrefix("2606:4700:4700::/48")
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			msg := iaPDReply(t,
				pdPrefixOpt(t, tc.cidr, time.Hour, 2*time.Hour),
				pdPrefixOpt(t, good.String(), time.Hour, 2*time.Hour),
			)
			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now())
			if len(live) != 1 || live[0].Prefix != good {
				t.Errorf("live = %v, want only valid GUA %s (bad %s must be skipped)", live, good, tc.cidr)
			}
			if len(withdrawn) != 0 {
				t.Errorf("withdrawn = %v, want empty", withdrawn)
			}
		})
	}
}

// Fail-on-revert positive cell: a legitimate GUA IA_PD still traverses the
// extraction boundary and reaches DeriveSubPrefix unchanged.
func TestExtractDelegatedPrefixesKeepsGlobalUnicast10856(t *testing.T) {
	want := netip.MustParsePrefix("2606:4700:4700::/48")
	msg := iaPDReply(t, pdPrefixOpt(t, want.String(), time.Hour, 2*time.Hour))
	live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now())
	if len(live) != 1 || live[0].Prefix != want {
		t.Fatalf("live = %v, want %s", live, want)
	}
	if len(withdrawn) != 0 {
		t.Fatalf("withdrawn = %v, want empty", withdrawn)
	}
	if got := DeriveSubPrefix(live[0].Prefix, 0); got != want {
		t.Fatalf("DeriveSubPrefix = %s, want %s", got, want)
	}
}
