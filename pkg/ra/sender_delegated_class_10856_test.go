package ra

import (
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func rawPrefixInfosForClassTest(t *testing.T, prefix *config.RAPrefix) []*ndp.PrefixInformation {
	t.Helper()
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes:  []*config.RAPrefix{prefix},
	})
	ra := s.buildRA()
	var out []*ndp.PrefixInformation
	for _, option := range ra.Options {
		if pi, ok := option.(*ndp.PrefixInformation); ok {
			out = append(out, pi)
		}
	}
	return out
}

// Delegated prefixes from every blocklisted class must be refused even when
// they bypass DHCP extraction and reach the RA sink directly.
func TestBuildRARejectsDelegatedBlocklistedClasses10856(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"link-local", "fe80::/64"},
		{"multicast", "ff02::1/128"},
		{"loopback", "::1/128"},
		{"unspecified", "::/128"},
		{"ipv4-compatible", "::c000:200/120"},
		{"ipv4-mapped", "::ffff:192.0.2.0/120"},
		{"site-local", "fec0::/48"},
		{"prefix-overlaps-blocklist", "fe00::/8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rawPrefixInfosForClassTest(t, &config.RAPrefix{
				Prefix: tc.cidr, OnLink: true, Autonomous: true, Delegated: true,
			})
			if len(got) != 0 {
				t.Fatalf("delegated %s emitted %d PIOs; want refusal", tc.cidr, len(got))
			}
		})
	}
}

// ULA and documentation space remain accepted by the intentionally narrowed
// blocklist, alongside ordinary GUA delegations.
func TestBuildRAKeepsDelegatedNonblockedClasses10856(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"GUA", "2606:4700:4700:1000::/64"},
		{"ULA", "fd00:1::/64"},
		{"documentation-RFC-3849", "2001:db8:1::/64"},
		{"documentation-RFC-9637", "3fff:1::/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rawPrefixInfosForClassTest(t, &config.RAPrefix{
				Prefix: tc.cidr, OnLink: true, Autonomous: true, Delegated: true,
			})
			if len(got) != 1 || got[0].PrefixLength != 64 || !got[0].OnLink || !got[0].AutonomousAddressConfiguration {
				t.Fatalf("delegated %s PIOs = %+v, want one on-link autonomous /64", tc.cidr, got)
			}
		})
	}
}

// Delegated provenance scopes the gate: the same operator-authored ::/0 that
// remains valid configuration must still be emitted by the sender.
func TestBuildRAKeepsOperatorZeroPrefix10856(t *testing.T) {
	got := rawPrefixInfosForClassTest(t, &config.RAPrefix{
		Prefix: "::/0", OnLink: true, Autonomous: true, Delegated: false,
	})
	if len(got) != 1 || got[0].PrefixLength != 0 {
		t.Fatalf("operator-authored ::/0 PIOs = %+v, want one /0 PIO", got)
	}
}
