package ra

import (
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func rawPrefixInfosForClassTest(t *testing.T, cfg *config.RAInterfaceConfig) []*ndp.PrefixInformation {
	t.Helper()
	s := newTestSender3895(cfg)
	ra := s.buildRA()
	var out []*ndp.PrefixInformation
	for _, option := range ra.Options {
		if pi, ok := option.(*ndp.PrefixInformation); ok {
			out = append(out, pi)
		}
	}
	return out
}

func delegatedClassCfg(prefixes ...*config.RAPrefix) *config.RAInterfaceConfig {
	return &config.RAInterfaceConfig{Interface: "trust0", Prefixes: prefixes}
}

// Delegated prefixes from every refused class must be refused even when they
// bypass DHCP extraction and reach the RA sink directly.
func TestBuildRARejectsDelegatedRefusedClasses10856(t *testing.T) {
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
		{"ula-fd", "fd00:1::/64"},
		{"ula-fc", "fc00:1::/64"},
		{"documentation-RFC-3849", "2001:db8:1::/64"},
		{"documentation-RFC-9637", "3fff:1::/64"},
		{"prefix-overlaps-refused-space", "fe00::/8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rawPrefixInfosForClassTest(t, delegatedClassCfg(&config.RAPrefix{
				Prefix: tc.cidr, OnLink: true, Autonomous: true, Delegated: true,
			}))
			if len(got) != 0 {
				t.Fatalf("delegated %s emitted %d PIOs; want refusal", tc.cidr, len(got))
			}
		})
	}
}

// Genuine global unicast delegations are still advertised. These controls
// pin that the policy is special-purpose-scoped, not a blanket deny.
func TestBuildRAKeepsDelegatedGlobalUnicast10856(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"GUA-2606", "2606:4700:4700:1000::/64"},
		{"GUA-2001", "2001:4860:4860:1000::/64"},
		{"GUA-6to4", "2002:0a00:0a00:1000::/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rawPrefixInfosForClassTest(t, delegatedClassCfg(&config.RAPrefix{
				Prefix: tc.cidr, OnLink: true, Autonomous: true, Delegated: true,
			}))
			if len(got) != 1 || got[0].PrefixLength != 64 || !got[0].OnLink || !got[0].AutonomousAddressConfiguration {
				t.Fatalf("delegated %s PIOs = %+v, want one on-link autonomous /64", tc.cidr, got)
			}
		})
	}
}

// #10856 overlap: a delegated PIO overlapping a configured (protected)
// prefix is refused at the sink even when a non-overlapping delegated
// sibling in the same RA is advertised. The protected set is box-wide, so
// the overlap need not be on this interface.
func TestBuildRARefusesDelegatedOverlapWithProtectedPrefixes10856(t *testing.T) {
	for _, tc := range []struct {
		name      string
		delegated string
		protected string
	}{
		{"equals-configured-iface-address", "2606:4700:1111::/64", "2606:4700:1111::/64"},
		{"contains-configured-ra-prefix", "2606:4700:2222::/63", "2606:4700:2222::/64"},
		{"inside-configured-nat64", "64:ff9b::1:0/112", "64:ff9b::/96"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			good := &config.RAPrefix{
				Prefix: "2606:4700:9999::/64", OnLink: true, Autonomous: true, Delegated: true,
			}
			cfg := delegatedClassCfg(&config.RAPrefix{
				Prefix: tc.delegated, OnLink: true, Autonomous: true, Delegated: true,
			}, good)
			cfg.ProtectedPrefixes = []string{tc.protected}
			got := rawPrefixInfosForClassTest(t, cfg)
			if len(got) != 1 || got[0].Prefix.String() != "2606:4700:9999::" {
				t.Fatalf("PIOs = %+v, want only the non-overlapping delegated 2606:4700:9999::/64 (overlapping %s vs %s must be refused)",
					got, tc.delegated, tc.protected)
			}
		})
	}
}

// Provenance still scopes the overlap gate: the same operator-authored
// prefix that equals a protected entry is CONFIGURATION, not a delegation,
// and must be emitted. (A configured prefix trivially "overlaps" itself.)
func TestBuildRAKeepsOperatorPrefixDespiteProtectedSet10856(t *testing.T) {
	cfg := delegatedClassCfg(&config.RAPrefix{
		Prefix: "2606:4700:1111::/64", OnLink: true, Autonomous: true, Delegated: false,
	})
	cfg.ProtectedPrefixes = []string{"2606:4700:1111::/64"}
	got := rawPrefixInfosForClassTest(t, cfg)
	if len(got) != 1 {
		t.Fatalf("operator-authored prefix overlapping the protected set produced %d PIOs, want 1", len(got))
	}
}

// Delegated provenance scopes the class gate: the same operator-authored ::/0
// that remains valid configuration must still be emitted by the sender.
func TestBuildRAKeepsOperatorZeroPrefix10856(t *testing.T) {
	got := rawPrefixInfosForClassTest(t, delegatedClassCfg(&config.RAPrefix{
		Prefix: "::/0", OnLink: true, Autonomous: true, Delegated: false,
	}))
	if len(got) != 1 || got[0].PrefixLength != 0 {
		t.Fatalf("operator-authored ::/0 PIOs = %+v, want one /0 PIO", got)
	}
}
