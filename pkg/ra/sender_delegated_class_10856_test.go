package ra

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Fail-on-revert: bad IA_PD classes must not create a Prefix Information
// Option even if they bypass the DHCP decoder. Delegated is required so the
// defense never rejects equivalent operator-authored configuration.
func TestBuildRARejectsDelegatedNonGUAClasses10856(t *testing.T) {
	for _, tc := range []struct {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := prefixInfosFor(t, &config.RAPrefix{
				Prefix: tc.cidr, OnLink: true, Autonomous: true, Delegated: true,
			})
			if len(got) != 0 {
				t.Fatalf("delegated %s emitted %d PIOs; want refusal", tc.cidr, len(got))
			}
		})
	}
}

func TestBuildRAKeepsDelegatedGlobalUnicast10856(t *testing.T) {
	got := prefixInfosFor(t, &config.RAPrefix{
		Prefix: "2606:4700:4700:1000::/64", OnLink: true, Autonomous: true, Delegated: true,
	})
	if len(got) != 1 || got[0].PrefixLength != 64 || !got[0].OnLink || !got[0].AutonomousAddressConfiguration {
		t.Fatalf("legitimate delegated GUA PIOs = %+v, want one on-link autonomous /64", got)
	}
}

func TestBuildRARejectsDelegatedPrefixOverlappingConfiguredPIO10856(t *testing.T) {
	got := prefixInfosFor(t,
		&config.RAPrefix{Prefix: "2606:4700:4700:1000::/64", OnLink: true, Autonomous: true},
		&config.RAPrefix{Prefix: "2606:4700:4700:1000::/64", OnLink: true, Autonomous: true, Delegated: true},
	)
	if len(got) != 1 {
		t.Fatalf("overlapping static+delegated prefixes emitted %d PIOs, want only operator-authored PIO", len(got))
	}
}
