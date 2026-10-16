package dhcp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// #14185: selectIANAAddress must refuse IA_NA candidates that IA_PD already
// refuses (#10856): non-global-unicast / special-purpose classes, addresses
// overlapping the protected (configured) prefix set, and candidates whose
// preferred lifetime exceeds their valid lifetime (RFC 8415 §21.6 MUST
// discard). Each offending IAADDR is skipped independently so a usable
// sibling is salvaged; a reply whose every IAADDR is refused yields no
// usable IA_NA (generic parse error, not the lifetime-0 invalidation
// sentinel).

func TestSelectIANAAddressRefusesInvalidClasses14185(t *testing.T) {
	good := "2606:4700:4700::42"
	for _, tc := range []struct {
		name string
		addr string
	}{
		{"loopback", "::1"},
		{"link-local", "fe80::1"},
		{"multicast", "ff02::1"},
		{"unspecified", "::"},
		{"ula", "fd00::1"},
		{"documentation", "2001:db8::1"},
		{"documentation-9637", "3fff::1"},
		{"ipv4-mapped", "::ffff:192.0.2.1"},
		{"site-local", "fec0::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adv := iaNAReply(t,
				&dhcpv6.OptIAAddress{
					IPv6Addr:          mustIP(t, tc.addr),
					PreferredLifetime: 999 * time.Second,
					ValidLifetime:     2000 * time.Second,
				},
				&dhcpv6.OptIAAddress{
					IPv6Addr:          mustIP(t, good),
					PreferredLifetime: 100 * time.Second,
					ValidLifetime:     500 * time.Second,
				},
			)
			addr, validLT, _ := selectIANAAddress(adv, nil, nil)
			if addr != netip.MustParseAddr(good) {
				t.Errorf("selected = %v, want salvaged sibling %s (refused class %s must be skipped)", addr, good, tc.addr)
			}
			if validLT != 500*time.Second {
				t.Errorf("validLT = %v, want 500s (sibling's own lifetime)", validLT)
			}

			// Alone: no usable IA_NA at all.
			solo := iaNAReply(t, &dhcpv6.OptIAAddress{
				IPv6Addr:          mustIP(t, tc.addr),
				PreferredLifetime: 100 * time.Second,
				ValidLifetime:     500 * time.Second,
			})
			if addr, _, _ := selectIANAAddress(solo, nil, nil); addr.IsValid() {
				t.Errorf("solo refused-class address %s selected as %v, want invalid", tc.addr, addr)
			}
			m := &Manager{}
			if _, err := m.parseV6Reply(context.Background(), "wan0", solo, nil); err == nil {
				t.Errorf("parseV6Reply accepted solo refused-class IA_NA %s", tc.addr)
			}
		})
	}
}

func TestSelectIANAAddressDiscardsPreferredGreaterThanValid14185(t *testing.T) {
	// RFC 8415 §21.6: discard any address whose preferred lifetime exceeds
	// its valid lifetime — even when it has the longest preferred lifetime
	// and would otherwise win ranking (the §21.6 trap: pref=0xFFFFFFFF /
	// valid=1s).
	adv := iaNAReply(t,
		&dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2606:4700:4700::99"),
			PreferredLifetime: 0xFFFFFFFF * time.Second,
			ValidLifetime:     time.Second,
		},
		&dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2606:4700:4700::42"),
			PreferredLifetime: 100 * time.Second,
			ValidLifetime:     500 * time.Second,
		},
	)
	addr, validLT, _ := selectIANAAddress(adv, nil, nil)
	if addr != netip.MustParseAddr("2606:4700:4700::42") {
		t.Errorf("selected = %v, want 2606:4700:4700::42 (pref>valid must be discarded before ranking)", addr)
	}
	if validLT != 500*time.Second {
		t.Errorf("validLT = %v, want 500s", validLT)
	}

	// Equal preferred/valid (incl. infinite) is not discarded.
	eq := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2606:4700:4700::7"),
		PreferredLifetime: 0xFFFFFFFF * time.Second,
		ValidLifetime:     0xFFFFFFFF * time.Second,
	})
	if addr, _, _ := selectIANAAddress(eq, nil, nil); addr != netip.MustParseAddr("2606:4700:4700::7") {
		t.Errorf("pref==valid infinite selected = %v, want 2606:4700:4700::7", addr)
	}

	// Solo pref>valid yields no usable IA_NA.
	solo := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2606:4700:4700::99"),
		PreferredLifetime: 300 * time.Second,
		ValidLifetime:     100 * time.Second,
	})
	if addr, _, _ := selectIANAAddress(solo, nil, nil); addr.IsValid() {
		t.Errorf("solo pref>valid selected %v, want invalid", addr)
	}
}

func TestSelectIANAAddressRefusesProtectedOverlap14185(t *testing.T) {
	protected := []netip.Prefix{netip.MustParsePrefix("2606:4700:1111::/64")}
	good := "2606:4700:9999::42"
	for _, tc := range []struct {
		name string
		addr string
	}{
		{"inside-protected", "2606:4700:1111::5"},
		{"equals-protected-host", "2606:4700:1111::"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adv := iaNAReply(t,
				&dhcpv6.OptIAAddress{
					IPv6Addr:          mustIP(t, tc.addr),
					PreferredLifetime: 999 * time.Second,
					ValidLifetime:     2000 * time.Second,
				},
				&dhcpv6.OptIAAddress{
					IPv6Addr:          mustIP(t, good),
					PreferredLifetime: 100 * time.Second,
					ValidLifetime:     500 * time.Second,
				},
			)
			if addr, _, _ := selectIANAAddress(adv, nil, protected); addr != netip.MustParseAddr(good) {
				t.Errorf("direct selected = %v, want salvaged sibling %s (protected-overlapping %s must be skipped)", addr, good, tc.addr)
			}
			// End-to-end through the Manager-installed protected set.
			m := NewManagerForTesting(nil)
			m.SetProtectedIPv6Prefixes(protected)
			solo := iaNAReply(t, &dhcpv6.OptIAAddress{
				IPv6Addr:          mustIP(t, tc.addr),
				PreferredLifetime: 100 * time.Second,
				ValidLifetime:     500 * time.Second,
			})
			if _, err := m.parseV6Reply(context.Background(), "wan0", solo, nil); err == nil {
				t.Errorf("parseV6Reply accepted IA_NA %s overlapping protected %v", tc.addr, protected)
			}
			res, err := m.parseV6Reply(context.Background(), "wan0", adv, nil)
			if err != nil {
				t.Fatalf("parseV6Reply with salvaged sibling: %v", err)
			}
			if got := res.lease.Address.Addr(); got != netip.MustParseAddr(good) {
				t.Errorf("lease address = %v, want salvaged %s", got, good)
			}
		})
	}
}

func TestSelectIANAAddressKeepsGlobalUnicast14185(t *testing.T) {
	for _, addr := range []string{"2606:4700:4700::1", "2001:4860:4860::1"} {
		adv := iaNAReply(t, &dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, addr),
			PreferredLifetime: 100 * time.Second,
			ValidLifetime:     500 * time.Second,
		})
		if got, _, _ := selectIANAAddress(adv, nil, nil); got != netip.MustParseAddr(addr) {
			t.Errorf("GUA %s selected = %v, want %s", addr, got, addr)
		}
	}
}
