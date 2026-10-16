package dhcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// mustIP parses an IPv6 literal for test IAADDR options.
func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

// iaNAReply builds a DHCPv6 Reply carrying a single IA_NA with the given
// IAADDR options, in order.
func iaNAReply(t *testing.T, addrs ...*dhcpv6.OptIAAddress) *dhcpv6.Message {
	t.Helper()
	adv, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	adv.MessageType = dhcpv6.MessageTypeReply
	iana := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	for _, a := range addrs {
		iana.Options.Add(a)
	}
	adv.AddOption(iana)
	return adv
}

// TestParseV6ReplyMultiIAAddrDeterministic covers #4383: an IA_NA reply may
// carry more than one IAADDR option, and xpf must select ONE address
// deterministically instead of installing whichever enumerated last.
//
// Reverting selectIANAAddress to the old last-wins overwrite turns the
// multi-address and valid-lifetime-0 subtests RED — last-wins would install
// the last-enumerated address and pair the lease with that address's
// (possibly stale or zero) valid-lifetime.
func TestParseV6ReplyMultiIAAddrDeterministic(t *testing.T) {
	m := &Manager{} // nil nlHandle: discoverIPv6Router returns no gateway

	t.Run("longest preferred-lifetime wins, lease uses its valid-lifetime", func(t *testing.T) {
		// B has the longest preferred-lifetime but is enumerated FIRST, so
		// last-wins would wrongly pick A (last). Deterministic selection
		// picks B and pairs LeaseTime with B's own valid-lifetime (600s),
		// not A's stale 200s.
		adv := iaNAReply(t,
			&dhcpv6.OptIAAddress{
				IPv6Addr:          mustIP(t, "2606:4700::b"),
				PreferredLifetime: 300 * time.Second,
				ValidLifetime:     600 * time.Second,
			},
			&dhcpv6.OptIAAddress{
				IPv6Addr:          mustIP(t, "2606:4700::a"),
				PreferredLifetime: 100 * time.Second,
				ValidLifetime:     200 * time.Second,
			},
		)

		res, err := m.parseV6Reply(context.Background(), "test0", adv, nil)
		if err != nil {
			t.Fatalf("parseV6Reply: %v", err)
		}
		wantAddr := netip.MustParseAddr("2606:4700::b")
		if got := res.lease.Address.Addr(); got != wantAddr {
			t.Errorf("selected address = %v, want %v (longest preferred-lifetime)", got, wantAddr)
		}
		if got, want := res.lease.LeaseTime, 600*time.Second; got != want {
			t.Errorf("lease time = %v, want %v (chosen address's valid-lifetime)", got, want)
		}
	})

	t.Run("single-address reply unchanged", func(t *testing.T) {
		adv := iaNAReply(t, &dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2606:4700::5"),
			PreferredLifetime: 100 * time.Second,
			ValidLifetime:     500 * time.Second,
		})
		res, err := m.parseV6Reply(context.Background(), "test0", adv, nil)
		if err != nil {
			t.Fatalf("parseV6Reply: %v", err)
		}
		if got := res.lease.Address.Addr(); got != netip.MustParseAddr("2606:4700::5") {
			t.Errorf("address = %v, want 2606:4700::5", got)
		}
		if got, want := res.lease.LeaseTime, 500*time.Second; got != want {
			t.Errorf("lease time = %v, want %v", got, want)
		}
	})

	t.Run("valid-lifetime-0 address skipped", func(t *testing.T) {
		// Z has the longest preferred-lifetime AND is enumerated last, so
		// both last-wins and a naive longest-preferred pick would install
		// it — but a valid-lifetime-0 address is expired/declined (F-264)
		// and must be skipped, leaving A the only usable choice.
		adv := iaNAReply(t,
			&dhcpv6.OptIAAddress{
				IPv6Addr:          mustIP(t, "2606:4700::a"),
				PreferredLifetime: 50 * time.Second,
				ValidLifetime:     400 * time.Second,
			},
			&dhcpv6.OptIAAddress{
				IPv6Addr:          mustIP(t, "2606:4700::dead"),
				PreferredLifetime: 999 * time.Second,
				ValidLifetime:     0,
			},
		)
		res, err := m.parseV6Reply(context.Background(), "test0", adv, nil)
		if err != nil {
			t.Fatalf("parseV6Reply: %v", err)
		}
		if got := res.lease.Address.Addr(); got != netip.MustParseAddr("2606:4700::a") {
			t.Errorf("address = %v, want 2606:4700::a (valid-lifetime-0 must be skipped)", got)
		}
		if got, want := res.lease.LeaseTime, 400*time.Second; got != want {
			t.Errorf("lease time = %v, want %v", got, want)
		}
	})

	t.Run("all addresses valid-lifetime-0 => no usable IA_NA", func(t *testing.T) {
		adv := iaNAReply(t, &dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2606:4700::dead"),
			PreferredLifetime: 100 * time.Second,
			ValidLifetime:     0,
		})
		if _, err := m.parseV6Reply(context.Background(), "test0", adv, nil); err == nil {
			t.Error("expected error when the only IA_NA address has valid-lifetime 0")
		}
	})
}

// TestSelectIANAAddressTieBreak verifies the first-seen tie-break when two
// IAADDR options share the longest preferred-lifetime.
func TestSelectIANAAddressTieBreak(t *testing.T) {
	adv := iaNAReply(t,
		&dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2606:4700::c"),
			PreferredLifetime: 300 * time.Second,
			ValidLifetime:     700 * time.Second,
		},
		&dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2606:4700::d"),
			PreferredLifetime: 300 * time.Second,
			ValidLifetime:     800 * time.Second,
		},
	)
	addr, validLT, _ := selectIANAAddress(adv, nil, nil)
	if addr != netip.MustParseAddr("2606:4700::c") {
		t.Errorf("tie-break address = %v, want 2606:4700::c (first-seen)", addr)
	}
	if validLT != 700*time.Second {
		t.Errorf("tie-break valid-lifetime = %v, want 700s (first-seen address's own)", validLT)
	}
}

// TestSelectIANAAddressMultipleIANA verifies selection scans across more
// than one IA_NA option in the same reply, not just the first.
func TestSelectIANAAddressMultipleIANA(t *testing.T) {
	adv, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	adv.MessageType = dhcpv6.MessageTypeReply

	iana1 := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	iana1.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2606:4700::1"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     200 * time.Second,
	})
	iana2 := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 2}}
	iana2.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2606:4700::2"),
		PreferredLifetime: 500 * time.Second,
		ValidLifetime:     900 * time.Second,
	})
	adv.AddOption(iana1)
	adv.AddOption(iana2)

	addr, validLT, _ := selectIANAAddress(adv, nil, nil)
	if addr != netip.MustParseAddr("2606:4700::2") {
		t.Errorf("address = %v, want 2606:4700::2 (longest preferred across IA_NA options)", addr)
	}
	if validLT != 900*time.Second {
		t.Errorf("valid-lifetime = %v, want 900s", validLT)
	}
}
