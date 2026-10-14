package dhcp

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// #10856 phase 2: IA_PD extraction is global-unicast-only. Every refused
// class is skipped independently; a valid sibling remains in the live set.
// The broad-prefix case pins whole-prefix overlap, not just the class of the
// prefix's first address.
func TestExtractDelegatedPrefixesRejectsRefusedClasses10856(t *testing.T) {
	bad := []struct {
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
		{"ula-fd", "fd00::/48"},
		{"ula-fc", "fc00::/48"},
		{"documentation-RFC-3849", "2001:db8:1::/48"},
		{"documentation-RFC-9637", "3fff:1::/32"},
		{"prefix-overlaps-refused-space", "fe00::/8"},
	}
	good := netip.MustParsePrefix("2606:4700:4700::/48")
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			msg := iaPDReply(t,
				pdPrefixOpt(t, tc.cidr, time.Hour, 2*time.Hour),
				pdPrefixOpt(t, good.String(), time.Hour, 2*time.Hour),
			)
			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now(), nil)
			if len(live) != 1 || live[0].Prefix != good {
				t.Errorf("live = %v, want only valid sibling %s (refused %s must be skipped)", live, good, tc.cidr)
			}
			if len(withdrawn) != 0 {
				t.Errorf("withdrawn = %v, want empty", withdrawn)
			}
		})
	}
}

// A refused-class prefix is never turned into a WITHDRAWAL either: the server
// did not revoke it, and manufacturing a withdrawal would let a spoofed
// reply tear down a held delegation. valid-lifetime 0 + refused class is
// simply absent from both sets.
func TestExtractDelegatedPrefixesRefusedClassIsNotWithdrawn10856(t *testing.T) {
	msg := iaPDReply(t,
		pdPrefixOpt(t, "2001:db8:dead::/56", time.Hour, 0),
		pdPrefixOpt(t, "fd00:dead::/56", time.Hour, 0),
	)
	live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now(), nil)
	if len(live) != 0 || len(withdrawn) != 0 {
		t.Fatalf("live = %v withdrawn = %v, want both empty (refusal must not synthesize a withdrawal)", live, withdrawn)
	}
}

// Genuine global unicast delegations are accepted. These controls pin that
// the policy is special-purpose-scoped, not a blanket deny.
func TestExtractDelegatedPrefixesKeepsGlobalUnicast10856(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"GUA-2606", "2606:4700:4700::/48"},
		{"GUA-2001", "2001:4860:4860::/48"},
		{"GUA-6to4", "2002:0a00:0a00::/48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := netip.MustParsePrefix(tc.cidr)
			msg := iaPDReply(t, pdPrefixOpt(t, tc.cidr, time.Hour, 2*time.Hour))
			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now(), nil)
			if len(live) != 1 || live[0].Prefix != want {
				t.Fatalf("live = %v, want %s", live, want)
			}
			if len(withdrawn) != 0 {
				t.Fatalf("withdrawn = %v, want empty", withdrawn)
			}
		})
	}
}

// #10856 overlap: an IA_PD prefix overlapping any protected (configured
// interface / RA / NAT64) prefix is refused while a non-overlapping sibling
// is salvaged. Containment works in BOTH directions: a delegation inside
// configured space and a delegation spanning it are both refused.
func TestExtractDelegatedPrefixesRefusesConfiguredOverlap10856(t *testing.T) {
	protected := []netip.Prefix{
		netip.MustParsePrefix("2606:4700:1111::/64"), // iface address prefix
		netip.MustParsePrefix("2606:4700:2222::/64"), // static RA prefix
		netip.MustParsePrefix("64:ff9b::/96"),        // NAT64 prefix
	}
	inside := netip.MustParsePrefix("2606:4700:3333:1::/64") // no overlap
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"equals-configured", "2606:4700:1111::/64"},
		{"contains-configured", "2606:4700:1111::/56"},
		{"inside-configured", "2606:4700:1111::aa/128"},
		{"overlaps-static-ra", "2606:4700:2222::/63"},
		{"inside-nat64", "64:ff9b::1:0/112"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := iaPDReply(t,
				pdPrefixOpt(t, tc.cidr, time.Hour, 2*time.Hour),
				pdPrefixOpt(t, inside.String(), time.Hour, 2*time.Hour),
			)
			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now(), protected)
			if len(live) != 1 || live[0].Prefix != inside {
				t.Fatalf("live = %v, want only non-overlapping sibling %s (overlapping %s must be skipped)", live, inside, tc.cidr)
			}
			if len(withdrawn) != 0 {
				t.Fatalf("withdrawn = %v, want empty", withdrawn)
			}
		})
	}
}

// The overlap set flows from the Manager (daemon-installed). A reply decoded
// through parseV6Reply must lose an overlapping delegation AND, when nothing
// usable survives, fail the reply outright — the acquire/renew loop retries
// instead of settling an empty lease. This cell compiles and runs against the
// pre-#10856-phase-2 base (no new API in the arrange), where it is RED: the
// overlapping delegation is accepted.
func TestParseV6ReplyRefusesOverlappingPDViaManagerState10856(t *testing.T) {
	m := NewManagerForTesting(nil)
	m.SetProtectedIPv6Prefixes([]netip.Prefix{netip.MustParsePrefix("2606:4700:1111::/64")})
	msg := iaPDReply(t,
		pdPrefixOpt(t, "2606:4700:1111::2/64", time.Hour, 2*time.Hour),
		pdPrefixOpt(t, "2606:4700:9999::/48", time.Hour, 2*time.Hour),
	)
	res, err := m.parseV6Reply(context.Background(), "wan0", msg, &DHCPv6Options{IATypes: []string{"ia-pd"}})
	if err != nil {
		t.Fatalf("parseV6Reply: %v", err)
	}
	if len(res.prefixes) != 1 || res.prefixes[0].Prefix != netip.MustParsePrefix("2606:4700:9999::/48") {
		t.Fatalf("prefixes = %v, want only the non-overlapping 2606:4700:9999::/48", res.prefixes)
	}

	// All delegations overlapping: the reply must fail, not return empty.
	m2 := NewManagerForTesting(nil)
	m2.SetProtectedIPv6Prefixes([]netip.Prefix{netip.MustParsePrefix("2606:4700::/32")})
	res2, err := m2.parseV6Reply(context.Background(), "wan0", iaPDReply(t,
		pdPrefixOpt(t, "2606:4700:1::/48", time.Hour, 2*time.Hour)), &DHCPv6Options{IATypes: []string{"ia-pd"}})
	if err == nil {
		t.Fatalf("reply with only an overlapping PD accepted: prefixes = %v", res2.prefixes)
	}
}

// The Manager-level decode path also enforces the class policy end to end:
// a documentation-only reply fails rather than storing a doc-space PD. This
// is the RED-pre cell for the class contract (compiles on the pre-change
// base, where the delegation is accepted and no error is returned).
func TestParseV6ReplyRefusesDocumentationPD10856(t *testing.T) {
	m := NewManagerForTesting(nil)
	_, err := m.parseV6Reply(context.Background(), "wan0",
		iaPDReply(t, pdPrefixOpt(t, "2001:db8:f00d::/48", time.Hour, 2*time.Hour)),
		&DHCPv6Options{IATypes: []string{"ia-pd"}})
	if err == nil {
		t.Fatal("documentation-space IA_PD reply accepted; want no usable PD error")
	}
}
