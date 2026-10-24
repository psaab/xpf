package dhcp

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// #12533: only explicitly pinned exceptions are permitted; unpinned
// refusal is retained.

func TestExtractPinnedDelegatedPrefixes12533(t *testing.T) {
	pins := []netip.Prefix{netip.MustParsePrefix("fd00:1234::/48")}
	protected := []netip.Prefix{netip.MustParsePrefix("2606:4700:1111::/64")}

	// Covered ULA accepted and marked Pinned.
	msg := iaPDReply(t, pdPrefixOpt(t, "fd00:1234::/56", time.Hour, 2*time.Hour))
	live, _, _ := extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), protected, pins)
	if len(live) != 1 || !live[0].Pinned {
		t.Fatalf("covered ULA live=%v, want 1 pinned", live)
	}
	// Exact pin accepted.
	msg = iaPDReply(t, pdPrefixOpt(t, "fd00:1234::/48", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, pins)
	if len(live) != 1 || !live[0].Pinned {
		t.Fatalf("exact pin live=%v, want 1 pinned", live)
	}
	// Uncovered ULA refused.
	msg = iaPDReply(t, pdPrefixOpt(t, "fd00:9999::/48", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, pins)
	if len(live) != 0 {
		t.Fatalf("uncovered ULA live=%v, want 0", live)
	}
	// Narrower pin does not authorize wider delegation.
	narrow := []netip.Prefix{netip.MustParsePrefix("fd00:1234:0:1::/64")}
	msg = iaPDReply(t, pdPrefixOpt(t, "fd00:1234::/48", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, narrow)
	if len(live) != 0 {
		t.Fatalf("wider-than-pin live=%v, want 0", live)
	}
	// Covered overlapping GUA accepted.
	pinGUA := []netip.Prefix{netip.MustParsePrefix("2606:4700::/32")}
	msg = iaPDReply(t, pdPrefixOpt(t, "2606:4700:1111::/64", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), protected, pinGUA)
	if len(live) != 1 || !live[0].Pinned {
		t.Fatalf("covered overlap live=%v, want 1 pinned", live)
	}
	// Unpinned overlap refused (control).
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), protected, nil)
	if len(live) != 0 {
		t.Fatalf("unpinned overlap live=%v, want 0", live)
	}
	// Pin from another client (different pin set) does not authorize.
	msg = iaPDReply(t, pdPrefixOpt(t, "fd00:5678::/48", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, pins)
	if len(live) != 0 {
		t.Fatalf("other-client pin live=%v, want 0", live)
	}
	// Mask refusal never bypassed: /0 via pin ::/0 still dropped by mask arm.
	msg = iaPDReply(t, pdPrefixOpt(t, "::/0", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, []netip.Prefix{netip.MustParsePrefix("::/0")})
	if len(live) != 0 {
		t.Fatalf("pin ::/0 live=%v, want 0 (mask arm)", live)
	}
	// Withdrawal honored even when pinned: valid 0 goes to withdrawn
	// (pin coverage is checked before lifetime partitioning, so a
	// covered ULA withdrawal is honored; an uncovered one is not
	// synthesized — see TestExtractDelegatedPrefixesRefusedClassIsNotWithdrawn10856).
	msg = iaPDReply(t, pdPrefixOpt(t, "fd00:1234::/56", time.Hour, 0))
	live, withdrawn, _ := extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, pins)
	if len(live) != 0 || len(withdrawn) != 1 {
		t.Fatalf("pinned withdrawal live=%v withdrawn=%v, want 0/1", live, withdrawn)
	}
	// Ordinary GUA unpinned not marked Pinned.
	msg = iaPDReply(t, pdPrefixOpt(t, "2606:4700:9999::/48", time.Hour, 2*time.Hour))
	live, _, _ = extractDelegatedPrefixesPinned(msg, "wan0", time.Now(), nil, pins)
	if len(live) != 1 || live[0].Pinned {
		t.Fatalf("ordinary GUA live=%v, want 1 unpinned", live)
	}
}

func TestParseV6ReplyPinnedViaOptions12533(t *testing.T) {
	m := NewManagerForTesting(nil)
	m.SetProtectedIPv6Prefixes([]netip.Prefix{netip.MustParsePrefix("2606:4700:1111::/64")})
	opts := &DHCPv6Options{IATypes: []string{"ia-pd"}, PinnedPrefixes: []string{"fd00:1234::/48", "2606:4700::/32"}}
	res, err := m.parseV6Reply(context.Background(), "wan0", iaPDReply(t,
		pdPrefixOpt(t, "fd00:1234::/56", time.Hour, 2*time.Hour),
		pdPrefixOpt(t, "2606:4700:1111::/64", time.Hour, 2*time.Hour),
	), opts)
	if err != nil {
		t.Fatalf("parse pinned: %v", err)
	}
	if len(res.prefixes) != 2 || !res.prefixes[0].Pinned || !res.prefixes[1].Pinned {
		t.Fatalf("prefixes=%v want 2 pinned", res.prefixes)
	}
	// Without pins same reply: ULA refused, overlap refused -> fails.
	m2 := NewManagerForTesting(nil)
	m2.SetProtectedIPv6Prefixes([]netip.Prefix{netip.MustParsePrefix("2606:4700:1111::/64")})
	_, err = m2.parseV6Reply(context.Background(), "wan0", iaPDReply(t,
		pdPrefixOpt(t, "fd00:1234::/56", time.Hour, 2*time.Hour)), &DHCPv6Options{IATypes: []string{"ia-pd"}})
	if err == nil {
		t.Fatal("unpinned ULA reply accepted, want error")
	}
}

func TestDelegatedPrefixesChangedPin12533(t *testing.T) {
	a := []DelegatedPrefix{{Prefix: netip.MustParsePrefix("fd00:1234::/48"), ValidLifetime: time.Hour}}
	b := []DelegatedPrefix{{Prefix: netip.MustParsePrefix("fd00:1234::/48"), ValidLifetime: time.Hour, Pinned: true}}
	if !delegatedPrefixesChanged(a, b) {
		t.Fatal("Pinned change must report changed")
	}
	if delegatedPrefixesChanged(a, a) {
		t.Fatal("identical must not report changed")
	}
}

func TestFingerprintV6IncludesPins12533(t *testing.T) {
	o1 := &DHCPv6Options{PinnedPrefixes: []string{"fd00::/48"}}
	o2 := &DHCPv6Options{PinnedPrefixes: []string{"fd00:1::/48"}}
	o3 := &DHCPv6Options{}
	if fingerprintV6("", o1) == fingerprintV6("", o2) || fingerprintV6("", o1) == fingerprintV6("", o3) {
		t.Fatal("pin change must change fingerprint (client restart)")
	}
}
