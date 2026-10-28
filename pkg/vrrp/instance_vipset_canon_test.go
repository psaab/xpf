package vrrp

import (
	"net"
	"testing"
)

// #2516 — vipAddrSet keyed its exclusion entries by the RAW configured VIP
// string (only "/prefix" stripped, no canonicalization), while the resolve
// paths look up by net.IP.String() (Go's canonical form). A non-canonically
// formatted IPv6 link-local VIP — uppercase hextets or a non-zero-compressed
// form like "fe80::AB" — therefore missed the "fe80::ab" lookup, so the VIP
// leaked into local link-local source selection: the engine then sends adverts
// FROM its own VIP and self-filters them as a peer's, causing spurious failover
// / master-election failure. The fix canonicalizes via net.ParseIP before
// inserting (canonAddr). These tests are the fail-on-revert gate.

// TestResolveIPv6LinkLocal_ExcludesNonCanonicalVIP is the core fail-on-revert:
// a VIP configured as "fe80::AB/64" (uppercase, non-canonical) must be excluded
// from link-local source selection because the interface reports it in Go's
// canonical "fe80::ab" form. Reverting canonAddr keys vipSet by "fe80::AB",
// the "fe80::ab" lookup misses, the VIP is wrongly selected as the source, and
// this test fails.
func TestResolveIPv6LinkLocal_ExcludesNonCanonicalVIP(t *testing.T) {
	vi := newInstance(Instance{
		Interface:        "reth0.80",
		GroupID:          2,
		Priority:         200,
		VirtualAddresses: []string{"fe80::AB/64"}, // non-canonical uppercase VIP
	}, &net.Interface{Name: "reth0.80", Index: 43}, make(chan VRRPEvent, 16), nil)
	// The VIP (fe80::ab) sorts BELOW the real per-node source (fe80::cd).
	// resolveIPv6LinkLocal picks the lowest candidate, so if the VIP is not
	// excluded it is wrongly selected — this is what makes the test fail on
	// revert (the bug is invisible if the VIP sorts above the real source).
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{
			ipnetAddr(t, "fe80::ab/64"), // the VIP, kernel canonical form (sorts low)
			ipnetAddr(t, "fe80::cd/64"), // the real per-node link-local source
		}, nil
	}

	got := vi.resolveIPv6LinkLocal(vi.vipAddrSet())
	if got == nil {
		t.Fatal("resolveIPv6LinkLocal = nil, want fe80::cd (the non-VIP source)")
	}
	if got.String() == "fe80::ab" {
		t.Fatalf("resolveIPv6LinkLocal = %v, the non-canonical VIP fe80::AB was NOT excluded "+
			"(vipSet keyed by raw config string) — #2516 regression", got)
	}
	if got.String() != "fe80::cd" {
		t.Fatalf("resolveIPv6LinkLocal = %v, want fe80::cd", got)
	}
}

// TestResolveIPv6LinkLocal_ExcludesCanonicalVIP is the no-regression guard: a
// VIP already in canonical form is still excluded exactly as before.
func TestResolveIPv6LinkLocal_ExcludesCanonicalVIP(t *testing.T) {
	vi := newInstance(Instance{
		Interface:        "reth0.80",
		GroupID:          2,
		Priority:         200,
		VirtualAddresses: []string{"fe80::ab/64"}, // already canonical
	}, &net.Interface{Name: "reth0.80", Index: 43}, make(chan VRRPEvent, 16), nil)
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{
			ipnetAddr(t, "fe80::ab/64"), // VIP, sorts below the real source
			ipnetAddr(t, "fe80::cd/64"),
		}, nil
	}

	got := vi.resolveIPv6LinkLocal(vi.vipAddrSet())
	if got == nil || got.String() != "fe80::cd" {
		t.Fatalf("resolveIPv6LinkLocal = %v, want fe80::cd (canonical VIP must stay excluded)", got)
	}
}

// TestResolveIPv6LinkLocal_NonLinkLocalVIPUnaffected confirms global/ULA VIPs
// are unaffected: a global IPv6 VIP never participates in link-local source
// selection (the candidate filter requires IsLinkLocalUnicast), so the
// link-local source is still chosen regardless.
func TestResolveIPv6LinkLocal_NonLinkLocalVIPUnaffected(t *testing.T) {
	vi := newInstance(Instance{
		Interface:        "reth0.80",
		GroupID:          2,
		Priority:         200,
		VirtualAddresses: []string{"2001:559:8585:80::1/64"}, // global VIP
	}, &net.Interface{Name: "reth0.80", Index: 43}, make(chan VRRPEvent, 16), nil)
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{
			ipnetAddr(t, "2001:559:8585:80::8/64"),
			ipnetAddr(t, "fe80::42/64"),
		}, nil
	}

	got := vi.resolveIPv6LinkLocal(vi.vipAddrSet())
	if got == nil || got.String() != "fe80::42" {
		t.Fatalf("resolveIPv6LinkLocal = %v, want fe80::42", got)
	}
}

// TestCanonAddr covers the helper directly: canonicalize parseable literals
// and CIDR hosts (#17150: the shared ParseVRRPVIP parse yields the host for
// both spellings), and fall back to the raw string for unparseable input.
func TestCanonAddr(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"fe80::AB", "fe80::ab"},    // uppercase -> lowercase
		{"fe80::0:ab", "fe80::ab"},  // non-compressed -> compressed
		{"fe80::ab", "fe80::ab"},    // already canonical
		{"10.0.61.1", "10.0.61.1"},  // IPv4 unchanged
		{"not-an-ip", "not-an-ip"},  // unparseable falls back to itself
		{"fe80::ab/64", "fe80::ab"}, // CIDR host canonicalized (#17150)
	}
	for _, c := range cases {
		if got := canonAddr(c.in); got != c.want {
			t.Errorf("canonAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
