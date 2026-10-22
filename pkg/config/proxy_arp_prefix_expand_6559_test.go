package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestProxyARPPrefixExpands_6559 is the fail-on-revert gate for #6559.
//
// Before this, `security nat proxy-arp ... address <prefix>` dropped the prefix
// LENGTH: the compiler stored the authored string and pkg/dataplane/proxyarp.go
// keyed its desired set on `prefix.Addr()` alone, so one statement installed one
// kernel proxy-neighbour. netip.ParsePrefix does not mask, so for a CANONICAL
// prefix the single installed entry was the NETWORK address — which no host ever
// ARPs for. The block therefore answered NOTHING while the per-interface
// proxy_arp sysctl was still switched on, and it committed clean because the
// only gate checked parseability and "10.0.1.0/24" parses fine.
func TestProxyARPPrefixExpands_6559(t *testing.T) {
	t.Run("a /29 installs every usable host", func(t *testing.T) {
		// The issue's own acceptance criterion. /29 = 8 addresses, 6 usable:
		// the network (.0) and broadcast (.7) are not ARP targets.
		got := expandProxyARPPrefix("198.51.100.0/29")
		want := []string{
			"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32",
			"198.51.100.4/32", "198.51.100.5/32", "198.51.100.6/32",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("/29 expansion = %q, want %q", got, want)
		}
	})

	t.Run("a non-canonical prefix expands to the same block", func(t *testing.T) {
		// `10.0.1.5/24` and `10.0.1.0/24` describe the SAME block. Without the
		// Masked() call the walk would start at the authored address and run off
		// the end of the block, so the installed set would depend on which
		// address inside it happened to be typed.
		a := expandProxyARPPrefix("198.51.100.5/29")
		b := expandProxyARPPrefix("198.51.100.0/29")
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("non-canonical /29 expanded differently:\n got %q\nwant %q", a, b)
		}
	})

	t.Run("a /31 keeps both addresses (RFC 3021)", func(t *testing.T) {
		// A /31 point-to-point link has no network or broadcast address; both
		// are usable. Subtracting 2 here would yield an empty set.
		got := expandProxyARPPrefix("198.51.100.0/31")
		want := []string{"198.51.100.0/32", "198.51.100.1/32"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("/31 expansion = %q, want %q", got, want)
		}
	})

	t.Run("a single host is untouched", func(t *testing.T) {
		for _, v := range []string{"192.0.2.1/32", "2001:db8::1/128"} {
			if got := expandProxyARPPrefix(v); !reflect.DeepEqual(got, []string{v}) {
				t.Fatalf("single host %q expanded to %q; must be untouched", v, got)
			}
		}
	})

	t.Run("an unparseable value is untouched", func(t *testing.T) {
		// The parse arm of validateProxyARPAddressesStrict owns this shape; the
		// expansion must not swallow it or change what it reports.
		if got := expandProxyARPPrefix("bogus/32"); !reflect.DeepEqual(got, []string{"bogus/32"}) {
			t.Fatalf("unparseable value expanded to %q; must be untouched", got)
		}
	})

	t.Run("an over-cap block is left authored for the gate", func(t *testing.T) {
		// /23 is 510 usable hosts, over the 256 cap. It must survive expansion
		// UNCHANGED so validateProxyARPAddressesStrict can see and reject it —
		// and so the tolerant path installs byte-identically to pre-#6559
		// (#1960 no-brick).
		if got := expandProxyARPPrefix("198.51.100.0/23"); !reflect.DeepEqual(got, []string{"198.51.100.0/23"}) {
			t.Fatalf("over-cap block expanded to %d entries; must be left authored, got %q", len(got), got)
		}
		// A v6 block far beyond any representable count must take the same path
		// rather than forming a wrapped host count.
		if got := expandProxyARPPrefix("2001:db8::/64"); !reflect.DeepEqual(got, []string{"2001:db8::/64"}) {
			t.Fatalf("v6 /64 expanded to %d entries; must be left authored, got %q", len(got), got)
		}
	})

	t.Run("a /24 fits the cap", func(t *testing.T) {
		// The realistic operator case from the issue: a directly-connected NAT
		// block. 254 usable hosts, under the 256 cap the range sibling carries.
		got := expandProxyARPPrefix("198.51.100.0/24")
		if len(got) != 254 {
			t.Fatalf("/24 expanded to %d entries, want 254", len(got))
		}
		if got[0] != "198.51.100.1/32" || got[253] != "198.51.100.254/32" {
			t.Fatalf("/24 expansion endpoints = %q..%q, want 198.51.100.1/32..198.51.100.254/32", got[0], got[253])
		}
		for _, bad := range []string{"198.51.100.0/32", "198.51.100.255/32"} {
			for _, g := range got {
				if g == bad {
					t.Fatalf("/24 expansion must exclude %s (network/broadcast are not ARP targets)", bad)
				}
			}
		}
	})
}

// TestProxyARPBareIPv6Suffix_6559 pins the prerequisite the expansion rests on:
// a bare IPv6 literal must compile to /128, not the unconditional /32 the
// compiler used to append. The old form parsed, and Addr() recovered the full
// address, so the INSTALL was correct by accident — but a 32-bit prefix on a
// 128-bit address is textually indistinguishable from an authored /32 v6 BLOCK,
// and the expansion keys on exactly that distinction. Leave it and every bare v6
// address becomes an over-cap block.
func TestProxyARPBareIPv6Suffix_6559(t *testing.T) {
	if got := proxyARPHostSuffix("2001:db8::1"); got != "/128" {
		t.Fatalf("bare IPv6 suffix = %q, want /128", got)
	}
	if got := proxyARPHostSuffix("192.0.2.1"); got != "/32" {
		t.Fatalf("bare IPv4 suffix = %q, want /32", got)
	}
	// An IPv4-mapped v6 literal is a v4 address and takes /32 — Is4In6 must not
	// be misread as "v6".
	if got := proxyARPHostSuffix("::ffff:192.0.2.1"); got != "/32" {
		t.Fatalf("IPv4-mapped suffix = %q, want /32", got)
	}
}

// TestProxyARPOverCapRejectedAtCommit_6559 drives the REAL compile path: an
// over-cap block must be rejected on the strict path (so the operator learns the
// block installs nothing) and downgraded to a warning on the tolerant one (#1960
// no-brick — an appliance already carrying such a block must still boot, and on
// that path the installed set is byte-identical to pre-#6559).
func TestProxyARPOverCapRejectedAtCommit_6559(t *testing.T) {
	cfgText := `
security { nat { proxy-arp { interface ge-0-0-0 { address 198.51.100.0/23; } } } }`

	t.Run("strict rejects", func(t *testing.T) {
		_, err := CompileConfig(parseHierText(t, cfgText))
		if err == nil {
			t.Fatal("an over-cap proxy-arp block committed clean; it installs one entry for the NETWORK address and answers nothing")
		}
		for _, want := range []string{"proxy-arp", "198.51.100.0/23", "510 hosts"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("rejection must name %q; got: %v", want, err)
			}
		}
	})

	t.Run("tolerant path loads with a warning", func(t *testing.T) {
		// #1960 no-brick: an appliance whose ACTIVE config already carries an
		// oversized block must still boot. The block is left authored on this
		// path, so the installed set is byte-identical to pre-#6559 (one entry
		// for the address as authored) — no worse than before the gate, and now
		// with a diagnostic.
		cfg, err := CompileConfigLenient(parseHierText(t, cfgText))
		if err != nil {
			t.Fatalf("tolerant path must LOAD an over-cap block (no-brick, #1960), got: %v", err)
		}
		if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "198.51.100.0/23") {
			t.Fatalf("tolerant path swallowed the over-cap block with no warning; warnings: %v", cfg.Warnings)
		}
		if got := cfg.Security.NAT.ProxyARP[0].Addresses; !reflect.DeepEqual(got, []string{"198.51.100.0/23"}) {
			t.Fatalf("tolerant Addresses = %q; the block must be left authored so the install matches pre-#6559", got)
		}
	})

	t.Run("in-cap block commits and expands", func(t *testing.T) {
		// The gate must not reject what the expansion can handle — an
		// over-broad predicate would brick every legitimate block.
		cfg, err := CompileConfig(parseHierText(t,
			`
security { nat { proxy-arp { interface ge-0-0-0 { address 198.51.100.0/30; } } } }`))
		if err != nil {
			t.Fatalf("an in-cap /30 was rejected: %v", err)
		}
		want := []string{"198.51.100.1/32", "198.51.100.2/32"}
		if got := cfg.Security.NAT.ProxyARP[0].Addresses; !reflect.DeepEqual(got, want) {
			t.Fatalf("in-cap /30 Addresses = %q, want %q", got, want)
		}
	})
}
