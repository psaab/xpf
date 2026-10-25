package config

import (
	"strings"
	"testing"
)

// #16875 (R3-B09-03): static-NAT and destination-NAT match/target
// literals in IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible
// (::a.b.c.d, excluding :: and ::1) form commit clean but a match in
// that form can never match: the userspace helper drops every native
// IPv6 frame whose src or dst is v4-mapped/compatible at ingress
// before NAT (#10686/#11669, ipv6_addr_is_v4_mapped_or_compat in
// userspace-dp/src/afxdp/frame/inspect.rs), and an IPv4 packet keys
// V4, missing the V6-keyed entry. A mapped TARGET/pool identity can
// be allocated outbound (the SNAT allocator keeps it in the V6 pool
// for any native-IPv6 source) but its return traffic is
// ingress-dropped, so it cannot carry bidirectional forwarding. The
// strict gates now reject such literals (warn on lenient),
// mirroring that predicate. Note the mapped 127/8 range
// (::ffff:127.x.x.x) is NOT exempt: Rust excludes only the exact
// ::1, and Go's netip IsLoopback would wrongly fold the mapped
// range out of the rejection (review fold on #17697).

func mappedStaticSet16875(match, prefix string) []string {
	return staticNATSet(match, prefix)
}

func TestMappedCompatStaticNATRejected16875(t *testing.T) {
	for _, tc := range []struct{ name, match, prefix string }{
		{"mapped match+target", "::ffff:203.0.113.5/128", "::ffff:10.0.0.5/128"},
		{"compat match+target", "::203.0.113.5/128", "::10.0.0.5/128"},
		{"mapped match only", "::ffff:203.0.113.5/128", "2001:db8::5/128"},
		{"compat target only", "2001:db8::1/128", "::10.0.0.5/128"},
		{"mapped bare match", "::ffff:203.0.113.5", "::ffff:10.0.0.5"},
		{"mapped loopback match", "::ffff:127.0.0.1/128", "2001:db8::5/128"},
		{"mapped loopback range match", "::ffff:127.0.0.2/128", "2001:db8::5/128"},
		{"mapped loopback hex match", "::ffff:7f00:2/128", "2001:db8::5/128"},
		{"mapped loopback target", "2001:db8::1/128", "::ffff:127.0.0.1/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, mappedStaticSet16875(tc.match, tc.prefix)))
			if err == nil {
				t.Fatalf("mapped/compat static-NAT %s -> %s must be rejected at commit", tc.match, tc.prefix)
			}
			if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("error must name the mapped/compat cause, got: %v", err)
			}
		})
	}
}

func TestMappedCompatStaticNATControls16875(t *testing.T) {
	for _, tc := range []struct{ name, match, prefix string }{
		{"native v6", "2001:db8::5/128", "2001:db8:1::5/128"},
		{"native v4", "203.0.113.5/32", "10.0.0.5/32"},
		{"unspecified v6", "::/128", "::/128"},
		{"loopback v6", "::1/128", "::1/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, mappedStaticSet16875(tc.match, tc.prefix))); err != nil {
				t.Fatalf("control %s -> %s must compile, got: %v", tc.match, tc.prefix, err)
			}
		})
	}
}

func TestMappedCompatStaticNATLenientWarns16875(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, mappedStaticSet16875(
		"::ffff:203.0.113.5/128", "::ffff:10.0.0.5/128")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped/compat literal, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatMappedLoopbackLenientWarns16875(t *testing.T) {
	// The mapped 127/8 range must warn on the tolerant path too — it
	// is inside the mapped rejection, not inside the ::1 exemption.
	cfg, err := CompileConfigLenient(buildTree(t, mappedStaticSet16875(
		"::ffff:127.0.0.1/128", "2001:db8::5/128")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped loopback literal, got: %v", cfg.Warnings)
	}
	cfg, err = CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::ffff:127.0.0.1")))
	if err != nil {
		t.Fatalf("lenient SNAT load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped loopback pool member, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatStaticSourceAddressRejected16875(t *testing.T) {
	// The static source selector is honored (SourceConstraint) and
	// the Rust ingress drop checks SRC or DST, so a mapped/compat
	// source is exactly as unsatisfiable as a mapped destination.
	for _, tc := range []struct{ name, src string }{
		{"mapped source", "::ffff:10.0.0.1/128"},
		{"compat source", "::10.0.0.1/128"},
		{"mapped loopback source", "::ffff:127.0.0.1/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set security zones security-zone untrust",
				"set security nat static rule-set rs1 from zone untrust",
				"set security nat static rule-set rs1 rule r1 match source-address " + tc.src,
				"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::5/128",
				"set security nat static rule-set rs1 rule r1 then static-nat prefix 2001:db8:1::5/128",
			}
			_, err := CompileConfig(buildTree(t, lines))
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") ||
				!strings.Contains(err.Error(), "match source-address") {
				t.Fatalf("mapped/compat static source %q must be rejected naming match source-address, got: %v", tc.src, err)
			}
		})
	}
	// Native v6 / v4 source selectors still compile.
	for _, src := range []string{"2001:db8:9::1/128", "10.0.0.1/32", "::1/128"} {
		lines := []string{
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match source-address " + src,
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::5/128",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 2001:db8:1::5/128",
		}
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("native static source %q must compile, got: %v", src, err)
		}
	}
	// Lenient warns for a mapped source selector.
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match source-address ::ffff:10.0.0.1/128",
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::5/128",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 2001:db8:1::5/128",
	}))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped static source, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatSourceMatchRejected16875(t *testing.T) {
	// DNAT `match source-address` and SNAT `match source-address` /
	// `match destination-address` are honored match slots; a
	// mapped/compat literal in any of them can never be satisfied.
	dnat := func(leaf, val string) []string {
		return []string{
			"set security zones security-zone untrust",
			"set security nat destination pool dp address 2001:db8::5",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match " + leaf + " " + val,
			"set security nat destination rule-set rs1 rule r1 match destination-address 2001:db8::5/128",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
		}
	}
	// De-duplicate the destination leaf when it is the slot under test.
	for _, tc := range []struct {
		name  string
		lines []string
		leaf  string
	}{
		{"dnat source mapped", dnat("source-address", "::ffff:10.0.0.1/128"), "match source-address"},
		{"dnat source compat", dnat("source-address", "::10.0.0.1/128"), "match source-address"},
		{"snat source mapped", snatFamilySet16600("source-address ::ffff:10.0.0.0/120", "2001:db8::5"), "match source-address"},
		{"snat source compat", snatFamilySet16600("source-address ::10.0.0.0/120", "2001:db8::5"), "match source-address"},
		{"snat destination mapped", append(snatFamilySet16600("source-address 2001:db8:1::/64", "2001:db8::5"),
			"set security nat source rule-set rs1 rule r1 match destination-address ::ffff:203.0.113.5/128"), "match destination-address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") ||
				!strings.Contains(err.Error(), tc.leaf) {
				t.Fatalf("%s must be rejected naming %s, got: %v", tc.name, tc.leaf, err)
			}
		})
	}
	// Controls: native source selectors compile for both kinds.
	if _, err := CompileConfig(buildTree(t, dnat("source-address", "2001:db8:9::1/128"))); err != nil {
		t.Fatalf("native DNAT source must compile, got: %v", err)
	}
	if _, err := CompileConfig(buildTree(t, snatFamilySet16600("source-address 2001:db8:1::/64", "2001:db8::5"))); err != nil {
		t.Fatalf("native SNAT source must compile, got: %v", err)
	}
}

func TestCompatAddressBookRejected16875(t *testing.T) {
	// A compat book value is not Is4In6, so the #10688 mapped-only
	// check missed it; the book gate now rejects compat too, so a
	// NAT name reference (or a static prefix-name target folded from
	// the book) cannot smuggle the spelling past the literal gate.
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"global entry alone", []string{
			"set security address-book global address c1 ::203.0.113.5/128",
		}},
		{"zone-local entry", []string{
			"set security zones security-zone trust address-book address c1 ::203.0.113.5/128",
		}},
		{"dnat destination-address-name", []string{
			"set security zones security-zone untrust",
			"set security address-book global address c1 ::203.0.113.5/128",
			"set security nat destination pool dp address 2001:db8::5",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address-name c1",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
		}},
		{"static prefix-name target", []string{
			"set security zones security-zone untrust",
			"set security address-book global address c1 ::10.0.0.5/128",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::5/128",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name c1",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), "IPv4-compatible") {
				t.Fatalf("compat address-book value (%s) must be rejected, got: %v", tc.name, err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient load must not fail (%s): %v", tc.name, err)
			}
			if !hasWarningContaining(cfg.Warnings, "IPv4-compatible") {
				t.Fatalf("lenient load must warn about the compat book value (%s), got: %v", tc.name, cfg.Warnings)
			}
		})
	}
	// Controls: :: and ::1 book entries, and native entries, compile.
	for _, v := range []string{"::/128", "::1/128", "2001:db8::5/128", "203.0.113.5/32"} {
		if _, err := CompileConfig(buildTree(t, []string{
			"set security address-book global address ok1 " + v,
		})); err != nil {
			t.Fatalf("control book entry %q must compile, got: %v", v, err)
		}
	}
}

func TestMappedCompatDNATRejected16875(t *testing.T) {
	for _, tc := range []struct{ name, match, pool string }{
		{"mapped match + mapped pool", "::ffff:203.0.113.5/128", "::ffff:10.0.0.5"},
		{"compat match + compat pool", "::203.0.113.5/128", "::10.0.0.5"},
		{"mapped match native pool", "::ffff:203.0.113.5/128", "2001:db8::5"},
		{"native match mapped pool", "2001:db8::1/128", "::ffff:10.0.0.5"},
		{"mapped prefix match", "::ffff:203.0.113.0/120", "::ffff:10.0.0.5"},
		{"mapped loopback match native pool", "::ffff:127.0.0.1/128", "2001:db8::5"},
		{"native match mapped loopback pool", "2001:db8::1/128", "::ffff:127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set security zones security-zone untrust",
				"set security nat destination pool dp address " + tc.pool,
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address " + tc.match,
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
			}
			_, err := CompileConfig(buildTree(t, lines))
			if err == nil {
				t.Fatalf("mapped/compat DNAT match %q pool %q must be rejected", tc.match, tc.pool)
			}
			if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("error must name the mapped/compat cause, got: %v", err)
			}
		})
	}
}

func TestMappedCompatDNATControls16875(t *testing.T) {
	for _, tc := range []struct{ name, match, pool string }{
		{"native v6", "2001:db8::5/128", "2001:db8:1::5"},
		{"native v4", "203.0.113.5/32", "10.0.0.5"},
		{"loopback match", "::1/128", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set security zones security-zone untrust",
				"set security nat destination pool dp address " + tc.pool,
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address " + tc.match,
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
			}
			if _, err := CompileConfig(buildTree(t, lines)); err != nil {
				t.Fatalf("control DNAT %q pool %q must compile, got: %v", tc.match, tc.pool, err)
			}
		})
	}
}

func TestMappedCompatDNATLenientWarns16875(t *testing.T) {
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address ::ffff:10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address ::ffff:203.0.113.5/128",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped/compat literal, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatSNATPoolRejected16875(t *testing.T) {
	for _, tc := range []struct{ name, pool string }{
		{"mapped pool member", "::ffff:192.0.2.1"},
		{"compat pool member", "::192.0.2.1"},
		{"mapped pool prefix", "::ffff:192.0.2.0/120"},
		{"mapped loopback pool member", "::ffff:127.0.0.1"},
		{"mapped loopback pool prefix", "::ffff:127.0.0.0/120"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, snatFamilySet16600(
				"source-address 2001:db8:1::/64", tc.pool)))
			if err == nil {
				t.Fatalf("mapped/compat SNAT pool member %q must be rejected", tc.pool)
			}
			if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("error must name the mapped/compat cause, got: %v", err)
			}
		})
	}
}

func TestMappedCompatSNATPoolControls16875(t *testing.T) {
	for _, tc := range []struct{ name, src, pool string }{
		{"native v6 pool", "source-address 2001:db8:1::/64", "2001:db8::5"},
		{"native v4 pool", "source-address 10.0.0.0/24", "192.0.2.5"},
		{"loopback v6 pool", "source-address 2001:db8:1::/64", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, snatFamilySet16600(tc.src, tc.pool))); err != nil {
				t.Fatalf("control SNAT pool %q must compile, got: %v", tc.pool, err)
			}
		})
	}
}

func TestMappedCompatSNATPoolLenientWarns16875(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::ffff:192.0.2.1")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped/compat pool member, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatPrefixContainsPredicate16875(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"::/126", true},  // contains ::2/::3 compat hosts
		{"::1/126", true}, // masks to ::/126, same set
		{"::/120", true},  // wider compat block
		{"::ffff:0:0/120", true},
		{"::ffff:127.0.0.0/120", true},
		{"::203.0.113.0/120", true},
		// Straddles: interval crosses into D2 without being rooted
		// in it — intersection must still fire.
		{"::fffe:0:0/95", true},
		{"::fffc:0:0/94", true},
		{"::ff00:0:0/88", true},
		{"::/96", true},
		{"::ffff:0:0/95", true}, // host-bits spelling, masks across D2
		{"::/127", false},       // exactly {::, ::1}, both exempt
		{"::1/127", false},      // masks to the same exempt-only set
		{"::", false},           // single exempt host
		{"::1", false},          // single exempt host
		{"::/128", false},       // single exempt host
		{"::1/128", false},
		{"2001:db8::/64", false},
		{"2001:db8::5", false},
		{"0.0.0.0/0", false},
		{"not-an-ip", false},
	} {
		if got := natPrefixContainsV4MappedOrCompat(tc.in); got != tc.want {
			t.Errorf("natPrefixContainsV4MappedOrCompat(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// The address predicate keeps its per-address exemptions: a
	// match-side ::/0 wildcard is NOT judged by the prefix predicate
	// at match slots.
	if natAddrIsV4MappedOrCompat("::/0") {
		t.Error("address predicate must keep ::/0 exempt")
	}
	// Only-semantics (match selectors): broad native prefixes are
	// NOT only-mapped/compat even though compat hosts are a subset.
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"::/0", false},
		{"0:0:0:0:0:0:0:0/0", false},
		{"::/1", false},
		{"::2/1", false},  // host-bits spelling of ::/1
		{"::2/0", false},  // host-bits spelling of ::/0
		{"::/127", false}, // exempt-only set
		{"2001:db8::/64", false},
		{"::/64", false},         // spans native space beyond ::/96
		{"::fffe:0:0/95", false}, // straddles D2 but also native
		{"::fffc:0:0/94", false},
		{"::ff00:0:0/88", false},
		{"::ffff:1.2.3.4/64", false}, // masks to ::/64, native-spanning
		{"::/126", true},
		{"::/96", true}, // exactly compat space
		{"::2/127", true},
		{"::203.0.113.0/120", true},
		{"::ffff:0:0/96", true},
		{"::ffff:0:0/95", false}, // straddle: also native above D2
		{"::ffff:203.0.113.0/120", true},
	} {
		if got := natPrefixIsV4MappedOrCompatOnly(tc.in); got != tc.want {
			t.Errorf("natPrefixIsV4MappedOrCompatOnly(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestMappedCompatGateWitnesses16875(t *testing.T) {
	// F2: compat-only match prefixes on the primary NAT kinds
	// (mask-blind at the address predicate before this fold).
	// (Subset question below, via the real compiler.)
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"snat source ::/96", []string{
			"set security zones security-zone trust", "set security zones security-zone untrust",
			"set security nat source pool P address 2001:db8::5",
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address ::/96",
			"set security nat source rule-set rs1 rule r1 then source-nat pool P",
		}},
		{"dnat destination ::/96", []string{
			"set security zones security-zone untrust",
			"set security nat destination pool dp address 2001:db8::5",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address ::/96",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
		}},
		{"static source ::/96", []string{
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match source-address ::/96",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::5/128",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 2001:db8:1::5/128",
		}},
		{"static block compat external", staticNATSet("::/126", "2001:db8::/126")},
		{"static block compat target", staticNATSet("2001:db8::/126", "::/126")},
		{"static block straddle target", staticNATSet("2001:db8::/95", "::fffe:0:0/95")},
		{"static block straddle external /95", staticNATSet("::fffe:0:0/95", "2001:db8::/95")},
		{"static block straddle external /94", staticNATSet("::fffc:0:0/94", "2001:db8::/94")},
		{"static block straddle external /88", staticNATSet("::ff00:0:0/88", "2001:db8::/88")},
		{"nptv6 compat target", []string{
			"set security zones security-zone trust",
			"set security nat static rule-set rs1 from zone trust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::/64",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix ::/64",
		}},
		{"nptv6 compat external", []string{
			"set security zones security-zone trust",
			"set security nat static rule-set rs1 from zone trust",
			"set security nat static rule-set rs1 rule r1 match destination-address ::/64",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:1::/64",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("%s must be rejected as mapped/compat, got: %v", tc.name, err)
			}
		})
	}
	// Controls that must stay viable: broad match selectors,
	// host-bits spellings and native block pairs. (The former
	// compat-rooted NPTv6 external control moved to the reject rows
	// above: the external is a reverse translation endpoint.)
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"snat source ::/0", snatFamilySet16600("source-address ::/0", "2001:db8::5")},
		{"snat source ::2/0", snatFamilySet16600("source-address ::2/0", "2001:db8::5")},
		{"static block native", staticNATSet("2001:db8::/64", "2001:db8:1::/64")},
		{"nptv6 native pair", []string{
			"set security zones security-zone trust",
			"set security nat static rule-set rs1 from zone trust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8::/64",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/64",
		}},
		{"book straddle selector", []string{
			"set security address-book global address c1 ::fffe:0:0/95",
		}},
		{"book hostbits wildcard", []string{
			"set security address-book global address c1 ::2/0",
		}},
		{"book native-spanning range ::2", []string{
			"set security address-book global address r1 range-address ::2 to 2001:db8::9",
		}},
		{"book native-spanning range ::1", []string{
			"set security address-book global address r1 range-address ::1 to 2001:db8::9",
		}},
	} {
		t.Run("control/"+tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("control %s must compile, got: %v", tc.name, err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "IPv4-mapped or IPv4-compatible") {
					t.Fatalf("control %s must not warn mapped/compat, got: %v", tc.name, cfg.Warnings)
				}
			}
			cfgL, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient control %s must compile: %v", tc.name, err)
			}
			for _, w := range cfgL.Warnings {
				if strings.Contains(w, "IPv4-mapped or IPv4-compatible") {
					t.Fatalf("lenient control %s must not warn mapped/compat, got: %v", tc.name, cfgL.Warnings)
				}
			}
		})
	}
}

func TestMappedCompatBookUnionExemptFragment16875(t *testing.T) {
	// An exempt fragment must not excuse compat siblings: the
	// merged union is compat-only in each row (gate3 F2).
	for _, tc := range []struct{ name, line string }{
		{"range ::1 to ::3", "set security address-book global address c1 range-address ::1 to ::3"},
		{"range :: to ::2", "set security address-book global address c1 range-address :: to ::2"},
		{"range ::1 to compat end", "set security address-book global address c1 range-address ::1 to ::255.255.255.255"},
		{"named range ::1 to ::3", "set security address-book book1 address c1 range-address ::1 to ::3"},
		{"zone-local range ::1 to ::3", "set security zones security-zone trust address-book address c1 range-address ::1 to ::3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, []string{tc.line}))
			if err == nil || !strings.Contains(err.Error(), "IPv4-") {
				t.Fatalf("compat-only union (%s) must reject, got: %v", tc.name, err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, []string{tc.line}))
			if err != nil {
				t.Fatalf("lenient must not fail: %v", err)
			}
			if !hasWarningContaining(cfg.Warnings, "IPv4-") {
				t.Fatalf("lenient must warn for compat-only union (%s), got: %v", tc.name, cfg.Warnings)
			}
		})
	}
	// DNAT name reference to a compat-only union rejects too.
	_, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security address-book global address c1 range-address ::1 to ::3",
		"set security nat destination pool dp address 2001:db8::5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address-name c1",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}))
	if err == nil {
		t.Fatal("DNAT reference to compat-only union must reject")
	}
	// Controls: exempt-only union and native-spanning union compile.
	for _, line := range []string{
		"set security address-book global address c1 range-address :: to ::1",
		"set security address-book global address c1 range-address ::1 to ::1",
		"set security address-book global address c1 range-address ::2 to 2001:db8::9",
	} {
		if _, err := CompileConfig(buildTree(t, []string{line})); err != nil {
			t.Fatalf("control union %q must compile, got: %v", line, err)
		}
	}
}

func TestMappedCompatSNATSubnetPoolRejected16875(t *testing.T) {
	for _, pool := range []string{"::/126", "::1/126", "::/120", "::ffff:0:0/120"} {
		if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address 2001:db8:1::/64", pool))); err == nil ||
			!strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
			t.Fatalf("SNAT subnet pool %q containing compat hosts must be rejected, got: %v", pool, err)
		}
	}
	// Controls: bare exempt hosts and native prefixes compile.
	for _, pool := range []string{"::", "::1", "::/128", "::1/128", "2001:db8::/120"} {
		if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address 2001:db8:1::/64", pool))); err != nil {
			t.Fatalf("control SNAT pool %q must compile, got: %v", pool, err)
		}
	}
	cfg, err := CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::/126")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the compat-containing pool, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatRound3Boundaries16875(t *testing.T) {
	// Book broad native prefixes compile in every book kind, with
	// no false warning (match selectors, not allocation sets).
	for _, tc := range []struct{ name, line string }{
		{"global zero", "set security address-book global address all-v6 ::/0"},
		{"global zero long", "set security address-book global address all-v6 0:0:0:0:0:0:0:0/0"},
		{"global half", "set security address-book global address half-v6 ::/1"},
		{"named zero", "set security address-book book1 address all-v6 ::/0"},
		{"zone-local zero", "set security zones security-zone trust address-book address all-v6 ::/0"},
		{"global exempt pair", "set security address-book global address pair ::/127"},
		{"global native", "set security address-book global address n 2001:db8::/32"},
	} {
		t.Run("book/"+tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{tc.line}))
			if err != nil {
				t.Fatalf("broad native book entry must compile, got: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "IPv4-mapped or IPv4-compatible") || strings.Contains(w, "IPv4-compatible IPv6") {
					t.Fatalf("broad native book entry must not warn mapped/compat, got: %v", cfg.Warnings)
				}
			}
			if _, err := CompileConfigLenient(buildTree(t, []string{tc.line})); err != nil {
				t.Fatalf("lenient must compile: %v", err)
			}
		})
	}
	// Range/wildcard expansions spanning native space compile; a
	// compat-only expansion still rejects (round-2 witness kept).
	for _, line := range []string{
		"set security address-book global address r1 range-address :: to 2001:db8::9",
		"set security address-book global address w1 wildcard-address ::/0:0:0:0::",
	} {
		if _, err := CompileConfig(buildTree(t, []string{line})); err != nil {
			t.Fatalf("native-spanning expansion %q must compile, got: %v", line, err)
		}
	}
	if _, err := CompileConfig(buildTree(t, []string{
		"set security address-book global address r1 range-address ::2 to ::3",
	})); err == nil || !strings.Contains(err.Error(), "IPv4-compatible") {
		t.Fatalf("compat-only range ::2-::3 must reject, got: %v", err)
	}
	// NAT64 broad/equivalent source selectors compile; compat-only
	// and mapped-only selectors still reject.
	nat64Src := func(src string) []string {
		return []string{
			"set security nat source pool P address 192.0.2.5",
			"set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set n64 match source-address " + src,
			"set security nat nat64 rule-set n64 source-pool P",
		}
	}
	for _, src := range []string{"::/1", "0:0:0:0:0:0:0:0/0", "::/0", "2001:db8::/64", "::/127"} {
		if _, err := CompileConfig(buildTree(t, nat64Src(src))); err != nil {
			t.Fatalf("NAT64 native source %q must compile, got: %v", src, err)
		}
	}
	for _, src := range []string{"::/126", "::2/127", "::ffff:0:0/96", "::203.0.113.0/120"} {
		if _, err := CompileConfig(buildTree(t, nat64Src(src))); err == nil ||
			!strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
			t.Fatalf("NAT64 compat/mapped-only source %q must reject, got: %v", src, err)
		}
	}
	// SNAT exempt-only subnet compiles; ::/126 still rejects.
	if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::/127"))); err != nil {
		t.Fatalf("SNAT pool ::/127 (exempt-only set) must compile, got: %v", err)
	}
	if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::1/127"))); err != nil {
		t.Fatalf("SNAT pool ::1/127 (masks to exempt-only set) must compile, got: %v", err)
	}
}

func TestMappedCompatExpandedBookRejected16875(t *testing.T) {
	dnatName := func(bookLines []string) []string {
		lines := []string{"set security zones security-zone untrust"}
		lines = append(lines, bookLines...)
		return append(lines,
			"set security nat destination pool dp address 2001:db8::5",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address-name c1",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp")
	}
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"range compat", dnatName([]string{
			"set security address-book global address c1 range-address ::203.0.113.5 to ::203.0.113.5"})},
		{"range mapped", dnatName([]string{
			"set security address-book global address c1 range-address ::ffff:203.0.113.5 to ::ffff:203.0.113.5"})},
		{"wildcard compat", dnatName([]string{
			"set security address-book global address c1 wildcard-address ::203.0.113.5/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"})},
		{"named book range compat", []string{
			"set security zones security-zone untrust",
			"set security address-book book1 address c1 range-address ::203.0.113.5 to ::203.0.113.5",
		}},
		{"zone-local wildcard compat", []string{
			"set security zones security-zone trust address-book address c1 wildcard-address ::203.0.113.5/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		}},
		{"nested set range compat", []string{
			"set security zones security-zone untrust",
			"set security address-book global address c1 range-address ::203.0.113.5 to ::203.0.113.5",
			"set security address-book global address-set s1 address c1",
			"set security nat destination pool dp address 2001:db8::5",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address-name s1",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil || (!strings.Contains(err.Error(), "IPv4-compatible") && !strings.Contains(err.Error(), "IPv4-mapped")) {
				t.Fatalf("expanded compat/mapped book value (%s) must be rejected, got: %v", tc.name, err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient load must not fail (%s): %v", tc.name, err)
			}
			if !hasWarningContaining(cfg.Warnings, "IPv4-") {
				t.Fatalf("lenient load must warn about the expanded book value (%s), got: %v", tc.name, cfg.Warnings)
			}
		})
	}
	// SNAT source-name through an expanded compat entry.
	snatLines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address c1 range-address ::203.0.113.5 to ::203.0.113.5",
		"set security nat source pool P address 2001:db8::5",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name c1",
		"set security nat source rule-set rs1 rule r1 then source-nat pool P",
	}
	if _, err := CompileConfig(buildTree(t, snatLines)); err == nil {
		t.Fatal("SNAT source-name resolving to a compat expansion must be rejected (book gate)")
	}
	// Controls: native range/wildcard expansions compile.
	for _, book := range []string{
		"set security address-book global address c1 range-address 2001:db8::5 to 2001:db8::9",
		"set security address-book global address c1 wildcard-address 2001:db8::5/ffff:ffff:ffff:ffff::",
		"set security address-book global address c1 range-address ::1 to ::1",
	} {
		if _, err := CompileConfig(buildTree(t, []string{book})); err != nil {
			t.Fatalf("control book entry %q must compile, got: %v", book, err)
		}
	}
}

func TestMappedCompatNAT64Rejected16875(t *testing.T) {
	nat64 := func(extra ...string) []string {
		lines := []string{"set security nat source pool P address 192.0.2.5"}
		return append(lines, extra...)
	}
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{"mapped prefix", nat64(
			"set security nat nat64 rule-set n64 prefix ::ffff:0:0/96",
			"set security nat nat64 rule-set n64 source-pool P"), "prefix"},
		{"compat source", nat64(
			"set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set n64 match source-address ::203.0.113.5/128",
			"set security nat nat64 rule-set n64 source-pool P"), "match source-address"},
		{"mapped source", nat64(
			"set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set n64 match source-address ::ffff:10.0.0.1/128",
			"set security nat nat64 rule-set n64 source-pool P"), "match source-address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NAT64 %s must be rejected naming %s, got: %v", tc.name, tc.want, err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient NAT64 load must not fail: %v", err)
			}
			if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("lenient load must warn about the NAT64 mapped/compat value, got: %v", cfg.Warnings)
			}
		})
	}
	// Controls: well-known prefix + native v6 source compile; ::/0
	// match-any source stays exempt.
	for _, lines := range [][]string{
		nat64("set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set n64 source-pool P"),
		nat64("set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set n64 match source-address 2001:db8::/64",
			"set security nat nat64 rule-set n64 source-pool P"),
		nat64("set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set n64 match source-address ::/0",
			"set security nat nat64 rule-set n64 source-pool P"),
	} {
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("native NAT64 control must compile, got: %v", err)
		}
	}
}

func TestMappedCompatPredicate16875(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"::ffff:203.0.113.5", true},
		{"::ffff:203.0.113.5/128", true},
		{"::ffff:203.0.113.0/120", true},
		{"::ffff:0:0", true}, // hex spelling of the mapped form
		{"::203.0.113.5", true},
		{"::203.0.113.5/128", true},
		// Mapped 127/8: Rust excludes only the exact ::1, so the whole
		// mapped loopback range is mapped (ingress-dropped). Go's
		// netip IsLoopback Unmaps and would exempt these — the
		// predicate must not use it (#17697 review fold).
		{"::ffff:127.0.0.1", true},
		{"::ffff:127.0.0.1/128", true},
		{"::ffff:127.0.0.2", true},
		{"::ffff:127.255.255.254/128", true},
		{"::ffff:7f00:1", true}, // hex spelling of ::ffff:127.0.0.1
		{"::127.0.0.1", true},   // compat loopback-range spelling
		{"::", false},           // unspecified excluded (Rust predicate)
		{"::1", false},          // loopback excluded
		{"::/0", false},
		{"::1/128", false},
		{"2001:db8::5", false},
		{"2001:db8::5/128", false},
		{"203.0.113.5", false},
		{"203.0.113.5/32", false},
		{"0.0.0.0/0", false},
		{"not-an-ip", false},
		{"", false},
		{"web-server", false},
	} {
		if got := natAddrIsV4MappedOrCompat(tc.in); got != tc.want {
			t.Errorf("natAddrIsV4MappedOrCompat(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
