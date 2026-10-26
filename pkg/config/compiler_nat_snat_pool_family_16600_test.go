package config

import (
	"strings"
	"testing"
)

// #16600: a source-NAT rule whose source match is single-family but
// whose pool has no member of that family committed clean; every
// matching flow was refused at runtime as WrongAddressFamily. The
// strict SNAT pool gate now rejects it (warn on tolerant load),
// mirroring the #13922 DNAT/static cross-family reject. Acceptance:
// the three DEFECT rows reject, while the control, a dual-family pool
// and an unconstrained rule still commit.

func snatFamilySet16600(srcMatch string, poolAddrs ...string) []string {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
	}
	for _, a := range poolAddrs {
		lines = append(lines, "set security nat source pool P address "+a)
	}
	lines = append(lines,
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
	)
	if srcMatch != "" {
		lines = append(lines, "set security nat source rule-set rs1 rule r1 match "+srcMatch)
	}
	lines = append(lines,
		"set security nat source rule-set rs1 rule r1 then source-nat pool P")
	return lines
}

func TestSourceNATPoolFamilyRejected16600(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		pool []string
	}{
		{"v4 rule v6-only pool", "source-address 10.0.0.0/24", []string{"2001:db8::5"}},
		{"v4 rule v4-mapped pool", "source-address 10.0.0.0/24", []string{"::ffff:192.0.2.1"}},
		{"v6 rule v4-only pool", "source-address 2001:db8:1::/64", []string{"192.0.2.5"}},
		// #17847: a whole-family wildcard literal is still single-family:
		// 0.0.0.0/0 matches only IPv4 sources, so a v6-only pool can never
		// serve it. The #17408 scaffold exemption applied to rules with NO
		// authored single-family match; an explicitly authored /0 IS the
		// authored match (the #17408 fixtures use dual-family matches).
		{"v4 wildcard rule v6-only pool", "source-address 0.0.0.0/0", []string{"2001:db8::5"}},
		{"v6 wildcard rule v4-only pool", "source-address ::/0", []string{"192.0.2.5"}},
		{"v4 bare wildcard rule v6-only pool", "source-address 0.0.0.0", []string{"2001:db8::5"}},
		{"v6 bare wildcard rule v4-only pool", "source-address ::", []string{"192.0.2.5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, snatFamilySet16600(tc.src, tc.pool...)))
			if err == nil || !strings.Contains(err.Error(), "address") {
				t.Fatalf("single-family SNAT with opposite-family pool must be rejected, got: %v", err)
			}
			if !strings.Contains(err.Error(), "WrongAddressFamily") {
				t.Fatalf("error must name the runtime refusal, got: %v", err)
			}
		})
	}
}

func TestSourceNATPoolFamilyAccepted16600(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		pool []string
	}{
		{"control v4 rule v4 pool", "source-address 10.0.0.0/24", []string{"192.0.2.5"}},
		{"dual-family pool", "source-address 10.0.0.0/24", []string{"2001:db8::5", "192.0.2.5"}},
		{"unconstrained rule v6 pool", "", []string{"2001:db8::5"}},
		{"dual-family match v6 pool", "source-address [ 10.0.0.0/24 2001:db8:1::/64 ]", []string{"2001:db8::5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, snatFamilySet16600(tc.src, tc.pool...))); err != nil {
				t.Fatalf("must commit, got: %v", err)
			}
		})
	}
	// #16875 supersedes the "v6 rule mapped pool" acceptance: a
	// ::ffff: pool member keys V6 (so the family gate alone passed
	// it) and CAN be allocated outbound to a native-IPv6 source, but
	// return traffic to the mapped identity is ingress-dropped, so
	// it cannot carry bidirectional forwarding. It is rejected as
	// mapped/compat; the family classification (mapped == v6) is
	// still pinned by sourceNATRuleSingleFamily16600 below.
	t.Run("v6 rule mapped pool rejected 16875", func(t *testing.T) {
		_, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address 2001:db8:1::/64", "::ffff:192.0.2.1")))
		if err == nil || !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
			t.Fatalf("mapped SNAT pool member must be rejected as mapped/compat (#16875), got: %v", err)
		}
	})
}

// Wildcard keywords are not valid SNAT `source-address` values on
// the strict path (the literal gate rejects them, and the name gate
// requires a defined book entry), but the builder lowers them by
// family when they reach the wire, so the helper classifies them
// defensively. Pin the helper directly.
func TestSourceNATRuleSingleFamilyWildcard16600(t *testing.T) {
	cfg := &Config{}
	rule := &NATRule{Match: NATMatch{SourceAddresses: []string{"any-ipv4"}}}
	if fam, ok := sourceNATRuleSingleFamily16600(cfg, rule); !ok || fam != "v4" {
		t.Fatalf("any-ipv4 literal = (%q,%v), want (v4,true)", fam, ok)
	}
	rule.Match.SourceAddresses = []string{"any"}
	if _, ok := sourceNATRuleSingleFamily16600(cfg, rule); ok {
		t.Fatal("any literal must be dual-family, not single")
	}
	rule.Match.SourceAddresses = []string{"any-ipv4", "2001:db8::/64"}
	if _, ok := sourceNATRuleSingleFamily16600(cfg, rule); ok {
		t.Fatal("mixed wildcard+literal must be dual-family, not single")
	}
}

func TestSourceNATPoolFamilyLenientWarnsWildcard17847(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 0.0.0.0/0", "2001:db8::5")))
	if err != nil {
		t.Fatalf("lenient compilation must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "WrongAddressFamily") {
		t.Fatalf("lenient compilation must warn about the wildcard SNAT family mismatch: %v", cfg.Warnings)
	}
}

func TestSourceNATPoolFamilyLenientWarns16600(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 10.0.0.0/24", "2001:db8::5")))
	if err != nil {
		t.Fatalf("lenient compilation must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "WrongAddressFamily") {
		t.Fatalf("lenient compilation must warn about the SNAT family mismatch: %v", cfg.Warnings)
	}
}

func TestSourceNATPoolFamilyNameMatch16600(t *testing.T) {
	book := []string{
		"set security address-book global address v4-a 10.0.0.0/24",
		"set security address-book global address v6-a 2001:db8:2::/64",
		"set security address-book global address-set v4-only address v4-a",
		"set security address-book global address-set mixed address v4-a",
		"set security address-book global address-set mixed address v6-a",
	}
	mk := func(name string, pool string) []string {
		lines := []string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
		}
		lines = append(lines, book...)
		lines = append(lines,
			"set security nat source pool P address "+pool,
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address-name "+name,
			"set security nat source rule-set rs1 rule r1 then source-nat pool P")
		return lines
	}
	if _, err := CompileConfig(buildTree(t, mk("v4-only", "2001:db8::5"))); err == nil {
		t.Fatal("v4-only source-address-name with v6-only pool must be rejected")
	}
	if _, err := CompileConfig(buildTree(t, mk("mixed", "2001:db8::5"))); err != nil {
		t.Fatalf("mixed source-address-name with v6 pool must commit: %v", err)
	}
	if _, err := CompileConfig(buildTree(t, mk("v4-a", "192.0.2.5"))); err != nil {
		t.Fatalf("v4 name with v4 pool must commit: %v", err)
	}
}

func TestSourceNATPoolFamilyFeedNameAdmitted16600(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name feed-clients profile feed-name malware",
		"set security nat source pool P address 2001:db8::5",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name feed-clients",
		"set security nat source rule-set rs1 rule r1 then source-nat pool P",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err != nil {
		t.Fatalf("direct feed binding must commit (runtime-resolved): %v", err)
	}
}

// #17408 scoped the #16600 gate to proven mismatches; #17847 then
// closed the remaining whole-family literal-wildcard exemption: a
// literal `0.0.0.0/0` covers every IPv4 source and no IPv6 source, so
// it is an IPv4-single-family authored match that translates ONLY IPv4
// traffic. Paired with a v6-only pool every matching flow is refused
// WrongAddressFamily — exactly the #16600 defect. Scoping to the
// proven mismatch is narrow, and the literal wildcard's parsed family
// is the comparable proved family: `0.0.0.0/0` is IPv4-only, `::/0` is
// IPv6-only. The prior #17408 admission of these literal shapes is
// superseded by #17847. Same-family wildcards, dual-wildcard pairs, an
// unconstrained rule, and a narrow cross-family mismatch retain their
// prior gate outcomes.
func TestSourceNATPoolFamilyWildcardSource17847(t *testing.T) {
	t.Run("v4-slash0 v6-only pool rejected", func(t *testing.T) {
		_, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address 0.0.0.0/0", "2001:db8::5")))
		if err == nil || !strings.Contains(err.Error(), "WrongAddressFamily") {
			t.Fatalf("0.0.0.0/0 is IPv4-only; v6-only pool must be rejected (#17847), got: %v", err)
		}
	})
	t.Run("v6-slash0 v4-only pool rejected", func(t *testing.T) {
		_, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address ::/0", "192.0.2.5")))
		if err == nil || !strings.Contains(err.Error(), "WrongAddressFamily") {
			t.Fatalf("::/0 is IPv6-only; v4-only pool must be rejected (#17847), got: %v", err)
		}
	})
	t.Run("v4-slash0 v4 pool admitted", func(t *testing.T) {
		if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address 0.0.0.0/0", "192.0.2.5"))); err != nil {
			t.Fatalf("0.0.0.0/0 with a v4 pool must commit (#17847), got: %v", err)
		}
	})
	t.Run("v6-slash0 v6 pool admitted", func(t *testing.T) {
		if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address ::/0", "2001:db8::5"))); err != nil {
			t.Fatalf("::/0 with a v6 pool must commit (#17847), got: %v", err)
		}
	})
	t.Run("dual wildcard match v6 pool admitted", func(t *testing.T) {
		if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address [ 0.0.0.0/0 ::/0 ]", "2001:db8::5"))); err != nil {
			t.Fatalf("dual-family source match with a v6 pool must commit (#17847), got: %v", err)
		}
	})
	t.Run("narrow mismatch still rejects", func(t *testing.T) {
		if _, err := CompileConfig(buildTree(t, snatFamilySet16600(
			"source-address 10.0.0.0/24", "2001:db8::/112"))); err == nil {
			t.Fatal("narrow v4 source with v6-only /112 pool must still reject (#16600)")
		}
	})
}
