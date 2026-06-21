package config

import (
	"strings"
	"testing"
)

// #2173: commit-time validation for the static-NAT / NAT64 host-mask rule.
// Static NAT is strictly host-1:1 and NAT64 source-pool entries are discrete
// host IPs, so a non-host mask (/24, /64, ...) is silently dropped by the
// dataplane (PR #2167 hardened parse_nat_addr / parse_pool_v4 to reject it).
// The commit gate surfaces the misconfiguration at commit instead.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

// staticNATSet builds a minimal valid static-NAT rule-set with the given
// match destination-address and then-prefix, zone defined to avoid the H15
// undefined-zone warning noise.
func staticNATSet(match, prefix string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address " + match,
		"set security nat static rule-set rs1 rule r1 then static-nat prefix " + prefix,
	}
}

func TestStaticNATHostMaskBareAddressOK(t *testing.T) {
	// Bare address (no mask) is a host form — must compile.
	tree := buildTree(t, staticNATSet("203.0.113.5", "10.0.0.5"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("bare host addresses must compile, got: %v", err)
	}
}

func TestStaticNATHostMaskSlash32OK(t *testing.T) {
	// Canonical IPv4 host mask /32 — must compile (this is what Junos emits
	// and what the Go compiler copies verbatim into the snapshot).
	tree := buildTree(t, staticNATSet("203.0.113.5/32", "10.0.0.5/32"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("/32 host masks must compile, got: %v", err)
	}
}

func TestStaticNATHostMaskSlash128OK(t *testing.T) {
	// Canonical IPv6 host mask /128 — must compile.
	tree := buildTree(t, staticNATSet("2001:db8::5/128", "2001:db8:1::5/128"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("/128 host masks must compile, got: %v", err)
	}
}

func TestStaticNATHostMaskRejectsV4NonHostMatch(t *testing.T) {
	// A /24 on the match destination-address is a non-host mask — reject at
	// commit (dataplane would silently drop the rule).
	tree := buildTree(t, staticNATSet("203.0.113.0/24", "10.0.0.5/32"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT match /24 (non-host) must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "match destination-address") ||
		!strings.Contains(msg, "203.0.113.0/24") ||
		!strings.Contains(msg, "host route") {
		t.Fatalf("error must name the rule + offending prefix + host-route rule, got: %v", err)
	}
}

func TestStaticNATHostMaskRejectsV4NonHostPrefix(t *testing.T) {
	// A /24 on the then static-nat prefix — reject at commit.
	tree := buildTree(t, staticNATSet("203.0.113.5/32", "10.0.0.0/24"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT prefix /24 (non-host) must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "then static-nat prefix") ||
		!strings.Contains(msg, "10.0.0.0/24") {
		t.Fatalf("error must name the prefix slot + offending value, got: %v", err)
	}
}

func TestStaticNATHostMaskRejectsV6NonHost(t *testing.T) {
	// A /64 on an IPv6 match — reject at commit.
	tree := buildTree(t, staticNATSet("2001:db8::/64", "2001:db8:1::5/128"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT IPv6 match /64 (non-host) must be rejected")
	}
	if !strings.Contains(err.Error(), "2001:db8::/64") {
		t.Fatalf("error must name the offending /64, got: %v", err)
	}
}

// NPTv6 rules (nptv6-prefix) ARE genuine prefix translations (RFC 6296) and
// MUST NOT be rejected by the host-mask gate — they never flow through the
// static_nat.rs parse_nat_addr host gate.
func TestStaticNATHostMaskNPTv6PrefixNotRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:aaaa::/48",
		"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:bbbb::/48",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("NPTv6 prefix rule must NOT be rejected by the host-mask gate, got: %v", err)
	}
}

// The NAT64 `then static-nat inet` rule is a prefix translation, not host-1:1
// static NAT: its match destination-address is the NAT64 well-known prefix
// (64:ff9b::/96, a legitimate non-host prefix). The whole rule must be exempt
// from the host-mask gate (Then == "inet").
func TestStaticNATHostMaskInetActionNotRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match source-address ::/0",
		"set security nat static rule-set rs1 rule r1 match destination-address 64:ff9b::/96",
		"set security nat static rule-set rs1 rule r1 then static-nat inet",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("static-nat inet (NAT64) rule with prefix match must compile, got: %v", err)
	}
}

// NAT64 source-pool: a non-host single pool address referenced by a nat64
// rule-set must be rejected at commit.
func TestNAT64SourcePoolHostMaskRejectsV4NonHost(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.0/24",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("nat64 source-pool address /24 (non-host) must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "p64") ||
		!strings.Contains(msg, "100.64.0.0/24") ||
		!strings.Contains(msg, "nat64") {
		t.Fatalf("error must name the pool, offending address, and nat64 ref, got: %v", err)
	}
}

func TestNAT64SourcePoolHostMaskHostOK(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("nat64 source-pool /32 host address must compile, got: %v", err)
	}
}

// A NAT64 source pool translates to IPv4 source addresses (the Rust
// parse_pool_v4 is IPv4-only). An IPv6 pool address — even a /128 "host" —
// is silently dropped by the dataplane, so the commit gate must reject it
// (Codex MAJOR: family-agnostic isHostMaskAddress would have wrongly accepted
// the /128).
func TestNAT64SourcePoolHostMaskRejectsIPv6(t *testing.T) {
	for _, a := range []string{"2001:db8::5/128", "2001:db8::5"} {
		tree := buildTree(t, []string{
			"set security nat source pool p64 address " + a,
			"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set rs1 source-pool p64",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("nat64 source-pool IPv6 address %q must be rejected (parse_pool_v4 is IPv4-only)", a)
		}
		if !strings.Contains(err.Error(), "IPv4 host route") {
			t.Fatalf("error must say IPv4 host route for %q, got: %v", a, err)
		}
	}
}

// The strict commit gate must NOT brick a daemon restart: a config committed
// before this gate existed (non-host static-NAT mask) must LOAD under the
// lenient path (Store.Load) with the violation downgraded to a warning —
// otherwise #1960 fail-closed-on-compile-failure bricks the daemon.
func TestStaticNATHostMaskLenientLoadAccepts(t *testing.T) {
	cases := [][]string{
		staticNATSet("203.0.113.0/24", "10.0.0.5/32"),      // v4 non-host match
		staticNATSet("203.0.113.5/32", "10.0.0.0/24"),      // v4 non-host prefix
		staticNATSet("2001:db8::/64", "2001:db8:1::5/128"), // v6 non-host match
		{
			"set security nat source pool p64 address 100.64.0.0/24",
			"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set rs1 source-pool p64",
		}, // nat64 pool non-host
	}
	for i, lines := range cases {
		// Strict rejects.
		if _, err := CompileConfig(buildTree(t, lines)); err == nil {
			t.Fatalf("case %d: strict CompileConfig must reject", i)
		}
		// Lenient accepts + warns.
		cfg, err := CompileConfigLenient(buildTree(t, lines))
		if err != nil {
			t.Fatalf("case %d: CompileConfigLenient must NOT fail (brick-on-restart), got: %v", i, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "host route") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("case %d: lenient load must emit a host-route warning, warnings=%v", i, cfg.Warnings)
		}
	}
}

// A valid (host-mask) config must NOT produce a host-mask warning under
// lenient compile (no false positive).
func TestStaticNATHostMaskLenientValidNoWarning(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, staticNATSet("203.0.113.5/32", "10.0.0.5/32")))
	if err != nil {
		t.Fatalf("valid config lenient compile: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "host route") {
			t.Fatalf("valid config must not warn, got: %q", w)
		}
	}
}

// isHostMaskAddress unit coverage: the predicate is the load-bearing core of
// the gate; a regression here silently changes which forms are rejected.
func TestIsHostMaskAddress(t *testing.T) {
	cases := []struct {
		in         string
		wantHost   bool
		wantParsed bool
	}{
		{"203.0.113.5", true, true},      // bare v4
		{"2001:db8::5", true, true},      // bare v6
		{"203.0.113.5/32", true, true},   // v4 host mask
		{"2001:db8::5/128", true, true},  // v6 host mask
		{"203.0.113.0/24", false, true},  // v4 non-host
		{"2001:db8::/64", false, true},   // v6 non-host
		{"203.0.113.5/128", false, true}, // cross-family mask on v4 -> non-host
		{"2001:db8::5/32", false, true},  // cross-family mask on v6 -> non-host
		{"not-an-ip", false, false},      // not an IP -> not our concern
		{"addr/", false, false},          // garbage suffix, bad IP part anyway
		{"203.0.113.5/", false, true},    // empty mask -> non-host (mask "" != "32")
		// IPv4-mapped IPv6: Rust IpAddr::from_str classifies as V6 (host_len
		// 128), so the colon-keyed family must agree — /128 is the host form,
		// /32 is NOT (Go's To4() would have wrongly chosen /32).
		{"::ffff:1.2.3.4", true, true},     // bare mapped -> host (V6)
		{"::ffff:1.2.3.4/128", true, true}, // mapped /128 -> host (V6 mask)
		{"::ffff:1.2.3.4/32", false, true}, // mapped /32 -> NOT host (V6 wants /128)
	}
	for _, c := range cases {
		host, parsed := isHostMaskAddress(c.in)
		if host != c.wantHost || parsed != c.wantParsed {
			t.Errorf("isHostMaskAddress(%q) = (host=%v, parsed=%v), want (host=%v, parsed=%v)",
				c.in, host, parsed, c.wantHost, c.wantParsed)
		}
	}
}

// isNAT64PoolHostAddress is IPv4-ONLY (mirrors Rust parse_pool_v4): bare IPv4
// or IPv4 /32 are installable; an IPv6 address (bare or any mask) and a
// non-host IPv4 mask are not.
func TestIsNAT64PoolHostAddress(t *testing.T) {
	cases := []struct {
		in         string
		wantHost   bool
		wantParsed bool
	}{
		{"100.64.0.7", true, true},       // bare IPv4
		{"100.64.0.7/32", true, true},    // IPv4 host mask
		{"100.64.0.0/24", false, true},   // IPv4 non-host
		{"2001:db8::5", false, true},     // bare IPv6 -> not installable (parsed)
		{"2001:db8::5/128", false, true}, // IPv6 /128 -> not installable (parsed)
		{"2001:db8::/64", false, true},   // IPv6 non-host
		{"100.64.0.7/128", false, true},  // cross-family mask on IPv4
		{"not-an-ip", false, false},      // not an IP
		{"100.64.0.7/", false, true},     // empty mask -> non-host
		// IPv4-mapped IPv6: Ipv4Addr::from_str REJECTS this (Rust drops it),
		// so the IPv4-only pool gate must reject it too — Go's To4() would
		// have wrongly accepted it as a v4 host.
		{"::ffff:1.2.3.4", false, true},    // mapped bare -> not IPv4 pool addr
		{"::ffff:1.2.3.4/32", false, true}, // mapped /32 -> not IPv4 pool addr
	}
	for _, c := range cases {
		host, parsed := isNAT64PoolHostAddress(c.in)
		if host != c.wantHost || parsed != c.wantParsed {
			t.Errorf("isNAT64PoolHostAddress(%q) = (host=%v, parsed=%v), want (host=%v, parsed=%v)",
				c.in, host, parsed, c.wantHost, c.wantParsed)
		}
	}
}
