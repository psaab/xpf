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
// from the host-mask gate (Then == "inet") — the host-mask check must never be
// the thing that flags it.
//
// #5859: `then static-nat inet` is itself now REJECTED at strict commit (no
// dataplane lowering; the literal "inet" installed a silently inert rule). This
// test proves the rejection is the #5859 inet gate — NOT a host-mask "host
// route" complaint about the /96 match — so the host-mask exemption still holds.
func TestStaticNATHostMaskInetActionNotRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match source-address ::/0",
		"set security nat static rule-set rs1 rule r1 match destination-address 64:ff9b::/96",
		"set security nat static rule-set rs1 rule r1 then static-nat inet",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-nat inet (NAT64) must be rejected at strict commit (#5859)")
	}
	// The rejection must come from the inet gate, not the host-mask gate: the
	// /96 match is a legitimate NAT64 prefix and must never draw a "host route"
	// error.
	if strings.Contains(err.Error(), "host route") {
		t.Fatalf("host-mask gate must EXEMPT the inet /96 match; got a host-route error: %v", err)
	}
	if !strings.Contains(err.Error(), "nat64") {
		t.Fatalf("rejection must be the #5859 inet gate (mention nat64), got: %v", err)
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

// #2182: the IPv4-mapped IPv6 literal (`::ffff:203.0.113.5`) is the
// pathological case where Go's net.ParseIP(...).To4() and Rust's IpAddr
// family decision DISAGREE — exercised end-to-end at COMMIT (not just the
// predicate-unit table). To4() returns non-nil (Go would call it IPv4 and
// accept a /32), but Rust's parse_nat_addr parses it as IpAddr::V6 and demands
// /128, so a /32 is silently dropped by the dataplane, re-creating the exact
// "commit passes, dataplane drops" gap #2173 closes. The /32 form must now be
// REJECTED at commit.
//
// #16875 supersedes the /128 half: a mapped /128 host pair used to
// compile as an IPv6 host mapping, but the helper drops every IPv6
// frame carrying a mapped identity at ingress before NAT (#10686),
// so the entry can never match. It is now rejected as mapped/compat
// by validateNATMappedCompatStrict; the family/host-mask classification
// itself (mapped == V6, /128 is the host mask) is unchanged and is
// still pinned by the predicate-unit table below.
func TestStaticNATHostMaskV4MappedV6RejectsSlash32(t *testing.T) {
	tree := buildTree(t, staticNATSet("::ffff:203.0.113.5/32", "10.0.0.5/32"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT v4-mapped-v6 match /32 must be rejected (Rust treats it as IPv6, requires /128)")
	}
	msg := err.Error()
	// Either gate may win the first-error slot (host-mask runs in the
	// tail gates, mapped/compat in the NAT registry); both name the
	// offending prefix. Accept the mapped/compat diagnostic too.
	if !strings.Contains(msg, "::ffff:203.0.113.5/32") ||
		!(strings.Contains(msg, "host route") || strings.Contains(msg, "IPv4-mapped")) {
		t.Fatalf("error must name the offending v4-mapped-v6 prefix + host-route/mapped rule, got: %v", err)
	}
}

func TestStaticNATHostMaskV4MappedV6AcceptsSlash128(t *testing.T) {
	// #16875: the mapped /128 pair no longer compiles — it keys V6 but
	// no mapped-identity frame survives ingress, so it can never match.
	tree := buildTree(t, staticNATSet("::ffff:203.0.113.5/128", "::ffff:10.0.0.5/128"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT v4-mapped-v6 /128 must be rejected as mapped/compat (#16875)")
	}
	if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("error must name the mapped/compat cause, got: %v", err)
	}
}

// NAT64 source pool: Rust's parse_pool_v4 (Ipv4Addr::from_str) rejects ANY
// colon-bearing literal, so the v4-mapped-v6 form is dropped regardless of
// mask. To4() would have wrongly accepted `::ffff:.../32` as an IPv4 pool
// host; the commit gate must reject BOTH /32 and /128 to match the dataplane.
// #16875: the mapped/compat gate may win the first-error slot over the
// host-mask gate for the /128 and bare forms (both reject); the /32
// form still reports the IPv4-host-route cause. Either diagnostic
// names the offending address.
func TestNAT64SourcePoolHostMaskRejectsV4MappedV6(t *testing.T) {
	for _, a := range []string{"::ffff:203.0.113.5/32", "::ffff:203.0.113.5/128", "::ffff:203.0.113.5"} {
		tree := buildTree(t, []string{
			"set security nat source pool p64 address " + a,
			"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set rs1 source-pool p64",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("nat64 source-pool v4-mapped-v6 address %q must be rejected (parse_pool_v4 is IPv4-only, rejects colon)", a)
		}
		if !strings.Contains(err.Error(), "IPv4 host route") && !strings.Contains(err.Error(), "IPv4-mapped") {
			t.Fatalf("error must say IPv4 host route or mapped/compat for %q, got: %v", a, err)
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

// #2182: the lenient warning text must be precise about dataplane impact. A
// static-NAT IP failure makes parse_nat_addr return None for the rule's
// match/then -> the WHOLE rule is dropped. A NAT64 source-pool entry is
// dropped individually by filter_map(parse_pool_v4) -> only that pool address
// is dropped, the rest of the pool/rule stays installed. The two warnings must
// say different things so the operator does not over-read the impact.
func TestNATHostMaskLenientWarningSuffixPrecision(t *testing.T) {
	staticCfg, err := CompileConfigLenient(buildTree(t, staticNATSet("203.0.113.0/24", "10.0.0.5/32")))
	if err != nil {
		t.Fatalf("static-NAT lenient compile: %v", err)
	}
	if !hasWarningContaining(staticCfg.Warnings, "rule dropped by dataplane") {
		t.Fatalf("static-NAT warning must say the rule is dropped, got: %v", staticCfg.Warnings)
	}

	poolCfg, err := CompileConfigLenient(buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.0/24",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	}))
	if err != nil {
		t.Fatalf("nat64-pool lenient compile: %v", err)
	}
	if !hasWarningContaining(poolCfg.Warnings, "only this pool address is dropped") {
		t.Fatalf("nat64-pool warning must say only the pool address is dropped, got: %v", poolCfg.Warnings)
	}
	// And it must NOT claim the whole rule is dropped.
	if hasWarningContaining(poolCfg.Warnings, "rule dropped by dataplane") {
		t.Fatalf("nat64-pool warning must NOT claim the whole rule is dropped, got: %v", poolCfg.Warnings)
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

// #3031: a valid block-to-block (subnet) static-NAT rule — equal-length
// non-host prefixes of the same family — must now COMPILE (the dataplane
// installs an offset-preserving 1:1 remap). It was previously rejected by the
// host-mask gate.
func TestStaticNATBlockToBlockV4Compiles(t *testing.T) {
	tree := buildTree(t, staticNATSet("198.51.100.0/24", "192.168.1.0/24"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("equal-length /24->/24 block static-NAT must compile, got: %v", err)
	}
}

func TestStaticNATBlockToBlockV6Compiles(t *testing.T) {
	tree := buildTree(t, staticNATSet("2001:db8:a::/120", "fd00:1::/120"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("equal-length /120->/120 v6 block static-NAT must compile, got: %v", err)
	}
}

// A mismatched-length pair (/24 -> /25) is NOT a 1:1 block map and stays
// rejected — the dataplane skips it, so the commit gate must surface it.
func TestStaticNATBlockMismatchedLengthRejected(t *testing.T) {
	tree := buildTree(t, staticNATSet("198.51.100.0/24", "192.168.1.0/25"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("mismatched-length block static-NAT (/24 -> /25) must be rejected")
	}
	if !strings.Contains(err.Error(), "host route") {
		t.Fatalf("error must still cite the host-route rule, got: %v", err)
	}
}

// A mixed-family pair (v4 -> v6) is not a block map and stays rejected.
func TestStaticNATBlockMixedFamilyRejected(t *testing.T) {
	tree := buildTree(t, staticNATSet("198.51.100.0/24", "2001:db8::/120"))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("mixed-family block static-NAT (v4 -> v6) must be rejected")
	}
}

// #5658: a block-to-block pair whose prefix length is ZERO (`/0` on both
// sides) maps the ENTIRE address family 1:1 — an identity translation that
// shadows every narrower static/DNAT rule. It must be HARD-REJECTED at strict
// commit even though isStaticBlockPair (equal-length non-host same-family)
// otherwise accepts it. v4 (0.0.0.0/0) and v6 (::/0) both.
func TestStaticNATBlockZeroLengthV4Rejected(t *testing.T) {
	tree := buildTree(t, staticNATSet("0.0.0.0/0", "10.0.0.0/0"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a /0 <-> /0 block static-NAT must be rejected (remaps the entire IPv4 family 1:1)")
	}
	if !strings.Contains(err.Error(), "zero-length") || !strings.Contains(err.Error(), "/0") {
		t.Fatalf("error must cite the zero-length /0 mapping, got: %v", err)
	}
}

func TestStaticNATBlockZeroLengthV6Rejected(t *testing.T) {
	tree := buildTree(t, staticNATSet("::/0", "fd00::/0"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a ::/0 <-> ::/0 block static-NAT must be rejected (remaps the entire IPv6 family 1:1)")
	}
	// The ::/0 match is viable (subset-false), but the fd00::/0
	// TARGET interval intersects dropped-non-exempt space, so the
	// #16875 intersection verdict can win this first-error slot over
	// the #5658 zero-length verdict. Either rejection is correct;
	// the zero-length-specific wording is pinned by the v4 twin
	// above (no mapped/compat intersection on that path).
	if !strings.Contains(err.Error(), "zero-length") && !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("error must cite the zero-length /0 mapping or the mapped/compat target intersection, got: %v", err)
	}
}

// #5658 lenient path: a /0 block must NOT brick a restart / peer-sync — it
// downgrades to a warning (the Rust backstop drops the whole rule) while a
// legitimate strict commit is rejected.
func TestStaticNATBlockZeroLengthLenientWarns(t *testing.T) {
	tree := buildTree(t, staticNATSet("0.0.0.0/0", "10.0.0.0/0"))
	// Strict rejects.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig must reject a /0 block")
	}
	// Lenient accepts + warns (must not fail the compile).
	cfg, err := CompileConfigLenient(buildTree(t, staticNATSet("0.0.0.0/0", "10.0.0.0/0")))
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT fail on a /0 block (brick-on-restart), got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zero-length") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load must emit a zero-length block warning, warnings=%v", cfg.Warnings)
	}
}

// #5658 false-reject guard: the fix is a ZERO-length reject ONLY, not an
// arbitrary non-zero floor. A legitimate large-but-intentional equal-length
// block (e.g. a /8 -> /8) must still compile clean — proving documented subnet
// static-NAT parity is preserved.
func TestStaticNATBlockLargeNonZeroPrefixStillCompiles(t *testing.T) {
	tree := buildTree(t, staticNATSet("10.0.0.0/8", "172.16.0.0/8"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a legitimate /8 -> /8 block must still compile (no arbitrary non-zero floor), got: %v", err)
	}
}

// #3202: a block-to-block (subnet) static-NAT rule that ALSO specifies a
// `match destination-port` and `then static-nat mapped-port` MUST be rejected
// at strict commit-check. The dataplane installs a block as an address-only,
// all-port 1:1 remap (StaticNatBlock has no port fields), so the port mapping
// would be silently dropped and "NAT only port 80 of this /24 -> 8080"
// degrades to "NAT every port of the /24". Reject so the operator authors a
// /32 host rule for the port forward, or drops the port tokens.
//
// Fail-on-revert: deleting the `if blockPair && (... port ...)` guard in
// validateNATHostMaskStrict makes this config compile cleanly → test RED.
func TestStaticNATBlockWithPortRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.0/24",
		"set security nat static rule-set rs1 rule r1 match destination-port 80",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 192.168.1.0/24 mapped-port 8080",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("block static-NAT (/24 -> /24) with match destination-port + mapped-port must be rejected")
	}
	if !strings.Contains(err.Error(), "subnet") || !strings.Contains(err.Error(), "address-only") {
		t.Fatalf("error must explain the subnet/address-only conflict, got: %v", err)
	}
}

// A block rule with ONLY a match destination-port (no mapped-port) is equally
// not representable by StaticNatBlock and must be rejected.
func TestStaticNATBlockWithMatchPortOnlyRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.0/24",
		"set security nat static rule-set rs1 rule r1 match destination-port 80",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 192.168.1.0/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("block static-NAT with a match destination-port (no mapped-port) must be rejected")
	}
}

// Regression (#3031): the address-only block static-NAT rule (NO port tokens)
// must still compile — the #3202 guard must not reject a portless block pair.
func TestStaticNATBlockNoPortStillCompiles(t *testing.T) {
	tree := buildTree(t, staticNATSet("198.51.100.0/24", "192.168.1.0/24"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("portless /24->/24 block static-NAT must still compile (#3031), got: %v", err)
	}
}

// isStaticBlockPair unit coverage.
func TestIsStaticBlockPair(t *testing.T) {
	cases := []struct {
		match, then string
		want        bool
	}{
		{"198.51.100.0/24", "192.168.1.0/24", true},  // equal-length block pair
		{"2001:db8:a::/120", "fd00:1::/120", true},   // v6 equal-length pair
		{"198.51.100.0/24", "192.168.1.0/25", false}, // mismatched length
		{"198.51.100.0/24", "2001:db8::/120", false}, // mixed family
		{"203.0.113.5/32", "10.0.0.5/32", false},     // both host
		{"203.0.113.5", "10.0.0.5", false},           // bare hosts
		{"203.0.113.5/32", "10.0.0.0/24", false},     // host vs block
		{"198.51.100.0/24", "10.0.0.5/32", false},    // block vs host
		{"198.51.100.0/33", "192.168.1.0/24", false}, // malformed mask
		{"book-name", "192.168.1.0/24", false},       // non-IP token
	}
	for _, c := range cases {
		if got := isStaticBlockPair(c.match, c.then); got != c.want {
			t.Errorf("isStaticBlockPair(%q, %q) = %v, want %v", c.match, c.then, got, c.want)
		}
	}
}

// #3206: a static-NAT match destination-address / then static-nat prefix that
// is NOT a parseable literal IP/CIDR (an address-book name, or a typo'd
// prefix) committed cleanly before this gate — the host-mask check only fires
// when the value parses, so an unparseable value fell through to the Rust
// dataplane, where parse_nat_prefix returns None and from_snapshots `continue`
// silently drops the WHOLE static-NAT mapping. The commit gate now rejects it.
//
// Fail-on-revert: delete the `#3206` blocks in validateNATHostMaskStrict and
// these reject tests compile cleanly → RED. The valid host (/32) and block
// (/24) tests in this file stay GREEN (no over-rejection of legit configs).

func TestStaticNATUnparseableMatchRejected(t *testing.T) {
	// An address-book name in the match destination-address slot.
	tree := buildTree(t, staticNATSet("web-server", "10.0.0.5/32"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT match with an unparseable address (address-book name) must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "match destination-address") ||
		!strings.Contains(msg, "web-server") ||
		!strings.Contains(msg, "not a valid IP address or CIDR prefix") {
		t.Fatalf("error must name the slot + offending value + reason, got: %v", err)
	}
}

func TestStaticNATUnparseablePrefixRejected(t *testing.T) {
	// A typo'd prefix in the then static-nat prefix slot (not a literal IP).
	tree := buildTree(t, staticNATSet("203.0.113.5/32", "10.0.0.300"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("static-NAT prefix with an unparseable value (typo) must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "then static-nat prefix") ||
		!strings.Contains(msg, "10.0.0.300") ||
		!strings.Contains(msg, "not a valid IP address or CIDR prefix") {
		t.Fatalf("error must name the prefix slot + offending value + reason, got: %v", err)
	}
}

// A valid host (/32) and a valid block (/24) static NAT must still compile —
// the #3206 unparseable gate must not over-reject legitimate literal values.
func TestStaticNATParseableValuesStillCompile(t *testing.T) {
	cases := [][]string{
		staticNATSet("203.0.113.5", "10.0.0.5"),              // bare hosts
		staticNATSet("203.0.113.5/32", "10.0.0.5/32"),        // /32 host pair
		staticNATSet("2001:db8::5/128", "2001:db8:1::5/128"), // /128 host pair
		staticNATSet("198.51.100.0/24", "192.168.1.0/24"),    // /24 block pair (#3031)
	}
	for i, lines := range cases {
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("case %d: parseable static-NAT must compile, got: %v", i, err)
		}
	}
}

// Lenient load must NOT brick the daemon on an unparseable static-NAT value —
// it accepts and warns (the dataplane independently drops the rule).
func TestStaticNATUnparseableLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, staticNATSet("web-server", "10.0.0.5/32")))
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "not a valid IP address or CIDR prefix") {
		t.Fatalf("lenient load must warn about the unparseable value, warnings=%v", cfg.Warnings)
	}
	if !hasWarningContaining(cfg.Warnings, "rule dropped by dataplane") {
		t.Fatalf("warning must say the rule is dropped by the dataplane, warnings=%v", cfg.Warnings)
	}
}
