package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6577 (prefix/address-SET half) fail-on-revert artifacts.
//
// The query half of #6577 fixed HOW containment is performed once a mapped
// address lands in the v6 branch (containsAnyV6). This is the other surface of
// the same defect: WHICH family set a mapped LITERAL is filed into.
//
// addCIDRValue used to classify a parsed value with `ipnet.IP.To4() != nil` /
// `ip.To4() != nil`. Go FOLDS an IPv4-mapped literal, so `::ffff:0:0/96` and
// every mapped `/97`-`/128` prefix — and a bare `::ffff:a.b.c.d` — landed in
// the V4 set. That is not benign misfiling: net.IPNet.Contains then folds the
// 16-byte network through To4() and slices the 16-byte mask to its TRAILING
// four bytes, so `::ffff:0:0/96` degrades to an IPv4 /0 matching EVERY IPv4
// address (measured: 8.8.8.8, 203.0.113.99, 10.0.0.1 all true), and a mapped
// `/120` aliases to the embedded IPv4 `/24`.
//
// The dataplane does the opposite. `parse_address` in
// userspace-dp/src/policy.rs does `prefix.parse::<IpNet>()`, and Rust's
// `Ipv4Addr::from_str` REJECTS a colon-bearing literal, so the arm taken is
// `Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net))`. PrefixV6
// compares unfolded u128s (prefix.rs). The box therefore matches ONLY
// mapped-form v6 destinations against such a rule and NEVER a plain IPv4 one.
//
// On a DENY that inverts the operator-visible answer in the dangerous
// direction: the simulator reported the rule covering all of IPv4 — a false
// sense of protection for traffic the box does not filter — while reporting no
// coverage for the mapped addresses the box actually denies.
//
// RED on revert: in addCIDRValue, change BOTH `addrValueFamily(val) == "v4"`
// tests back to `ipnet.IP.To4() != nil` and `ip.To4() != nil` respectively
// (restoring `ip4`/`ip` as the stored IP). Per-test accounting:
//
//	TestMappedIPv6PrefixDoesNotMatchPlainIPv4_6577    -> FAIL (assertion)
//	TestMappedIPv6PrefixMatchesMappedDestination_6577 -> FAIL (assertion)
//	TestBareMappedIPv6AddressClassifiedV6_6577        -> FAIL (assertion)
//	TestMappedLiteralsClassifiedV6_6577               -> FAIL (assertion)
//	TestAddressFamilyClassificationUnchanged_6577     -> PASS (over-reach guard)

// mappedPrefixCfg is a DENY scoped to a mapped-form destination prefix,
// followed by a permit-all. Both literals are DIRECT policy address tokens
// (not address-book entries), which is the path where Go and Rust are supposed
// to agree exactly: pkg/dataplane/userspace passes a direct literal through
// unchanged (classifyPolicyAddresses) and Rust's parse_address classifies it.
// `net.ParseCIDR` accepts the token at commit
// (policyMatchAddressTokenRecognized), so this config is reachable.
func mappedPrefixCfg(denyDst string) *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name:   "block-mapped-range",
					Match:  config.PolicyMatch{DestinationAddresses: []string{denyDst}},
					Action: config.PolicyDeny,
				},
				&config.Policy{
					Name:   "allow-rest",
					Match:  config.PolicyMatch{},
					Action: config.PolicyPermit,
				},
			),
		},
	}, config.ApplicationsConfig{})
}

// TestMappedIPv6PrefixDoesNotMatchPlainIPv4_6577 is the security-relevant
// direction: a `::ffff:0:0/96` DENY must NOT be reported as covering ordinary
// IPv4 traffic. The dataplane holds that literal as a PrefixV6, and a plain
// IPv4 packet is only ever tested against the v4 prefix set — which this rule
// contributes nothing to. A simulator that answers DENY here tells the operator
// their IPv4 traffic is filtered when the box forwards it.
func TestMappedIPv6PrefixDoesNotMatchPlainIPv4_6577(t *testing.T) {
	const denyDst = "::ffff:0:0/96"

	// Precondition: the fold this fix defends against is real. If ParseCIDR
	// ever stops folding, the premise changes and this test must be re-derived
	// rather than silently passing.
	_, ipnet, err := net.ParseCIDR(denyDst)
	if err != nil {
		t.Fatalf("precondition: ParseCIDR(%q) must succeed (it is accepted at commit): %v", denyDst, err)
	}
	if ipnet.IP.To4() == nil {
		t.Fatalf("precondition: ParseCIDR(%q).IP.To4() must be non-nil (the fold #6577 closes)", denyDst)
	}
	// And the fold really is catastrophic, not merely untidy: in the v4 bucket
	// this prefix matches an address that is nowhere near it.
	if !ipnet.Contains(net.ParseIP("203.0.113.99")) {
		t.Fatalf("precondition: a v4-filed %q must (wrongly) contain 203.0.113.99 — "+
			"that over-match is the bug being fixed", denyDst)
	}

	res := Match(mappedPrefixCfg(denyDst), Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("10.1.2.3"),
		DstIP:     net.ParseIP("203.0.113.99"),
		SrcFamily: "v4",
		DstFamily: "v4",
	})
	if res.Action != config.PolicyPermit || res.PolicyName != "allow-rest" {
		t.Fatalf("a %q DENY is a V6 prefix on the box (parse_address -> IpNet::V6) and can never "+
			"match a plain IPv4 destination; the simulator must not claim IPv4 coverage the "+
			"dataplane does not enforce. want permit via allow-rest, got %v via %q",
			denyDst, res.Action, res.PolicyName)
	}
}

// TestMappedIPv6PrefixMatchesMappedDestination_6577 is the other half of the
// same inversion, and promotes the former synthetic `::ffff:0:0/96` boundary
// row to a real policy-level case: the prefix now reaches the v6 set through
// resolveToken/addCIDRValue, so a mapped destination inside it must DENY,
// exactly as PrefixV6::contains does on the box.
func TestMappedIPv6PrefixMatchesMappedDestination_6577(t *testing.T) {
	const denyDst = "::ffff:0:0/96"
	const dstText = "::ffff:198.51.100.9"

	if got := config.NATAddrFamily(dstText); got != "v6" {
		t.Fatalf("config.NATAddrFamily(%q) = %q, want v6", dstText, got)
	}

	res := Match(mappedPrefixCfg(denyDst), Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("2001:db8::1"),
		DstIP:     net.ParseIP(dstText),
		SrcFamily: "v6",
		DstFamily: config.NATAddrFamily(dstText),
	})
	// #16803 supersedes the policy-attribution half at the Match level:
	// since #10686 the box drops the mapped destination at ingress before
	// policy, so Match reports the ingress drop rather than block-mapped-range.
	// The prefix-classification contract this file pins is unchanged
	// (resolveTokenFamilies below).
	if !res.V4MappedCompatIngressDrop || res.Action != config.PolicyDeny || res.PolicyName != "" {
		t.Fatalf("mapped dst %q must report the #10686 ingress drop (#16803), got %+v", dstText, res)
	}
}

// TestBareMappedIPv6AddressClassifiedV6_6577 covers the bare-IP branch of
// addCIDRValue, which had the identical defect: `::ffff:10.0.0.1` became a v4
// /32 while Rust's `Err(_)` arm parses it as an Ipv6Addr and stores a v6 /128.
// Both directions are asserted so a fix that merely moved the bucket without
// preserving matching would still be caught.
func TestBareMappedIPv6AddressClassifiedV6_6577(t *testing.T) {
	const denyDst = "::ffff:10.0.0.1"
	cfg := mappedPrefixCfg(denyDst)

	// The embedded IPv4 address must NOT inherit the deny.
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("10.1.2.3"),
		DstIP:     net.ParseIP("10.0.0.1"),
		SrcFamily: "v4",
		DstFamily: "v4",
	})
	if res.Action != config.PolicyPermit || res.PolicyName != "allow-rest" {
		t.Fatalf("a bare %q DENY is a v6 /128 on the box and must not shadow the embedded "+
			"IPv4 address; want permit via allow-rest, got %v via %q",
			denyDst, res.Action, res.PolicyName)
	}

	// The mapped form itself must.
	res = Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("2001:db8::1"),
		DstIP:     net.ParseIP(denyDst),
		SrcFamily: "v6",
		DstFamily: config.NATAddrFamily(denyDst),
	})
	// #16803: same ingress-drop supersession as above — the mapped
	// destination never reaches the bare v6 /128 deny at the Match level.
	if !res.V4MappedCompatIngressDrop || res.Action != config.PolicyDeny || res.PolicyName != "" {
		t.Fatalf("mapped destination %q must report the #10686 ingress drop (#16803), got %+v", denyDst, res)
	}
}

// resolveTokenFamilies runs a token through the REAL production construction
// path and reports which family sets it populated.
func resolveTokenFamilies(t *testing.T, tok string) (nV4, nV6 int, anyV4, anyV6 bool) {
	t.Helper()
	cfg := cfgWith(config.SecurityConfig{}, config.ApplicationsConfig{})
	v4nets, v6nets, a4, a6 := resolveToken(cfg, nil, tok)
	return len(v4nets), len(v6nets), a4, a6
}

// TestMappedLiteralsClassifiedV6_6577 pins the classification itself, through
// resolveToken/addCIDRValue rather than a hand-built net.IPNet — bypassing
// production construction is exactly how the prefix half of #6577 was missed.
// Every row here is a literal Rust classifies as V6.
func TestMappedLiteralsClassifiedV6_6577(t *testing.T) {
	for _, tok := range []string{
		"::ffff:0:0/96",       // the mapped range itself
		"::ffff:10.0.0.0/120", // aliased to the embedded 10.0.0.0/24 pre-fix
		"::ffff:203.0.113.9/128",
		"::ffff:10.0.0.1", // bare mapped address
	} {
		nV4, nV6, a4, a6 := resolveTokenFamilies(t, tok)
		if nV4 != 0 || nV6 != 1 || a4 || a6 {
			t.Errorf("resolveToken(%q) = v4:%d v6:%d anyV4:%v anyV6:%v; want v4:0 v6:1 — "+
				"Rust's parse_address takes the IpNet::V6 arm for every colon-bearing literal",
				tok, nV4, nV6, a4, a6)
		}
	}
}

// TestAddressFamilyClassificationUnchanged_6577 is the over-reach guard: the
// colon-strict switch must move ONLY the mapped forms. Every row below
// classified identically before the fix and must stay GREEN under the revert.
func TestAddressFamilyClassificationUnchanged_6577(t *testing.T) {
	cases := []struct {
		tok          string
		nV4, nV6     int
		anyV4, anyV6 bool
		why          string
	}{
		{"10.0.0.0/8", 1, 0, false, false, "ordinary v4 prefix"},
		{"10.0.1.0/24", 1, 0, false, false, "ordinary v4 prefix"},
		{"0.0.0.0/0", 1, 0, false, false, "v4 default route as a literal"},
		{"10.0.1.5", 1, 0, false, false, "bare dotted quad"},
		{"2001:db8::/32", 0, 1, false, false, "ordinary v6 prefix"},
		{"::/0", 0, 1, false, false, "v6 default route as a literal"},
		{"2001:db8::1", 0, 1, false, false, "bare genuine v6 address"},
		// Below /96 the masked network loses the ::ffff marker, so To4() was
		// already nil and these were ALREADY v6. Pinned so the fix is seen to
		// have moved nothing that was previously correct.
		{"::ffff:0:0/95", 0, 1, false, false, "mapped prefix shorter than /96 was already v6"},
		{"::ffff:0:0/0", 0, 1, false, false, "masks to :: — already v6"},
		{"any", 0, 0, true, true, "both-family wildcard"},
		{"any-ipv4", 0, 0, true, false, "v4 wildcard"},
		{"any4", 0, 0, true, false, "v4 wildcard alias"},
		{"any-ipv6", 0, 0, false, true, "v6 wildcard"},
		{"any6", 0, 0, false, true, "v6 wildcard alias"},
		{"", 0, 0, false, false, "empty token contributes nothing (#3261)"},
		{"not-an-address", 0, 0, false, false, "unparseable literal contributes nothing"},
	}
	for _, c := range cases {
		nV4, nV6, a4, a6 := resolveTokenFamilies(t, c.tok)
		if nV4 != c.nV4 || nV6 != c.nV6 || a4 != c.anyV4 || a6 != c.anyV6 {
			t.Errorf("resolveToken(%q) = v4:%d v6:%d anyV4:%v anyV6:%v; want v4:%d v6:%d anyV4:%v anyV6:%v — %s",
				c.tok, nV4, nV6, a4, a6, c.nV4, c.nV6, c.anyV4, c.anyV6, c.why)
		}
	}
}

// TestOrdinaryV4PolicyUnaffectedByPrefixFix_6577 is the end-to-end over-reach
// guard: an ordinary v4 policy must still match after the classification
// change. Stays GREEN under the revert.
func TestOrdinaryV4PolicyUnaffectedByPrefixFix_6577(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"trust-net": {Name: "trust-net", Value: "10.0.1.0/24"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "permit-trust-net",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"10.0.9.0/24"},
					DestinationAddresses: []string{"trust-net"},
				},
				Action: config.PolicyPermit,
			}),
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("10.0.9.9"),
		DstIP:     net.ParseIP("10.0.1.5"),
		SrcFamily: "v4",
		DstFamily: "v4",
	})
	if res.Action != config.PolicyPermit || res.PolicyName != "permit-trust-net" {
		t.Fatalf("ordinary v4 matching (literal source + book destination) must be unchanged; "+
			"got %v via %q", res.Action, res.PolicyName)
	}
}
