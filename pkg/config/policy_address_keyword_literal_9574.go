package config

// PolicyAddressWildcardFamilies reports which address families a policy
// match-all keyword covers, and whether tok is one at all (#9523, #9574). It is
// the single source for the keyword set: IsPolicyAddressWildcardKeyword, the
// userspace snapshot builder and the match-policies simulator all ask it, so a
// keyword cannot be recognised on one surface and not on another.
//
//	any              both families
//	any-ipv4, any4   IPv4 only
//	any-ipv6, any6   IPv6 only
func PolicyAddressWildcardFamilies(tok string) (v4, v6, ok bool) {
	switch tok {
	case "any":
		return true, true, true
	case "any-ipv4", "any4":
		return true, false, true
	case "any-ipv6", "any6":
		return false, true, true
	}
	return false, false, false
}

// PolicyAddressKeywordLiteral returns the literal the userspace wire carries
// for a policy address token: `0.0.0.0/0` for an IPv4-only keyword, `::/0` for an
// IPv6-only keyword, and tok unchanged otherwise (including `any`, which every
// dataplane parser reads as both families).
//
// #9574: this rewrite used to run in compilePolicy (normalizePolicyAddrToken,
// #2008 H11), BEFORE any address-book resolution. The compiled token was
// therefore already `0.0.0.0/0`, and name-before-literal resolution let an
// address-book object NAMED `0.0.0.0/0` — a legal name in Junos and in xpf —
// capture every `any-ipv4` in every policy. The compiled config now keeps the
// keyword; every resolver classifies it as a keyword before any name lookup;
// and only the snapshot builder turns it into the CIDR the dataplane parses, so
// the wire is byte-identical to before for every config without such an object.
// The #2008 H11 reason for the rewrite (the dataplane must receive a parseable
// CIDR) still holds; only its position moved.
func PolicyAddressKeywordLiteral(tok string) string {
	v4, v6, ok := PolicyAddressWildcardFamilies(tok)
	switch {
	case !ok || (v4 && v6):
		return tok
	case v4:
		return "0.0.0.0/0"
	default:
		return "::/0"
	}
}
