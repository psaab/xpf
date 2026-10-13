package config

import (
	"net"
	"strings"
)

// CIDRMaskHelperRefusesPadding reports whether cidr is a valid Go CIDR whose
// zero-padded prefix mask the pinned userspace helper (ipnet 2.12.0) cannot
// parse, so strict commit and the publication mirror must refuse it.
//
// The predicate is deliberately narrower than "any zero-padded mask" (#12178):
// ipnet reads the v4 mask with read_number(10, 2, 33) and the v6 mask with
// read_number(10, 3, 129), so it accepts "10.0.0.0/08" and "2001:db8::/032"
// (and "/064") while refusing "10.0.0.0/008" and "2001:db8::/0064". Those
// accepted spellings are unambiguous and installed by the helper before
// #12047, so refusing them bricks the operator's next commit after upgrade
// (#1960/#7481 no-brick reasoning). Reject only spellings the helper itself
// drops. Determine the family from the address text, as the helper does:
// IPv4-mapped IPv6 literals are parsed as IPv6 by ipnet even though Go's
// address-book snapshot builder files them as IPv4 (#10688).
//
// The name states the verdict, not the spelling: a leading zero in "/08" is
// not refused by the helper. Consumers that accept such a mask must normalize
// it before passing it to stricter parsers such as netip.ParsePrefix (#12178).
func CIDRMaskHelperRefusesPadding(cidr string) bool {
	slash := strings.LastIndexByte(cidr, '/')
	if slash < 0 {
		return false
	}
	mask := cidr[slash+1:]
	if len(mask) <= 1 || mask[0] != '0' {
		return false
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return false
	}
	// Mirror ipnet's maximum mask digit count; net.ParseCIDR above supplies
	// the matching family-specific range check.
	maxDigits := 2
	if strings.Contains(cidr[:slash], ":") {
		maxDigits = 3
	}
	return len(mask) > maxDigits
}

// normalizeCIDRMaskPadding removes only leading zeros from a CIDR mask. It
// leaves signs, whitespace, and all other syntax untouched so the caller's
// parser still decides whether the rest of the token is valid.
func normalizeCIDRMaskPadding(cidr string) string {
	slash := strings.LastIndexByte(cidr, '/')
	if slash < 0 {
		return cidr
	}
	mask := cidr[slash+1:]
	for len(mask) > 1 && mask[0] == '0' {
		mask = mask[1:]
	}
	if len(mask) == len(cidr)-slash-1 {
		return cidr
	}
	return cidr[:slash+1] + mask
}

// normalizeHelperSupportedCIDRMaskPadding writes the mask of a valid Go CIDR
// without leading zeros when the userspace helper also parses its padding
// ("10.0.0.0/08" -> "10.0.0.0/8", "2001:db8::/032" -> "2001:db8::/32"). Every
// other value is returned unchanged: helper-refused padding stays visible to the
// strict gates and to the fail-closed publication path (#12507), and ranges,
// bare hosts, identities and malformed tokens keep the operator's text for their
// own validators.
//
// The compiler applies it to static-route destinations and IPsec selector
// values. Their netip-based consumers — the FRR render belt, FRRAddrFamily in
// the #9820/#11421 family gate, the #11380/#11422 selector models — refuse every
// padded mask, so a helper-supported padded value used to reach the userspace
// helper but not FRR or those gates.
func normalizeHelperSupportedCIDRMaskPadding(cidr string) string {
	normalized := normalizeCIDRMaskPadding(cidr)
	if normalized == cidr {
		return cidr // no padded mask: skip the parse
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil || CIDRMaskHelperRefusesPadding(cidr) {
		return cidr
	}
	return normalized
}
