package config

import (
	"net"
	"strings"
)

// CIDRMaskHasRedundantLeadingZero reports whether cidr has a valid Go CIDR
// spelling whose prefix mask has redundant leading-zero digits that the
// pinned userspace helper (ipnet 2.12.0) cannot parse.
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
func CIDRMaskHasRedundantLeadingZero(cidr string) bool {
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
