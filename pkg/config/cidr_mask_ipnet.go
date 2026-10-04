package config

import (
	"net"
	"strings"
)

// CIDRMaskHasRedundantLeadingZero reports whether cidr has a valid Go CIDR
// spelling whose prefix mask contains redundant leading-zero digits. Policy
// address literals and address-book prefixes use canonical decimal masks so
// their authored spelling is handled consistently by every userspace parser.
func CIDRMaskHasRedundantLeadingZero(cidr string) bool {
	slash := strings.LastIndexByte(cidr, '/')
	if slash < 0 {
		return false
	}
	mask := cidr[slash+1:]
	if len(mask) <= 1 || mask[0] != '0' {
		return false
	}
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}
