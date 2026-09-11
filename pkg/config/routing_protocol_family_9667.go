package config

import "sort"

// #9667: which address families a routing protocol's routes carry, and which
// families an export use site can redistribute into.
//
// FRR's redistribute grammar is per family (lib/route_types.txt lists each
// source for ipv4, ipv6 or both). pkg/frr filters what it renders by these
// families (#9510), and the strict commit gate refuses a bare export token
// whose family its use site cannot carry. Both read this one table, so the gate
// and the renderer cannot disagree about a keyword's family.

// ProtocolFamilies is a set of address families.
type ProtocolFamilies uint8

const (
	FamilyIPv4 ProtocolFamilies = 1 << iota
	FamilyIPv6
	FamilyBoth = FamilyIPv4 | FamilyIPv6
)

func (f ProtocolFamilies) String() string {
	switch f {
	case FamilyIPv4:
		return "IPv4"
	case FamilyIPv6:
		return "IPv6"
	case FamilyBoth:
		return "IPv4 and IPv6"
	}
	return "no"
}

// redistributionSourceFamilies is keyed by the FRR keyword that
// FRRRoutingProtocolKeyword returns (FRR stable/10.6 lib/route_types.txt).
var redistributionSourceFamilies = map[string]ProtocolFamilies{
	"kernel":    FamilyBoth,
	"connected": FamilyBoth,
	"static":    FamilyBoth,
	"rip":       FamilyIPv4,
	"ripng":     FamilyIPv6,
	"ospf":      FamilyIPv4,
	"ospf6":     FamilyIPv6,
	"isis":      FamilyBoth,
	"bgp":       FamilyBoth,
}

// RedistributionSourceFamilies returns the families the FRR keyword kw carries.
func RedistributionSourceFamilies(kw string) (ProtocolFamilies, bool) {
	f, ok := redistributionSourceFamilies[kw]
	return f, ok
}

// RedistributionSourceKeywords returns every keyword with a family row, sorted.
func RedistributionSourceKeywords() []string {
	out := make([]string, 0, len(redistributionSourceFamilies))
	for kw := range redistributionSourceFamilies {
		out = append(out, kw)
	}
	sort.Strings(out)
	return out
}

// exportUseSiteFamilies is the set of families each redistribute-backed export
// use site can carry. BGP carries both: pkg/frr renders a bare token's IPv4
// routes under `router bgp` and its IPv6 routes under `address-family ipv6
// unicast` (#9667). OSPFv2 and RIP are IPv4-only, OSPFv3 is IPv6-only, and
// IS-IS carries both.
var exportUseSiteFamilies = map[string]ProtocolFamilies{
	"protocols ospf":  FamilyIPv4,
	"protocols ospf3": FamilyIPv6,
	"protocols rip":   FamilyIPv4,
	"protocols isis":  FamilyBoth,
	"protocols bgp":   FamilyBoth,
}
