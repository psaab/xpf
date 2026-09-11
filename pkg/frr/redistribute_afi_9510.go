package frr

import "github.com/psaab/xpf/pkg/config"

// #9510: FRR's `redistribute` grammar is per ADDRESS FAMILY. A source keyword
// the enclosing node's grammar does not list is rejected at parse, exactly like
// a typo, not accepted and ignored. `from protocol ospf6` committed clean and
// rendered `redistribute ospf6 route-map X` under `router ospf`.
//
// The two tables transcribe FRR stable/10.6:
//
//   - frrRedistSourceAFI is lib/route_types.txt's ipv4/ipv6 columns for every
//     keyword config.FRRRoutingProtocolKeyword can produce.
//   - frrRedistNodeAFI is the family of the redistribute grammar installed at
//     the node each generateProtocols call site writes the line into.
//     lib/route_types.pl builds a daemon's source list with
//     collect($daemon, ipv4, ipv6), which keeps a source only when
//     (ipv4 && source.ipv4) || (ipv6 && source.ipv6).
//
// The BGP row is the one that is easy to get wrong. bgpd is dual-stack, but a
// bare-token export is written directly under `router bgp` (BGP_NODE), and
// bgpd/bgp_vty.c installs only the *_ipv4_hidden redistribute commands there,
// built from FRR_IP_REDIST_STR_BGPD. The IPv6 grammar is installed only under
// `address-family ipv6 unicast` (BGP_IPV6_NODE), so `redistribute ospf6` under
// `router bgp` is rejected the same way it is under `router ospf`. Since #9667
// the BGP renderer writes a bare token's IPv6 routes into that address family,
// through the "bgp-ipv6" node row.
type redistAFI uint8

const (
	afiV4 redistAFI = 1 << iota
	afiV6
	afiBoth = afiV4 | afiV6
)

// frrRedistSourceAFI is derived from config's family table (#9667), which the
// strict commit gate reads too, so the gate and this filter cannot disagree.
var frrRedistSourceAFI = func() map[string]redistAFI {
	out := make(map[string]redistAFI)
	for _, kw := range config.RedistributionSourceKeywords() {
		fam, _ := config.RedistributionSourceFamilies(kw)
		var a redistAFI
		if fam&config.FamilyIPv4 != 0 {
			a |= afiV4
		}
		if fam&config.FamilyIPv6 != 0 {
			a |= afiV6
		}
		out[kw] = a
	}
	return out
}()

var frrRedistNodeAFI = map[string]redistAFI{
	"ospf":  afiV4, // ospfd: FRR_REDIST_STR_OSPFD
	"ospf6": afiV6, // ospf6d: FRR_REDIST_STR_OSPF6D
	"rip":   afiV4, // ripd: FRR_REDIST_STR_RIPD
	"bgp":   afiV4, // BGP_NODE: FRR_IP_REDIST_STR_BGPD only, see above
	// BGP_IPV6_NODE, `address-family ipv6 unicast`: FRR_IP6_REDIST_STR_BGPD.
	// Written by resolveBGPIPv6Redistribute (#9667).
	"bgp-ipv6": afiV6,
	"isis":     afiBoth,
}

// redistSourceFitsNode reports whether the redistribute grammar at the router
// named by self lists source.
//
// It narrows only what the tables prove FRR rejects. self "" (no enclosing
// router, the unit-test shape) and a source outside the table pass through
// unchanged. redistribute_afi_9510_test.go binds both tables, to every call
// site's self literal and to the whole keyword domain, so neither can fall out
// of coverage silently.
func redistSourceFitsNode(source, self string) bool {
	node, ok := frrRedistNodeAFI[self]
	if !ok {
		return true
	}
	src, ok := frrRedistSourceAFI[source]
	if !ok {
		return true
	}
	return node&src != 0
}
