package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInboundIngressDestinations returns, per family, every firewall-local
// address the host-inbound chain judges: each view's addresses, then the
// addressed-but-unzoned ones (#4420), first-seen order, no duplicates. It is the
// destination set of the #9637 ingress-zone rules, which judge a packet by the
// zone it arrived on whichever of these addresses it names.
func hostInboundIngressDestinations(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string) (v4, v6 []string) {
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	add := func(out *[]string, seen map[string]bool, addrs []string) {
		for _, a := range addrs {
			if !seen[a] {
				seen[a] = true
				*out = append(*out, a)
			}
		}
	}
	for _, v := range views {
		add(&v4, seen4, v.V4Addrs)
		add(&v6, seen6, v.V6Addrs)
	}
	add(&v4, seen4, unzonedV4)
	add(&v6, seen6, unzonedV6)
	return v4, v6
}

// hostInboundEmitsIngressDrop reports whether emitHostInboundZoneIngress emits a
// catch-all drop for the view in a family. The counter pre-pass consults it, so
// the chain never references a counter the table did not declare.
func hostInboundEmitsIngressDrop(v dpuserspace.ZoneHostInboundView, dests []string) bool {
	return len(v.IngressNetdevs) > 0 && hostInboundEmitsDrop(v, dests)
}

// emitHostInboundZoneIngress emits the #9637 ingress-zone rules for one view and
// family. The rules use the view's own service and protocol matches, and its
// per-zone deny counter. Each rule is scoped to the view's ingress netdevs and
// to EVERY judged local address, not only the view's own.
//
// Junos admits host-inbound traffic by the zone of the interface it arrives on.
// The destination-address rules alone judged a packet by the zone that owns the
// address it names. A client on a zone that denies ssh could therefore reach ssh
// on another zone's address, and a zone that admits ssh was refused on another
// zone's address. #9637 measured the refusal on the loss cluster.
func emitHostInboundZoneIngress(rules *[]string, v dpuserspace.ZoneHostInboundView, family string, dests []string) {
	if len(v.IngressNetdevs) == 0 || len(dests) == 0 {
		return
	}
	scope := "iifname " + nftIifnameSet(v.IngressNetdevs) + " " + family + " daddr " + nftAddrSet(dests)
	if hostInboundAllowsAll(v) {
		*rules = append(*rules, "    "+scope+" accept")
		return
	}
	for _, m := range hostInboundMatchSet(v, family) {
		*rules = append(*rules, "    "+scope+" "+m.match+" "+m.action)
	}
	cn := xnft.HostInboundDenyCounterName(v.Zone, family)
	*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
}
