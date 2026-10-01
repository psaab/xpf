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

// hostInboundAmbiguousIngressNetdevs returns the builder's single, sorted list
// of effective netdevs claimed by multiple zone views. The builder attaches
// this list to one view only, rather than duplicating its global guard.
func hostInboundAmbiguousIngressNetdevs(views []dpuserspace.ZoneHostInboundView) []string {
	for _, v := range views {
		if len(v.IngressDenyNetdevs) > 0 {
			return v.IngressDenyNetdevs
		}
	}
	return nil
}

func hostInboundEmitsAmbiguousIngressDrop(views []dpuserspace.ZoneHostInboundView, dests []string) bool {
	return len(hostInboundAmbiguousIngressNetdevs(views)) > 0 && len(dests) > 0
}

// emitHostInboundZoneIngress emits the #9637 ingress-zone rules for one view
// and family. Normal rules use the view's service and protocol matches, its
// per-zone deny counter, and EVERY judged local address, not only the view's
// own. Ambiguous netdevs are handled separately after their address-owner
// service admits.
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

// emitHostInboundAmbiguousIngressAccepts applies each address owner's rights
// to packets arriving on an ambiguous effective netdev. The destination address
// is the only remaining zone discriminator, so these scoped accepts precede
// the counted ambiguous catch-all drop.
func emitHostInboundAmbiguousIngressAccepts(rules *[]string, views []dpuserspace.ZoneHostInboundView, family string, wgZonePorts map[string][]uint16) {
	netdevs := hostInboundAmbiguousIngressNetdevs(views)
	if len(netdevs) == 0 {
		return
	}
	for _, v := range views {
		addrs := v.V4Addrs
		if family == "ip6" {
			addrs = v.V6Addrs
		}
		if len(addrs) == 0 {
			continue
		}
		scope := "iifname " + nftIifnameSet(netdevs) + " " + family + " daddr " + nftAddrSet(addrs)
		if hostInboundAllowsAll(v) {
			*rules = append(*rules, "    "+scope+" accept")
			continue
		}
		for _, m := range hostInboundMatchSet(v, family) {
			*rules = append(*rules, "    "+scope+" "+m.match+" "+m.action)
		}
		emitHostInboundZoneWireGuardAccept(rules, scope, wgZonePorts[v.Zone])
	}
}

// emitHostInboundAmbiguousIngressDrop fails closed for unmatched traffic on an
// ambiguous effective netdev. The junos-host counter is shared with unzoned
// drops because neither case has a uniquely attributable source zone.
func emitHostInboundAmbiguousIngressDrop(rules *[]string, views []dpuserspace.ZoneHostInboundView, family string, dests []string) {
	netdevs := hostInboundAmbiguousIngressNetdevs(views)
	if len(netdevs) == 0 || len(dests) == 0 {
		return
	}
	cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
	scope := "iifname " + nftIifnameSet(netdevs) + " " + family + " daddr " + nftAddrSet(dests)
	*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
}
