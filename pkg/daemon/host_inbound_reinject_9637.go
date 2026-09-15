package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInboundReinjectDestinations returns, per family, the VIEW (zoned)
// firewall-local addresses the #9637-residual reinject accept admits to:
// each view's addresses, first-seen order, no duplicates. Unzoned addresses
// are EXCLUDED by construction — the #4420 catch-all DROP must keep judging
// unzoned-dst reinjects exactly as today, which is why the accept is
// views-scoped rather than blanket (plan v5 §5.1).
func hostInboundReinjectDestinations(views []dpuserspace.ZoneHostInboundView) (v4, v6 []string) {
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
	return v4, v6
}

// emitHostInboundReinjectAccept appends the #9637-residual reinject exemption
// for one family: packets the userspace dataplane adjudicated through a
// LocalDelivery host-inbound gate (hit/miss/flowless) and reinjected through
// the adjudicated slow-path TUN are accepted to view addresses without
// re-judging them by the address owner. Placed after the global accepts and
// the junos-host program jumps and before the #9637 ingress-zone rules, in
// BOTH chain shapes. The destination-only fallback rules, unzoned drops,
// lifeline subtraction, RETH VIP sets, and fences are untouched: any packet
// not arriving on the TUN, and any TUN packet naming a non-view address, is
// judged exactly as today.
//
// The accept admits ONLY userspace-gated reinjects (trusted TUN): the old
// D2/D3/D4/NAT-T delegation paths ride the delegated TUN and meet the
// destination rules exactly as pre-#9637 (operator narrowing — no flips, no
// sign-off). D1 freshness is closed pre-landing by the dataplaneFresh gate
// (the caller omits this rule when the dataplane does not run this
// generation's snapshot, including cancellation-closeout renders).
func emitHostInboundReinjectAccept(rules *[]string, family string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	cn := xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptReinject)
	*rules = append(*rules, "    iifname \""+xnft.HostInboundReinjectIfname+"\" "+family+" daddr "+nftAddrSet(addrs)+" counter name \""+cn+"\" accept")
}
