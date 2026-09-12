package nftables

// hostInboundIngressDestinations mirrors the daemon oracle's helper of the same
// name: every judged firewall-local address per family (each view's, then the
// unzoned ones), first-seen order, no duplicates (#9637).
func hostInboundIngressDestinations(views []HostInboundZoneView, unzonedV4, unzonedV6 []string) (v4, v6 []string) {
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

// hostInboundEmitsIngressDrop mirrors the oracle's predicate: the ingress-zone
// rules for a family end in a catch-all drop.
func hostInboundEmitsIngressDrop(v HostInboundZoneView, dests []string) bool {
	return len(v.IngressNetdevs) > 0 && hostInboundEmitsDrop(v, dests)
}

// emitHostInboundZoneIngressNetlink mirrors emitHostInboundZoneIngress (#9637):
// the view's matches, scoped to its ingress netdevs and every judged address.
func emitHostInboundZoneIngressNetlink(p *nlPlan, v HostInboundZoneView, f nlFamily, dests []string) {
	if len(v.IngressNetdevs) == 0 || len(dests) == 0 {
		return
	}
	scoped := func() *ruleAsm { return p.rule().iifname(v.IngressNetdevs).daddr(f, dests, false) }
	if hostInboundAllowsAll(v) {
		scoped().emit(verdictAccept()...)
		return
	}
	for _, frag := range hostInboundMatchFragments(v, f) {
		a := scoped()
		frag.build(a)
		if frag.reject {
			a.emit(rejectTCPReset()...)
		} else {
			a.emit(verdictAccept()...)
		}
	}
	cn := HostInboundDenyCounterName(v.Zone, familyToken(f))
	scoped().counterRef(cn).emit(verdictDrop()...)
}
