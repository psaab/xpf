package nftables

// hostInboundIngressDestinations mirrors the daemon oracle's helper of the same
// name: every judged firewall-local address per family (each view's, then the
// unzoned ones), first-seen order, no duplicates (#9637). It feeds the unzoned
// and ambiguous guards; ordinary zone-ingress rules use only zone-owned
// destinations.
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

func hostInboundZoneIngressDestinations(views []HostInboundZoneView) (v4, v6 []string) {
	return hostInboundIngressDestinations(views, nil, nil)
}

// hostInboundEmitsIngressDrop mirrors the oracle's predicate: the ingress-zone
// rules for a family end in a catch-all drop.
func hostInboundEmitsIngressDrop(v HostInboundZoneView, dests []string) bool {
	return len(v.IngressNetdevs) > 0 && hostInboundEmitsDrop(v, dests)
}

// hostInboundAmbiguousIngressNetdevs returns the builder's single, sorted list
// of effective netdevs claimed by multiple zone views. The builder attaches
// this list to one view only, rather than duplicating its global guard.
func hostInboundAmbiguousIngressNetdevs(views []HostInboundZoneView) []string {
	for _, v := range views {
		if len(v.IngressDenyNetdevs) > 0 {
			return v.IngressDenyNetdevs
		}
	}
	return nil
}

func hostInboundEmitsAmbiguousIngressDrop(views []HostInboundZoneView, dests []string) bool {
	return len(hostInboundAmbiguousIngressNetdevs(views)) > 0 && len(dests) > 0
}

func hostInboundEmitsUnzonedIngressDrop(netdevs, dests []string) bool {
	return len(netdevs) > 0 && len(dests) > 0
}

// emitHostInboundZoneIngressNetlink mirrors the daemon oracle: normal view
// matches are scoped to ingress netdevs and every zone-owned destination.
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

// emitHostInboundAmbiguousIngressAcceptsNetlink applies each destination
// owner's rights to packets arriving on an ambiguous effective netdev. The
// destination is the only remaining zone discriminator, so these accepts
// precede the counted ambiguous catch-all drop.
func emitHostInboundAmbiguousIngressAcceptsNetlink(p *nlPlan, views []HostInboundZoneView, f nlFamily, wgZonePorts map[string][]uint16) {
	netdevs := hostInboundAmbiguousIngressNetdevs(views)
	if len(netdevs) == 0 {
		return
	}
	for _, v := range views {
		addrs := v.V4Addrs
		if f == famV6 {
			addrs = v.V6Addrs
		}
		if len(addrs) == 0 {
			continue
		}
		if hostInboundAllowsAll(v) {
			p.rule().iifname(netdevs).daddr(f, addrs, false).emit(verdictAccept()...)
			continue
		}
		for _, frag := range hostInboundMatchFragments(v, f) {
			a := p.rule().iifname(netdevs).daddr(f, addrs, false)
			frag.build(a)
			if frag.reject {
				a.emit(rejectTCPReset()...)
			} else {
				a.emit(verdictAccept()...)
			}
		}
		if ports := wgZonePorts[v.Zone]; len(ports) > 0 {
			p.rule().iifname(netdevs).daddr(f, addrs, false).
				l4Port(protoUDP, "dport", portsFromUint16(ports), false).
				emit(verdictAccept()...)
		}
	}
}

// emitHostInboundAmbiguousIngressDropNetlink fails closed for unmatched
// traffic on an ambiguous effective netdev. The junos-host counter is shared
// with unzoned drops because neither case has a uniquely attributable zone.
func emitHostInboundAmbiguousIngressDropNetlink(p *nlPlan, views []HostInboundZoneView, f nlFamily, dests []string) {
	netdevs := hostInboundAmbiguousIngressNetdevs(views)
	if len(netdevs) == 0 || len(dests) == 0 {
		return
	}
	cn := HostInboundDenyCounterName(unzonedHostInboundZoneLabel, familyToken(f))
	p.rule().iifname(netdevs).daddr(f, dests, false).counterRef(cn).emit(verdictDrop()...)
}

// emitHostInboundUnzonedIngressDropNetlink denies configured unzoned physical
// ingress before the residual established accept and destination-only fallback.
func emitHostInboundUnzonedIngressDropNetlink(p *nlPlan, netdevs []string, f nlFamily, dests []string) {
	if !hostInboundEmitsUnzonedIngressDrop(netdevs, dests) {
		return
	}
	cn := HostInboundDenyCounterName(unzonedHostInboundZoneLabel, familyToken(f))
	p.rule().iifname(netdevs).daddr(f, dests, false).counterRef(cn).emit(verdictDrop()...)
}

// emitHostInboundUnzonedVRFIngressDropNetlink matches an unzoned VRF slave
// before any zone policy scoped to the shared LOCAL_IN master.
func emitHostInboundUnzonedVRFIngressDropNetlink(p *nlPlan, slaves []string, f nlFamily, dests []string) {
	if !hostInboundEmitsUnzonedIngressDrop(slaves, dests) {
		return
	}
	cn := HostInboundDenyCounterName(unzonedHostInboundZoneLabel, familyToken(f))
	p.rule().sdifname(slaves).daddr(f, dests, false).counterRef(cn).emit(verdictDrop()...)
}
