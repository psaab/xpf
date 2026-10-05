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

func hostInboundWGGuardEmits(addrs []string, listenPorts []uint16) bool {
	return len(addrs) > 0 && len(listenPorts) > 0
}

func hostInboundWGAddressesForFamily(v HostInboundZoneView, f nlFamily) []string {
	if f == famV6 {
		return v.V6Addrs
	}
	return v.V4Addrs
}

func hostInboundWGZoneAddresses(views []HostInboundZoneView, f nlFamily) (zones []string, addresses map[string][]string, ambiguous []string) {
	owners := make(map[string]string)
	ambiguousSet := make(map[string]bool)
	for _, view := range views {
		for _, addr := range hostInboundWGAddressesForFamily(view, f) {
			if owner, ok := owners[addr]; ok && owner != view.Zone {
				ambiguousSet[addr] = true
				continue
			}
			owners[addr] = view.Zone
		}
	}
	addresses = make(map[string][]string)
	seenZones, seenAmbiguous := map[string]bool{}, map[string]bool{}
	seenAddrs := make(map[string]map[string]bool)
	for _, view := range views {
		for _, addr := range hostInboundWGAddressesForFamily(view, f) {
			if ambiguousSet[addr] {
				if !seenAmbiguous[addr] {
					ambiguous = append(ambiguous, addr)
					seenAmbiguous[addr] = true
				}
				continue
			}
			if owners[addr] != view.Zone {
				continue
			}
			if !seenZones[view.Zone] {
				zones = append(zones, view.Zone)
				seenZones[view.Zone] = true
			}
			if seenAddrs[view.Zone] == nil {
				seenAddrs[view.Zone] = make(map[string]bool)
			}
			if !seenAddrs[view.Zone][addr] {
				addresses[view.Zone] = append(addresses[view.Zone], addr)
				seenAddrs[view.Zone][addr] = true
			}
		}
	}
	return zones, addresses, ambiguous
}

func hostInboundWGZoneIngress(views []HostInboundZoneView) map[string][]string {
	ingress := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for _, view := range views {
		if seen[view.Zone] == nil {
			seen[view.Zone] = make(map[string]bool)
		}
		for _, device := range view.IngressNetdevs {
			if !seen[view.Zone][device] {
				ingress[view.Zone] = append(ingress[view.Zone], device)
				seen[view.Zone][device] = true
			}
		}
	}
	return ingress
}

func hostInboundWGIntersectPorts(ports, listenPorts []uint16) []uint16 {
	allowed := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		allowed[port] = true
	}
	var out []uint16
	for _, port := range listenPorts {
		if allowed[port] {
			out = append(out, port)
		}
	}
	return out
}

func hostInboundWGSubtractPorts(listenPorts, allowedPorts []uint16) []uint16 {
	allowed := make(map[uint16]bool, len(allowedPorts))
	for _, port := range allowedPorts {
		allowed[port] = true
	}
	var out []uint16
	for _, port := range listenPorts {
		if !allowed[port] {
			out = append(out, port)
		}
	}
	return out
}

func hostInboundWGAmbiguousAddresses(views []HostInboundZoneView, f nlFamily) []string {
	_, _, ambiguous := hostInboundWGZoneAddresses(views, f)
	return ambiguous
}

func emitHostInboundWireGuardMismatchDropsNetlink(p *nlPlan, views []HostInboundZoneView, unzoned []string, f nlFamily, listenPorts []uint16, zonePorts map[string][]uint16) {
	if len(listenPorts) == 0 {
		return
	}
	zones, addresses, ambiguous := hostInboundWGZoneAddresses(views, f)
	ingress := hostInboundWGZoneIngress(views)
	for _, zone := range zones {
		allowed := hostInboundWGIntersectPorts(zonePorts[zone], listenPorts)
		cn := HostInboundDenyCounterName(zone, familyToken(f))
		if len(allowed) == 0 || len(ingress[zone]) == 0 {
			p.rule().daddr(f, addresses[zone], false).
				l4Port(protoUDP, "dport", portsFromUint16(listenPorts), false).
				counterRef(cn).emit(verdictDrop()...)
			continue
		}
		if disallowed := hostInboundWGSubtractPorts(listenPorts, allowed); len(disallowed) > 0 {
			p.rule().daddr(f, addresses[zone], false).
				l4Port(protoUDP, "dport", portsFromUint16(disallowed), false).
				counterRef(cn).emit(verdictDrop()...)
		}
		p.rule().iifnameExcept(ingress[zone]).daddr(f, addresses[zone], false).
			l4Port(protoUDP, "dport", portsFromUint16(allowed), false).
			counterRef(cn).emit(verdictDrop()...)
	}
	sentinel := HostInboundDenyCounterName(unzonedHostInboundZoneLabel, familyToken(f))
	if len(ambiguous) > 0 {
		p.rule().daddr(f, ambiguous, false).
			l4Port(protoUDP, "dport", portsFromUint16(listenPorts), false).
			counterRef(sentinel).emit(verdictDrop()...)
	}
	if len(unzoned) > 0 {
		p.rule().daddr(f, unzoned, false).
			l4Port(protoUDP, "dport", portsFromUint16(listenPorts), false).
			counterRef(sentinel).emit(verdictDrop()...)
	}
}

// emitHostInboundWireGuardIngressNetlink emits only the exact selected-port
// accepts after earlier mismatch drops and broad reply admits.
func emitHostInboundWireGuardIngressNetlink(p *nlPlan, views []HostInboundZoneView, f nlFamily, listenPorts []uint16, zonePorts map[string][]uint16) {
	if len(listenPorts) == 0 {
		return
	}
	zones, addresses, _ := hostInboundWGZoneAddresses(views, f)
	ingress := hostInboundWGZoneIngress(views)
	for _, zone := range zones {
		ports := hostInboundWGIntersectPorts(zonePorts[zone], listenPorts)
		if len(ports) == 0 || len(ingress[zone]) == 0 || len(addresses[zone]) == 0 {
			continue
		}
		p.rule().iifname(ingress[zone]).daddr(f, addresses[zone], false).
			l4Port(protoUDP, "dport", portsFromUint16(ports), false).
			emit(verdictAccept()...)
	}
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
// owner's host services to packets arriving on an ambiguous effective netdev.
// WireGuard is deliberately absent because its ingress cannot be established.
func emitHostInboundAmbiguousIngressAcceptsNetlink(p *nlPlan, views []HostInboundZoneView, f nlFamily) {
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
