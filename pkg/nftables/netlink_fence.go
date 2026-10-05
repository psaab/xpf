package nftables

// netlink_fence.go builds the #5644 cold-boot fail-closed fence and the #5789
// additive coverage-gap fence via netlink, mirroring the text oracles in
// pkg/daemon/daemon_nft.go. The cold-boot fence removes per-service ACCEPTs and
// drops catalog multicast groups on represented ingress before established
// admits. Persistent DHCP backstops classify FIB-local and anycast destinations
// plus the VRF-slave IPv6 link-local fallback; the additive gap fence applies
// the same predicates while preserving retained main-table and multicast policy.

// hostInboundFenceMandatoryAdmitsNetlink mirrors the text oracle's shared
// mandatory admits: global ESP/AH, established/related, IPv6 ND, and v4/v6
// PMTUD/error. Cold-boot multicast drops are inserted between ESP/AH and the
// established-flow admit. WireGuard admissions have serving-zone scope; no
// named counters are added to the transient fence.
func hostInboundFenceMandatoryAdmitsNetlink(p *nlPlan) {
	p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
	emitHostInboundFenceEstablishedAndL3AdmitsNetlink(p)
}

func emitHostInboundFenceEstablishedAndL3AdmitsNetlink(p *nlPlan) {
	p.rule().ctEstablishedRelated().emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{1, 2, 3, 4}).emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{133, 134, 135, 136, 137}).emit(verdictAccept()...)
	p.rule().icmpType(famV4, []uint8{3, 11, 12}).emit(verdictAccept()...)
}

// emitHostInboundFenceWGAdmitsNetlink scopes the fence exception to a unique
// destination owner and the matching transport-zone ingress.
func emitHostInboundFenceWGAdmitsNetlink(p *nlPlan, views []HostInboundZoneView, wgZonePorts map[string][]uint16) {
	for _, v := range views {
		ports := wgZonePorts[v.Zone]
		emitFenceWGIngressAcceptNetlink(p, views, v, famV4, v.V4Addrs, ports)
		emitFenceWGIngressAcceptNetlink(p, views, v, famV6, v.V6Addrs, ports)
	}
}

func emitFenceWGIngressAcceptNetlink(p *nlPlan, views []HostInboundZoneView, view HostInboundZoneView, f nlFamily, candidates []string, ports []uint16) {
	ingress := HostInboundWGIngressByZone(views)[view.Zone]
	if len(ingress.IIFNames()) == 0 || len(candidates) == 0 || len(ports) == 0 {
		return
	}
	addrs := uniqueFenceWGAddresses(views, view.Zone, f, candidates)
	emitHostInboundWGIngressAcceptNetlink(p, ingress, f, addrs, ports)
}

func uniqueFenceWGAddresses(views []HostInboundZoneView, zone string, f nlFamily, candidates []string) []string {
	owners := make(map[string]string)
	ambiguous := make(map[string]bool)
	for _, v := range views {
		addrs := v.V4Addrs
		if f == famV6 {
			addrs = v.V6Addrs
		}
		for _, addr := range addrs {
			if owner, ok := owners[addr]; ok && owner != v.Zone {
				ambiguous[addr] = true
				continue
			}
			owners[addr] = v.Zone
		}
	}
	var unique []string
	for _, addr := range candidates {
		if owners[addr] == zone && !ambiguous[addr] {
			unique = append(unique, addr)
		}
	}
	return unique
}

// intersectFenceWGAddresses returns the zone addresses also covered by a gap
// fence. Gap accepts must never extend beyond its uncovered destination set.
func intersectFenceWGAddresses(zoneAddrs, uncovered []string) []string {
	if len(zoneAddrs) == 0 || len(uncovered) == 0 {
		return nil
	}
	var scoped []string
	for _, addr := range zoneAddrs {
		for _, missing := range uncovered {
			if addr == missing {
				scoped = append(scoped, addr)
				break
			}
		}
	}
	return scoped
}

func emitHostInboundGapFenceWGAdmitsNetlink(p *nlPlan, spec GapFenceSpec) {
	for _, v := range spec.Views {
		ports := spec.WGZonePorts[v.Zone]
		v4 := intersectFenceWGAddresses(v.V4Addrs, spec.UncoveredV4)
		v6 := intersectFenceWGAddresses(v.V6Addrs, spec.UncoveredV6)
		emitFenceWGIngressAcceptNetlink(p, spec.Views, v, famV4, v4, ports)
		emitFenceWGIngressAcceptNetlink(p, spec.Views, v, famV6, v6, ports)
	}
}

// emitDHCPBackstopAdmitsNetlink admits DHCPv6 server replies only on
// interfaces whose effective policy allows the dhcpv6 service. DHCPv4 uses
// AF_PACKET and does not traverse this input chain.
func emitDHCPBackstopAdmitsNetlink(p *nlPlan, admitV6, vrfSlavesV6 []string) {
	emitV6 := func(r *ruleAsm) {
		r.needNfproto(famV6)
		r.daddr(famV6, []string{"fe80::/10"}, false)
		r.l4Port(protoUDP, "sport", portsFromUint16([]uint16{547}), false)
		r.l4Port(protoUDP, "dport", portsFromUint16([]uint16{earlyInputBarrierDHCPv6ClientPort}), false).emit(verdictAccept()...)
	}
	if len(admitV6) > 0 {
		emitV6(p.rule().iifname(admitV6))
	}
	if len(vrfSlavesV6) > 0 {
		emitV6(p.rule().sdifname(vrfSlavesV6))
	}
}

// emitDHCPBackstopDropNetlink mirrors the final text-oracle drops. Ordinary
// devices match iifname; only the configured VRF-slave subset uses sdifname.
// FIB type guards classify local and anycast destinations independently of
// Ethernet packet type; the IPv6 VRF path also matches fe80::/10 directly
// because strict route lookup can return unreachable for link-local addresses.
func emitDHCPBackstopDropNetlink(p *nlPlan, f nlFamily, netdevs, vrfSlaves []string) {
	if len(netdevs) > 0 {
		r := p.rule().iifname(netdevs)
		r.needNfproto(f)
		r.fibLocalOrAnycast().emit(verdictDrop()...)
	}
	if len(vrfSlaves) > 0 {
		r := p.rule().sdifname(vrfSlaves)
		r.needNfproto(f)
		r.fibLocalOrAnycast().emit(verdictDrop()...)
		if f == famV6 {
			// VRF-strict lookup can return unreachable for link-local
			// destinations despite a local address on the slave.
			linkLocal := p.rule().sdifname(vrfSlaves)
			linkLocal.needNfproto(famV6)
			linkLocal.daddr(famV6, []string{"fe80::/10"}, false).emit(verdictDrop()...)
		}
	}
}

// emitDHCPBackstopGapDropNetlink keeps the interface-wide fallback from
// overriding addresses already covered by the retained main table. FIB type
// guards drop uncovered local or anycast destinations without letting an L2
// group MAC bypass them; VRF link-local fallback preserves the same exclusion.
func emitDHCPBackstopGapDropNetlink(p *nlPlan, f nlFamily, netdevs, vrfSlaves, retained []string) {
	emit := func(r *ruleAsm) {
		r.fibLocalOrAnycast()
		if len(retained) > 0 {
			r.daddr(f, retained, true)
		}
		r.emit(verdictDrop()...)
	}
	if len(netdevs) > 0 {
		r := p.rule().iifname(netdevs)
		r.needNfproto(f)
		emit(r)
	}
	if len(vrfSlaves) > 0 {
		r := p.rule().sdifname(vrfSlaves)
		r.needNfproto(f)
		emit(r)
		if f == famV6 {
			// The FIB lookup can be unreachable for VRF link-local
			// destinations, so retain an explicit prefix-scoped drop. Keep
			// the retained main-table coverage exclusion on this path too.
			linkLocal := p.rule().sdifname(vrfSlaves)
			linkLocal.needNfproto(famV6)
			linkLocal.daddr(famV6, []string{"fe80::/10"}, false)
			if len(retained) > 0 {
				linkLocal.daddr(famV6, retained, true)
			}
			linkLocal.emit(verdictDrop()...)
		}
	}
}

// buildHostInboundFenceNetlink mirrors buildHostInboundFencePayload: the
// mandatory admits plus a catch-all DROP for every firewall-local address the
// real ruleset would scope (per host-inbound-configured zone + the unzoned set).
// The caller has created the table + `input` chain (priority
// nftHostInboundPriority, policy accept).
//
// INVARIANT (#5719): this fence declares NO named counter object, and the
// observability surface now DEPENDS on that. ReadHostInboundDenyCounters reports
// a present-but-counterless xpf_hostinbound table as HostInboundTableCounterless,
// which is how REST/Prometheus tell "enforcing, uncounted, degraded" from "no
// table, genuinely zero denies". Giving the fence a counter would silently turn
// that signal back into an authoritative zero — add a distinct fence-state
// signal instead.
func buildHostInboundFenceNetlink(p *nlPlan, spec FenceSpec) {
	emitHostInboundStaleReplyGuards(p, HostInboundStaleReplyFenceRules(
		spec.Views, spec.UnzonedV4, spec.UnzonedV6, spec.WGListenPorts,
	))
	// Preserve global ESP/AH, then deny catalog groups before established flows.
	p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
	emitHostInboundMulticastFenceDropsNetlink(p, spec.Views, spec.UnzonedIngressNetdevs, spec.UnzonedIngressVRFSlaves)
	emitHostInboundFenceEstablishedAndL3AdmitsNetlink(p)
	buildFenceDropsAfterMandatoryAdmitsNetlink(p, spec)
}

// buildLo0FenceNetlink mirrors buildLo0FencePayload. The lo0 cold-boot fence
// shares mandatory admits and address drops with host-inbound, but must preserve
// its established-flow accept without the host-inbound-specific stale-reply
// guard.
func buildLo0FenceNetlink(p *nlPlan, spec FenceSpec) {
	buildFenceMandatoryDropsNetlink(p, spec)
}

func buildFenceMandatoryDropsNetlink(p *nlPlan, spec FenceSpec) {
	hostInboundFenceMandatoryAdmitsNetlink(p)
	buildFenceDropsAfterMandatoryAdmitsNetlink(p, spec)
}

func buildFenceDropsAfterMandatoryAdmitsNetlink(p *nlPlan, spec FenceSpec) {
	emitHostInboundFenceWGAdmitsNetlink(p, spec.Views, spec.WGZonePorts)
	emitDHCPBackstopAdmitsNetlink(p, spec.DHCPv6Admit, spec.DHCPv6AdmitVRFSlaves)
	for _, v := range spec.Views {
		if len(v.V4Addrs) > 0 {
			p.rule().daddr(famV4, v.V4Addrs, false).emit(verdictDrop()...)
		}
		if len(v.V6Addrs) > 0 {
			p.rule().daddr(famV6, v.V6Addrs, false).emit(verdictDrop()...)
		}
	}
	if len(spec.UnzonedV4) > 0 {
		p.rule().daddr(famV4, spec.UnzonedV4, false).emit(verdictDrop()...)
	}
	if len(spec.UnzonedV6) > 0 {
		p.rule().daddr(famV6, spec.UnzonedV6, false).emit(verdictDrop()...)
	}
	// #10751/#11577: keep backstop interfaces denied after destination rules.
	emitDHCPBackstopDropNetlink(p, famV4, spec.UnleasedV4, spec.UnleasedVRFSlavesV4)
	emitDHCPBackstopDropNetlink(p, famV6, spec.UnleasedV6, spec.UnleasedVRFSlavesV6)
}

// buildHostInboundGapFenceNetlink mirrors buildHostInboundGapFencePayload: the
// mandatory admits, the lifeline-ingress exception for shared values, explicit
// drops for supplied uncovered addresses, then family-scoped DHCP backstops
// excluding retained covered destinations. The caller has created the table +
// `input` chain (priority nftHostInboundGapPriority, policy accept).
func buildHostInboundGapFenceNetlink(p *nlPlan, spec GapFenceSpec) {
	emitHostInboundStaleReplyGuards(p, HostInboundStaleReplyGuardRules(
		nil, spec.UncoveredV4, spec.UncoveredV6, spec.WGListenPorts, false,
	))
	hostInboundFenceMandatoryAdmitsNetlink(p)
	emitHostInboundGapFenceWGAdmitsNetlink(p, spec)
	emitDHCPBackstopAdmitsNetlink(p, spec.DHCPv6Admit, spec.DHCPv6AdmitVRFSlaves)
	// #10751 M1/Opus9: lifeline-shared values stay reachable on
	// lifeline ingress (exception ACCEPTs) while denied everywhere
	// else (bare DROP below). TWO rules per family: iifname covers
	// unenslaved lifelines (name observed directly); meta sdifname
	// covers VRF-enslaved lifelines (LOCAL_IN shows the master, sdif
	// recovers the member) — WITHOUT admitting the whole VRF, so a
	// non-lifeline fxp1 member stays denied. sdifname is inert on
	// non-VRF traffic (unset, misses). Both precede the DROP; with no
	// lifeline set both are omitted and shared stays denied on all
	// ingress (fail-closed). sdifname needs 5.17+; emitted unguarded —
	// the ≥6.18 platform floor covers it (README/bake; below-floor
	// kernels unsupported, no fallback by design — a support floor,
	// not an enforced runtime gate). Expression orders match the
	// oracle text — parity-pinned.
	if len(spec.LifelineNetdevs) > 0 {
		if len(spec.SharedV4) > 0 {
			p.rule().iifname(spec.LifelineNetdevs).daddr(famV4, spec.SharedV4, false).emit(verdictAccept()...)
			p.rule().sdifname(spec.LifelineNetdevs).daddr(famV4, spec.SharedV4, false).emit(verdictAccept()...)
		}
		if len(spec.SharedV6) > 0 {
			p.rule().iifname(spec.LifelineNetdevs).daddr(famV6, spec.SharedV6, false).emit(verdictAccept()...)
			p.rule().sdifname(spec.LifelineNetdevs).daddr(famV6, spec.SharedV6, false).emit(verdictAccept()...)
		}
	}
	if len(spec.UncoveredV4) > 0 {
		p.rule().daddr(famV4, spec.UncoveredV4, false).emit(verdictDrop()...)
	}
	if len(spec.UncoveredV6) > 0 {
		p.rule().daddr(famV6, spec.UncoveredV6, false).emit(verdictDrop()...)
	}
	// #10751/#11577: keep backstop interfaces denied after destination rules.
	emitDHCPBackstopGapDropNetlink(p, famV4, spec.UnleasedV4, spec.UnleasedVRFSlavesV4, spec.RetainedV4)
	emitDHCPBackstopGapDropNetlink(p, famV6, spec.UnleasedV6, spec.UnleasedVRFSlavesV6, spec.RetainedV6)
}
