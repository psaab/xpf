package nftables

// netlink_fence.go builds the #5644 cold-boot fail-closed fence and the #5789
// additive coverage-gap fence via netlink, mirroring the fence text oracles in
// pkg/daemon/daemon_nft.go. Both fences are the real host-inbound table with
// every per-service ACCEPT removed: scope-independent mandatory admits, then
// per-zone WireGuard accepts, followed by catch-all DROPs (no named counters)
// for their fenced firewall-local addresses.

// hostInboundFenceMandatoryAdmitsNetlink mirrors hostInboundFenceMandatoryAdmits:
// the fence chain's scope-independent mandatory admits — established/related,
// raw ESP/AH, IPv6 ND, and v4/v6 PMTUD/error. WireGuard admissions are emitted
// separately with serving-zone destination scope. No named counters (a fence is
// transient).
func hostInboundFenceMandatoryAdmitsNetlink(p *nlPlan) {
	p.rule().ctEstablishedRelated().emit(verdictAccept()...)
	p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{1, 2, 3, 4}).emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{133, 134, 135, 136, 137}).emit(verdictAccept()...)
	p.rule().icmpType(famV4, []uint8{3, 11, 12}).emit(verdictAccept()...)
}

// emitHostInboundFenceWGAdmitsNetlink scopes each fence's WG exception to the
// addresses of zones that serve the configured listen port(s).
func emitHostInboundFenceWGAdmitsNetlink(p *nlPlan, views []HostInboundZoneView, wgZonePorts map[string][]uint16) {
	for _, v := range views {
		ports := wgZonePorts[v.Zone]
		emitHostInboundZoneWireGuardAcceptNetlink(p, famV4, v.V4Addrs, ports)
		emitHostInboundZoneWireGuardAcceptNetlink(p, famV6, v.V6Addrs, ports)
	}
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
		if len(ports) == 0 {
			continue
		}
		emitHostInboundZoneWireGuardAcceptNetlink(p, famV4, intersectFenceWGAddresses(v.V4Addrs, spec.UncoveredV4), ports)
		emitHostInboundZoneWireGuardAcceptNetlink(p, famV6, intersectFenceWGAddresses(v.V6Addrs, spec.UncoveredV6), ports)
	}
}

// emitUnleasedDHCPAdmitsNetlink mirrors emitUnleasedDHCPAdmits: the per-family
// DHCP-client admits for still-unleased netdevs — `iifname <dev> udp dport
// <68|546> accept`, family-guarded exactly like the early-input barrier's own
// DHCP admits (input_barrier_10751.go). Placed with the mandatory admits,
// BEFORE every destination rule: on an already-up link the unzoned
// link-local DROP would otherwise shadow a first ADVERTISE/OFFER (a
// multicast-originated reply is not conntrack-established, so only the
// DHCP admit lets it through), deadlocking acquisition behind the LAST
// interface DROP. Scoped to the unleased netdevs of each family, so leased
// families stay under pure destination judgement. Expression order (iifname,
// nfproto, l4proto, dport) matches the oracle text — parity-pinned. A no-op
// for the lo0 fence (its spec never carries unleased netdevs).
func emitUnleasedDHCPAdmitsNetlink(p *nlPlan, unleasedV4, unleasedV6 []string) {
	if len(unleasedV4) > 0 {
		r := p.rule().iifname(unleasedV4)
		r.needNfproto(famV4)
		r.l4Port(protoUDP, "dport", portsFromUint16([]uint16{earlyInputBarrierDHCPv4ClientPort}), false).emit(verdictAccept()...)
	}
	if len(unleasedV6) > 0 {
		r := p.rule().iifname(unleasedV6)
		r.needNfproto(famV6)
		r.l4Port(protoUDP, "dport", portsFromUint16([]uint16{earlyInputBarrierDHCPv6ClientPort}), false).emit(verdictAccept()...)
	}
}

// emitUnleasedDropNetlink appends one family-guarded backstop DROP
// (`iifname <dev> meta nfproto <fam> drop`, mirroring
// emitUnleasedHostInboundDeny). The guard is load-bearing: a bare iifname
// DROP would also deny the other family's fallthrough on a mixed-leased
// interface. No-op on an empty set. Expression order (iifname, nfproto)
// matches the oracle text — parity-pinned.
func emitUnleasedDropNetlink(p *nlPlan, f nlFamily, netdevs []string) {
	if len(netdevs) == 0 {
		return
	}
	r := p.rule().iifname(netdevs)
	r.needNfproto(f)
	r.emit(verdictDrop()...)
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
	buildFenceMandatoryDropsNetlink(p, spec)
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
	emitHostInboundFenceWGAdmitsNetlink(p, spec.Views, spec.WGZonePorts)
	// #10751 F8-A: admit the DHCP client's own replies before the
	// destination drops (no-op for lo0 — see emitUnleasedDHCPAdmitsNetlink).
	emitUnleasedDHCPAdmitsNetlink(p, spec.UnleasedV4, spec.UnleasedV6)
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
	// #10751 R7-B: unleased-DHCP interface backstop (see the real builder).
	emitUnleasedDropNetlink(p, famV4, spec.UnleasedV4)
	emitUnleasedDropNetlink(p, famV6, spec.UnleasedV6)
}

// buildHostInboundGapFenceNetlink mirrors buildHostInboundGapFencePayload: the
// mandatory admits, the lifeline-ingress exception for shared values, then a
// catch-all DROP for ONLY the supplied uncovered addresses. The caller has
// created the table + `input` chain (priority nftHostInboundGapPriority,
// policy accept).
func buildHostInboundGapFenceNetlink(p *nlPlan, spec GapFenceSpec) {
	emitHostInboundStaleReplyGuards(p, HostInboundStaleReplyGuardRules(
		nil, spec.UncoveredV4, spec.UncoveredV6, spec.WGListenPorts, false,
	))
	hostInboundFenceMandatoryAdmitsNetlink(p)
	emitHostInboundGapFenceWGAdmitsNetlink(p, spec)
	// #10751 F8-A: admit the DHCP client's own replies before the
	// destination drops (see emitUnleasedDHCPAdmitsNetlink).
	emitUnleasedDHCPAdmitsNetlink(p, spec.UnleasedV4, spec.UnleasedV6)
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
	// #10751 R7-B: unleased-DHCP interface backstop (see the real builder).
	emitUnleasedDropNetlink(p, famV4, spec.UnleasedV4)
	emitUnleasedDropNetlink(p, famV6, spec.UnleasedV6)
}
