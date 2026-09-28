package nftables

// netlink_fence.go builds the #5644 cold-boot fail-closed fence and the #5789
// additive coverage-gap fence via netlink, mirroring buildHostInboundFencePayload
// / buildHostInboundGapFencePayload / hostInboundFenceMandatoryAdmits in
// pkg/daemon/daemon_nft.go (the parity ORACLE). Both fences are the real
// host-inbound table with every per-service ACCEPT removed: the shared mandatory
// admits (return/ND/PMTUD/ESP-AH/WG) followed by a catch-all DROP (no named
// counter) for the fenced firewall-local addresses.

// hostInboundFenceMandatoryAdmitsNetlink mirrors hostInboundFenceMandatoryAdmits:
// the fence chain's mandatory-admit rules — established/related, raw ESP/AH, IPv6
// ND, v4/v6 PMTUD/error, and the configured WireGuard listen port(s). No named
// counters (a fence is transient).
func hostInboundFenceMandatoryAdmitsNetlink(p *nlPlan, wgListenPorts []uint16) {
	p.rule().ctEstablishedRelated().emit(verdictAccept()...)
	p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{1, 2, 3, 4}).emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{133, 134, 135, 136, 137}).emit(verdictAccept()...)
	p.rule().icmpType(famV4, []uint8{3, 11, 12}).emit(verdictAccept()...)
	if len(wgListenPorts) > 0 {
		p.rule().l4Port(protoUDP, "dport", portsFromUint16(wgListenPorts), false).emit(verdictAccept()...)
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
	hostInboundFenceMandatoryAdmitsNetlink(p, spec.WGListenPorts)
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
	if len(spec.UnleasedV4) > 0 {
		p.rule().iifname(spec.UnleasedV4).emit(verdictDrop()...)
	}
	if len(spec.UnleasedV6) > 0 {
		p.rule().iifname(spec.UnleasedV6).emit(verdictDrop()...)
	}
}

// buildHostInboundGapFenceNetlink mirrors buildHostInboundGapFencePayload: the
// mandatory admits plus a catch-all DROP for ONLY the supplied uncovered
// addresses. The caller has created the table + `input` chain (priority
// nftHostInboundGapPriority, policy accept).
func buildHostInboundGapFenceNetlink(p *nlPlan, spec GapFenceSpec) {
	emitHostInboundStaleReplyGuards(p, HostInboundStaleReplyGuardRules(
		nil, spec.UncoveredV4, spec.UncoveredV6, spec.WGListenPorts, false,
	))
	hostInboundFenceMandatoryAdmitsNetlink(p, spec.WGListenPorts)
	// #10751 F8-A: admit the DHCP client's own replies before the
	// destination drops (see emitUnleasedDHCPAdmitsNetlink).
	emitUnleasedDHCPAdmitsNetlink(p, spec.UnleasedV4, spec.UnleasedV6)
	if len(spec.UncoveredV4) > 0 {
		p.rule().daddr(famV4, spec.UncoveredV4, false).emit(verdictDrop()...)
	}
	if len(spec.UncoveredV6) > 0 {
		p.rule().daddr(famV6, spec.UncoveredV6, false).emit(verdictDrop()...)
	}
	// #10751 R7-B: unleased-DHCP interface backstop (see the real builder).
	if len(spec.UnleasedV4) > 0 {
		p.rule().iifname(spec.UnleasedV4).emit(verdictDrop()...)
	}
	if len(spec.UnleasedV6) > 0 {
		p.rule().iifname(spec.UnleasedV6).emit(verdictDrop()...)
	}
}
