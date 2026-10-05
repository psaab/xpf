package nftables

// netlink_hostinbound.go builds the `inet xpf_hostinbound` chain via netlink,
// mirroring buildHostInboundFilterPayload / emitHostInboundZone /
// emitJunosHostDenyProgram in pkg/daemon/daemon_nft.go (the parity ORACLE)
// rule-for-rule and in the SAME order. The rendering re-derives the per-token
// service/protocol matches from the SHARED SSOT (config.HostInboundServiceMatch
// / config.HostInboundProtocolMatch), so the only difference between this build
// and the oracle text is the rendering-to-kernel step — which the T1
// ruleset-parity test pins.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// unzonedHostInboundZoneLabel mirrors dpuserspace.UnzonedHostInboundZoneLabel:
// the reserved zone label the #4420 addressed-but-unzoned catch-all drop counter
// is keyed under, so ReadHostInboundDenyCounters recovers zone="junos-host".
const unzonedHostInboundZoneLabel = "junos-host"

// buildHostInboundNetlink queues the full host-inbound table (counters + chain +
// rules) into the plan, mirroring buildHostInboundFilterPayload. The caller has
// already created the table + `input` chain (priority nftHostInboundPriority,
// policy accept) on the plan.
func buildHostInboundNetlink(p *nlPlan, spec HostInboundSpec) {
	declareHostInboundCounters(p, spec)

	// #9504: each program's first-match rules live in a regular chain the input
	// chain jumps to. The chains are declared first, so every jump names a chain
	// already in the batch; their rules follow the input chain's, as in the
	// oracle text.
	chains := make([]*nftables.Chain, len(spec.Programs))
	for i, prog := range spec.Programs {
		chains[i] = p.regularChain(HostInboundJunosHostChainName(i, prog.Zone))
	}
	if spec.Overlay != nil {
		overlay := CanonicalHostInputFenceOverlay(*spec.Overlay)
		if len(overlay.MasterSet) > 0 {
			p.rule().iifname(overlay.MasterSet).
				counterRef(HostInputFenceOverlayCounterName(overlay)).
				emit(verdictDrop()...)
		}
	}
	if len(spec.Programs) > 0 {
		// junos-host path — coarse-then-fine order (#4146).
		p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
		emitHostInboundStaleReplyGuards(p, HostInboundStaleReplyGuardRules(
			spec.Views, spec.UnzonedV4, spec.UnzonedV6, spec.WGListenPorts, hostInboundTrustedReinject(spec),
		))
		emitHostInboundScreenFloodNetlink(p, HostInboundScreenFloodRules(spec.Views), true)
		emitJunosHostMulticastProgramJumpsNetlink(p, spec.Programs)
		emitHostInboundMulticastGuardsNetlink(p, spec.Views, spec.UnzonedIngressNetdevs, spec.UnzonedIngressVRFSlaves)
		p.rule().ctEstablishedRelated().ctDirectionReply().emit(verdictAccept()...)
		for i, prog := range spec.Programs {
			emitJunosHostProgramJumpNetlink(p, i, prog)
		}
		emitHostInboundScreenFloodNetlink(p, HostInboundScreenFloodRules(spec.Views), false)
		emitHostInboundICMPAcceptsNetlink(p)
	} else {
		p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
		emitHostInboundStaleReplyGuards(p, HostInboundStaleReplyGuardRules(
			spec.Views, spec.UnzonedV4, spec.UnzonedV6, spec.WGListenPorts, hostInboundTrustedReinject(spec),
		))
		emitHostInboundScreenFloodNetlink(p, HostInboundScreenFloodRules(spec.Views), true)
		emitJunosHostMulticastProgramJumpsNetlink(p, spec.Programs)
		emitHostInboundMulticastGuardsNetlink(p, spec.Views, spec.UnzonedIngressNetdevs, spec.UnzonedIngressVRFSlaves)
		p.rule().ctEstablishedRelated().ctDirectionReply().emit(verdictAccept()...)
		emitHostInboundScreenFloodNetlink(p, HostInboundScreenFloodRules(spec.Views), false)
		emitHostInboundICMPAcceptsNetlink(p)
	}

	// #10751/#11577: scoped DHCPv6 server replies pass before the backstop
	// drops only on interfaces whose effective zone policy permits dhcpv6;
	// DHCPv4 uses AF_PACKET and bypasses the input chain.
	emitDHCPBackstopAdmitsNetlink(p, spec.DHCPv6Admit, spec.DHCPv6AdmitVRFSlaves)

	// #9637 residual: the userspace-adjudicated reinject exemption, immediately
	// before the ingress-zone rules in both chain shapes. Omitted unless the
	// dataplane runs this generation's snapshot (the D1 fail-closed gate).
	if spec.DataplaneFresh {
		reinjectV4, reinjectV6 := hostInboundReinjectDestinations(spec.Views)
		emitHostInboundReinjectAcceptNetlink(p, famV4, reinjectV4)
		emitHostInboundReinjectAcceptNetlink(p, famV6, reinjectV6)
	}
	ingressV4, ingressV6 := hostInboundIngressDestinations(spec.Views, spec.UnzonedV4, spec.UnzonedV6)
	// #11409: VRF slave-name guards precede rules scoped to the shared
	// LOCAL_IN master, so a zoned sibling cannot admit an unzoned member.
	emitHostInboundUnzonedVRFIngressDropNetlink(p, spec.UnzonedIngressVRFSlaves, famV4, ingressV4)
	emitHostInboundUnzonedVRFIngressDropNetlink(p, spec.UnzonedIngressVRFSlaves, famV6, ingressV6)
	// #9637: unambiguous ingress scopes take their zone's service rights first.
	// Unzoned destination addresses are excluded so a zone cannot admit another
	// interface's address; its catch-all still denies them below.
	zoneIngressV4, zoneIngressV6 := hostInboundZoneIngressDestinations(spec.Views)
	for _, v := range spec.Views {
		emitHostInboundZoneIngressNetlink(p, v, famV4, zoneIngressV4)
		emitHostInboundZoneIngressNetlink(p, v, famV6, zoneIngressV6)
	}
	emitHostInboundAmbiguousIngressAcceptsNetlink(p, spec.Views, famV4, spec.WGZonePorts)
	emitHostInboundAmbiguousIngressDropNetlink(p, spec.Views, famV4, ingressV4)
	emitHostInboundAmbiguousIngressAcceptsNetlink(p, spec.Views, famV6, spec.WGZonePorts)
	emitHostInboundAmbiguousIngressDropNetlink(p, spec.Views, famV6, ingressV6)
	// #11409: physical ingress with no surviving zone is denied before the
	// residual established accept and destination-only fallback.
	emitHostInboundUnzonedIngressDropNetlink(p, spec.UnzonedIngressNetdevs, famV4, ingressV4)
	emitHostInboundUnzonedIngressDropNetlink(p, spec.UnzonedIngressNetdevs, famV6, ingressV6)
	p.rule().ctEstablishedRelated().emit(verdictAccept()...)
	for _, v := range spec.Views {
		emitHostInboundZoneNetlink(p, v, famV4, v.V4Addrs, spec.WGZonePorts[v.Zone])
		emitHostInboundZoneNetlink(p, v, famV6, v.V6Addrs, spec.WGZonePorts[v.Zone])
	}
	emitUnzonedHostInboundDenyNetlink(p, famV4, "ip", spec.UnzonedV4)
	emitUnzonedHostInboundDenyNetlink(p, famV6, "ip6", spec.UnzonedV6)
	// #10751/#11577: final family-specific DHCP backstops follow every
	// destination rule, preserving addressed-zone service accepts.
	emitDHCPBackstopDropNetlink(p, famV4, spec.UnleasedV4, spec.UnleasedVRFSlavesV4)
	emitDHCPBackstopDropNetlink(p, famV6, spec.UnleasedV6, spec.UnleasedVRFSlavesV6)
	for i, prog := range spec.Programs {
		p.inChain(chains[i], func() { emitJunosHostProgramChainNetlink(p, prog) })
	}
}

// emitHostInboundStaleReplyGuards mirrors hostInboundStaleReplyGuardText:
// catalogued box-originated replies to a currently denied local service are
// dropped before the broad reply-direction accept. Expression order matches
// the oracle (ct state, ct direction, iifname, daddr, dport) so T1 parity
// holds.
func emitHostInboundStaleReplyGuards(p *nlPlan, guards []StaleReplyGuardRule) {
	for _, guard := range guards {
		family := famV4
		if guard.Family == "ip6" {
			family = famV6
		}
		proto := uint8(protoTCP)
		if guard.Proto == config.HostInboundProtoUDP {
			proto = protoUDP
		}
		rule := p.rule().
			ctEstablishedRelated().
			ctDirectionReply()
		if len(guard.Ingress) > 0 {
			if guard.IngressNegated {
				rule.iifnameExcept(guard.Ingress)
			} else {
				rule.iifname(guard.Ingress)
			}
		}
		rule.
			daddr(family, guard.Addresses, false).
			l4Port(proto, "dport", portsFromUint16(guard.Ports), false).
			emit(verdictDrop()...)
	}
}

// declareHostInboundCounters mirrors buildHostInboundFilterPayload's counter
// pre-pass: the 3 global ICMP-accept counters, per-zone/family deny counters,
// the ambiguous-ingress junos-host counters, the #9637 reinject-accept counter
// (fresh + addressed views only), the unzoned deny counters, and the junos-host
// deny counters, each declared exactly once and in the same order.
func declareHostInboundCounters(p *nlPlan, spec HostInboundSpec) {
	seen := map[string]bool{}
	decl := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		p.counterObj(name)
	}
	if spec.Overlay != nil {
		decl(HostInputFenceOverlayCounterName(*spec.Overlay))
	}
	for _, typ := range HostInboundAcceptCounterTypes {
		decl(HostInboundAcceptCounterName(typ))
	}
	for _, rule := range HostInboundScreenFloodRules(spec.Views) {
		if rule.AggregateThreshold > 0 {
			decl(HostInboundScreenFloodCounterName(rule, false))
		}
		if rule.SourceThreshold > 0 {
			decl(HostInboundScreenFloodCounterName(rule, true))
		}
	}
	ingressV4, ingressV6 := hostInboundIngressDestinations(spec.Views, spec.UnzonedV4, spec.UnzonedV6)
	zoneIngressV4, zoneIngressV6 := hostInboundZoneIngressDestinations(spec.Views)
	for _, v := range spec.Views {
		if hostInboundEmitsDrop(v, v.V4Addrs) || hostInboundEmitsIngressDrop(v, zoneIngressV4) {
			decl(HostInboundDenyCounterName(v.Zone, "ip"))
		}
		if hostInboundEmitsDrop(v, v.V6Addrs) || hostInboundEmitsIngressDrop(v, zoneIngressV6) {
			decl(HostInboundDenyCounterName(v.Zone, "ip6"))
		}
	}
	if hostInboundEmitsAmbiguousIngressDrop(spec.Views, ingressV4) {
		decl(HostInboundDenyCounterName(unzonedHostInboundZoneLabel, "ip"))
	}
	if hostInboundEmitsAmbiguousIngressDrop(spec.Views, ingressV6) {
		decl(HostInboundDenyCounterName(unzonedHostInboundZoneLabel, "ip6"))
	}
	if hostInboundEmitsUnzonedIngressDrop(spec.UnzonedIngressNetdevs, ingressV4) ||
		hostInboundEmitsUnzonedIngressDrop(spec.UnzonedIngressVRFSlaves, ingressV4) {
		decl(HostInboundDenyCounterName(unzonedHostInboundZoneLabel, "ip"))
	}
	if hostInboundEmitsUnzonedIngressDrop(spec.UnzonedIngressNetdevs, ingressV6) ||
		hostInboundEmitsUnzonedIngressDrop(spec.UnzonedIngressVRFSlaves, ingressV6) {
		decl(HostInboundDenyCounterName(unzonedHostInboundZoneLabel, "ip6"))
	}
	// #9637 residual: the reinject-accept counter, declared exactly when the
	// accept rules render (fresh + addressed views), mirroring the oracle —
	// AFTER the per-zone deny counters and BEFORE the unzoned ones (T1
	// parity diffs declaration order, so the positions must agree).
	if spec.DataplaneFresh {
		if rv4, rv6 := hostInboundReinjectDestinations(spec.Views); len(rv4) > 0 || len(rv6) > 0 {
			decl(HostInboundAcceptCounterName(HostInboundAcceptReinject))
		}
	}
	if len(spec.UnzonedV4) > 0 {
		decl(HostInboundDenyCounterName(unzonedHostInboundZoneLabel, "ip"))
	}
	if len(spec.UnzonedV6) > 0 {
		decl(HostInboundDenyCounterName(unzonedHostInboundZoneLabel, "ip6"))
	}
	for _, prog := range spec.Programs {
		if len(prog.RulesV4) > 0 {
			decl(HostInboundJunosHostDenyCounterName(prog.Zone, "ip"))
		}
		if len(prog.RulesV6) > 0 {
			decl(HostInboundJunosHostDenyCounterName(prog.Zone, "ip6"))
		}
	}
}

// emitHostInboundICMPAcceptsNetlink mirrors emitHostInboundICMPAccepts: the
// global ND + v4/v6 PMTUD/error accepts, each carrying its named aggregate
// counter (#4759).
func emitHostInboundICMPAcceptsNetlink(p *nlPlan) {
	p.rule().icmpType(famV6, []uint8{1, 2, 3, 4}).
		counterRef(HostInboundAcceptCounterName(HostInboundAcceptICMP6Error)).emit(verdictAccept()...)
	p.rule().icmpType(famV6, []uint8{133, 134, 135, 136, 137}).
		counterRef(HostInboundAcceptCounterName(HostInboundAcceptICMP6ND)).emit(verdictAccept()...)
	p.rule().icmpType(famV4, []uint8{3, 11, 12}).
		counterRef(HostInboundAcceptCounterName(HostInboundAcceptICMP4Error)).emit(verdictAccept()...)
}

// emitHostInboundMulticastGuardsNetlink mirrors the text oracle's
// ingress-scoped group/protocol admits and catalog-group default drops. It is
// deliberately before both established accepts; ambiguous/unzoned ingress and
// shared VRF slaves get drops without zone accepts.
func emitHostInboundMulticastGuardsNetlink(p *nlPlan, views []HostInboundZoneView, unzonedIngressNetdevs, unzonedIngressVRFSlaves []string) {
	ambiguous := hostInboundAmbiguousIngressNetdevs(views)
	for _, f := range []nlFamily{famV4, famV6} {
		family := familyToken(f)
		groups := config.HostInboundMulticastGroupsForFamily(family)
		if len(groups) == 0 {
			continue
		}
		if len(unzonedIngressVRFSlaves) > 0 {
			p.rule().sdifname(unzonedIngressVRFSlaves).daddr(f, groups, false).emit(verdictDrop()...)
		}
		if len(ambiguous) > 0 {
			p.rule().iifname(ambiguous).daddr(f, groups, false).emit(verdictDrop()...)
		}
		if len(unzonedIngressNetdevs) > 0 {
			p.rule().iifname(unzonedIngressNetdevs).daddr(f, groups, false).emit(verdictDrop()...)
		}
		for _, v := range views {
			if len(v.IngressNetdevs) == 0 {
				continue
			}
			if hostInboundAllowsAll(v) {
				p.rule().iifname(v.IngressNetdevs).daddr(f, groups, false).emit(verdictAccept()...)
			} else {
				multicastRules := v.MulticastRules
				if len(multicastRules) == 0 {
					multicastRules = config.HostInboundMulticastRules(v.Protocols)
				}
				for _, multicastRule := range multicastRules {
					if multicastRule.Family != family {
						continue
					}
					for _, frag := range renderHIMatchFragments(config.HostInboundProtocolMatch(multicastRule.Protocol, family), f) {
						a := p.rule().iifname(v.IngressNetdevs).daddr(f, []string{multicastRule.Group}, false)
						frag.build(a)
						a.emit(verdictAccept()...)
					}
				}
			}
			p.rule().iifname(v.IngressNetdevs).daddr(f, groups, false).emit(verdictDrop()...)
		}
	}
}

// emitHostInboundMulticastFenceDropsNetlink keeps the host-inbound cold-boot
// fence fail-closed for every catalog group. The additive gap fence deliberately
// does not call this: its later base chain must not override valid grants in the
// retained main table.
func emitHostInboundMulticastFenceDropsNetlink(p *nlPlan, views []HostInboundZoneView, unzonedIngressNetdevs, unzonedIngressVRFSlaves []string) {
	ambiguous := hostInboundAmbiguousIngressNetdevs(views)
	for _, f := range []nlFamily{famV4, famV6} {
		groups := config.HostInboundMulticastGroupsForFamily(familyToken(f))
		if len(groups) == 0 {
			continue
		}
		if len(unzonedIngressVRFSlaves) > 0 {
			p.rule().sdifname(unzonedIngressVRFSlaves).daddr(f, groups, false).emit(verdictDrop()...)
		}
		if len(ambiguous) > 0 {
			p.rule().iifname(ambiguous).daddr(f, groups, false).emit(verdictDrop()...)
		}
		if len(unzonedIngressNetdevs) > 0 {
			p.rule().iifname(unzonedIngressNetdevs).daddr(f, groups, false).emit(verdictDrop()...)
		}
		for _, v := range views {
			if len(v.IngressNetdevs) > 0 {
				p.rule().iifname(v.IngressNetdevs).daddr(f, groups, false).emit(verdictDrop()...)
			}
		}
	}
}

// emitJunosHostMulticastProgramJumpsNetlink mirrors the text oracle: explicit
// fine-program denies inspect catalog-group packets before coarse multicast
// admission, while permits return to the zone protocol gate.
func emitJunosHostMulticastProgramJumpsNetlink(p *nlPlan, programs []JunosHostProgram) {
	for i, prog := range programs {
		if len(prog.IngressIfnames) == 0 {
			continue
		}
		for _, f := range []nlFamily{famV4, famV6} {
			groups := config.HostInboundMulticastGroupsForFamily(familyToken(f))
			if len(groups) == 0 {
				continue
			}
			p.rule().iifname(prog.IngressIfnames).daddr(f, groups, false).
				emit(verdictJump(HostInboundJunosHostChainName(i, prog.Zone))...)
		}
	}
}

// emitHostInboundZoneWireGuardAcceptNetlink admits a zone's WireGuard tunnels
// (#11076): `daddr <zone-addrs> udp dport <zone-ports> accept`, rendered inside
// the zone's own section after its service accepts and before its catch-all
// deny — ordered with zone policy, never above it. No-op when the zone serves
// no WG tunnels. Unzoned addresses match no zone section and keep falling to
// the unzoned deny.
func emitHostInboundZoneWireGuardAcceptNetlink(p *nlPlan, f nlFamily, addrs []string, wgPorts []uint16) {
	if len(addrs) == 0 || len(wgPorts) == 0 {
		return
	}
	p.rule().daddr(f, addrs, false).l4Port(protoUDP, "dport", portsFromUint16(wgPorts), false).emit(verdictAccept()...)
}

// emitHostInboundZoneNetlink mirrors emitHostInboundZone for one zone/family.
func emitHostInboundZoneNetlink(p *nlPlan, v HostInboundZoneView, f nlFamily, addrs []string, wgPorts []uint16) {
	if len(addrs) == 0 {
		return
	}
	if hostInboundAllowsAll(v) {
		p.rule().daddr(f, addrs, false).emit(verdictAccept()...)
		return
	}
	family := familyToken(f)
	for _, frag := range hostInboundMatchFragments(v, f) {
		a := p.rule().daddr(f, addrs, false)
		frag.build(a)
		if frag.reject {
			a.emit(rejectTCPReset()...)
		} else {
			a.emit(verdictAccept()...)
		}
	}
	emitHostInboundZoneWireGuardAcceptNetlink(p, f, addrs, wgPorts)
	// Catch-all default-deny with named counter (#3361).
	cn := HostInboundDenyCounterName(v.Zone, family)
	p.rule().daddr(f, addrs, false).counterRef(cn).emit(verdictDrop()...)
}

// emitUnzonedHostInboundDenyNetlink mirrors emitUnzonedHostInboundDeny (#4420).
func emitUnzonedHostInboundDenyNetlink(p *nlPlan, f nlFamily, family string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	cn := HostInboundDenyCounterName(unzonedHostInboundZoneLabel, family)
	p.rule().daddr(f, addrs, false).counterRef(cn).emit(verdictDrop()...)
}

// emitJunosHostProgramJumpNetlink mirrors emitJunosHostProgramJump (#4146,
// #9504): the ident exemption shield, then the iifname-scoped jump to the
// zone's subchain. There is deliberately NO IKE shield (#10524, mirroring the
// text-oracle deletion): the fine DENY governs denied sources' IKE.
func emitJunosHostProgramJumpNetlink(p *nlPlan, index int, prog JunosHostProgram) {
	// #10524: the pre-fix IKE accept (`iifname <IKEExemptNetdevs> udp dport
	// { 500, 4500 } accept`) is deleted here exactly as in the text oracle —
	// its terminal accept re-admitted denied IKE ahead of the fine jump.
	// Ident shield KEPT (mirroring the oracle disposition): a terminal TCP RST
	// still refuses the connection and cannot re-admit traffic.
	if prog.HasApplicationAnyDeny && prog.CoarseIdentResets {
		p.rule().iifname(prog.IdentResetNetdevs).
			l4Port(protoTCP, "dport", []nlPort{{113, 113}}, false).
			emit(rejectTCPReset()...)
	}
	p.rule().iifname(prog.IngressIfnames).emit(verdictJump(HostInboundJunosHostChainName(index, prog.Zone))...)
}

// emitJunosHostProgramChainNetlink mirrors emitJunosHostProgramChain: the zone's
// rules in first-match order, IPv4 then IPv6.
func emitJunosHostProgramChainNetlink(p *nlPlan, prog JunosHostProgram) {
	for _, r := range prog.RulesV4 {
		emitJunosHostRuleNetlink(p, prog.Zone, r)
	}
	for _, r := range prog.RulesV6 {
		emitJunosHostRuleNetlink(p, prog.Zone, r)
	}
}

// emitJunosHostRuleNetlink mirrors emitJunosHostRule: the family guard, the L4
// fragment, the address predicates, then the counter and verdict. A verdict
// that answers TCP with a RST splits an `application any` rule, TCP first.
func emitJunosHostRuleNetlink(p *nlPlan, zone string, r JunosHostDenyRule) {
	f := famFor(r.Family)
	cn := HostInboundJunosHostDenyCounterName(zone, r.Family)
	finish := func(a *ruleAsm, tcp bool) {
		applyJunosHostSrcPredicate(a, f, r)
		applyJunosHostDstPredicate(a, f, r)
		switch {
		case r.Verdict == config.JunosHostReturn:
			a.emit(verdictReturn()...)
		case r.Verdict.SplitsTCP() && tcp:
			a.counterRef(cn)
			a.emit(rejectTCPReset()...)
		case r.Verdict == config.JunosHostReject:
			a.counterRef(cn)
			a.emit(rejectICMPXAdminProhibited()...)
		default:
			a.counterRef(cn)
			a.emit(verdictDrop()...)
		}
	}
	if len(r.L4) == 0 {
		if r.Verdict.SplitsTCP() {
			a := p.rule()
			a.needNfproto(f)
			a.needL4proto(protoTCP)
			finish(a, true)
		}
		a := p.rule()
		a.needNfproto(f)
		finish(a, false)
		return
	}
	for _, l4 := range r.L4 {
		a := p.rule()
		a.needNfproto(f)
		applyJunosHostL4(a, f, l4)
		finish(a, l4.Proto == protoTCP)
	}
}

// applyJunosHostL4 mirrors renderJunosHostL4.
func applyJunosHostL4(a *ruleAsm, f nlFamily, l4 JunosHostDenyL4) {
	switch l4.Proto {
	case config.HostInboundProtoTCP, config.HostInboundProtoUDP:
		proto := l4.Proto
		matched := false
		if len(l4.Ports) > 0 {
			a.l4Port(proto, "dport", portsFromSpec(l4.Ports), false)
			matched = true
		}
		if len(l4.SourcePorts) > 0 {
			a.l4Port(proto, "sport", portsFromSpec(l4.SourcePorts), false)
			matched = true
		}
		if !matched {
			a.l4protoSet([]uint8{proto})
		}
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		if l4.ICMPType == nil {
			a.l4protoSet([]uint8{l4.Proto})
			return
		}
		a.icmpType(f, []uint8{*l4.ICMPType})
		if l4.ICMPCode != nil {
			a.icmpCode(f, []uint8{*l4.ICMPCode})
		}
	default:
		a.l4protoSet([]uint8{l4.Proto})
	}
}

// applyJunosHostSrcPredicate mirrors junosHostSrcPredicate: the positive /
// excluded / any source match.
func applyJunosHostSrcPredicate(a *ruleAsm, f nlFamily, r JunosHostDenyRule) {
	switch {
	case r.SrcExcluded && len(r.Src) > 0:
		a.saddr(f, r.Src, true)
	case r.SrcAny || (r.SrcExcluded && len(r.Src) == 0):
		// match every source (no positive saddr predicate)
	default:
		if len(r.Src) > 0 {
			a.saddr(f, r.Src, false)
		}
	}
}

// applyJunosHostDstPredicate mirrors junosHostDstPredicate: the positive /
// excluded / any destination match from an explicit `match destination-address`.
// Emitted AFTER the source predicate so the expression order matches the
// exec-nft oracle byte for byte (the T1 parity gate diffs kernel rule dumps,
// which preserve expression order).
func applyJunosHostDstPredicate(a *ruleAsm, f nlFamily, r JunosHostDenyRule) {
	switch {
	case r.DstExcluded && len(r.Dst) > 0:
		a.daddr(f, r.Dst, true)
	case r.DstAny || (r.DstExcluded && len(r.Dst) == 0):
		// match every destination (no positive daddr predicate)
	default:
		if len(r.Dst) > 0 {
			a.daddr(f, r.Dst, false)
		}
	}
}

// --- service/protocol fragment derivation -----------------------------------

// hiFragment is one deduped host-inbound service/protocol match: a canonical
// dedup key, whether it rejects (ident-reset) or accepts, and a builder that
// appends the match exprs to a rule assembler.
type hiFragment struct {
	key    string
	reject bool
	build  func(a *ruleAsm)
}

// hostInboundMatchFragments mirrors hostInboundMatchSet: the de-duplicated,
// order-preserving service+protocol match fragments for a zone/family. Dedup is
// on the canonical match key (equivalent to the oracle's nft-fragment-string
// dedup), so two tokens yielding the same match collapse to one rule.
func hostInboundMatchFragments(v HostInboundZoneView, f nlFamily) []hiFragment {
	family := familyToken(f)
	var out []hiFragment
	seen := map[string]bool{}
	add := func(frag hiFragment) {
		if frag.key == "" || seen[frag.key] {
			return
		}
		seen[frag.key] = true
		out = append(out, frag)
	}
	// #3226: mirror the oracle — expand each authored token to the concrete
	// services it stands for (`all` → the named-service union) and take the
	// reject verdict from the CONCRETE token. Keying `reject` on the AUTHORED
	// token would render `all`'s expanded tcp/113 fragment as an ACCEPT, since
	// `all` != "ident-reset", admitting ident probes the per-token form resets.
	for _, s := range v.SystemServices {
		for _, sub := range config.HostInboundServiceTokenExpansion(s) {
			reject := sub == "ident-reset"
			for _, frag := range renderHIMatchFragments(config.HostInboundServiceMatch(sub, family), f) {
				frag.reject = reject
				add(frag)
			}
		}
	}
	for _, prot := range v.Protocols {
		for _, frag := range renderHIMatchFragments(config.HostInboundProtocolMatch(prot, family), f) {
			add(frag)
		}
	}
	return out
}

// renderHIMatchFragments mirrors renderHostInboundMatches: it lowers a token's
// []config.L4Match into ordered match fragments, coalescing consecutive
// same-proto ICMP matches into a single type set.
func renderHIMatchFragments(ms []config.L4Match, f nlFamily) []hiFragment {
	var out []hiFragment
	for i := 0; i < len(ms); {
		m := ms[i]
		switch m.Proto {
		case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
			var types []uint8
			for i < len(ms) && ms[i].Proto == m.Proto && ms[i].ICMPType != nil {
				types = append(types, *ms[i].ICMPType)
				i++
			}
			if len(types) == 0 {
				i++
				continue
			}
			tvals := types
			out = append(out, hiFragment{
				key:   familyToken(f) + ":icmp:" + intsKey(u8ToInts(tvals)),
				build: func(a *ruleAsm) { a.icmpType(f, tvals) },
			})
		case config.HostInboundProtoTCP:
			ports := portsFromConfig(m.Ports)
			out = append(out, hiFragment{
				key:   "tcp:" + portsKey(ports),
				build: func(a *ruleAsm) { a.l4Port(protoTCP, "dport", ports, false) },
			})
			i++
		case config.HostInboundProtoUDP:
			ports := portsFromConfig(m.Ports)
			out = append(out, hiFragment{
				key:   "udp:" + portsKey(ports),
				build: func(a *ruleAsm) { a.l4Port(protoUDP, "dport", ports, false) },
			})
			i++
		default:
			proto := m.Proto
			out = append(out, hiFragment{
				key:   "l4proto:" + strconv.Itoa(int(proto)),
				build: func(a *ruleAsm) { a.l4protoSet([]uint8{proto}) },
			})
			i++
		}
	}
	return out
}

// hostInboundEmitsDrop mirrors hostInboundEmitsDrop in the oracle.
func hostInboundEmitsDrop(v HostInboundZoneView, addrs []string) bool {
	return len(addrs) > 0 && !hostInboundAllowsAll(v)
}

// hostInboundAllowsAll mirrors hostInboundAllowsAll in the oracle.
func hostInboundAllowsAll(v HostInboundZoneView) bool {
	for _, s := range v.SystemServices {
		if config.HostInboundFullAdmitService(s) {
			return true
		}
	}
	return false
}

// --- shared helpers ---------------------------------------------------------

const (
	protoTCP = 6
	protoUDP = 17
)

func familyToken(f nlFamily) string {
	if f.v6 {
		return "ip6"
	}
	return "ip"
}

func portsFromConfig(prs []config.PortRange) []nlPort {
	out := make([]nlPort, len(prs))
	for i, pr := range prs {
		out[i] = nlPort{lo: pr.Lo, hi: pr.Hi}
	}
	return out
}

func portsFromSpec(prs []PortRange) []nlPort {
	out := make([]nlPort, len(prs))
	for i, pr := range prs {
		out[i] = nlPort{lo: pr.Lo, hi: pr.Hi}
	}
	return out
}

func portsFromUint16(ports []uint16) []nlPort {
	out := make([]nlPort, len(ports))
	for i, p := range ports {
		out[i] = nlPort{lo: p, hi: p}
	}
	return out
}

func portsKey(ports []nlPort) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		if p.isRange() {
			parts[i] = strconv.Itoa(int(p.lo)) + "-" + strconv.Itoa(int(p.hi))
		} else {
			parts[i] = strconv.Itoa(int(p.lo))
		}
	}
	return strings.Join(parts, ",")
}

func intsKey(vals []int) string {
	sorted := append([]int(nil), vals...)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, v := range sorted {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func u8ToInts(vals []uint8) []int {
	out := make([]int, len(vals))
	for i, v := range vals {
		out[i] = int(v)
	}
	return out
}

// emitHostInboundScreenFloodNetlink mirrors the text renderer's two-phase
// placement: reply-direction packets are screened before their early accept,
// while original-direction packets are screened after any fine Junos-host
// program has run.
func emitHostInboundScreenFloodNetlink(p *nlPlan, rules []HostInboundScreenFloodRule, repliesOnly bool) {
	for _, screen := range rules {
		base := func() *ruleAsm {
			a := p.rule()
			if repliesOnly {
				a.ctEstablishedRelated().ctDirectionReply()
			}
			if len(screen.IngressNetdevs) > 0 {
				a.iifname(screen.IngressNetdevs)
				// Ingress names can carry both IP families; scope every
				// family-specific source key and protocol matcher explicitly.
				a.needNfproto(screenFloodFamily(screen))
			} else {
				a.daddr(screenFloodFamily(screen), screen.Addresses, false)
			}
			switch screen.Protocol {
			case "udp":
				a.needL4proto(uint8(unix.IPPROTO_UDP))
			case "icmp":
				a.needL4proto(uint8(unix.IPPROTO_ICMP))
			case "icmpv6":
				a.needL4proto(uint8(unix.IPPROTO_ICMPV6))
			case "tcp-syn":
				a.tcpFlags(0x02, 0x10)
			default:
				return nil
			}
			return a
		}

		if screen.SourceThreshold > 0 {
			sourceSet := addHostInboundScreenFloodSet(p, screen, true)
			if sourceSet == nil {
				continue
			}
			perSource := base()
			if perSource == nil {
				continue
			}
			perSource.add(hostInboundScreenSourceKey(screen)).
				add(sourceSet).
				counterRef(HostInboundScreenFloodCounterName(screen, true))
			if screen.AlarmWithoutDrop {
				perSource.add(hostInboundScreenFloodAlarm(screen, true)...)
				perSource.emit()
			} else {
				perSource.emit(verdictDrop()...)
			}
		}

		if screen.AggregateThreshold > 0 && p.err == nil {
			globalSet := addHostInboundScreenFloodSet(p, screen, false)
			if globalSet == nil {
				continue
			}
			aggregate := base()
			if aggregate == nil {
				continue
			}
			aggregate.add(hostInboundScreenAggregateKey()).
				add(globalSet).
				counterRef(HostInboundScreenFloodCounterName(screen, false))
			if screen.AlarmWithoutDrop {
				aggregate.add(hostInboundScreenFloodAlarm(screen, false)...)
				aggregate.emit()
			} else {
				aggregate.emit(verdictDrop()...)
			}
		}
	}
}

func screenFloodLimit(rate uint32) *expr.Limit {
	return &expr.Limit{
		Type:  expr.LimitTypePkts,
		Rate:  uint64(rate),
		Over:  true,
		Unit:  expr.LimitTimeSecond,
		Burst: rate,
	}
}

func hostInboundScreenFloodAlarm(screen HostInboundScreenFloodRule, source bool) []expr.Any {
	return []expr.Any{
		&expr.Limit{
			Type:  expr.LimitTypePkts,
			Rate:  1,
			Unit:  expr.LimitTimeSecond,
			Burst: 1,
		},
		&expr.Log{
			Level: expr.LogLevelWarning,
			Key:   1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_LEVEL,
			Data:  []byte(HostInboundScreenFloodAlarmPrefix(screen, source)),
		},
	}
}

func screenFloodFamily(rule HostInboundScreenFloodRule) nlFamily {
	if rule.Family == "ip6" {
		return famV6
	}
	return famV4
}

func hostInboundScreenAggregateKey() *expr.Immediate {
	return &expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}
}

func hostInboundScreenSourceKey(rule HostInboundScreenFloodRule) *expr.Payload {
	offset, length := uint32(12), uint32(4)
	if rule.Family == "ip6" {
		offset, length = 8, 16
	}
	return &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
	}
}

func addHostInboundScreenFloodSet(p *nlPlan, rule HostInboundScreenFloodRule, source bool) *expr.Dynset {
	if p.err != nil {
		return nil
	}
	setName := HostInboundScreenFloodAggregateSetName(rule)
	keyType := nftables.TypeMark
	size := uint32(1)
	rate := rule.AggregateThreshold
	if source {
		setName = HostInboundScreenFloodSetName(rule)
		keyType = nftables.TypeIPAddr
		if rule.Family == "ip6" {
			keyType = nftables.TypeIP6Addr
		}
		size = HostInboundScreenFloodMeterSize
		rate = rule.SourceThreshold
	}
	set := p.screenFloodSets[setName]
	if set == nil {
		set = &nftables.Set{
			Table:      p.table,
			Name:       setName,
			Dynamic:    true,
			HasTimeout: true,
			Timeout:    HostInboundScreenFloodMeterTimeout,
			Size:       size,
			KeyType:    keyType,
		}
		if err := p.c.AddSet(set, nil); err != nil {
			p.fail(fmt.Errorf("add host-inbound screen flood meter set %q: %w", set.Name, err))
			return nil
		}
		if p.screenFloodSets == nil {
			p.screenFloodSets = make(map[string]*nftables.Set)
		}
		p.screenFloodSets[set.Name] = set
	}
	return &expr.Dynset{
		SrcRegKey: 1,
		SetID:     set.ID,
		SetName:   set.Name,
		Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
		Exprs:     []expr.Any{screenFloodLimit(rate)},
	}
}
