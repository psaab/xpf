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
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
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

	if len(spec.Programs) > 0 {
		// junos-host path — coarse-then-fine order (#4146).
		p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
		p.rule().ctEstablishedRelated().ctDirectionReply().emit(verdictAccept()...)
		for _, prog := range spec.Programs {
			emitJunosHostDenyProgramNetlink(p, prog)
		}
		emitHostInboundICMPAcceptsNetlink(p)
		emitHostInboundWireGuardAcceptNetlink(p, spec.WGListenPorts)
		p.rule().ctEstablishedRelated().emit(verdictAccept()...)
	} else {
		p.rule().ctEstablishedRelated().emit(verdictAccept()...)
		p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...)
		emitHostInboundICMPAcceptsNetlink(p)
		emitHostInboundWireGuardAcceptNetlink(p, spec.WGListenPorts)
	}

	// #9637: ingress-zone rules first, as in the oracle.
	ingressV4, ingressV6 := hostInboundIngressDestinations(spec.Views, spec.UnzonedV4, spec.UnzonedV6)
	for _, v := range spec.Views {
		emitHostInboundZoneIngressNetlink(p, v, famV4, ingressV4)
		emitHostInboundZoneIngressNetlink(p, v, famV6, ingressV6)
	}
	for _, v := range spec.Views {
		emitHostInboundZoneNetlink(p, v, famV4, v.V4Addrs)
		emitHostInboundZoneNetlink(p, v, famV6, v.V6Addrs)
	}
	emitUnzonedHostInboundDenyNetlink(p, famV4, "ip", spec.UnzonedV4)
	emitUnzonedHostInboundDenyNetlink(p, famV6, "ip6", spec.UnzonedV6)
}

// declareHostInboundCounters mirrors buildHostInboundFilterPayload's counter
// pre-pass: the 3 global ICMP-accept counters, then per-zone/family deny
// counters, the unzoned deny counters, and the junos-host deny counters, each
// declared exactly once and in the same order.
func declareHostInboundCounters(p *nlPlan, spec HostInboundSpec) {
	seen := map[string]bool{}
	decl := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		p.counterObj(name)
	}
	for _, typ := range HostInboundAcceptCounterTypes {
		decl(HostInboundAcceptCounterName(typ))
	}
	ingressV4, ingressV6 := hostInboundIngressDestinations(spec.Views, spec.UnzonedV4, spec.UnzonedV6)
	for _, v := range spec.Views {
		if hostInboundEmitsDrop(v, v.V4Addrs) || hostInboundEmitsIngressDrop(v, ingressV4) {
			decl(HostInboundDenyCounterName(v.Zone, "ip"))
		}
		if hostInboundEmitsDrop(v, v.V6Addrs) || hostInboundEmitsIngressDrop(v, ingressV6) {
			decl(HostInboundDenyCounterName(v.Zone, "ip6"))
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

// emitHostInboundWireGuardAcceptNetlink mirrors emitHostInboundWireGuardAccept:
// a single coarse `udp dport <wg-port(s)> accept` (#5582). No-op when unset.
func emitHostInboundWireGuardAcceptNetlink(p *nlPlan, wgListenPorts []uint16) {
	if len(wgListenPorts) == 0 {
		return
	}
	p.rule().l4Port(protoUDP, "dport", portsFromUint16(wgListenPorts), false).emit(verdictAccept()...)
}

// emitHostInboundZoneNetlink mirrors emitHostInboundZone for one zone/family.
func emitHostInboundZoneNetlink(p *nlPlan, v HostInboundZoneView, f nlFamily, addrs []string) {
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

// emitJunosHostDenyProgramNetlink mirrors emitJunosHostDenyProgram (#4146).
func emitJunosHostDenyProgramNetlink(p *nlPlan, prog JunosHostProgram) {
	if prog.HasApplicationAnyDeny {
		if prog.CoarseAdmitsIKE {
			p.rule().iifname(prog.IKEExemptNetdevs).
				l4Port(protoUDP, "dport", []nlPort{{500, 500}, {4500, 4500}}, false).
				emit(verdictAccept()...)
		}
		if prog.CoarseIdentResets {
			p.rule().iifname(prog.IdentResetNetdevs).
				l4Port(protoTCP, "dport", []nlPort{{113, 113}}, false).
				emit(rejectTCPReset()...)
		}
	}
	for _, r := range prog.RulesV4 {
		emitJunosHostDropRuleNetlink(p, prog, r)
	}
	for _, r := range prog.RulesV6 {
		emitJunosHostDropRuleNetlink(p, prog, r)
	}
}

// emitJunosHostDropRuleNetlink mirrors emitJunosHostDropRule: one nft rule per
// L4 fragment (or a single rule for `application any`).
func emitJunosHostDropRuleNetlink(p *nlPlan, prog JunosHostProgram, r JunosHostDenyRule) {
	f := famFor(r.Family)
	cn := HostInboundJunosHostDenyCounterName(prog.Zone, r.Family)
	finish := func(a *ruleAsm) {
		applyJunosHostSrcPredicate(a, f, r)
		applyJunosHostDstPredicate(a, f, r)
		a.counterRef(cn)
		a.emit(verdictDrop()...)
	}
	if len(r.L4) == 0 {
		a := p.rule().iifname(prog.IngressIfnames)
		finish(a)
		return
	}
	for _, l4 := range r.L4 {
		a := p.rule().iifname(prog.IngressIfnames)
		applyJunosHostL4(a, f, l4)
		finish(a)
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
// excluded / any source match plus the earlier-permit `saddr !=` subtractions.
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
	if len(r.PermitSubtract) > 0 {
		a.saddr(f, r.PermitSubtract, true)
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
