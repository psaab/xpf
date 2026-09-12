package config

import (
	"fmt"
	"sort"
	"strings"
)

// junos_host_deny.go is the config-level SSOT for the #4146 kernel-nft
// enforcement of the `to-zone junos-host` DENY on the DIRECT host-bound path.
//
// A direct host-bound packet (to a firewall interface IP / VRRP VIP) is
// delivered by the Linux kernel — the XDP shim shunts local-destined packets to
// it before userspace-dp ever sees them — so the fine `to-zone junos-host`
// security policy, which historically ran only on the userspace AF_XDP
// LocalDelivery path, never applied to it (the #4146 security gap). This file
// PROJECTS the effective ordered junos-host policy program per ingress zone into
// a first-match, representability-gated rule program that the kernel
// `xpf_hostinbound` nft chain (pkg/daemon/daemon_nft.go) renders. It is deliberately in pkg/config —
// the lowest package that owns policies, zones, the address book, applications,
// schedulers and feed bindings — so the #4168 commit WARNING
// (compiler_validate_warn.go) can reuse the SAME rendered-policy decision that
// drives kernel emission, and the pkg/dataplane/userspace wrapper
// (BuildJunosHostPrograms) can layer the kernel-netdev iifname scope on top.
//
// Design invariants (see docs/research/4146-junos-host-direct-deny/plan.md):
//   - ONE effective ordered program per ingress zone, assembled in Rust's exact
//     three tiers: exact `from-zone Z to-zone junos-host` -> `from-zone any
//     to-zone junos-host` (#3090) -> applicable global `to-zone junos-host`
//     (mirrors policymatch.matchJunosHost / userspace-dp evaluate_junos_host_
//     policy_l3_aware).
//   - WHOLE-PROGRAM representability gate: if ANY contributing term (any tier)
//     is un-representable, the WHOLE program emits nothing and every one of its
//     junos-host policies keeps the #4168 warning. Never a per-term partial.
//   - FIRST-MATCH, NEVER A FINE ACCEPT (#9504): each ingress zone's program
//     renders, in authored order, into its own nft subchain. A `deny` drops
//     (answering TCP with a RST on a `tcp-rst` zone), a `reject` answers (TCP
//     RST, else ICMP administratively prohibited), and a `permit` RETURNS from
//     the subchain so the coarse host-inbound gate still decides. A permit never
//     emits a fine accept (that could re-admit a coarse-rejected service — Rust
//     poll_descriptor/mod.rs:138). A packet no rule matches returns too: the
//     runtime has no implicit junos-host default-deny (policy.rs
//     evaluate_junos_host_policy_l3_aware, policymatch.matchJunosHost), and
//     neither does this program.
//   - Fine-eligible L4 domain: ESP/AH (proto 50/51) are always exempt; IKE
//     500/4500 is exempt when the ingress zone's coarse host-inbound admits ike;
//     ident-reset TCP/113 is exempt only when the zone's effective coarse verdict
//     is the RST (ident-reset set AND not all/any-service). The daemon renders
//     these as exemption rules ahead of an `application any` drop.

// junosHostSelfZone is the reserved to-zone token that names the firewall's own
// host (RE) traffic context. Mirrors policymatch.JunosHostZone.
const junosHostSelfZone = "junos-host"

// JunosHostDenyL4 is one representable L4 match fragment projected from a
// junos-host policy's `match application`. An empty JunosHostDenyProgram rule
// L4 list means the deny was `application any` (matches every protocol).
type JunosHostDenyL4 struct {
	// Proto is the IP protocol number: HostInboundProtoTCP/UDP/ICMP/ICMPv6 or a
	// bare protocol number (e.g. 47 for GRE). Never 50/51/500-bearing/113-bearing
	// for a representable deny — a deny scoped to an IPsec/ident tuple is
	// un-representable (the IPsec/ident path owns it).
	Proto uint8
	// Ports is the destination-port spec for TCP/UDP (nil = all ports).
	Ports []PortRange
	// SourcePorts is the source-port spec for TCP/UDP (nil = all).
	SourcePorts []PortRange
	// ICMPType / ICMPCode constrain an ICMP/ICMPv6 fragment (nil = any).
	ICMPType *uint8
	ICMPCode *uint8
}

// JunosHostVerdict is what a projected junos-host rule does with a packet it
// matches (#9504). Every verdict except JunosHostReturn is DENY-class: the
// packet does not reach the host.
type JunosHostVerdict uint8

const (
	// JunosHostDrop is `then deny` on an ingress zone without `tcp-rst`: a
	// silent drop.
	JunosHostDrop JunosHostVerdict = iota
	// JunosHostDropTCPReset is `then deny` on a `tcp-rst` ingress zone. The
	// runtime answers a TCP packet with a RST and drops everything else
	// silently (reject_reply.rs enqueue_deny_reply).
	JunosHostDropTCPReset
	// JunosHostReject is `then reject`: a TCP RST for TCP and an ICMP/ICMPv6
	// destination-unreachable, administratively prohibited, for everything
	// else (reject_reply.rs).
	JunosHostReject
	// JunosHostReturn is `then permit`: the packet leaves the zone's subchain
	// and the coarse host-inbound gate decides. It is never an accept.
	JunosHostReturn
)

// SplitsTCP reports whether the verdict answers TCP differently from every other
// protocol (with a RST), so an `application any` rule renders a TCP rule ahead of
// the rest.
func (v JunosHostVerdict) SplitsTCP() bool {
	return v == JunosHostReject || v == JunosHostDropTCPReset
}

// JunosHostDenyRule is one projected rule for a single family, in first-match
// order. Despite the name it carries every verdict a junos-host term can have
// (Verdict). The daemon renders it inside the ingress zone's subchain as
//
//	[<l4>] <fam> saddr <src> [<fam> daddr <dst>] <verdict>
//
// SrcAny (no source constraint) and SrcExcluded (`saddr != Src`) mirror the
// policymatch.matchAddr family semantics; a rule is only emitted for a family
// whose positive source set is non-empty OR whose match is source-any/excluded.
// Dst*/Dst are the SAME projection applied to an explicit `match
// destination-address` (#4146 destination slice) — the host chain only ever sees
// host-destined packets, so a `daddr` predicate narrows the deny to the authored
// firewall address(es). It is NEVER the zone scope (that stays `iifname`).
type JunosHostDenyRule struct {
	Family      string // "ip" or "ip6"
	SrcAny      bool   // true => match every source (no saddr predicate)
	SrcExcluded bool   // true => `saddr != Src` (source-address-excluded)
	Src         []string
	// Verdict is what the rule does with a packet it matches (#9504).
	Verdict JunosHostVerdict
	// DstAny / DstExcluded / Dst mirror Src* for `match destination-address`.
	// DstAny (the overwhelmingly common `destination-address any`) renders NO
	// daddr predicate, so an unscoped deny is byte-identical to the pre-slice
	// rule.
	DstAny      bool // true => match every destination (no daddr predicate)
	DstExcluded bool // true => `daddr != Dst` (destination-address-excluded)
	Dst         []string
	// L4 is the OR-expanded set of L4 fragments; the daemon emits one nft rule
	// per fragment. Empty means `application any` (all protocols).
	L4 []JunosHostDenyL4
}

// JunosHostDenyProgram is the effective ordered junos-host program for one
// ingress zone.
type JunosHostDenyProgram struct {
	Zone string
	// InterfaceRefs are the zone's NON-lifeline interface refs (config names,
	// e.g. "reth0.50"). Informational; the actual iifname scope is IngressNetdevs.
	InterfaceRefs []string
	// IngressNetdevs is the sorted set of kernel netdev names a host-bound packet
	// on this zone arrives with — the iifname scope the daemon renders each DROP
	// rule with (JunosHostZoneIngressNetdevs). EXCLUDES lifelines and any netdev
	// shared with another zone (a cross-zone-ambiguous physical parent). Empty
	// when the zone resolves to no unambiguous non-lifeline netdev: the program
	// then emits NOTHING and its denies keep the #4168 warning — the config
	// projection gates Representable/RenderedPolicyKeys on this so the warning can
	// never be suppressed for a deny that produced no kernel rule (§8 inv-1/12).
	IngressNetdevs []string
	// Representable is false when any contributing term is un-representable; the
	// program then carries NO rules and the daemon emits nothing for the zone.
	Representable bool
	// RulesV4 / RulesV6 are the projected rules, each family in first-match
	// order. A non-empty list never ends in a JunosHostReturn.
	RulesV4 []JunosHostDenyRule
	RulesV6 []JunosHostDenyRule
	// CoarseAdmitsIKE / CoarseIdentResets drive the daemon's fine-eligible-L4
	// exemption rules ahead of an `application any` drop (§6.6). They are true
	// iff at least one ingress netdev in the zone admits the exemption
	// (len(IKEExemptNetdevs) / len(IdentResetNetdevs) > 0) — NOT a zone-wide
	// union of every per-interface override (#5565).
	CoarseAdmitsIKE   bool
	CoarseIdentResets bool
	// IKEExemptNetdevs / IdentResetNetdevs are the SUBSET of IngressNetdevs whose
	// EFFECTIVE per-interface host-inbound set admits IKE (udp 500/4500) /
	// answers TCP/113 with a RST (#5565). The daemon scopes the IKE / ident
	// exemption shield to these netdevs instead of the whole zone iifname set, so
	// a per-INTERFACE `ike` / `ident-reset` override is never widened to a sibling
	// interface in the same zone that did not configure it. A genuinely
	// zone-level exception (authored on the zone's own host-inbound-traffic)
	// admits on every interface, so its subset equals IngressNetdevs and the
	// shield stays zone-wide (no regression). Sorted; each a subset of
	// IngressNetdevs.
	IKEExemptNetdevs  []string
	IdentResetNetdevs []string
	// HasApplicationAnyDeny is true when the program contains a rendered
	// `application any` rule with a DENY-class verdict, so the daemon knows to
	// emit the IKE/ident exemption shields ahead of it.
	HasApplicationAnyDeny bool
}

// JunosHostDenyProjection is the whole-config result: the per-zone programs the
// daemon renders, plus the set of junos-host policy keys that rendered an
// enforced kernel rule (so the #4168 warning is suppressed for exactly those).
type JunosHostDenyProjection struct {
	Programs           []JunosHostDenyProgram
	RenderedPolicyKeys map[string]bool
}

// JunosHostZonePairPolicyKey / JunosHostGlobalPolicyKey are the stable identity
// keys used to correlate a rendered program back to the emitting policy so the
// #4168 warning can suppress exactly the rendered ones. Both the projection and
// the warning compute the same key.
func JunosHostZonePairPolicyKey(fromZone, name string) string {
	return "zp\x00" + fromZone + "\x00" + name
}

func JunosHostGlobalPolicyKey(name string) string {
	return "gl\x00" + name
}

// junosHostTerm is one contributing policy term in an ingress zone's effective
// ordered program, carrying its representability verdict and projected match.
type junosHostTerm struct {
	key    string
	action PolicyAction
	// per-family resolved source
	srcV4, srcV6       []string
	srcAnyV4, srcAnyV6 bool
	srcExcluded        bool
	// per-family resolved destination (`match destination-address`)
	dstV4, dstV6       []string
	dstAnyV4, dstAnyV6 bool
	dstExcluded        bool
	// resolved application L4 fragments (nil => application any)
	l4            []JunosHostDenyL4
	appAny        bool
	representable bool
	// lenientDropped marks a PERMIT whose tolerant-path compile silently dropped
	// a match / then-permit constraint (#5575 LenientContentDropped). Its empty
	// dimension would resolve to `any` here, so it contributes nothing (#9572).
	lenientDropped bool
}

// BuildJunosHostDenyProjection projects every configured ingress zone's
// effective `to-zone junos-host` policy program into the kernel-representable
// DROP-only form. It is the SSOT consumed by both the daemon nft codegen (via
// the pkg/dataplane/userspace wrapper) and the #4168 commit warning.
func BuildJunosHostDenyProjection(cfg *Config) JunosHostDenyProjection {
	out := JunosHostDenyProjection{RenderedPolicyKeys: map[string]bool{}}
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return out
	}
	feedBound := junosHostFeedBoundNames(cfg)
	lifelines := HostInboundLifelineSet(cfg)
	// Per-zone kernel netdev iifname scope, WITH what could not be scoped
	// (#6564 member 8). A zone that resolved only SOME of its candidates still
	// emits rules for the survivors — protection that works is never withdrawn —
	// but the policy is not enforced on every ingress path of the zone, so its
	// #4168 warning must not be suppressed. A non-empty check cannot tell that
	// apart from full coverage, which is why the projection reads the coverage
	// and not the netdev list.
	coverageByZone := junosHostZoneNetdevCoverageMap(cfg)

	// Per-policy-key bookkeeping to decide rendered-vs-warned (§3.3): a policy is
	// rendered (warning suppressed) iff it is a DENY or REJECT that applies to
	// >=1 enforceable ingress zone and EVERY enforceable zone it applies to has a
	// representable program that emitted it. A PERMIT is NEVER suppressed: its
	// "deny non-permitted" half is enforced on no path, because the runtime has
	// no implicit junos-host default-deny (#9504).
	appliesEnforceable := map[string]int{}
	blockedByUnrep := map[string]bool{}
	actionByKey := map[string]PolicyAction{}

	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)

	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		terms := junosHostEffectiveTerms(cfg, zoneName, feedBound)
		if len(terms) == 0 {
			continue
		}
		ifaceRefs := junosHostNonLifelineRefs(zone, lifelines)
		cov := coverageByZone[zoneName]
		netdevs := cov.Scoped
		// TWO decisions, deliberately not one boolean (#6564 member 8).
		//
		// emitsRules gates kernel emission: a DROP needs >=1 usable netdev to
		// scope it by iifname. Unchanged.
		//
		// fullyScoped gates the #4168 warning SUPPRESSION, and it is a COVERAGE
		// question, not an existence one. A zone that had candidates and could
		// not use all of them is not enforcing the policy on every ingress path,
		// whether it salvaged some of them or none. Note the two cases are not
		// the same predicate: a zone with NO candidates at all (lifeline-only, or
		// no interfaces) has nothing to enforce and must NOT block suppression —
		// which is exactly what distinguishes it from a zone whose candidates all
		// turned out to be unscopable.
		emitsRules := len(netdevs) > 0
		fullyScoped := len(cov.Unscopable) == 0
		representable := true
		for _, t := range terms {
			if !t.representable {
				representable = false
				break
			}
		}
		// A `tcp-rst` ingress zone is representable (#9504): its denies render
		// as JunosHostDropTCPReset, the RST the runtime sends for a TCP deny.
		var prog JunosHostDenyProgram
		// emitted is the subset of this zone's term keys that actually produced
		// >=1 rule; nil whenever no program was projected at all (#6705).
		var emitted map[string]bool
		if emitsRules && representable {
			// #9504: a permit renders as a return in first-match order, so a
			// narrow-application, source-excluded or destination-scoped permit
			// ahead of a deny no longer makes the program un-representable.
			prog, emitted = junosHostProjectProgram(zoneName, ifaceRefs, terms, zone.TCPRst)
			prog.IngressNetdevs = netdevs
			// #5565: scope the fine-eligible-L4 (IKE / ident) exemption to the
			// SPECIFIC netdevs whose effective per-interface host-inbound set
			// admits it, NOT the whole zone. A per-interface `ike`/`ident-reset`
			// override then shields only the interface that configured it; a
			// zone-level exception still covers every netdev (its subset equals
			// netdevs). The CoarseAdmits* bits follow the subsets so the daemon
			// never emits a shield with no scope.
			prog.IKEExemptNetdevs, prog.IdentResetNetdevs =
				junosHostZoneExemptNetdevs(cfg, zoneName, zone, netdevs)
			prog.CoarseAdmitsIKE = len(prog.IKEExemptNetdevs) > 0
			prog.CoarseIdentResets = len(prog.IdentResetNetdevs) > 0
		}
		// Bookkeeping for the warning.
		for _, t := range terms {
			actionByKey[t.key] = t.action
			// A zone that tried to scope and could not use every candidate blocks
			// suppression even when it emitted nothing at all — the policy is
			// unenforced on that zone's ingress either way, and saying so is the
			// whole job of the #4168 advisory.
			if !fullyScoped {
				blockedByUnrep[t.key] = true
			}
			if !emitsRules {
				continue
			}
			appliesEnforceable[t.key]++
			if !representable {
				blockedByUnrep[t.key] = true
				continue
			}
			// #6705: representable is not enforced. A deny term can survive every
			// representability check and still project NO rule — an earlier
			// application-any permit for every source shadows it, its application
			// resolves entirely to the other family, or its address match is the
			// #5828 degenerate empty set. Suppressing the #4168 warning on that
			// key told the operator the deny was enforced by the kernel gate when
			// the kernel gate had been handed nothing to enforce, so a config that
			// commits cleanly with ZERO warnings produced an empty DROP program.
			// Emission is the property the suppression actually claims, so gate on
			// it directly rather than on the representability that implied it.
			// No action guard here on purpose: the suppression loop below already
			// restricts RenderedPolicyKeys to deny and reject, so blocking a permit's
			// key is unobservable. A `t.action == PolicyDeny` condition here read
			// as load-bearing while no test could distinguish it either way —
			// mutating it away changed nothing — so it is stated once, where it
			// is actually enforced, instead of twice.
			if !emitted[t.key] {
				blockedByUnrep[t.key] = true
			}
		}
		if !emitsRules || !representable {
			out.Programs = append(out.Programs, JunosHostDenyProgram{
				Zone:          zoneName,
				InterfaceRefs: ifaceRefs,
				Representable: false,
			})
			continue
		}
		out.Programs = append(out.Programs, prog)
	}

	for key, n := range appliesEnforceable {
		if a := actionByKey[key]; n > 0 && !blockedByUnrep[key] && (a == PolicyDeny || a == PolicyReject) {
			out.RenderedPolicyKeys[key] = true
		}
	}
	return out
}

// junosHostNonLifelineRefs returns the zone's interface refs that are not
// management/cluster-control lifelines, sorted.
func junosHostNonLifelineRefs(zone *ZoneConfig, lifelines map[string]bool) []string {
	var refs []string
	for _, ref := range zone.Interfaces {
		if ref == "" || HostInboundLifelineInterface(ref, lifelines) {
			continue
		}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

// junosHostEffectiveTerms assembles the ingress zone's effective ordered
// junos-host term list in Rust's exact three-tier order (exact zone-pair ->
// from-any -> global), each term projected + representability-checked. It
// mirrors policymatch.matchJunosHost's tier enumeration.
func junosHostEffectiveTerms(cfg *Config, zone string, feedBound map[string]bool) []junosHostTerm {
	var terms []junosHostTerm
	add := func(key string, p *Policy) {
		if p == nil {
			return
		}
		terms = append(terms, junosHostProjectTerm(cfg, key, p, feedBound))
	}
	// Tier 1: exact `from-zone <zone> to-zone junos-host`.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != junosHostSelfZone || zpp.FromZone != zone {
			continue
		}
		for _, p := range zpp.Policies {
			add(JunosHostZonePairPolicyKey(zpp.FromZone, p.Name), p)
		}
	}
	// Tier 2: `from-zone any to-zone junos-host` (#3090).
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != junosHostSelfZone || zpp.FromZone != "any" {
			continue
		}
		for _, p := range zpp.Policies {
			add(JunosHostZonePairPolicyKey(zpp.FromZone, p.Name), p)
		}
	}
	// Tier 3: global `match to-zone junos-host`, from-zone scope gated (#3639).
	for _, p := range cfg.Security.GlobalPolicies {
		if p == nil || !IsHostToZoneScope(p.Match.ToZones) {
			continue
		}
		if !(IsWildcardZoneSet(p.Match.FromZones) || containsZone(p.Match.FromZones, zone)) {
			continue
		}
		add(JunosHostGlobalPolicyKey(p.Name), p)
	}
	return terms
}

func containsZone(zs []string, z string) bool {
	for _, v := range zs {
		if v == z {
			return true
		}
	}
	return false
}

// junosHostProjectTerm resolves one policy's match into a representable term. A
// scheduler-gated policy, a feed-tainted / non-static source or destination, an
// un-reducible application, or an application scoped to an IPsec/ident exempt
// tuple marks the term un-representable. Every action is representable (#9504):
// deny, reject and permit each keep their verdict in first-match order.
func junosHostProjectTerm(cfg *Config, key string, p *Policy, feedBound map[string]bool) junosHostTerm {
	t := junosHostTerm{key: key, action: p.Action, representable: true}
	// A #5575-poisoned PERMIT contributes no subtraction (#9572). The tolerant
	// compile left a dimension it dropped EMPTY, and every resolver below reads
	// an empty dimension as `any`: an omitted `application` became an
	// application-any permit and an omitted `source-address` a permit for every
	// source, so the permitAll arm erased every later deny from the kernel
	// program. The userspace snapshot builder refuses the same policy
	// (policies_lower.go), yet the daemon still installs this program from the
	// refused config — and on the host-bound path this program IS the
	// enforcement. The operator's real carve is unknowable from the dropped
	// content, so the permit is skipped entirely: later denies render as
	// authored, which can only drop MORE host-bound traffic than configured,
	// never admit traffic a deny names. It is skipped before resolution, so an
	// un-representable leftover dimension cannot empty the zone's program
	// either. A poisoned DENY is not changed here: its empty dimension widens a
	// DROP, the fail-closed direction.
	if p.LenientContentDropped && p.Action == PolicyPermit {
		t.lenientDropped = true
		return t
	}
	// Scheduler-gated policies are time-windowed and cannot be an always-on
	// static rule (§6.2). A permit is no exception: rendered as an always-on
	// return it would carve later denies outside its window.
	if p.SchedulerName != "" {
		t.representable = false
	}
	// Source resolution (static-only, feed-untainted).
	v4, v6, anyV4, anyV6, ok := junosHostResolveAddrSet(cfg, p.Match.SourceAddresses, feedBound)
	if !ok {
		t.representable = false
	}
	t.srcV4, t.srcV6, t.srcAnyV4, t.srcAnyV6 = v4, v6, anyV4, anyV6
	t.srcExcluded = p.Match.SourceAddressExcluded
	// Destination resolution (static-only, feed-untainted — same gate as the
	// source). An explicit `match destination-address` on a DENY is representable:
	// the kernel `xpf_hostinbound` chain hooks the INPUT path, so every packet it
	// sees is already host-destined, and a `daddr` predicate simply narrows the
	// deny to the firewall address(es) the operator authored. A destination that
	// names no firewall address matches nothing in the chain — exactly as the
	// Rust/policymatch evaluation of that policy matches nothing — so the live
	// firewall-local address set is NOT needed to render it correctly.
	//
	// The same holds for a PERMIT or a REJECT (#9504): a destination-scoped
	// permit renders as a return carrying the same `daddr` predicate, so its
	// carve of a later deny is exactly as wide as authored.
	dv4, dv6, dAnyV4, dAnyV6, dok := junosHostResolveAddrSet(cfg, p.Match.DestinationAddresses, feedBound)
	if !dok {
		t.representable = false
	}
	t.dstV4, t.dstV6, t.dstAnyV4, t.dstAnyV6 = dv4, dv6, dAnyV4, dAnyV6
	t.dstExcluded = p.Match.DestinationAddressExcluded
	// Application resolution.
	l4, appAny, appOK := junosHostResolveApplications(cfg, p.Match.Applications)
	if !appOK {
		t.representable = false
	}
	t.l4, t.appAny = l4, appAny
	return t
}

// junosHostProjectProgram renders a representable ingress-zone program as one
// first-match rule list per family (#9504). Every term keeps its authored
// verdict (junosHostTermVerdict), so a permit ahead of a deny carves it the way
// the runtime does, in any dimension: the permit's rule returns from the
// subchain before the deny's rule is reached. A packet no rule matches returns
// as well, which is the runtime's deliver-on-no-match lifeline.
//
// Two refinements shorten the lists without changing any verdict:
//   - once a permit's rule returns EVERY packet of a family (application any,
//     every source, every destination), no later rule of that family can match
//     and none is emitted. That is also what keeps #6705's warning on a deny the
//     permit shadows: the deny emitted nothing, so nothing enforces it.
//   - trailing returns are dropped: a return with nothing after it is the
//     subchain's own end.
func junosHostProjectProgram(zone string, ifaceRefs []string, terms []junosHostTerm, tcpRst bool) (JunosHostDenyProgram, map[string]bool) {
	prog := JunosHostDenyProgram{
		Zone:          zone,
		InterfaceRefs: ifaceRefs,
		Representable: true,
	}
	// emitted records the term keys that contributed AT LEAST ONE rule. A deny
	// term can be fully representable and still project nothing — a permit ahead
	// of it returns every packet, its application resolves entirely to the other
	// family, or its address match is the #5828 degenerate empty set. The caller
	// needs that distinction because "representable" and "enforced" are
	// different properties: without it a deny that emitted zero rules still
	// counted as rendered and had its #4168 warning suppressed, so the operator
	// got neither the enforcement nor the diagnostic (#6705).
	emitted := map[string]bool{}
	var doneV4, doneV6 bool
	for _, t := range terms {
		if t.action == PolicyPermit && t.lenientDropped {
			continue // #9572: a #5575-poisoned permit carves nothing.
		}
		verdict := junosHostTermVerdict(t.action, tcpRst)
		add := func(family string, rules *[]JunosHostDenyRule, done *bool) {
			if *done {
				return
			}
			r, ok := junosHostBuildRule(family, t, verdict)
			if !ok {
				return
			}
			*rules = append(*rules, r)
			emitted[t.key] = true
			if verdict == JunosHostReturn {
				*done = junosHostRuleMatchesFamily(r)
			} else if t.appAny {
				prog.HasApplicationAnyDeny = true
			}
		}
		add("ip", &prog.RulesV4, &doneV4)
		add("ip6", &prog.RulesV6, &doneV6)
	}
	prog.RulesV4 = junosHostTrimTrailingReturns(prog.RulesV4)
	prog.RulesV6 = junosHostTrimTrailingReturns(prog.RulesV6)
	return prog, emitted
}

// junosHostTermVerdict maps a term's action to its rule verdict on an ingress
// zone. A deny on a `tcp-rst` zone answers TCP with a RST, as the runtime's
// enqueue_deny_reply does; on any other zone it is silent.
func junosHostTermVerdict(action PolicyAction, tcpRst bool) JunosHostVerdict {
	switch {
	case action == PolicyPermit:
		return JunosHostReturn
	case action == PolicyReject:
		return JunosHostReject
	case tcpRst:
		return JunosHostDropTCPReset
	default:
		return JunosHostDrop
	}
}

// junosHostRuleMatchesFamily reports whether a rule matches every packet of its
// family: no L4 constraint and no source or destination predicate.
// junosHostProjectAddrMatch never sets SrcAny (or DstAny) together with the
// excluded flag, so the two wildcard bits are the whole test.
func junosHostRuleMatchesFamily(r JunosHostDenyRule) bool {
	return len(r.L4) == 0 && r.SrcAny && r.DstAny
}

// junosHostTrimTrailingReturns drops the returns at the end of a family's rule
// list: with nothing after them they only restate the subchain's end.
func junosHostTrimTrailingReturns(rules []JunosHostDenyRule) []JunosHostDenyRule {
	n := len(rules)
	for n > 0 && rules[n-1].Verdict == JunosHostReturn {
		n--
	}
	if n == 0 {
		return nil
	}
	return rules[:n]
}

// junosHostBuildRule projects one term to a single-family rule carrying the
// given verdict. Returns ok=false when the family's match resolves to "match
// nothing": a constrained positive source or destination with no prefix of this
// family, a degenerate `any`+excluded set, or an application entirely of the
// other family.
func junosHostBuildRule(family string, t junosHostTerm, verdict JunosHostVerdict) (JunosHostDenyRule, bool) {
	var src, dst []string
	var srcAny, dstAny bool
	if family == "ip" {
		src, srcAny = t.srcV4, t.srcAnyV4
		dst, dstAny = t.dstV4, t.dstAnyV4
	} else {
		src, srcAny = t.srcV6, t.srcAnyV6
		dst, dstAny = t.dstV6, t.dstAnyV6
	}
	l4 := junosHostFamilyL4(family, t.l4)
	if !t.appAny && len(l4) == 0 {
		// The term's application resolved entirely to the OTHER family (e.g. an
		// ICMPv6 app on the inet chain) -> matches nothing here.
		return JunosHostDenyRule{}, false
	}
	// #6613: an `*-excluded` whose resolved set is empty in BOTH families is not
	// "match everything" — Rust's rule_l3_matches fails CLOSED on it
	// (`!(v4_empty && v6_empty)`, userspace-dp/src/policy.rs), so projecting the
	// match-all arm here would widen the authored scope to every firewall
	// address while the dataplane denies nothing. The per-family helper cannot
	// see the other family, so the cross-family emptiness is computed here and
	// passed in. Strict commit already rejects an empty/dangling address-set,
	// but the LENIENT load / peer-sync path does not, so a config persisted by
	// an older binary reaches this projection.
	srcEmptyBoth := !t.srcAnyV4 && !t.srcAnyV6 && len(t.srcV4) == 0 && len(t.srcV6) == 0
	dstEmptyBoth := !t.dstAnyV4 && !t.dstAnyV6 && len(t.dstV4) == 0 && len(t.dstV6) == 0

	rule := JunosHostDenyRule{Family: family, L4: l4, Verdict: verdict}
	matchAny, matchExcluded, set, ok := junosHostProjectAddrMatch(src, srcAny, t.srcExcluded, srcEmptyBoth)
	if !ok {
		return JunosHostDenyRule{}, false
	}
	rule.SrcAny, rule.SrcExcluded, rule.Src = matchAny, matchExcluded, set
	matchAny, matchExcluded, set, ok = junosHostProjectAddrMatch(dst, dstAny, t.dstExcluded, dstEmptyBoth)
	if !ok {
		return JunosHostDenyRule{}, false
	}
	rule.DstAny, rule.DstExcluded, rule.Dst = matchAny, matchExcluded, set
	return rule, true
}

// junosHostProjectAddrMatch projects ONE family's address match — the resolved
// per-family CIDR set, that family's wildcard bit, and the `*-excluded` flag —
// into the rule's (any, excluded, set) predicate triple. ok=false means the
// match resolves to "match NOTHING" for this family, so the caller must project
// no rule at all.
//
// This is the SINGLE formula for BOTH the source and the destination dimension
// so the two can never drift. In particular the #5828 degenerate case — `any`
// (or the family-scoped `any-ipv4`/`any-ipv6`) together with `*-excluded`, i.e.
// "every address EXCEPT every address" = the empty set — must project NO rule on
// EITHER dimension. Classifying its empty concrete set as the "any" arm instead
// would invert the authored domain into an UNCONDITIONAL drop and could lock out
// all direct host-bound traffic on the ingress zone.
//
// The other arms mirror policymatch.matchAddr:
//   - constrained + excluded: match every address NOT in the set. A family with
//     no prefix in the excluded set therefore matches ALL of that family (e.g.
//     `10.0.0.0/8` + excluded drops every IPv6 address and every non-10/8 IPv4
//     one) — the intended match-all-of-opposite-family semantic.
//   - wildcard, not excluded: match everything, with no predicate rendered.
//   - constrained positive with no prefix of this family: matches nothing
//     (Junos empty-positive-set semantic).
//
// emptyBothFamilies reports that the authored match resolved to NO prefix in
// EITHER family and carries no wildcard. Combined with `excluded` that is the
// degenerate "everything except nothing" form, which Rust fails CLOSED on
// (rule_l3_matches requires !(v4_empty && v6_empty)); projecting the match-all
// arm for it would silently widen the authored scope to every firewall address
// while the dataplane denies nothing. It is unreachable via strict commit — the
// address-set member gate rejects an empty/dangling set — but reachable on the
// lenient load / peer-sync path from a config an older binary persisted.
func junosHostProjectAddrMatch(set []string, anyFam, excluded, emptyBothFamilies bool) (matchAny, matchExcluded bool, out []string, ok bool) {
	switch {
	case excluded:
		if anyFam {
			return false, false, nil, false
		}
		if emptyBothFamilies {
			// Fail CLOSED, matching Rust: project no rule at all rather than an
			// unconditional drop.
			return false, false, nil, false
		}
		return len(set) == 0, len(set) > 0, append([]string(nil), set...), true
	case anyFam:
		return true, false, nil, true
	case len(set) == 0:
		return false, false, nil, false
	default:
		return false, false, append([]string(nil), set...), true
	}
}

// junosHostSvcAdmitsIKE reports whether an EFFECTIVE per-interface host-inbound
// system-services set coarse-admits IKE/NAT-T (udp 500/4500) — the `ike`/`ipsec`
// token or a full admit.
func junosHostSvcAdmitsIKE(svc []string) bool {
	for _, s := range svc {
		// Match enforcement, which lower-cases every token before admitting
		// (unionHostInboundTokens/lowerTokens in pkg/dataplane/userspace, the
		// Rust classify_system_service). The sibling protocol path in this file
		// already normalizes (junosHostReduceApp, line ~776); the service path must
		// too or a lenient-loaded upper-case `IKE`/`IPSEC`/`ALL` is admitted by
		// enforcement yet missed here, so the coarse `application any` shield
		// drops the very IKE/NAT-T it was supposed to exempt (#5557).
		s = strings.ToLower(strings.TrimSpace(s))
		if HostInboundFullAdmitService(s) {
			return true
		}
		// #3226: `all` is no longer a full admit — it EXPANDS to the named
		// system-service union, which contains `ike`/`ipsec` (udp 500/4500).
		// Walk the expansion rather than string-comparing the authored token,
		// or an `all` zone loses its IKE exemption here while enforcement still
		// admits IKE, and the coarse `application any` shield drops the very
		// IKE/NAT-T it exists to exempt — the #5565 failure mode, reopened.
		for _, e := range HostInboundServiceTokenExpansion(s) {
			if e == "ike" || e == "ipsec" {
				return true
			}
		}
	}
	return false
}

// junosHostZoneExemptNetdevs returns the subset of `netdevs` (a zone's rendered
// ingress iifname scope from JunosHostZoneIngressNetdevs) whose EFFECTIVE
// per-interface host-inbound set admits IKE (udp 500/4500) and, separately, the
// subset that answers TCP/113 with a RST (ident-reset). It is the #5565 fix for
// the earlier zone-wide projection, which unioned every per-interface override
// into a single bit and widened a per-interface `ike`/`ident-reset` exception to
// every interface in the zone.
//
// A netdev admits IKE / RSTs ident if ANY interface ref whose host-bound traffic
// arrives on it (its own logical unit, or — for a VLAN subunit riding a physical
// parent — the parent) admits it. The union mirrors the coarse host-inbound gate
// (which keys on the interface's effective set, InterfaceHostInboundEffective) so
// the shield never false-denies a configured per-interface override, while a
// sibling interface that configured no exception is left out of the subset. A
// genuinely zone-level exception (authored on the zone's own
// host-inbound-traffic) is folded into every interface's effective set, so its
// subset equals `netdevs` and the shield stays zone-wide.
//
// The netdev→ref row walk mirrors JunosHostZoneIngressNetdevs exactly (physical
// row + one row per unit, plus the physical parent for a VLAN subunit) so the
// two agree on which ref feeds which netdev; results are filtered to `netdevs`
// so a cross-zone-ambiguous parent excluded from the iifname scope is never
// shielded.
func junosHostZoneExemptNetdevs(cfg *Config, zoneName string, zone *ZoneConfig, netdevs []string) (ikeNetdevs, identNetdevs []string) {
	// #8862: hoisted. junosHostLinuxName rebuilds the tunnel-name map on every
	// call and that map walks every interface and every unit, so resolving one
	// name per interface AND per unit here was quadratic. Same shape as #8854.
	tunNames := tunnelNameMapFn(cfg)
	if cfg == nil || zone == nil || len(netdevs) == 0 {
		return nil, nil
	}
	keep := make(map[string]bool, len(netdevs))
	for _, nd := range netdevs {
		keep[nd] = true
	}
	// Per-netdev accumulation of the effective coarse verdict across every
	// interface ref whose host-bound traffic arrives on it.
	//
	// #7173: this UNIONS the verdicts of VLAN siblings that share one physical
	// parent — addRow calls note(parent, ...) for every unit — so a parent's
	// entry is the union of what each of its units admits, not any single
	// unit's. That is deliberate and it errs toward OVER-shielding: an
	// exemption one unit needs is applied to the parent, so a sibling unit is
	// shielded where it did not strictly have to be. It is safe in the
	// direction that matters because the exempted services are authenticated
	// (IKE) or self-limiting (ident-reset) and the units share a zone, so the
	// union cannot admit anything the zone's own policy does not already allow.
	//
	// Recorded here rather than only in the issue: the natural "fix" is to make
	// the parent entry per-unit, which would narrow the shield and is the wrong
	// direction for a defense-in-depth surface.
	type verdict struct{ ike, ident, fullAdmit bool }
	byNetdev := make(map[string]*verdict, len(netdevs))
	note := func(nd, ref string) {
		if nd == "" || !keep[nd] {
			return
		}
		svc, _, _ := zone.InterfaceHostInboundEffective(ref)
		v := byNetdev[nd]
		if v == nil {
			v = &verdict{}
			byNetdev[nd] = v
		}
		if junosHostSvcAdmitsIKE(svc) {
			v.ike = true
		}
		for _, s := range svc {
			// Case-fold to match enforcement (see junosHostSvcAdmitsIKE): a
			// lenient-loaded upper-case `ALL`/`IDENT-RESET` must set the same
			// coarse verdict here as the dataplane/Rust classifier reaches, or
			// the shield diverges from what is actually admitted (#5557).
			s = strings.ToLower(strings.TrimSpace(s))
			if HostInboundFullAdmitService(s) {
				v.fullAdmit = true
			}
			// #3226: walk the expansion so `all` — which now stands for the
			// named-service union INCLUDING ident-reset — still marks the
			// netdev as answering TCP/113 with a RST. Comparing the authored
			// token alone would silently drop the ident-reset exception on
			// every `all` zone the moment `all` stopped being a full admit.
			for _, e := range HostInboundServiceTokenExpansion(s) {
				if e == "ident-reset" {
					v.ident = true
				}
			}
		}
	}
	zoneByIface := junosHostZoneByInterface(cfg)
	addRow := func(name, own, parent string, vlan int) {
		if zoneByIface[name] != zoneName {
			return
		}
		note(own, name)
		if vlan != 0 && parent != "" {
			note(parent, name)
		}
	}
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		addRow(ifName, junosHostLinuxNameWith(cfg, ifName, nil, tunNames), "", 0)
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			addRow(unitName, junosHostLinuxNameWith(cfg, ifName, unit, tunNames),
				junosHostLinuxNameWith(cfg, ifName, nil, tunNames), unit.VlanID)
		}
	}
	// Emit subsets in the sorted netdevs order for a deterministic iifname set.
	for _, nd := range netdevs {
		v := byNetdev[nd]
		if v == nil {
			continue
		}
		if v.ike {
			ikeNetdevs = append(ikeNetdevs, nd)
		}
		if v.ident && !v.fullAdmit {
			identNetdevs = append(identNetdevs, nd)
		}
	}
	return ikeNetdevs, identNetdevs
}

// Reasons a zone's candidate ingress netdev cannot be used as an iifname scope.
const (
	// junosHostNetdevAmbiguous: the netdev is claimed by MORE THAN ONE zone (a
	// shared physical parent — a zone on a trunk's untagged unit-0 while the
	// SAME parent carries another zone's tagged VLAN subunits). Scoping a deny
	// by it would over-fire on the other zone's ingress.
	junosHostNetdevAmbiguous = "cross-zone-ambiguous"
	// junosHostNetdevVRFEnslaved (#6619): the netdev is enslaved to an l3mdev
	// VRF master by the routing-instance bind in pkg/daemon
	// (applyVRFReconcile -> BindInterfaceToVRF -> LinkSetMaster). At the
	// netfilter LOCAL_IN hook the l3mdev rcv handler has already replaced
	// skb->dev with the VRF device, so `meta iifname` reports the MASTER and an
	// `iifname "<enslaved>"` rule matches nothing. Measured on the kernel floor
	// this project targets, at the exact hook and priority xpf_hostinbound
	// installs: 0 hits on the enslaved name, 3 on the master, and 3 on an
	// unconditional counter — the hook runs exactly once, so there is no second
	// pass carrying the enslaved name.
	junosHostNetdevVRFEnslaved = "vrf-enslaved"
)

// junosHostUnscopableNetdev is one candidate ingress netdev that cannot serve as
// an iifname scope, with the reason.
type junosHostUnscopableNetdev struct {
	Netdev string
	Reason string
}

// junosHostZoneNetdevCoverage is one zone's iifname-scope resolution.
//
// The three states are NOT interchangeable and the projection reads them
// differently (#6564 member 8):
//
//   - No candidates at all (both fields empty) — a lifeline-only zone, or one
//     with no interfaces. There is NOTHING to enforce, so this must not block a
//     policy's warning suppression.
//   - Scoped non-empty, Unscopable empty — fully resolved. Rules are emitted and
//     the policy is genuinely enforced on every ingress path of the zone.
//   - Unscopable non-empty — the zone HAD candidates and at least one of its OWN
//     ingress netdevs could not be used. Whatever survived is still emitted
//     (never withdraw protection that works), but the policy is NOT enforced on
//     every ingress path of the zone, so its warning must not be suppressed.
//     This covers both "some resolved" and "none resolved"; the difference
//     between them is only whether any rule is emitted, not whether the policy
//     is fully enforced.
//
// Only an OWN netdev counts toward Unscopable. A dropped PARENT superset
// candidate does not: a VLAN subunit contributes its physical parent as an extra
// candidate for the bondless-RETH case, and on a plain 802.1Q trunk that parent
// is never where the subunit's frames arrive, so its loss is not a gap. Counting
// it would warn on every trunk carrying an untagged unit-0 in one zone and
// tagged subunits in others — an ordinary correct config, and the population an
// advisory must not fire on if operators are to keep reading it.
type junosHostZoneNetdevCoverage struct {
	Scoped     []string
	Unscopable []junosHostUnscopableNetdev
}

// JunosHostZoneIngressNetdevs returns, per security zone, the sorted set of
// kernel netdev names a host-bound packet on that zone arrives with — the
// iifname scope for the zone's #4146 junos-host DROP rules. It EXCLUDES
// lifelines, any netdev claimed by MORE THAN ONE zone (an ambiguous shared
// physical parent — e.g. a zone on a trunk's untagged unit-0 while the SAME
// parent carries other zones' tagged VLAN subunits) so a zone's deny can never
// over-fire on another zone's ingress, and any netdev enslaved to an l3mdev VRF
// (#6619) because `iifname` at LOCAL_IN names the VRF master, not the enslaved
// device, so such a rule matches nothing.
//
// It is the SSOT for the iifname scope: the dataplane BuildJunosHostPrograms
// consumes JunosHostDenyProgram.IngressNetdevs (populated from this) for kernel
// emission. Warning suppression is gated on the richer
// junosHostZoneNetdevCoverage below, NOT on this result being non-empty: a zone
// that resolved SOME of its candidates emits rules while still not enforcing the
// policy on every ingress path, and a non-empty check cannot tell that from full
// coverage (#6564 member 8). The netdev-name resolution mirrors the dataplane
// interface-snapshot LinuxName (userspace.snapshotLinuxName) exactly, pinned
// byte-for-byte by TestJunosHostZoneNetdevsMatchSnapshot so the two planes
// cannot drift.
func JunosHostZoneIngressNetdevs(cfg *Config) map[string][]string {
	cov := junosHostZoneNetdevCoverageMap(cfg)
	if len(cov) == 0 {
		return nil
	}
	out := map[string][]string{}
	for zone, c := range cov {
		if len(c.Scoped) > 0 {
			out[zone] = c.Scoped
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// junosHostVRFEnslavedNetdevs returns the set of kernel netdev names the daemon
// binds to an l3mdev VRF master. It mirrors applyVRFReconcile
// (pkg/daemon/daemon_apply_interfaces.go) exactly: every interface member of
// every routing instance whose instance-type is not `forwarding` (a forwarding
// instance creates no VRF device and enslaves nothing).
//
// Members are resolved through netdevByRef — the SAME ref->netdev map the
// candidate walk builds — so a bare physical member (`ge-0/0/1`) and its
// untagged unit-0, which share one netdev, are both covered by a single entry,
// and a member naming no configured interface contributes nothing (it cannot be
// a zone candidate either). A VLAN subunit is a distinct kernel device with its
// own master, so enslaving the parent does NOT enslave the subunit — keying on
// the netdev rather than the ref gets that right without a special case.
func junosHostVRFEnslavedNetdevs(cfg *Config, netdevByRef map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" {
			continue
		}
		for _, member := range ri.Interfaces {
			if member == "" {
				continue
			}
			if nd := netdevByRef[CanonicalInterfaceUnitRef(member)]; nd != "" {
				out[nd] = true
			}
		}
	}
	return out
}

// junosHostZoneNetdevCoverageMap resolves every zone's iifname scope and records
// what it could NOT use, so the projection can distinguish "nothing to enforce"
// from "could not fully enforce".
func junosHostZoneNetdevCoverageMap(cfg *Config) map[string]junosHostZoneNetdevCoverage {
	// #8862: hoisted. junosHostLinuxName rebuilds the tunnel-name map on every
	// call and that map walks every interface and every unit, so resolving one
	// name per interface AND per unit here was quadratic. Same shape as #8854.
	tunNames := tunnelNameMapFn(cfg)
	if cfg == nil || len(cfg.Security.Zones) == 0 || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	zoneByIface := junosHostZoneByInterface(cfg)
	// cand[zone][netdev] records whether the netdev is the zone's OWN ingress
	// device (true) or only a conservative PARENT superset candidate (false).
	// The distinction decides whether losing it is a coverage GAP: a subunit's
	// own netdev is where its frames actually arrive, whereas the physical
	// parent is added for the bondless-RETH case where they may ride the member
	// instead. Losing a parent candidate costs a plain 802.1Q zone nothing —
	// tagged frames are demuxed to the subunit netdev — so treating it as a gap
	// would warn on every trunk that carries an untagged unit-0 in one zone and
	// tagged subunits in others, which is an ordinary correct config.
	cand := map[string]map[string]bool{}   // zone -> netdev -> isOwn
	claims := map[string]map[string]bool{} // netdev -> zone set
	addCand := func(zone, nd string, own bool) {
		if zone == "" || nd == "" {
			return
		}
		if cand[zone] == nil {
			cand[zone] = map[string]bool{}
		}
		cand[zone][nd] = cand[zone][nd] || own
		if claims[nd] == nil {
			claims[nd] = map[string]bool{}
		}
		claims[nd][zone] = true
	}
	// One "row" per physical interface + one per unit, mirroring the dataplane
	// interface snapshot: the row's own netdev is the candidate, plus (for a VLAN
	// subunit whose frames ride the physical parent) the parent netdev.
	addRow := func(name, own, parent string, vlan int) {
		if HostInboundLifelineInterface(name, lifelines) {
			return
		}
		zone := zoneByIface[name]
		if zone == "" {
			return
		}
		addCand(zone, own, true)
		if vlan != 0 && parent != "" {
			addCand(zone, parent, false)
		}
	}
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	// Pass 1: ref -> netdev for every physical and unit row, so the VRF member
	// list resolves through the SAME name rule the candidates use.
	netdevByRef := junosHostNetdevByRef(cfg, func(ifName string, unit *InterfaceUnit) string {
		return junosHostLinuxNameWith(cfg, ifName, unit, tunNames)
	})
	enslaved := junosHostVRFEnslavedNetdevs(cfg, netdevByRef)
	// Pass 2: the candidate walk. One "row" per physical interface + one per
	// unit, mirroring the dataplane interface snapshot.
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		addRow(ifName, junosHostLinuxNameWith(cfg, ifName, nil, tunNames), "", 0)
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			addRow(unitName, junosHostLinuxNameWith(cfg, ifName, unit, tunNames),
				junosHostLinuxNameWith(cfg, ifName, nil, tunNames), unit.VlanID)
		}
	}
	out := map[string]junosHostZoneNetdevCoverage{}
	for zone, nds := range cand {
		var c junosHostZoneNetdevCoverage
		names := make([]string, 0, len(nds))
		for nd := range nds {
			names = append(names, nd)
		}
		sort.Strings(names)
		for _, nd := range names {
			reason := ""
			switch {
			// Ambiguity is reported first: it is the pre-existing reason and the
			// one an operator resolves by re-zoning, whereas an enslaved netdev
			// is not scopable by any zoning change.
			case len(claims[nd]) != 1:
				reason = junosHostNetdevAmbiguous
			case enslaved[nd]:
				reason = junosHostNetdevVRFEnslaved
			}
			if reason == "" {
				c.Scoped = append(c.Scoped, nd)
				continue
			}
			// Only an OWN netdev that could not be scoped is a coverage gap. A
			// dropped PARENT superset candidate is not: the subunit's own netdev
			// still covers where its frames arrive.
			if nds[nd] {
				c.Unscopable = append(c.Unscopable,
					junosHostUnscopableNetdev{Netdev: nd, Reason: reason})
			}
		}
		out[zone] = c
	}
	return out
}

// junosHostLinuxName resolves an interface ref to its kernel netdev name,
// mirroring userspace.snapshotLinuxName EXACTLY (VLAN subunit -> parent.vlanid,
// reth unit resolution, tunnel name map, physical passthrough). Kept here so the
// #4146 iifname scope can be resolved purely from config (the dataplane consumes
// the result via JunosHostDenyProgram.IngressNetdevs); TestJunosHostZoneNetdevs
// MatchSnapshot pins it against the snapshot.
//
// The secure-tunnel arm is NOT mirrored — it is SHARED
// (Config.SecureTunnelUnitNetdev, xfrmi.go). #6691: that rule cannot be
// re-derived here, because the netdev depends on the authored bind-interface
// string rather than on the ref, and this function does not otherwise read the
// IPsec config at all. A mirrored copy of it drifted once already and left a
// junos-host deny scoped to a nonexistent netdev; the remaining arms are still
// mirrors, held by the parity test, which now carries a secure-tunnel case.
// junosHostLinuxName resolves one interface/unit to its Linux device name,
// building the tunnel-name map itself. A caller resolving MANY names should
// hoist the map once and use junosHostLinuxNameWith (#8862).
func junosHostLinuxName(cfg *Config, ifName string, unit *InterfaceUnit) string {
	return junosHostLinuxNameWith(cfg, ifName, unit, tunnelNameMapFn(cfg))
}

// junosHostLinuxNameWith is junosHostLinuxName with the tunnel-name map
// supplied by the caller. The map walks every interface and every unit, so
// rebuilding it per name made the enclosing per-interface/per-unit loops
// quadratic — this was 49% cumulative in the profile taken after #8854.
//
// The map is REQUIRED rather than optionally nil: TunnelNameMap returns a
// non-nil EMPTY map when no tunnels are configured, so nil would be a sentinel
// colliding with a legitimate value.
func junosHostLinuxNameWith(cfg *Config, ifName string, unit *InterfaceUnit, tunNames map[string]string) string {
	if unit != nil {
		// #6691: a secure-tunnel unit's netdev is resolved from the AUTHORED
		// bind-interface, NOT by the unit-zero collapse below. Both this and
		// snapshotLinuxName call the one resolver rather than restating the
		// rule — restating it is how the iifname scope of a junos-host deny
		// came to name `st0` while the decrypted traffic arrived on `st0.0`,
		// leaving the deny unable to fire. Placed FIRST, matching
		// ResolveKernelIfName's ordering (the st rule precedes the tunnel-name
		// map there too).
		if dev, ok := cfg.SecureTunnelUnitNetdev(fmt.Sprintf("%s.%d", ifName, unit.Number)); ok {
			return dev
		}
		if tunnelNames := tunNames; len(tunnelNames) > 0 {
			ref := fmt.Sprintf("%s.%d", ifName, unit.Number)
			if linuxName, ok := tunnelNames[ref]; ok && linuxName != "" {
				return linuxName
			}
		}
		if unit.VlanID > 0 {
			return fmt.Sprintf("%s.%d", LinuxIfName(cfg.ResolveReth(ifName)), unit.VlanID)
		}
		if strings.HasPrefix(ifName, "reth") {
			if unit.Number == 0 {
				return LinuxIfName(cfg.ResolveReth(ifName))
			}
			return LinuxIfName(cfg.ResolveReth(fmt.Sprintf("%s.%d", ifName, unit.Number)))
		}
		if unit.Number == 0 {
			return LinuxIfName(ifName)
		}
		return LinuxIfName(fmt.Sprintf("%s.%d", ifName, unit.Number))
	}
	if strings.HasPrefix(ifName, "reth") {
		return LinuxIfName(cfg.ResolveReth(ifName))
	}
	return LinuxIfName(ifName)
}

// junosHostZoneByInterface maps every interface ref (physical, base, and each
// unit) to its security zone, mirroring userspace.buildInterfaceZoneMap so the
// netdev resolution above assigns the same zone the dataplane snapshot does.
func junosHostZoneByInterface(cfg *Config) map[string]string {
	out := make(map[string]string, len(cfg.Security.Zones))
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			// #5878 phase 2: bind on the canonical logical-unit identity so this
			// mirror resolves ge-0/0/0.01 to the same runtime unit (ge-0/0/0.1)
			// the dataplane snapshot does — the consumer looks this map up by the
			// canonical "%s.%d" unit name.
			iface := CanonicalInterfaceUnitRef(rawIface)
			if _, exists := out[iface]; !exists {
				out[iface] = zoneName
			}
			if base, unit, ok := strings.Cut(iface, "."); ok && base != "" {
				if _, exists := out[base]; !exists {
					out[base] = zoneName
				}
				if unit != "" {
					continue
				}
			}
			if ifCfg := cfg.Interfaces.Interfaces[iface]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					unitName := fmt.Sprintf("%s.%d", iface, unitNum)
					if _, exists := out[unitName]; !exists {
						out[unitName] = zoneName
					}
				}
			}
		}
	}
	return out
}
