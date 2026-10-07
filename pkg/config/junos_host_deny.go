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
//   - FIRST-MATCH, NEVER A FINE ACCEPT (#9504), WITH A KERNEL TERMINAL DENY
//     FOR PERMIT PROGRAMS (#11065): each ingress zone's program renders, in
//     authored order, into its own nft subchain. A `deny` silently drops, a
//     `reject` answers (TCP RST, else ICMP administratively prohibited), and a
//     `permit` RETURNS from the subchain so the coarse host-inbound gate still
//     decides. Zone `tcp-rst` applies to transit TCP session misses, not policy
//     denies. A permit never emits a fine accept (that could re-admit a coarse-
//     rejected service — Rust poll_descriptor/mod.rs:138). If a permit matches
//     a subset of one family, the kernel subchain's terminal deny refuses the
//     on the direct host-bound path. The userspace path deliberately keeps its
//     deliver-on-no-match lifeline (policy.rs
//     evaluate_junos_host_policy_l3_aware, policymatch.matchJunosHost), so
//     permit warnings remain for that residual path; host-inbound admission
//     must suffice wherever the kernel deny-half does not reach (lifeline,
//     lo0, unzoned-addressed, tunnel paths).
//   - Fine-eligible metadata: ESP/AH (proto 50/51) are always exempt; the
//     IKE subset feeds the #10524 overlap advisory, while ident-reset TCP/113
//     is exempt only when the effective coarse verdict is the RST
//     (ident-reset set AND not all/any-service). The daemon renders only the
//     retained ident RST ahead of an `application any` drop; it never renders
//     an IKE ACCEPT.

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
	// JunosHostDrop is `then deny`: a silent drop. The ingress zone's
	// `tcp-rst` setting affects TCP session misses, not policy denies.
	JunosHostDrop JunosHostVerdict = iota
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
	return v == JunosHostReject
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

// HostInboundVRFIngressScope pairs a LOCAL_IN-visible VRF master with the
// enslaved devices whose packets belong to one zone.
type HostInboundVRFIngressScope struct {
	Master string
	Slaves []string
}

// JunosHostDenyProgram is the effective ordered junos-host program for one
// ingress zone.
type JunosHostDenyProgram struct {
	Zone string
	// InterfaceRefs are the zone's NON-lifeline interface refs (config names,
	// e.g. "reth0.50"). Informational; the actual iifname scope is IngressNetdevs.
	InterfaceRefs []string
	// IngressNetdevs is the sorted set of direct iifname scopes. VRF members
	// whose master is shared (or has an unzoned/lifeline co-member) use
	// IngressVRFScopes instead, so LOCAL_IN identity is recovered with sdifname.
	IngressNetdevs   []string
	IngressVRFScopes []HostInboundVRFIngressScope
	// Representable is false when any contributing term is un-representable; the
	// program then carries NO rules and the daemon emits nothing for the zone.
	Representable bool
	// RulesV4 / RulesV6 are the projected rules, each family in first-match
	// order. If the program has any scoped PERMIT, every family without a
	// match-all permit ends in the #11065 terminal deny, after authored returns.
	RulesV4 []JunosHostDenyRule
	RulesV6 []JunosHostDenyRule
	// CoarseAdmitsIKE / CoarseIdentResets describe effective coarse metadata for
	// fine-eligible L4. CoarseIdentResets drives the retained terminal ident RST;
	// CoarseAdmitsIKE plus IKE exemption scopes identifies #10524 overlap eligibility.
	CoarseAdmitsIKE   bool
	CoarseIdentResets bool
	// These subsets identify the VRF slaves whose coarse host-inbound set admits
	// IKE or answers TCP/113 with a RST. IKE metadata is warning-only; ident scopes
	// are rendered as the retained terminal RST shield.
	IKEExemptVRFScopes  []HostInboundVRFIngressScope
	IdentResetVRFScopes []HostInboundVRFIngressScope
	IKEExemptNetdevs    []string
	IdentResetNetdevs   []string
	// HasApplicationAnyDeny is true when the program contains a rendered
	// `application any` rule with a DENY-class verdict. The daemon uses this
	// aggregate shape together with CoarseIdentResets to retain the ident RST;
	// the warning validator joins individual policy provenance separately.
	HasApplicationAnyDeny bool
}

type junosHostPolicyCoverageGaps map[string]map[string]string // zone -> netdev -> reason

// JunosHostDenyProjection is the whole-config result: the per-zone programs the
// daemon renders, plus policy-key and coverage bookkeeping for the #4168
// warning. RenderedPolicyKeys is the aggregate set of DENY/REJECT keys that have
// at least one applicable enforceable ordinary zone and for which every
// applicable ordinary zone was fully scoped, representable, and emitted the key.
// The validator suppresses only when this set contains the key and
// LifelineOnlyZones has no entry for it.
// RenderedApplicationAnyPolicyKeysByZone is narrower provenance for #10524:
// it records application-any DENY/REJECT keys that emitted a rule in each
// surviving zone, even when that zone has partial netdev coverage and therefore
// cannot enter the global RenderedPolicyKeys suppression set.
//
// RenderedPolicyZoneKeys records the ordinary zones that emitted each aggregate
// rendered key. LifelineOnlyZones records policy applicability on fully-scoped
// zones with a configured lifeline ref and no non-lifeline candidates: there is
// no kernel rule by design, so the warning is retained. unscopableIngressByKey
// records candidate netdevs skipped by the iifname scope, so the retained
// warning can name the exact uncovered path.
type JunosHostDenyProjection struct {
	Programs                               []JunosHostDenyProgram
	RenderedPolicyKeys                     map[string]bool
	RenderedApplicationAnyPolicyKeysByZone map[string]map[string]bool
	// RenderedPolicyZoneKeys maps a policy key to the enforceable ingress
	// zones where it rendered an enforced DENY/REJECT kernel rule. The inner
	// value is a zone set; consumers sort names before operator-visible formatting.
	RenderedPolicyZoneKeys map[string]map[string]bool
	// LifelineOnlyZones maps a policy key to sorted zones where the policy
	// applies with a configured lifeline ref but no non-lifeline candidates
	// (no kernel rule by design, lifeline NEVER-deny). A rendered key with a
	// non-empty entry keeps its warning.
	LifelineOnlyZones map[string][]string
	// unscopableIngressByKey maps each policy key to its direct-path ingress
	// coverage gaps, keyed by zone then kernel netdev, with the reason.
	unscopableIngressByKey map[string]junosHostPolicyCoverageGaps
}

// JunosHostZonePairPolicyKey / JunosHostGlobalPolicyKey are the stable identity
// keys used to correlate a rendered program back to the emitting policy. The
// projection and warning compute the same key; coverage-aware suppression also
// consults LifelineOnlyZones when the policy applies to configured lifeline-only
// applicability.
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
	// skipPermit marks an incomplete permit whose match intent is absent from
	// the compiled policy, either because policy content was dropped or a
	// referenced application carries dropped match constraints. Such a permit
	// must not carve later denies in the kernel projection.
	skipPermit bool
}

// BuildJunosHostDenyProjection projects every configured ingress zone's
// effective `to-zone junos-host` policy program into the kernel-representable
// DROP-only form. It is the SSOT consumed by both the daemon nft codegen (via
// the pkg/dataplane/userspace wrapper) and the #4168 commit warning.
func BuildJunosHostDenyProjection(cfg *Config) JunosHostDenyProjection {
	out := JunosHostDenyProjection{
		RenderedPolicyKeys:                     map[string]bool{},
		RenderedApplicationAnyPolicyKeysByZone: map[string]map[string]bool{},
		RenderedPolicyZoneKeys:                 map[string]map[string]bool{},
		LifelineOnlyZones:                      map[string][]string{},
		unscopableIngressByKey:                 map[string]junosHostPolicyCoverageGaps{},
	}
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

	// Per-policy-key bookkeeping to decide rendered-vs-warned (§3.3): a DENY or
	// REJECT policy is rendered at policy level iff it applies to >=1 ordinary
	// enforceable ingress zone and EVERY such zone's whole program has emitted
	// it. A permit's kernel deny-half is now enforced on the direct host-bound
	// path, but the runtime's deliberate userspace no-match lifeline remains, so
	// its warning is retained. LifelineOnlyZones also retains warnings for
	// uncovered configured lifeline applicability.
	appliesEnforceable := map[string]int{}
	blockedByUnrep := map[string]bool{}
	actionByKey := map[string]PolicyAction{}
	// renderedZonesByKey records the enforceable zones where a term emitted a
	// kernel rule. It is copied into RenderedPolicyZoneKeys for aggregate-rendered
	// DENY/REJECT keys.
	renderedZonesByKey := map[string]map[string]bool{}
	// lifelineZonesByKey records policy applicability on configured lifeline-only
	// zones with no non-lifeline candidates and therefore no kernel rule. Keep it
	// separate from blockedByUnrep: an unscopable ordinary candidate is an
	// ordinary coverage gap.
	lifelineZonesByKey := map[string]map[string]bool{}

	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	excludedZones := ZoneQuarantineExclusions(zoneNames)

	for _, zoneName := range zoneNames {
		if _, excluded := excludedZones[zoneName]; excluded {
			continue
		}
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		terms := junosHostEffectiveTerms(cfg, zoneName, feedBound)
		if len(terms) == 0 {
			continue
		}
		ifaceRefs := junosHostNonLifelineRefs(zone, lifelines)
		hasLifelineRef := false
		for _, ref := range zone.Interfaces {
			if HostInboundLifelineInterface(ref, lifelines) {
				hasLifelineRef = true
				break
			}
		}
		cov := coverageByZone[zoneName]
		netdevs := cov.Scoped
		vrfScopes := cov.VRFScopes
		// TWO decisions, deliberately not one boolean (#6564 member 8).
		//
		// emitsRules gates kernel emission: a DROP needs at least one direct
		// iifname or VRF master+sdifname scope.
		//
		// fullyScoped gates #4168 warning suppression for ordinary ingress
		// coverage. A zone with any unresolved own ingress still warns, even if
		// some direct or slave-scoped rules survive.
		emitsRules := len(netdevs) > 0 || len(vrfScopes) > 0
		fullyScoped := len(cov.Unscopable) == 0
		representable := true
		for _, t := range terms {
			if !t.representable {
				representable = false
				break
			}
		}
		var prog JunosHostDenyProgram
		// emitted is the subset of this zone's term keys that actually produced
		// >=1 rule; nil whenever no program was projected at all (#6705).
		var emitted map[string]bool
		if emitsRules && representable {
			prog, emitted = junosHostProjectProgram(zoneName, ifaceRefs, terms)
			prog.IngressNetdevs = netdevs
			prog.IngressVRFScopes = vrfScopes
			prog.IKEExemptNetdevs, prog.IdentResetNetdevs,
				prog.IKEExemptVRFScopes, prog.IdentResetVRFScopes =
				junosHostZoneExemptNetdevs(cfg, zoneName, zone, netdevs, vrfScopes)
			prog.CoarseAdmitsIKE = len(prog.IKEExemptNetdevs) > 0 || len(prog.IKEExemptVRFScopes) > 0
			prog.CoarseIdentResets = len(prog.IdentResetNetdevs) > 0 || len(prog.IdentResetVRFScopes) > 0
			for key, didEmit := range emitted {
				if !didEmit {
					continue
				}
				if renderedZonesByKey[key] == nil {
					renderedZonesByKey[key] = map[string]bool{}
				}
				renderedZonesByKey[key][zoneName] = true
			}
		}
		// No candidates on a configured lifeline-only zone is intentional. It must
		// not block ordinary-zone enforcement, but applicable policy keys still need
		// one warning for this uncovered zone. A zone with no configured lifeline ref
		// is not an ingress path and must not affect suppression.
		if !emitsRules && fullyScoped && hasLifelineRef {
			for _, t := range terms {
				if lifelineZonesByKey[t.key] == nil {
					lifelineZonesByKey[t.key] = map[string]bool{}
				}
				lifelineZonesByKey[t.key][zoneName] = true
			}
		}
		// #10524 exact provenance: retain the app-any DENY/REJECT keys that
		// emitted a rule in THIS surviving zone. This intentionally ignores
		// fullyScoped / global RenderedPolicyKeys status; partial coverage still
		// needs the overlap advisory for the netdevs where the rule exists.
		if emitsRules && representable {
			appAnyKeys := make(map[string]bool)
			for _, t := range terms {
				if emitted[t.key] && t.appAny &&
					(t.action == PolicyDeny || t.action == PolicyReject) {
					appAnyKeys[t.key] = true
				}
			}
			out.RenderedApplicationAnyPolicyKeysByZone[zoneName] = appAnyKeys
		}
		// Bookkeeping for the warning.
		for _, t := range terms {
			actionByKey[t.key] = t.action
			// Preserve the per-policy reason for every unscopable candidate;
			// the warning must identify the ingress gap, not imply that no
			// kernel policy is installed anywhere.
			if len(cov.Unscopable) > 0 {
				if out.unscopableIngressByKey[t.key] == nil {
					out.unscopableIngressByKey[t.key] = junosHostPolicyCoverageGaps{}
				}
				if out.unscopableIngressByKey[t.key][zoneName] == nil {
					out.unscopableIngressByKey[t.key][zoneName] = map[string]string{}
				}
				for _, gap := range cov.Unscopable {
					out.unscopableIngressByKey[t.key][zoneName][gap.Netdev] = gap.Reason
				}
			}
			// No rule can cover every candidate when any own netdev was
			// unscopable, even if scoped siblings still received protection.
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
			if zones := renderedZonesByKey[key]; len(zones) > 0 {
				out.RenderedPolicyZoneKeys[key] = zones
			}
		}
	}
	for key, zones := range lifelineZonesByKey {
		names := make([]string, 0, len(zones))
		for zone := range zones {
			names = append(names, zone)
		}
		sort.Strings(names)
		out.LifelineOnlyZones[key] = names
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
// tuple marks the term un-representable. A permit with dropped application
// matches is skipped so it cannot carve a later deny. Otherwise each
// representable action keeps its verdict in first-match order (#9504).
func junosHostProjectTerm(cfg *Config, key string, p *Policy, feedBound map[string]bool) junosHostTerm {
	t := junosHostTerm{key: key, action: p.Action, representable: true}
	// A LenientContentDropped permit has policy enforcement intent absent from
	// the compiled policy. A referenced application with match drops has the
	// same problem for this projection: userspace refuses that reference too
	// (ApplicationReferenceMatchDrops, #9525), but the kernel host-bound path
	// must independently avoid turning it into an unconstrained permit. Skip the
	// permit before resolution; any later deny rules remain authored and can
	// only drop more traffic. A poisoned DENY is left intact because widening a
	// DROP is the fail-closed direction.
	if p.Action == PolicyPermit {
		if p.LenientContentDropped {
			t.skipPermit = true
			return t
		}
		// `any` subsumes every named application in a policy match, so a bad
		// sibling reference cannot widen this all-protocol match.
		containsAny := false
		for _, name := range p.Match.Applications {
			if name == "" || name == "any" {
				containsAny = true
				break
			}
		}
		if !containsAny {
			for _, name := range p.Match.Applications {
				if len(ApplicationReferenceMatchDrops(name, &cfg.Applications)) > 0 {
					t.skipPermit = true
					return t
				}
			}
		}
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
// subchain before the deny's rule is reached.
//
// #11065: a scoped permit can leave traffic unmatched by an authored rule.
// Append a terminal deny in every family that is not covered by a match-all
// permit, including families where the permit did not emit a rule (e.g. an
// IPv4-only permit must not leave IPv6 on coarse fallback). Preserve each
// permit return ahead of the terminal; a match-all permit already returns
// every packet in its family and makes that family's terminal unnecessary.
// The userspace `None => deliver` lifeline is unchanged, so the existing permit
// warning stays to describe that residual path.
func junosHostProjectProgram(zone string, ifaceRefs []string, terms []junosHostTerm) (JunosHostDenyProgram, map[string]bool) {
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
	var doneV4, doneV6, hasPermitV4, hasPermitV6 bool
	for _, t := range terms {
		if t.action == PolicyPermit && t.skipPermit {
			continue // An incomplete permit carves nothing.
		}
		verdict := junosHostTermVerdict(t.action)
		add := func(family string, rules *[]JunosHostDenyRule, done, hasPermit *bool) {
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
				*hasPermit = true
				*done = junosHostRuleMatchesFamily(r)
			} else if t.appAny {
				prog.HasApplicationAnyDeny = true
			}
		}
		add("ip", &prog.RulesV4, &doneV4, &hasPermitV4)
		add("ip6", &prog.RulesV6, &doneV6, &hasPermitV6)
	}
	terminal := junosHostTermVerdict(PolicyDeny)
	hasPermitProgram := hasPermitV4 || hasPermitV6
	if hasPermitProgram && !doneV4 {
		prog.RulesV4 = append(prog.RulesV4, JunosHostDenyRule{
			Family: "ip", SrcAny: true, DstAny: true, Verdict: terminal,
		})
	} else {
		prog.RulesV4 = junosHostTrimTrailingReturns(prog.RulesV4)
	}
	if hasPermitProgram && !doneV6 {
		prog.RulesV6 = append(prog.RulesV6, JunosHostDenyRule{
			Family: "ip6", SrcAny: true, DstAny: true, Verdict: terminal,
		})
	} else {
		prog.RulesV6 = junosHostTrimTrailingReturns(prog.RulesV6)
	}
	return prog, emitted
}

// junosHostTermVerdict maps a term's action to its rule verdict.
func junosHostTermVerdict(action PolicyAction) JunosHostVerdict {
	switch action {
	case PolicyPermit:
		return JunosHostReturn
	case PolicyReject:
		return JunosHostReject
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
// token or a full admit. The result feeds projection metadata and the #10524
// overlap warning; it does not authorize an IKE render in the fine window.
func junosHostSvcAdmitsIKE(svc []string) bool {
	for _, s := range svc {
		// Match enforcement, which lower-cases every token before admitting
		// (unionHostInboundTokens/lowerTokens in pkg/dataplane/userspace, the
		// Rust classify_system_service). The sibling protocol path in this file
		// already normalizes (junosHostReduceApp, line ~776); the service path must
		// too or a lenient-loaded upper-case `IKE`/`IPSEC`/`ALL` is admitted by
		// enforcement yet missed here, so the #10524 overlap warning is skipped.
		s = strings.ToLower(strings.TrimSpace(s))
		if HostInboundFullAdmitService(s) {
			return true
		}
		// #3226: `all` is no longer a full admit — it EXPANDS to the named
		// system-service union, which contains `ike`/`ipsec` (udp 500/4500).
		// Walk the expansion rather than string-comparing the authored token,
		// or an `all` zone loses its IKE metadata while enforcement still admits
		// IKE and the #10524 warning becomes a false negative.
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
// parent — the parent) admits it. For VRF members, LOCAL_IN sees the VRF master;
// the raw member netdev is therefore translated to its master before filtering
// against `netdevs`. The union mirrors the coarse host-inbound gate (which keys on
// the interface's effective set, InterfaceHostInboundEffective) so IKE warning
// metadata and the retained ident RST scope never miss a configured per-interface
// override, while a sibling interface that configured no exception is left out.
// A genuinely zone-level exception (authored on the zone's own
// host-inbound-traffic) is folded into every interface's effective set, so its
// subset equals `netdevs`.
//
// The netdev→ref row walk mirrors JunosHostZoneIngressNetdevs exactly (physical
// row + one row per unit, plus the physical parent for a VLAN subunit) so the
// two agree on which ref feeds which netdev; results are filtered to `netdevs`
// so a cross-zone-ambiguous parent excluded from the iifname scope is never
// included in warning metadata or ident RST scope.
func junosHostZoneExemptNetdevs(cfg *Config, zoneName string, zone *ZoneConfig, netdevs []string, vrfScopes []HostInboundVRFIngressScope) (ikeNetdevs, identNetdevs []string, ikeVRFScopes, identVRFScopes []HostInboundVRFIngressScope) {
	tunNames := tunnelNameMapFn(cfg)
	if cfg == nil || zone == nil || (len(netdevs) == 0 && len(vrfScopes) == 0) {
		return nil, nil, nil, nil
	}
	keep := make(map[string]bool, len(netdevs))
	for _, nd := range netdevs {
		keep[nd] = true
	}
	vrfScopeSlaves := make(map[string]map[string]bool, len(vrfScopes))
	for _, scope := range vrfScopes {
		if vrfScopeSlaves[scope.Master] == nil {
			vrfScopeSlaves[scope.Master] = make(map[string]bool, len(scope.Slaves))
		}
		for _, slave := range scope.Slaves {
			vrfScopeSlaves[scope.Master][slave] = true
		}
	}
	type verdict struct{ ike, ident, fullAdmit bool }
	byNetdev := make(map[string]*verdict, len(netdevs))
	byVRFSlave := make(map[string]map[string]*verdict, len(vrfScopes))
	vrfMasterByNetdev := junosHostVRFMasterNetdevs(cfg, tunNames)
	note := func(nd, ref string) {
		var v *verdict
		if master, enslaved := vrfMasterByNetdev[nd]; enslaved {
			if master == "" {
				return
			}
			if keep[master] {
				nd = master
				v = byNetdev[nd]
				if v == nil {
					v = &verdict{}
					byNetdev[nd] = v
				}
			} else if vrfScopeSlaves[master][nd] {
				if byVRFSlave[master] == nil {
					byVRFSlave[master] = map[string]*verdict{}
				}
				v = byVRFSlave[master][nd]
				if v == nil {
					v = &verdict{}
					byVRFSlave[master][nd] = v
				}
			} else {
				return
			}
		} else {
			if nd == "" || !keep[nd] {
				return
			}
			v = byNetdev[nd]
			if v == nil {
				v = &verdict{}
				byNetdev[nd] = v
			}
		}
		svc, _, _ := zone.InterfaceHostInboundEffective(ref)
		if junosHostSvcAdmitsIKE(svc) {
			v.ike = true
		}
		for _, s := range svc {
			s = strings.ToLower(strings.TrimSpace(s))
			if HostInboundFullAdmitService(s) {
				v.fullAdmit = true
			}
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
	masters := make([]string, 0, len(byVRFSlave))
	for master := range byVRFSlave {
		masters = append(masters, master)
	}
	sort.Strings(masters)
	for _, master := range masters {
		var ikeSlaves, identSlaves []string
		for slave, v := range byVRFSlave[master] {
			if v.ike {
				ikeSlaves = append(ikeSlaves, slave)
			}
			if v.ident && !v.fullAdmit {
				identSlaves = append(identSlaves, slave)
			}
		}
		sort.Strings(ikeSlaves)
		sort.Strings(identSlaves)
		if len(ikeSlaves) > 0 {
			ikeVRFScopes = append(ikeVRFScopes, HostInboundVRFIngressScope{Master: master, Slaves: ikeSlaves})
		}
		if len(identSlaves) > 0 {
			identVRFScopes = append(identVRFScopes, HostInboundVRFIngressScope{Master: master, Slaves: identSlaves})
		}
	}
	return ikeNetdevs, identNetdevs, ikeVRFScopes, identVRFScopes
}

// Reasons a zone's candidate ingress netdev cannot be used as an iifname scope.
const (
	// junosHostNetdevAmbiguous: the netdev is claimed by MORE THAN ONE zone (a
	// shared physical parent — a zone on a trunk's untagged unit-0 while the
	// SAME parent carries another zone's tagged VLAN subunits). Scoping a deny
	// by it would over-fire on the other zone's ingress.
	junosHostNetdevAmbiguous = "cross-zone-ambiguous"
	// junosHostNetdevVRFEnslaved (#6619): a member whose LOCAL_IN-visible
	// master cannot be resolved because a device is claimed by conflicting
	// routing instances. A normal VRF member is instead scoped by its master;
	// scoping the raw enslaved name would never match LOCAL_IN.
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
//   - No candidates at all (both fields empty) — a zone with a configured
//     lifeline ref and no non-lifeline interfaces. There is NOTHING to enforce,
//     so this must not block ordinary-zone suppression. The projection records
//     this configured lifeline applicability so a shared or per-zone policy
//     retains one warning; a no-interface zone is not recorded.
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
	VRFScopes  []HostInboundVRFIngressScope
	Unscopable []junosHostUnscopableNetdev
}

// JunosHostZoneIngressNetdevs returns the sorted LOCAL_IN iifname components
// for each zone's #4146 junos-host scope. Direct devices are returned as-is;
// VRF members contribute their master, which MUST be paired with that zone's
// `meta sdifname` members from BuildJunosHostDenyProjection.IngressVRFScopes.
// A master by itself is not a safe enforcement scope.
//
// Lifelines and unresolved ownership are excluded. The daemon consumes the full
// projection, including both direct and member-paired scopes; warning
// suppression uses the richer coverage result, not this component list being
// non-empty (#6564 member 8).
func JunosHostZoneIngressNetdevs(cfg *Config) map[string][]string {
	cov := junosHostZoneNetdevCoverageMap(cfg)
	if len(cov) == 0 {
		return nil
	}
	out := map[string][]string{}
	for zone, c := range cov {
		names := append([]string(nil), c.Scoped...)
		for _, scope := range c.VRFScopes {
			names = append(names, scope.Master)
		}
		if len(names) > 0 {
			sort.Strings(names)
			out[zone] = names
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// junosHostVRFMasterNetdevs maps every daemon-bound routing-instance device key
// to the l3mdev master visible at LOCAL_IN. RI list members use the daemon's
// member-key resolver; explicit tunnel routing-instance stanzas use the shared
// tunnel-claim traversal. A present empty value means conflicting or unsupported
// ownership, so no zone may guess which master is effective.
func junosHostVRFMasterNetdevs(cfg *Config, tunnelNames map[string]string) map[string]string {
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	masters := map[string]string{ManagementVRFInstanceName: ManagementVRFDeviceName}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" || ri.InstanceType == "forwarding" ||
			IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		masters[ri.Name] = LinuxIfName("vrf-" + ri.Name)
	}
	recordMaster := func(nd, master string) {
		if nd == "" {
			return
		}
		if previous, exists := out[nd]; exists {
			if previous != master {
				out[nd] = ""
			}
			return
		}
		out[nd] = master
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" || ri.InstanceType == "forwarding" ||
			IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		master := masters[ri.Name]
		for _, key := range RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri) {
			recordMaster(key.LinuxName, master)
		}
	}
	// The tunnel manager binds explicit stanza devices directly, outside the
	// RI interface-list binder above. Use the same deterministic ownership
	// claims as membership conflict detection (#11310), and retain an empty
	// target for stanza owners with no known VRF so their deny stays warned.
	for _, claim := range routingInstanceTunnelDeviceClaims(cfg) {
		if claim.Instance == "" {
			continue
		}
		recordMaster(claim.LinuxName, masters[claim.Instance])
	}
	return out
}

// junosHostVRFEnslavedNetdevs returns direct candidate netdevs with an
// authored VRF member identity. Snapshot-derived host-inbound views augment
// generated fan-down keys from their own LOCAL_IN master mapping; this
// config-only set retains the pre-existing raw-device semantics used by the
// coarse/unzoned host-inbound paths.
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
			probe := CanonicalInterfaceUnitRef(member)
			if keys := InterfaceUnitRefKeys(cfg, member); len(keys) > 0 {
				probe = keys[0]
			}
			if nd := netdevByRef[probe]; nd != "" {
				out[nd] = true
			}
		}
	}
	return out
}

// junosHostZoneNetdevCoverageMap resolves every zone's LOCAL_IN-visible iifname
// scope and records what it could NOT use, so the projection can distinguish
// "nothing to enforce" from "could not fully enforce".
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
	// Candidates are rewritten to the LOCAL_IN-visible VRF master before
	// ownership is resolved. The distinction decides whether losing a parent
	// candidate is a coverage gap: a subunit's own netdev is where its frames
	// actually arrive, whereas the physical parent is added for the bondless-
	// RETH case where they may ride the member.
	cand := map[string]map[string]bool{} // zone -> raw netdev -> isOwn
	addCand := func(zone, nd string, own bool) {
		if zone == "" || nd == "" {
			return
		}
		if cand[zone] == nil {
			cand[zone] = map[string]bool{}
		}
		cand[zone][nd] = cand[zone][nd] || own
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
	vrfMasterByNetdev := junosHostVRFMasterNetdevs(cfg, tunNames)
	// Walk every physical interface + unit row, mirroring the dataplane
	// interface snapshot.
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
	// A VRF master is safe for a zone-scoped fine DENY only when every
	// enslaved member has an OWN candidate in a zone. An unzoned or lifeline
	// co-member also arrives with the same LOCAL_IN iifname, so a rule on the
	// master would over-fire on traffic that has no zone identity.
	ownedVRFMember := map[string]bool{}
	for _, nds := range cand {
		for slave, own := range nds {
			if own {
				ownedVRFMember[slave] = true
			}
		}
	}
	unownedVRFMaster := map[string]bool{}
	for slave, master := range vrfMasterByNetdev {
		if master != "" && !ownedVRFMember[slave] {
			unownedVRFMaster[master] = true
		}
	}
	vrfScopeSlaves := map[string]map[string]map[string]bool{} // zone -> master -> own slave set
	vrfSlaveOwners := map[string]int{}
	for zone, nds := range cand {
		for slave, own := range nds {
			master, enslaved := vrfMasterByNetdev[slave]
			if !own || !enslaved || master == "" {
				continue
			}
			vrfSlaveOwners[slave]++
			if vrfScopeSlaves[zone] == nil {
				vrfScopeSlaves[zone] = map[string]map[string]bool{}
			}
			if vrfScopeSlaves[zone][master] == nil {
				vrfScopeSlaves[zone][master] = map[string]bool{}
			}
			vrfScopeSlaves[zone][master][slave] = true
		}
	}
	for zone, masters := range vrfScopeSlaves {
		for master, slaves := range masters {
			for slave := range slaves {
				if vrfSlaveOwners[slave] != 1 {
					delete(slaves, slave)
				}
			}
			if len(slaves) == 0 {
				delete(masters, master)
			}
		}
		if len(masters) == 0 {
			delete(vrfScopeSlaves, zone)
		}
	}
	effectiveCand := map[string]map[string]bool{}   // zone -> LOCAL_IN netdev -> isOwn
	effectiveClaims := map[string]map[string]bool{} // LOCAL_IN netdev -> zone set
	unresolved := map[string]map[string]bool{}      // zone -> own netdev with conflicting VRF masters
	addEffective := func(zone, nd string, own bool) {
		if effectiveCand[zone] == nil {
			effectiveCand[zone] = map[string]bool{}
		}
		effectiveCand[zone][nd] = effectiveCand[zone][nd] || own
		if effectiveClaims[nd] == nil {
			effectiveClaims[nd] = map[string]bool{}
		}
		effectiveClaims[nd][zone] = true
	}
	for zone, nds := range cand {
		for nd, own := range nds {
			if master, enslaved := vrfMasterByNetdev[nd]; enslaved {
				if master == "" {
					if own {
						if unresolved[zone] == nil {
							unresolved[zone] = map[string]bool{}
						}
						unresolved[zone][nd] = true
					}
					continue
				}
				nd = master
			}
			addEffective(zone, nd, own)
		}
	}
	for zone, nds := range effectiveCand {
		c := out[zone]
		names := make([]string, 0, len(nds))
		for nd := range nds {
			names = append(names, nd)
		}
		sort.Strings(names)
		for _, nd := range names {
			if slaves := vrfScopeSlaves[zone][nd]; nds[nd] && len(slaves) > 0 {
				slaveNames := make([]string, 0, len(slaves))
				for slave := range slaves {
					slaveNames = append(slaveNames, slave)
				}
				sort.Strings(slaveNames)
				c.VRFScopes = append(c.VRFScopes,
					HostInboundVRFIngressScope{Master: nd, Slaves: slaveNames})
				continue
			}
			if len(effectiveClaims[nd]) != 1 || unownedVRFMaster[nd] {
				// As with raw candidates, a dropped parent superset is not a
				// coverage gap: only an OWN ingress device must be covered.
				if nds[nd] {
					c.Unscopable = append(c.Unscopable,
						junosHostUnscopableNetdev{Netdev: nd, Reason: junosHostNetdevAmbiguous})
				}
				continue
			}
			c.Scoped = append(c.Scoped, nd)
		}
		out[zone] = c
	}
	for zone, nds := range unresolved {
		c := out[zone]
		names := make([]string, 0, len(nds))
		for nd := range nds {
			names = append(names, nd)
		}
		sort.Strings(names)
		for _, nd := range names {
			c.Unscopable = append(c.Unscopable,
				junosHostUnscopableNetdev{Netdev: nd, Reason: junosHostNetdevVRFEnslaved})
		}
		out[zone] = c
	}
	for zone := range cand {
		if _, exists := out[zone]; !exists {
			out[zone] = junosHostZoneNetdevCoverage{}
		}
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
	excludedZones := ZoneQuarantineExclusions(zoneNames)
	conflictedInterfaces := QuarantinedZoneInterfaceKeys(cfg)
	for _, zoneName := range zoneNames {
		if _, excluded := excludedZones[zoneName]; excluded {
			continue
		}
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			// #5878 phase 2, declared-aware (#9821): bind on the split identity
			// so this mirror resolves ge-0/0/0.01 AND ge-0/0/5.0.01 onto the
			// canonical unit rows the dataplane snapshot emits — the consumer
			// looks this map up by the canonical "%s.%d" unit name. Inserting
			// the Literal (not the legacy canon) keeps a padded multi-dot
			// spelling from stranding a `.01` key no row carries.
			s := cfg.SplitInterfaceUnitRef(rawIface)
			if _, conflicted := conflictedInterfaces[s.Literal]; !conflicted {
				if _, exists := out[s.Literal]; !exists {
					out[s.Literal] = zoneName
				}
			}
			if s.HasUnit {
				// Unit (or trailing-dot) reference: also bind the physical
				// base, mirroring InterfaceZoneMap's zone-specific fan-up.
				if s.Base != "" {
					if _, conflicted := conflictedInterfaces[s.Literal]; conflicted {
						continue
					}
					if _, conflicted := conflictedInterfaces[s.Base]; conflicted {
						continue
					}
					if _, exists := out[s.Base]; !exists {
						out[s.Base] = zoneName
					}
				}
				continue
			}
			if ifCfg := cfg.Interfaces.Interfaces[s.Base]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					unitName := fmt.Sprintf("%s.%d", s.Base, unitNum)
					if _, conflicted := conflictedInterfaces[unitName]; conflicted {
						continue
					}
					if _, exists := out[unitName]; !exists {
						out[unitName] = zoneName
					}
				}
			}
		}
	}
	return out
}
