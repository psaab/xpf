package userspace

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// host_inbound_classify.go is the #3627 B1a host-inbound admission CLASSIFIER:
// given a host-bound (to-zone junos-host) query tuple and the ingress zone, it
// reports WHICH host-inbound-traffic system-service / protocol token admits the
// packet — or that the box denies it, admits it globally (ICMP error/ND, ESP/AH),
// or cannot classify it. It is consumed by the operator-plane match-policies
// simulator (pkg/policymatch) so the host-inbound verdict names the admitting
// token instead of the fixed "local delivery subject to host-inbound-traffic"
// string.
//
// It is a DIAGNOSTIC, not the enforcement path: the kernel-nft chain
// (pkg/daemon/daemon_nft.go) and the Rust AF_XDP classifier
// (userspace-dp/.../forwarding/host_inbound.rs) enforce. To avoid a THIRD
// token->port truth drifting from those two, the classifier reads the SAME
// structured SSOT the nft builder renders from (config.HostInboundServiceMatch /
// config.HostInboundProtocolMatch, #3627 B1a) and mirrors the global pre-accepts
// the nft chain applies at the top of `chain input`
// (buildHostInboundFilterPayload) and the Rust is_icmp_host_inbound_global_accept
// (#3171): ESP/AH raw data plane, ICMP error/PMTUD, and the IPv6 ND set.
//
// Faithful to the enforcement paths (plan §5): a zone can carry MULTIPLE
// per-interface effective views (#3362). A zone-scoped query (no ingress
// interface) classifies EACH view independently and reports HostInboundAmbiguous
// when they DISAGREE (one interface admits, a sibling default-denies) rather than
// OR-ing them into a zone-wide first-admit that lies for the denying interfaces
// (#5579); when the views agree — the common single-view case — it reports that
// shared verdict. An ingress-interface-scoped query
// (ClassifyHostInboundForInterface) evaluates ONLY that interface's effective
// view, so an operator can certify one interface's TRUE posture. Post-#3405 a
// configured zone with no host-inbound-traffic stanza default-DENIES (its view
// carries empty token sets), so "unmatched host policy" does NOT imply delivery.
// Lifeline interfaces (fxp0/em0/fab*) are excluded from the views and so are
// never classified here (their host traffic is served unconditionally); the
// ingress-interface selector rejects a lifeline ref for the same reason.

// HostInboundStatus classifies how the ingress zone's host-inbound-traffic
// admission gate treats a host-bound query tuple (#3627 B1a). It is presence-safe
// so the four states are distinguishable — a bare token string could not tell
// "denied" from "not computed" from "admitted by a global accept".
type HostInboundStatus int

const (
	// HostInboundNotComputed is the zero value: the admission was not computed
	// (not a host-bound query, or no config). Rendered as absence.
	HostInboundNotComputed HostInboundStatus = iota
	// HostInboundIndeterminate: the query omits the protocol, or omits the
	// destination-port / icmp-type a port/ICMP token needs, so the admitting
	// token cannot be identified. Never reported as a false admit.
	HostInboundIndeterminate
	// HostInboundGlobalAccept: admitted by a GLOBAL pre-accept independent of the
	// zone's host-inbound-traffic set (ICMP error/PMTUD, IPv6 ND, or the raw
	// ESP/AH data plane), matching the top-of-chain nft accepts (#3171).
	HostInboundGlobalAccept
	// HostInboundTokenAdmit: admitted by a named host-inbound-traffic token
	// (Token/Kind identify it).
	HostInboundTokenAdmit
	// HostInboundDenied: the ingress zone's host-inbound-traffic admits nothing
	// matching this tuple — the box drops the packet (Junos default-deny).
	HostInboundDenied
	// HostInboundAmbiguous: the ingress zone carries MULTIPLE distinct effective
	// host-inbound views (per-interface overrides, #3362) that would classify
	// this tuple DIFFERENTLY — one interface admits it, another denies it (#5579).
	// A zone-scoped query cannot answer for the whole zone without lying for the
	// sibling interfaces, so the classifier reports ambiguity and names the
	// differing interface groups (Ambiguous) instead of OR-ing them into a
	// zone-wide first-admit. Supply an ingress-interface selector to get one
	// interface's true admission.
	HostInboundAmbiguous
)

func (s HostInboundStatus) String() string {
	switch s {
	case HostInboundIndeterminate:
		return "indeterminate"
	case HostInboundGlobalAccept:
		return "global-accept"
	case HostInboundTokenAdmit:
		return "token-admit"
	case HostInboundDenied:
		return "denied"
	case HostInboundAmbiguous:
		return "ambiguous"
	default:
		return "not-computed"
	}
}

// HostInboundAdmission is the classifier verdict for a host-bound query tuple
// (#3627 B1a). Token/Kind are meaningful only when Status == HostInboundTokenAdmit.
type HostInboundAdmission struct {
	Status HostInboundStatus
	// Token is the admitting host-inbound-traffic token (e.g. "ssh", "bgp",
	// "all"); set only for HostInboundTokenAdmit.
	Token string
	// Kind is the stanza the token belongs to: "system-services" or "protocols".
	// Set only for HostInboundTokenAdmit.
	Kind string
	// Ambiguous carries, for Status == HostInboundAmbiguous, the per-effective-view
	// verdicts that DISAGREE for this tuple (#5579) — one group of interfaces
	// admits it, another denies it. It lets the operator see WHICH interfaces have
	// which posture without re-querying each, and directs them to the
	// ingress-interface selector for the interface-scoped truth. Empty for every
	// other status.
	Ambiguous []HostInboundViewVerdict
}

// HostInboundViewVerdict is one distinct per-interface host-inbound verdict in a
// zone that has divergent per-interface effective views (#5579). It pairs the
// interfaces sharing an effective host-inbound token set with the admission that
// set produces for the query tuple.
type HostInboundViewVerdict struct {
	// Interfaces are the interface refs whose effective host-inbound token set
	// yields this verdict (may be empty for the zone-default view that no
	// addressed interface fell into). Sorted.
	Interfaces []string
	Status     HostInboundStatus
	Token      string
	Kind       string
}

// Describe renders the operator-facing one-line explanation of the admission,
// appended to the host-inbound match-policies verdict. Empty for
// HostInboundNotComputed (nothing to say).
func (a HostInboundAdmission) Describe() string {
	switch a.Status {
	case HostInboundTokenAdmit:
		// `all` is NOT a full admit since #3226 — it expands to the union of
		// named services, so a zone carrying only `all` still DENIES gre/47,
		// tcp/113 and anything else outside that union. Saying "all host
		// services open" here contradicted the enforcement on the same zone in
		// the same breath.
		if a.Token == "any-service" {
			return "admitted by host-inbound-traffic system-services any-service (all host services open)"
		}
		if a.Token == "all" {
			return "admitted by host-inbound-traffic system-services all (the union of " +
				"named system-services; NOT a packet-wide admit — see `show " +
				"host-inbound-traffic services`)"
		}
		return fmt.Sprintf("admitted by host-inbound-traffic %s %s", a.Kind, a.Token)
	case HostInboundGlobalAccept:
		return "admitted by a global accept (ICMP error/PMTUD, IPv6 ND, or ESP/AH) independent of this zone's host-inbound-traffic set"
	case HostInboundDenied:
		return "DENIED by host-inbound-traffic — no system-service/protocol admits this tuple, so the box drops it"
	case HostInboundIndeterminate:
		return "indeterminate — specify protocol (and destination-port or icmp-type) to identify the admitting host-inbound-traffic token"
	case HostInboundAmbiguous:
		var parts []string
		for _, g := range a.Ambiguous {
			scope := "zone-default"
			if len(g.Interfaces) > 0 {
				scope = strings.Join(g.Interfaces, ", ")
			}
			parts = append(parts, fmt.Sprintf("[%s] %s", scope,
				HostInboundAdmission{Status: g.Status, Token: g.Token, Kind: g.Kind}.Describe()))
		}
		return "AMBIGUOUS — per-interface host-inbound-traffic posture differs across this zone's interfaces; " +
			"specify ingress-interface to get one interface's true admission: " + strings.Join(parts, "; ")
	default:
		return ""
	}
}

// ClassifyHostInbound reports how the ingress zone's host-inbound-traffic gate
// treats a host-bound query tuple (#3627 B1a). proto/hasProto carry the resolved
// IP protocol number (hasProto false = the query omitted the protocol); dstPort
// is the destination port (<= 0 = unspecified); icmpType is the ICMP/ICMPv6 type
// (nil = unspecified); family is "ip" / "ip6" from the query's destination
// address, or "" when the query gives no IP (both families are then tried and
// admission is reported if either admits).
func ClassifyHostInbound(cfg *config.Config, fromZone string, proto uint8, hasProto bool, dstPort int, icmpType *uint8, family string) HostInboundAdmission {
	if cfg == nil || fromZone == "" {
		return HostInboundAdmission{Status: HostInboundNotComputed}
	}

	views := viewsForZone(cfg, fromZone)
	if len(views) == 0 {
		// An undefined / unconfigured ingress zone has no effective view; classify
		// against an empty view so an isolated global-accept (ESP/AH, ICMP error,
		// IPv6 ND) or an indeterminate/denied verdict is reported exactly as
		// before the #5579 per-view refactor.
		return classifyOneView(ZoneHostInboundView{Zone: fromZone}, proto, hasProto, dstPort, icmpType, family)
	}

	// #5579: classify EACH effective view independently and only fold them into a
	// single verdict when they AGREE. A zone with no per-interface override yields
	// exactly one view (pre-#3362 shape), so the common case is byte-identical to
	// the historical first-admit behavior. When a mixed zone's views DISAGREE
	// (one interface admits, a sibling default-denies), report HostInboundAmbiguous
	// with the differing interface groups rather than OR-ing them into a zone-wide
	// first-admit that lies for the denying interfaces — the false-admission #5579
	// removes. Supply an ingress-interface selector to resolve one interface.
	first := classifyOneView(views[0], proto, hasProto, dstPort, icmpType, family)
	groups := []HostInboundViewVerdict{verdictFor(views[0], first)}
	agree := true
	for _, v := range views[1:] {
		a := classifyOneView(v, proto, hasProto, dstPort, icmpType, family)
		groups = append(groups, verdictFor(v, a))
		if a.Status != first.Status || a.Token != first.Token || a.Kind != first.Kind {
			agree = false
		}
	}
	if agree {
		return first
	}
	return HostInboundAdmission{Status: HostInboundAmbiguous, Ambiguous: groups}
}

// verdictFor pairs a view's interfaces with the admission it produced (#5579).
func verdictFor(v ZoneHostInboundView, a HostInboundAdmission) HostInboundViewVerdict {
	return HostInboundViewVerdict{
		Interfaces: v.Interfaces,
		Status:     a.Status,
		Token:      a.Token,
		Kind:       a.Kind,
	}
}

// ClassifyHostInboundForInterface classifies the host-inbound admission for a
// SINGLE ingress interface's EFFECTIVE host-inbound view (#5579). Unlike
// ClassifyHostInbound — which folds every view in the zone with a first-admit OR
// — it evaluates ONLY ifaceRef's effective token set (its per-interface
// override where declared, which REPLACES the zone-level set — #6515, #3362 —
// with the same physical→unit inheritance the enforcement view builder uses),
// so a mixed zone reports the interface's TRUE
// posture (admit vs deny) instead of a zone-wide first-admit fold. ifaceRef is
// expected to be a caller-validated interface assigned to fromZone (see
// ResolveHostInboundIngressInterface); an unresolved zone/interface yields
// HostInboundNotComputed defensively.
func ClassifyHostInboundForInterface(cfg *config.Config, fromZone, ifaceRef string, proto uint8, hasProto bool, dstPort int, icmpType *uint8, family string) HostInboundAdmission {
	if cfg == nil || fromZone == "" || ifaceRef == "" {
		return HostInboundAdmission{Status: HostInboundNotComputed}
	}
	zone := cfg.Security.Zones[fromZone]
	if zone == nil {
		return HostInboundAdmission{Status: HostInboundNotComputed}
	}
	// Resolve THIS interface's effective host-inbound token set with the same SSOT
	// the enforcement view builder uses (effectiveHostInboundTokens over the
	// zone-level stanza and the per-interface override — the override REPLACES the
	// zone set when present, #6515 — physical→unit inheritance included), then
	// classify that single view.
	// #9821 D6: look the override up on the ref's declared-aware SPLIT
	// Literal (cfg is in scope), so a query for `p.0.01` finds an override
	// authored as `p.0.1` — the cfg-free canonicalization first-cut onto
	// `p` and missed. Undotted refs are byte-identical (step-4 Literal ≡
	// legacy canon).
	split := cfg.SplitInterfaceUnitRef(ifaceRef)
	svc, prot := effectiveHostInboundTokens(zone, split.Literal, buildInterfaceHostInboundMap(cfg)[split.Literal])
	v := ZoneHostInboundView{Zone: fromZone, Interfaces: []string{ifaceRef}, SystemServices: svc, Protocols: prot}
	return classifyOneView(v, proto, hasProto, dstPort, icmpType, family)
}

// classifyOneView classifies a host-bound query tuple against a SINGLE effective
// host-inbound view — the shared per-view core of ClassifyHostInbound and
// ClassifyHostInboundForInterface (#5579). It mirrors the original whole-zone
// ordering (full-admit → global pre-accept → indeterminate short-circuits →
// per-view token admit → default-deny) scoped to one view's token set.
func classifyOneView(v ZoneHostInboundView, proto uint8, hasProto bool, dstPort int, icmpType *uint8, family string) HostInboundAdmission {
	// Full-admit (`any-service` ONLY — #3226 narrowed `system-services all` to
	// the named union) admits everything,
	// independent of the tuple — report it even when the tuple is otherwise
	// indeterminate.
	for _, s := range v.SystemServices {
		if config.HostInboundFullAdmitService(s) {
			return HostInboundAdmission{Status: HostInboundTokenAdmit, Token: s, Kind: "system-services"}
		}
	}

	// Global pre-accepts (ICMP error/PMTUD, IPv6 ND, ESP/AH), mirroring the
	// top-of-chain nft accepts (#3171). Needs the protocol.
	if hasProto && hostInboundGlobalAccept(proto, icmpType) {
		return HostInboundAdmission{Status: HostInboundGlobalAccept}
	}

	if !hasProto {
		return HostInboundAdmission{Status: HostInboundIndeterminate}
	}
	// A port/ICMP token cannot be identified without the port / icmp-type.
	if (proto == config.HostInboundProtoTCP || proto == config.HostInboundProtoUDP) && dstPort <= 0 {
		return HostInboundAdmission{Status: HostInboundIndeterminate}
	}
	if (proto == config.HostInboundProtoICMP || proto == config.HostInboundProtoICMPv6) && icmpType == nil {
		return HostInboundAdmission{Status: HostInboundIndeterminate}
	}

	fams := []string{family}
	if family == "" {
		fams = []string{"ip", "ip6"}
	}
	for _, fam := range fams {
		if tok, kind, ok := hostInboundViewAdmit(v, proto, dstPort, icmpType, fam); ok {
			return HostInboundAdmission{Status: HostInboundTokenAdmit, Token: tok, Kind: kind}
		}
	}
	// The zone is configured (post-#3405 every configured zone enforces) and
	// nothing in this view admits — default-deny.
	return HostInboundAdmission{Status: HostInboundDenied}
}

// ResolveHostInboundIngressInterface validates an ingress-interface selector
// (#5579) for a host-bound match-policies query: the ref must name an interface
// assigned to fromZone. It is the SSOT reject used by every operator surface
// (REST / gRPC / local CLI) so an unknown, zone-mismatched, or lifeline ref
// fails the query CLOSED with a clear error instead of silently degrading to the
// zone-wide fold. An empty ref (selector omitted) is not an error. cfg must be
// non-nil (callers skip validation during the no-config boot window, which
// returns the default-deny verdict regardless of any interface).
//
// A management/cluster lifeline interface (fxp0 / em0 / fab*) is rejected: its
// host traffic is served UNCONDITIONALLY (excluded from the host-inbound deny),
// so per-interface host-inbound classification does not describe it — reporting a
// token/deny verdict for a lifeline would be a fresh false answer. The error
// tells the operator the lifeline is always served.
func ResolveHostInboundIngressInterface(cfg *config.Config, fromZone, ifaceRef string) error {
	if ifaceRef == "" {
		return nil
	}
	if cfg == nil {
		return nil
	}
	if hostInboundLifelineInterface(ifaceRef, hostInboundLifelineSet(cfg)) {
		return fmt.Errorf("ingress-interface %q is a management/cluster lifeline (fxp0/em0/fab*); its host traffic is served unconditionally and is not subject to per-interface host-inbound classification", ifaceRef)
	}
	// The classifier (ClassifyHostInboundForInterface) keys the effective
	// host-inbound token set on the LOGICAL-UNIT ref via
	// buildInterfaceHostInboundMap(cfg)[ifaceRef]. A bare-PHYSICAL ref (e.g.
	// `reth0` / `ge-0/0/0`) is NOT that key: a UNIT-authored override
	// (`set ... interfaces reth0.50 host-inbound-traffic ...`) lands on the
	// `reth0.50` key, never on the physical `reth0` key, so classifying the
	// physical ref would SILENTLY DROP the override and report a FALSE-DENY that
	// disagrees with the true per-unit posture (#5579 review). Keep the validator's
	// accepted namespace identical to what the classifier keys on: require a
	// logical-unit ref, rejecting a bare physical that carries one-or-more units
	// and pointing the operator at the unit form. (A unit-less physical carrying
	// only a physical-level override is keyed correctly on the physical key, so it
	// is not rejected here — it falls through to the zone-membership check.)
	// #9821 D6: physical/unit inference on the declared-aware split — a bare
	// `p.0` (declared, dotted) IS a physical ref and must hit the rejection
	// below, not bypass it on dot-presence; the redirect names the Base's
	// smallest unit. The zone probe follows on the split Literal, so
	// `p.0.01` validates against the zone its canonical unit binds.
	split := cfg.SplitInterfaceUnitRef(ifaceRef)
	if !split.HasUnit {
		if ic := cfg.Interfaces.Interfaces[split.Base]; ic != nil && len(ic.Units) > 0 {
			return fmt.Errorf("ingress-interface %q is a physical interface; specify the logical unit, e.g. %s.%d", ifaceRef, split.Base, smallestUnitNumber(ic.Units))
		}
	}
	zone := buildInterfaceZoneMap(cfg)[split.Literal]
	if zone == "" {
		return fmt.Errorf("unknown ingress-interface %q (not assigned to any security zone)", ifaceRef)
	}
	if zone != fromZone {
		return fmt.Errorf("ingress-interface %q is in zone %q, not from-zone %q", ifaceRef, zone, fromZone)
	}
	return nil
}

// smallestUnitNumber returns the lowest configured unit number of an interface,
// used to name a representative logical unit in the bare-physical reject message
// so the operator can copy a ready-to-use ref. Units is never empty at the call
// site.
func smallestUnitNumber(units map[int]*config.InterfaceUnit) int {
	min := -1
	for u := range units {
		if min == -1 || u < min {
			min = u
		}
	}
	if min == -1 {
		return 0
	}
	return min
}

// viewsForZone returns the host-inbound effective views for the given ingress
// zone (there may be several, #3362).
func viewsForZone(cfg *config.Config, zone string) []ZoneHostInboundView {
	var out []ZoneHostInboundView
	for _, v := range BuildZoneHostInboundViews(cfg) {
		if v.Zone == zone {
			out = append(out, v)
		}
	}
	return out
}

// hostInboundViewAdmit reports the first token in the view that admits the tuple
// (system-services before protocols), skipping the non-admitting ident-reset
// (Reject). Family-scoped via the SSOT.
func hostInboundViewAdmit(v ZoneHostInboundView, proto uint8, dstPort int, icmpType *uint8, family string) (token, kind string, admitted bool) {
	for _, s := range v.SystemServices {
		for _, m := range config.HostInboundServiceMatch(s, family) {
			if !m.Reject && l4MatchAdmits(m, proto, dstPort, icmpType) {
				return s, "system-services", true
			}
		}
	}
	for _, p := range v.Protocols {
		for _, m := range config.HostInboundProtocolMatch(p, family) {
			if l4MatchAdmits(m, proto, dstPort, icmpType) {
				return p, "protocols", true
			}
		}
	}
	return "", "", false
}

// l4MatchAdmits reports whether a structured host-inbound match admits the query
// tuple (proto, dstPort, icmpType). It mirrors the Rust ZoneHostInbound::admits
// per-tuple semantics against the SSOT L4Match shape.
func l4MatchAdmits(m config.L4Match, proto uint8, dstPort int, icmpType *uint8) bool {
	if m.Proto != proto {
		return false
	}
	switch m.Proto {
	case config.HostInboundProtoTCP, config.HostInboundProtoUDP:
		if len(m.Ports) == 0 {
			return true
		}
		if dstPort <= 0 || dstPort > 65535 {
			return false
		}
		dp := uint16(dstPort)
		for _, pr := range m.Ports {
			if dp >= pr.Lo && dp <= pr.Hi {
				return true
			}
		}
		return false
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		if m.ICMPType == nil {
			return true
		}
		if icmpType == nil {
			return false
		}
		return *icmpType == *m.ICMPType
	default:
		// Bare IP protocol (gre/ospf/pim/...): the protocol match is sufficient.
		return true
	}
}

// hostInboundGlobalAccept mirrors the top-of-chain nft global accepts
// (buildHostInboundFilterPayload) and the Rust is_icmp_host_inbound_global_accept
// (#3171): the raw ESP (50) / AH (51) data plane, and the ICMP error/PMTUD +
// IPv6 ND subtypes, are admitted regardless of the zone's host-inbound-traffic
// set. Echo-request (v4 8 / v6 128) and IPv4 router-advert/solicit (9/10) are
// NOT global — they stay gated on the `ping` / `router-discovery` tokens.
func hostInboundGlobalAccept(proto uint8, icmpType *uint8) bool {
	// Raw ESP / AH data plane (nft `meta l4proto { 50, 51 } accept`).
	if proto == 50 || proto == 51 {
		return true
	}
	if icmpType == nil {
		return false
	}
	t := *icmpType
	switch proto {
	case config.HostInboundProtoICMP: // ICMPv4 errors: dest-unreach(3), time-exceeded(11), param-problem(12)
		return t == 3 || t == 11 || t == 12
	case config.HostInboundProtoICMPv6: // ICMPv6 errors 1-4 + ND 133-137
		switch t {
		case 1, 2, 3, 4, 133, 134, 135, 136, 137:
			return true
		}
	}
	return false
}
