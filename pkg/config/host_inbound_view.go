package config

import (
	"sort"
	"strings"
)

// host_inbound_view.go is the shared presentation SSOT for a security zone's
// host-inbound-traffic admission posture (#3654 L02). Before #3654 every text /
// CLI surface (local `show security zones` / `show interfaces` / `test
// security-zone interface`, gRPC text zones + interface diagnostic, and the
// remote `cmd/cli` zone view) re-implemented the same ad-hoc "print the
// zone-level HostInboundTraffic set" block and every one of them dropped the
// per-interface override (#3362) and the no-stanza default-deny posture
// (#3405). Routing all six through this one presenter keeps them from drifting
// again and mirrors the structured REST/gRPC contract (#3328/#3405/#3653):
// every configured zone is host-inbound ENFORCING, and the EFFECTIVE admission
// set for an interface is its interface-level `host-inbound-traffic` stanza when
// it declares one, otherwise the zone-level set (#6515 — Junos REPLACE
// semantics; see EffectiveHostInboundTokens).

// UnionHostInboundTokens returns the order-preserving union of two host-inbound
// token lists: a's tokens first in their authored order, then any of b's not
// already present, with empties skipped and exact-duplicate tokens collapsed. It
// preserves the authored token case so the text surfaces show tokens exactly as
// the structured API does (the dataplane path lower-cases for map keying, a
// concern that does not apply to display — every membership predicate that
// consumes this, notably HostInboundFullAdmitService, is case-insensitive).
// Called with a nil second argument it is a normalizer (trim + dedup).
//
// SCOPE (#6515). This unions tokens authored at the SAME level. It is NOT how
// the zone level and the interface level combine: an interface stanza REPLACES
// the zone stanza — see EffectiveHostInboundTokens, which every zone-to-interface
// resolution must route through. Two live callers union within one level:
//   - the #3720 physical→unit resolution in InterfaceHostInboundEffective and in
//     the dataplane's buildInterfaceHostInboundMap, where a physical-interface
//     override and a unit-level override on the same unit are both
//     "interface-level" statements;
//   - #4544 repeated `host-inbound-traffic { }` blocks under one stanza.
func UnionHostInboundTokens(zone, iface []string) []string {
	seen := make(map[string]bool, len(zone)+len(iface))
	out := make([]string, 0, len(zone)+len(iface))
	add := func(src []string) {
		for _, t := range src {
			t = strings.TrimSpace(t)
			// Dedup on the CASE-FOLDED token, append the AUTHORED one
			// (#7171). Keying on the raw token made `ssh` and `SSH`
			// two distinct members, so a zone and an interface (or two
			// repeated host-inbound-traffic blocks) spelling one service
			// differently rendered it TWICE. Every membership predicate
			// downstream is case-insensitive, so both spellings resolve to
			// the same admission -- the duplicate exists only in the
			// display, which is precisely where this function's output
			// goes. Folding the KEY without folding the VALUE keeps the
			// authored case this function documents itself as preserving.
			k := strings.ToLower(t)
			if t == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, t)
		}
	}
	add(zone)
	add(iface)
	return out
}

// EffectiveHostInboundTokens returns the EFFECTIVE host-inbound token set for one
// interface, given the zone-level list, that interface's own list, and whether
// the interface declares a `host-inbound-traffic` stanza at all. It is the SSOT
// for the zone↔interface combination; every surface that resolves an interface's
// admission — the kernel nft enforcement view builder, the per-interface
// classifier, the commit-time advisories, the duplicate-host-address commit gate,
// and all six display surfaces — must route through it or through a wrapper that
// delegates to it, or they will describe different firewalls.
//
// REPLACE, not union (#6515). Junos: "You can configure these parameters at the
// zone level, in which case they affect all interfaces of the zone, or at the
// interface level. (Interface configuration overrides that of the zone.)"
// — Security Zones, security-zone-configuration. So the zone-level stanza governs
// exactly the interfaces that declare NO stanza of their own; an interface that
// declares one is described entirely by it, and the zone's tokens do not reach it.
//
// The flag is presence, NOT emptiness: an explicit `host-inbound-traffic { }` on
// an interface is a deny-all override and must not fall back to the zone set.
// parseHostInboundNode already distinguishes the two (a present-but-empty stanza
// compiles to a non-nil empty struct, an absent one to nil).
//
// GRANULARITY. The whole stanza replaces, not each leaf: an interface stanza that
// declares only `protocols` also drops the zone's `system-services`. That is the
// literal reading of the sentence above, and the community consensus states it
// the same way ("if you configure anything under specific interface level, then
// zone-specific configuration doesn't apply to this interface anymore"). No
// vendor text was found describing a per-leaf inheritance, so none is invented
// here — see docs/host-inbound-service-matrix.md.
//
// Before #6515 this combination was a UNION, asserted in-tree as "Junos additive
// semantics". An interface stanza could then only WIDEN admission and never
// narrow it: a zone admitting `protocols ospf` with an interface stanza admitting
// only `ping` still admitted OSPF on that interface, where Junos denies it. The
// migration this flip imposes on configs that relied on the union is named at
// commit by validateHostInboundOverrideReplaceWarnings.
func EffectiveHostInboundTokens(zone, iface []string, overridden bool) []string {
	if overridden {
		return UnionHostInboundTokens(iface, nil)
	}
	return UnionHostInboundTokens(zone, nil)
}

// HostInboundDenyReason returns the parenthetical explaining WHY a zone or
// interface admits no host-inbound traffic, for the default-deny posture line
// (#3654 M03). overridden marks that the interface declares its own
// host-inbound-traffic stanza; zoneConfigured marks that a zone-level stanza is
// present. All three cases default-DENY host-bound traffic post-#3405; the
// wording only tells the operator which stanza produced the empty set.
func HostInboundDenyReason(overridden, zoneConfigured bool) string {
	switch {
	case overridden:
		return "interface override: deny-all"
	case zoneConfigured:
		return "empty stanza"
	default:
		return "no stanza"
	}
}

// InterfaceHostInboundEffective returns the EFFECTIVE host-inbound admission set
// for a single interface ref in the zone: the per-interface override for ref when
// ref declares one (#6515 replace semantics — see EffectiveHostInboundTokens),
// otherwise the zone-level set. overridden reports whether ref declares its own
// host-inbound-traffic stanza (#3362). Used by the interface-scoped surfaces
// (`show interfaces`, `test security-zone interface`, gRPC interface diagnostic)
// which must show the effective set for ONE interface rather than iterate the
// whole zone.
func (z *ZoneConfig) InterfaceHostInboundEffective(ref string) (svc, proto []string, overridden bool) {
	var zoneSvc, zoneProto []string
	if z != nil && z.HostInboundTraffic != nil {
		// #7490: the ZONE-LEVEL system-services list as it applies to THIS ref.
		// The zone-level `dhcp` / `bootp` authorization is withheld from an
		// interface that runs a DHCP server or relay (and not the firewall's own
		// client), because the vendor rule those two tokens come from is an
		// argument about a SERVER needing ingress identity.
		//
		// Applied HERE, inside the shared resolver, rather than at each caller:
		// this one function is what sixteen diagnostic surfaces and the nft
		// enforcement path both reach, and the #6640 lesson is that a rule
		// copied to callers is a rule that grows a divergence. The stamp it
		// reads is derived at compile (resolveDerivedConfig step 7) because the
		// answer needs the whole *Config and this method has only a *ZoneConfig.
		//
		// Protocols are untouched: the exception is about two SYSTEM-SERVICES
		// tokens.
		zoneSvc = z.ZoneLevelSystemServicesFor(z.HostInboundTraffic.SystemServices, ref)
		zoneProto = z.HostInboundTraffic.Protocols
	}
	if z == nil {
		return UnionHostInboundTokens(zoneSvc, nil), UnionHostInboundTokens(zoneProto, nil), false
	}
	// The INTERFACE-level half comes from InterfaceHostInboundOverride, which owns
	// the #3720 (H05) physical∪unit union: the physical and the unit level are
	// BOTH "interface level", so the override for a unit is the UNION of the two,
	// exactly as the dataplane resolves it in buildInterfaceHostInboundMap. (#6515
	// replaces the ZONE level with that result; it does not change how the two
	// interface-level statements combine with each other.) Before #3720 this read
	// only the exact ref, so `show interfaces <unit>` reported "no override /
	// default-deny" while the dataplane admitted the inherited physical override —
	// the diagnostic gave the OPPOSITE answer to enforcement.
	//
	// It is a CALL and not a second copy of that walk because a divergence between
	// the two would always be a bug: the #6519 advisory asks
	// InterfaceHostInboundOverride "does the interface's own stanza authorize this
	// service?" precisely to decide what the ZONE-level stanza is answerable for,
	// and it has to be asking about the same set this resolver admits.
	var ovSvc, ovProto []string
	ovSvc, ovProto, overridden = z.InterfaceHostInboundOverride(ref)
	if !overridden {
		return UnionHostInboundTokens(zoneSvc, nil), UnionHostInboundTokens(zoneProto, nil), false
	}
	return EffectiveHostInboundTokens(zoneSvc, ovSvc, true),
		EffectiveHostInboundTokens(zoneProto, ovProto, true), true
}

// InterfaceHostInboundView is a single per-interface host-inbound override
// (#3362) projected for display: the interface-local override tokens plus the
// EFFECTIVE admitted set that actually reaches the host on that interface —
// which post-#6515 IS the override, the zone-level set having been replaced.
type InterfaceHostInboundView struct {
	Interface               string
	SystemServices          []string
	Protocols               []string
	EffectiveSystemServices []string
	EffectiveProtocols      []string
}

// HostInboundView is the zone-scoped presentation view shared by the
// zone-listing surfaces (`show security zones`, gRPC text zones, remote
// cmd/cli). ZoneConfigured records whether a zone-level host-inbound-traffic
// stanza is present (populated or explicit-empty); the zone-level admitted set
// is in ZoneSystemServices / ZoneProtocols; Interfaces holds the per-interface
// overrides in sorted order.
type HostInboundView struct {
	ZoneConfigured     bool
	ZoneSystemServices []string
	ZoneProtocols      []string
	Interfaces         []InterfaceHostInboundView
	// LifelineInterfaces lists the zone's interfaces that are management /
	// cluster-control LIFELINES (fxp0 / configured control-interface /
	// fabric-interface) and are therefore EXCLUDED from host-inbound deny
	// scoping — their host-bound traffic is always admitted regardless of this
	// zone's host-inbound-traffic set (#3682, #11068). Sorted, deduplicated.
	// Empty unless the view is built with the lifeline set via
	// HostInboundViewWithLifelines. Rendered as an explicit exemption line so the
	// implicit management-plane exception is auditable rather than silent.
	LifelineInterfaces []string
}

// HostInboundView builds the presentation view for a zone from its typed
// config. Nil-safe (returns a zero view for a nil zone). The lifeline-exemption
// section (#3682) is empty; use HostInboundViewWithLifelines to populate it.
func (z *ZoneConfig) HostInboundView() HostInboundView {
	return z.HostInboundViewWithLifelines(nil)
}

// HostInboundViewWithLifelines builds the zone presentation view and, in
// addition to HostInboundView, records which of the zone's interfaces are
// host-inbound LIFELINES (management / cluster-control interfaces excluded from
// host-inbound deny scoping — #3682). lifelines is the config-derived lifeline
// base-name set from HostInboundLifelineSet(cfg); nil matches no configured
// names (the fixed fxp0 default is supplied by that set). Nil-safe. The recorded
// interfaces make the implicit exemption operator-visible on every zone view
// that routes through this presenter.
func (z *ZoneConfig) HostInboundViewWithLifelines(lifelines map[string]bool) HostInboundView {
	v := z.hostInboundViewBase()
	if z == nil {
		return v
	}
	seen := make(map[string]bool, len(z.Interfaces))
	for _, ref := range z.Interfaces {
		if !HostInboundLifelineInterface(ref, lifelines) || seen[ref] {
			continue
		}
		seen[ref] = true
		v.LifelineInterfaces = append(v.LifelineInterfaces, ref)
	}
	sort.Strings(v.LifelineInterfaces)
	return v
}

// hostInboundViewBase builds the zone-level + per-interface-override view
// without the lifeline-exemption section. Nil-safe (returns a zero view for a
// nil zone).
func (z *ZoneConfig) hostInboundViewBase() HostInboundView {
	v := HostInboundView{}
	if z == nil {
		return v
	}
	if z.HostInboundTraffic != nil {
		v.ZoneConfigured = true
		v.ZoneSystemServices = append([]string(nil), z.HostInboundTraffic.SystemServices...)
		v.ZoneProtocols = append([]string(nil), z.HostInboundTraffic.Protocols...)
	}
	for _, ref := range z.SortedInterfaceHostInboundRefs() {
		ov := z.InterfaceHostInbound[ref]
		if ov == nil {
			continue
		}
		// SystemServices/Protocols show the tokens authored on THIS ref; the
		// effective set is resolved through InterfaceHostInboundEffective so a
		// unit ref also folds in a physical-parent override (#3720 H05) and the
		// zone level is then REPLACED by the result (#6515) — the same
		// resolution the dataplane enforces.
		effSvc, effProto, _ := z.InterfaceHostInboundEffective(ref)
		v.Interfaces = append(v.Interfaces, InterfaceHostInboundView{
			Interface:               ref,
			SystemServices:          append([]string(nil), ov.SystemServices...),
			Protocols:               append([]string(nil), ov.Protocols...),
			EffectiveSystemServices: effSvc,
			EffectiveProtocols:      effProto,
		})
	}
	return v
}

// RenderInterfaceHostInbound returns the host-inbound presentation block for
// ONE interface ref in the zone (#3654 H06/H08 — the per-interface admission
// diagnostic), one line per slice element with NO trailing newline. It shows
// the zone-level admitted set and, when ref declares its own
// host-inbound-traffic override, both a marker and the EFFECTIVE admitted set for
// that interface (post-#6515 the override REPLACES the zone-level set, so the
// effective set can be NARROWER than the zone line printed above it). A
// default-deny posture line is
// emitted when the effective set is empty, so a blank section cannot be misread
// as "not enforced".
//
// #3682: lifeline reports whether ref is a management / cluster-control lifeline
// (from HostInboundLifelineInterface). A lifeline interface is EXCLUDED from
// host-inbound deny scoping, so in place of the (misleading) default-deny
// posture line the diagnostic renders an explicit lifeline-exempt marker — the
// operator sees WHY this interface admits host-bound traffic the zone set would
// otherwise deny.
func (z *ZoneConfig) RenderInterfaceHostInbound(ref string, lifeline bool, l HostInboundLabels) []string {
	var zoneSvc, zoneProto []string
	zoneConfigured := false
	if z != nil && z.HostInboundTraffic != nil {
		zoneConfigured = true
		// #7490: the zone-level line this render shows for ONE interface must be
		// the zone level AS IT APPLIES THERE, or the diagnostic would print a
		// `dhcp` the interface no longer admits — the exact shape of divergence
		// this file exists to prevent.
		zoneSvc = z.ZoneLevelSystemServicesFor(z.HostInboundTraffic.SystemServices, ref)
		zoneProto = z.HostInboundTraffic.Protocols
	}
	effSvc, effProto, overridden := z.InterfaceHostInboundEffective(ref)

	join := func(toks []string) string {
		if len(toks) == 0 {
			return "(none)"
		}
		return strings.Join(toks, l.Sep)
	}
	var lines []string
	if len(zoneSvc) > 0 {
		lines = append(lines, l.Indent+l.ServicesLabel+": "+strings.Join(zoneSvc, l.Sep))
	}
	if len(zoneProto) > 0 {
		lines = append(lines, l.Indent+l.ProtocolsLabel+": "+strings.Join(zoneProto, l.Sep))
	}
	if overridden {
		lines = append(lines,
			l.Indent+"Host-inbound interface override on "+ref+":",
			l.Indent+"  effective "+strings.ToLower(l.ServicesLabel)+": "+join(effSvc),
			l.Indent+"  effective "+strings.ToLower(l.ProtocolsLabel)+": "+join(effProto),
		)
	}
	// #3682: a lifeline interface is excluded from host-inbound deny scoping, so
	// its host-bound traffic is always admitted regardless of the zone/effective
	// set. Render the exemption explicitly (in place of the default-deny line
	// that would otherwise be misleading here) so the exception is auditable.
	if lifeline {
		lines = append(lines, l.Indent+"Host-inbound: lifeline-exempt "+
			"(management/fabric, bypasses host-inbound deny)")
		return lines
	}
	if len(effSvc) == 0 && len(effProto) == 0 {
		lines = append(lines, l.Indent+"Host-inbound: default deny ("+
			HostInboundDenyReason(overridden, zoneConfigured)+")")
	}
	return lines
}

// HostInboundLabels lets each zone-listing surface keep its established
// zone-level line labels and token separator while sharing the presentation
// logic for the per-interface override block and the default-deny posture line.
type HostInboundLabels struct {
	Indent         string // leading indent for each rendered line
	Sep            string // token-list separator (" " or ", ")
	ServicesLabel  string // zone-level system-services label
	ProtocolsLabel string // zone-level protocols label
}

// Render returns the host-inbound presentation block for a zone (#3654), one
// line per slice element with NO trailing newline. It emits, in order: the
// zone-level system-services / protocols lines (when non-empty), an explicit
// default-deny posture line when the zone admits nothing at the zone level
// (M03 — so a blank host-inbound section can never be misread as "not
// enforced"), and one block per per-interface override showing the
// interface-local tokens plus the effective (zone UNION interface) admitted set
// (H04/H07/H09).
//
// The zone-level default-deny posture line is emitted regardless of whether any
// per-interface override exists (#3671 / H08): the zone posture still governs
// every NON-overridden interface in the zone, so a partial interface override
// must not erase the visible default posture for the rest of the zone. The
// override blocks are ADDITIONAL context printed below the zone posture, never a
// replacement for it.
func (v HostInboundView) Render(l HostInboundLabels) []string {
	join := func(toks []string) string {
		if len(toks) == 0 {
			return "(none)"
		}
		return strings.Join(toks, l.Sep)
	}
	var lines []string
	if len(v.ZoneSystemServices) > 0 {
		lines = append(lines, l.Indent+l.ServicesLabel+": "+strings.Join(v.ZoneSystemServices, l.Sep))
	}
	if len(v.ZoneProtocols) > 0 {
		lines = append(lines, l.Indent+l.ProtocolsLabel+": "+strings.Join(v.ZoneProtocols, l.Sep))
	}
	// The zone-level default-deny posture line is emitted whenever the zone
	// admits nothing at the zone level, REGARDLESS of whether per-interface
	// overrides exist (#3671 / H08). The zone posture governs every
	// non-overridden interface, so a partial interface override must not
	// suppress the visible zone posture; the override blocks below are
	// additional context, not a replacement.
	if len(v.ZoneSystemServices) == 0 && len(v.ZoneProtocols) == 0 {
		lines = append(lines, l.Indent+"Host-inbound: default deny ("+
			HostInboundDenyReason(false, v.ZoneConfigured)+")")
	}
	if len(v.Interfaces) > 0 {
		lines = append(lines, l.Indent+"Host-inbound interface overrides:")
		for _, iface := range v.Interfaces {
			lines = append(lines,
				l.Indent+"  "+iface.Interface+":",
				l.Indent+"    override system-services: "+join(iface.SystemServices),
				l.Indent+"    override protocols: "+join(iface.Protocols),
				l.Indent+"    effective system-services: "+join(iface.EffectiveSystemServices),
				l.Indent+"    effective protocols: "+join(iface.EffectiveProtocols),
			)
		}
	}
	// #3682 (L05): make the implicit management/cluster-control lifeline
	// exemption operator-visible. Only fxp0 and configured control/fabric roles
	// are excluded from this zone's host-inbound deny scoping (#11068); their
	// host-bound traffic is always admitted. Rendered so the exception is
	// auditable rather than silently dropping out of default-deny.
	if len(v.LifelineInterfaces) > 0 {
		lines = append(lines,
			l.Indent+"Host-inbound lifeline-exempt interfaces (management/fabric, "+
				"bypass host-inbound deny): "+strings.Join(v.LifelineInterfaces, l.Sep))
	}
	return lines
}
