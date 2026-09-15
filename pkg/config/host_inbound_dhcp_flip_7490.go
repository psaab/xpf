package config

import (
	"fmt"
	"strings"
)

// host_inbound_dhcp_flip_7490.go is the ENFORCEMENT half of the #6519 DHCP
// scope parity gap: the zone-level `dhcp` / `bootp` authorization is now
// WITHHELD from an interface that runs a DHCP server or relay.
//
// #6519 stage 1 shipped the commit-time advisory
// (host_inbound_dhcp_scope_6519.go); #7490 decided which of its three options
// to implement. This is option 2 — flip for the SERVER/RELAY role only.
//
// ── THE VENDOR SENTENCE, AND EXACTLY HOW FAR IT REACHES ──────────────────
//
// Juniper, Security Zones: "All services (except DHCP and BOOTP) can be
// configured either per zone or per interface. A DHCP server is configured only
// per interface because the incoming interface must be known by the server to
// be able to send out DHCP replies."
//
// That is an argument about a SERVER needing ingress identity. It says nothing
// about a client. Junos itself does not accept these tokens at the zone level
// at ALL, for any role — so flipping every role would be the more Junos-faithful
// change — but applying a rule past its own stated justification is an error
// docs/engineering-style.md names, and here the penalty is not a wrong warning:
//
//   - #7489 established that the token is LOAD-BEARING. The AF_XDP userspace
//     dataplane enforces host-inbound on its local-delivery path, fail-closed.
//   - So a zoned, non-lifeline interface running the firewall's OWN DHCPv4
//     client would lose udp/68, and with it its unicast lease renewals, and
//     with those its ADDRESS — on a box whose recovery path may be a console.
//
// Hence: withhold where the vendor's reasoning reaches (server/relay), and
// decline to extend it where it does not (client). #7490 records that option 1
// (flip every role) stays available if strict parity is later judged worth an
// upgrade break, and that taking it AFTER this change is a smaller step than
// taking it now.
//
// ── THE ASYMMETRY IS AN XPF INVENTION, NOT A JUNOS BEHAVIOUR ─────────────
//
// Junos has no per-role rule here. An operator who observes that a zone-level
// `dhcp` works for a client and not for a server, and concludes that is what
// Junos does, will carry that belief somewhere it is false. It is documented as
// an xpf invention in docs/host-inbound-service-matrix.md in those words, and
// the same words belong in any operator-facing message about it.
//
// ── ONE CLASSIFIER, NOT TWO ──────────────────────────────────────────────
//
// The role comes from hostInboundDHCPRolesFor — the SAME classifier the stage
// 1.5 advisory annotates its output with. A second classifier that disagreed
// with the advisory's would be worse than either alone: the advisory would tell
// an operator which interfaces to migrate and enforcement would withhold on a
// different set. Lifelines are skipped here for the same reason the advisory
// skips them, and it matters more here: they are excluded from host-inbound
// deny scoping entirely, so filtering their token list would change what the
// DIAGNOSTIC surfaces render without changing what is admitted — inventing a
// divergence rather than closing one.

// stampZoneDHCPScopeWithheld derives ZoneConfig.DHCPScopeWithheld for every
// zone in cfg. Called from resolveDerivedConfig (P5), after the section
// compilers have populated interfaces, zones, `system services
// dhcp-local-server` / `dhcpv6-local-server` and `forwarding-options
// dhcp-relay` — all four are inputs to the role classifier.
//
// It stamps BOTH spellings of a member ref: the ref as the zone's Interfaces
// list authored it, and every configured unit beneath a bare physical ref. The
// zone member is routinely a bare physical (`reth1`) while the enforcement path
// resolves per unit (`reth1.0`), and a map that answered for only one spelling
// would withhold on one plane and not the other.
func stampZoneDHCPScopeWithheld(cfg *Config) {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return
	}
	scope := NewHostInboundZoneScope(cfg)
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		var withheld map[string]bool
		mark := func(ref string) {
			if ref == "" || !scope.WithholdsZoneLevelDHCP(ref) {
				return
			}
			if withheld == nil {
				withheld = map[string]bool{}
			}
			// #9821: stamp the canonical Literal alongside the authored
			// spelling so padded multi-dot refs (`p.0.01`) withhold the
			// canonical unit (`p.0.1`) the enforcement path resolves.
			// Single-dot behavior is byte-identical (Literal == legacy canon).
			withheld[ref] = true
			withheld[cfg.SplitInterfaceUnitRef(ref).Literal] = true
		}
		for _, ref := range zone.Interfaces {
			mark(ref)
			// #9821: bare-vs-unit decided by the split (declared-first):
			// a dotted-physical member fans down onto its units.
			s := cfg.SplitInterfaceUnitRef(ref)
			if s.HasUnit {
				continue
			}
			if ifc := cfg.Interfaces.Interfaces[s.Base]; ifc != nil {
				for unitNum := range ifc.Units {
					mark(fmt.Sprintf("%s.%d", s.Base, unitNum))
				}
			}
		}
		zone.DHCPScopeWithheld = withheld
	}
}

// WithholdsZoneLevelDHCPFor reports whether this zone's ZONE-LEVEL dhcp/bootp
// authorization is withheld from ref, reading the derived stamp.
//
// EXACT lookup (modulo unit-ref canonicalization) and NOT a walk up to the
// physical parent. The stamp already records every spelling that should be
// withheld — the authored ref, its canonical form, and each configured unit
// beneath a bare physical — so a parent fallback would add nothing for the refs
// it is right about and would be WRONG for the rest: a physical whose unit 0
// runs a DHCP server is itself withheld, and falling back would then withhold
// from `ge-0/0/7.50` as well, a sibling unit with no DHCP role, denying DHCP on
// an unrelated VLAN unit.
//
// That is the same leak hostInboundSameInterface refuses one level down
// ("basing both sides on the physical would collapse those two, over-matching a
// sibling unit's DHCP role onto an interface that has none"), and a fallback
// here would have reintroduced it above the classifier that prevents it. Found
// by mutation: deleting the fallback changed no test outcome, which is what
// prompted asking whether it was doing anything at all.
func (z *ZoneConfig) WithholdsZoneLevelDHCPFor(ref string) bool {
	if z == nil || len(z.DHCPScopeWithheld) == 0 || ref == "" {
		return false
	}
	return z.DHCPScopeWithheld[ref] || z.DHCPScopeWithheld[CanonicalInterfaceUnitRef(ref)]
}

// ZoneLevelSystemServicesFor returns the zone-level `system-services` list AS
// IT APPLIES TO ref: unchanged when the zone-level DHCP authorization still
// reaches ref, and with the DHCP-exception tokens removed when it does not.
//
// A zone-level `all` is EXPANDED rather than dropped or kept. `all` stands for
// the named-service union, which contains dhcp and bootp
// (HostInboundAllExpansionServices), and every plane expands it at the
// admission predicate rather than in the list — so leaving it verbatim would
// re-authorize the two tokens through the back door and the flip would be
// half-done, which is the failure mode #6519's own advisory calls out for the
// warning path. There is no token spelling for "all except dhcp", so on a
// withheld interface the union is materialised. The rendered set then reads as
// the expansion rather than `all`, which is the truthful rendering: `all` is no
// longer what that interface admits.
//
// Returns the input slice itself when nothing is withheld, so the
// overwhelmingly common path allocates nothing.
func (z *ZoneConfig) ZoneLevelSystemServicesFor(zoneSvc []string, ref string) []string {
	if len(zoneSvc) == 0 || !z.WithholdsZoneLevelDHCPFor(ref) {
		return zoneSvc
	}
	out := make([]string, 0, len(zoneSvc))
	for _, tok := range zoneSvc {
		t := strings.ToLower(strings.TrimSpace(tok))
		if t == "all" {
			for _, e := range HostInboundAllExpansionServices() {
				if !hostInboundIsDHCPExceptionToken(e) {
					out = append(out, e)
				}
			}
			continue
		}
		if hostInboundIsDHCPExceptionToken(t) {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// HostInboundZoneScope holds the two config-derived inputs the #7490 role gate
// needs, so stamping a whole config derives them ONCE rather than per interface.
type HostInboundZoneScope struct {
	cfg        *Config
	lifelines  map[string]bool
	serverRefs []string
}

// NewHostInboundZoneScope derives the lifeline set and the DHCP server/relay
// interface list once for cfg.
func NewHostInboundZoneScope(cfg *Config) HostInboundZoneScope {
	if cfg == nil {
		return HostInboundZoneScope{}
	}
	return HostInboundZoneScope{
		cfg:        cfg,
		lifelines:  HostInboundLifelineSet(cfg),
		serverRefs: hostInboundDHCPServerRefs(cfg),
	}
}

// WithholdsZoneLevelDHCP reports whether the ZONE-LEVEL `dhcp` / `bootp`
// authorization is withheld from ref.
//
// The predicate is server AND NOT client, and the conjunction is the whole
// point rather than an optimisation. hostInboundDHCPRoles keeps the two roles
// as independent booleans precisely because an interface can be BOTH — a relay
// member that also runs the firewall's own client — and on such an interface
// the client half is what holds up the address. Withholding on `server` alone
// would take the address from exactly the configuration the client carve-out
// exists to protect.
//
// Lifelines withhold nothing, for the reason the file header gives: they are
// excluded from host-inbound deny scoping entirely, so filtering their token
// list would change what the DIAGNOSTIC surfaces render without changing what
// is admitted — inventing a divergence rather than closing one.
func (s HostInboundZoneScope) WithholdsZoneLevelDHCP(ref string) bool {
	if s.cfg == nil || ref == "" {
		return false
	}
	if HostInboundLifelineInterface(ref, s.lifelines) {
		return false
	}
	roles := hostInboundDHCPRolesFor(s.cfg, s.serverRefs, ref)
	return roles.server && !roles.client
}

// hostInboundIsDHCPExceptionToken reports whether an already-lower-cased token
// is one of the two the vendor sentence names.
//
// It reads hostInboundDHCPExceptionServices — the advisory's own list — rather
// than spelling "dhcp"/"bootp" again, so the enforcement flip and the advisory
// cannot come to cover different tokens. `dhcpv6` is not in that list and is
// deliberately out of scope: the vendor sentence names DHCP and BOOTP, and
// extending it to the v6 token would be inference presented as citation.
func hostInboundIsDHCPExceptionToken(tok string) bool {
	for _, e := range hostInboundDHCPExceptionServices {
		if tok == e {
			return true
		}
	}
	return false
}
