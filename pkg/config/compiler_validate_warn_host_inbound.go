package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateHostInboundMulticastWarnings emits the #4455 (HI-1) commit-time
// advisory for a zone whose `host-inbound-traffic protocols` admits a MULTICAST
// routing protocol (OSPF/RIP/PIM/VRRP/IGMP/router-discovery/... — see the
// protocol->group catalog in host_inbound_multicast.go and
// docs/host-inbound-multicast.md).
//
// VERIFY-FIRST (current master): the kernel `xpf_hostinbound` `chain input`
// (buildHostInboundFilterPayload) matches host-local UNICAST daddr only and runs
// `policy accept`, so a host-bound packet to a well-known routing multicast group
// (224.0.0.5, 224.0.0.18, ...) matches no per-zone `daddr` set and is admitted
// PACKET-WIDE — on EVERY ingress interface — rather than scoped to the zone whose
// `host-inbound-traffic protocols` opted in (as Junos implies). The Rust AF_XDP
// classifier (host_inbound_admits) has no destination-address dimension, so it
// does not gate host-bound multicast either. This is FAIL-OPEN-BUT-BOUNDED (the
// host delivers only to groups a joined daemon subscribed; ND/PMTUD/ESP control
// is already globally accepted), a parity/hardening gap — NOT an open door.
//
// WARN-only: the config is valid Junos, and the enforcement (a per-zone
// `iifname`-scoped admission model on BOTH surfaces, the #1960 fail-closed-on-
// revert migration gating, and the kernel/Rust lockstep) is DEFERRED (#4455), so
// this must not reject or change forwarding. Mirrors the #3226 `system-services
// all` packet-wide-admit advisory. Emitted for the zone-level stanza AND every
// per-interface override (#3362); one advisory per stanza.
func validateHostInboundMulticastWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	var warnings []string
	advise := func(where string, protocols []string) {
		toks := hostInboundMulticastTokensPresent(protocols)
		if len(toks) == 0 {
			return
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s: host-bound routing multicast (%s) is currently admitted "+
				"PACKET-WIDE via the kernel input-chain accept fall-through, "+
				"not scoped to this zone's ingress interface — a known "+
				"Junos-parity gap (#4455), pending the per-zone iifname "+
				"multicast admission model.", where,
			hostInboundMulticastGroupSummary(toks)))
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		if zone.HostInboundTraffic != nil {
			advise(
				fmt.Sprintf("zone %q host-inbound-traffic", name),
				zone.HostInboundTraffic.Protocols)
		}
		// #3362: per-interface overrides carry the same `protocols` grammar and
		// the same packet-wide multicast breadth — warn on each.
		for _, ifRef := range zone.SortedInterfaceHostInboundRefs() {
			hi := zone.InterfaceHostInbound[ifRef]
			if hi == nil {
				continue
			}
			advise(
				fmt.Sprintf("zone %q interface %q host-inbound-traffic", name, ifRef),
				hi.Protocols)
		}
	}
	return warnings
}

// hostInboundAdmitsRoutingProtocol reports whether a host-inbound-traffic
// `protocols` token set admits the given routing-protocol token, honoring the
// `all` expansion (#3199 — `all` expands to every routing protocol, so it
// admits ospf/ospf3/rip). Used by the #4455 Component B advisory below.
func hostInboundAdmitsRoutingProtocol(protocols []string, token string) bool {
	for _, p := range protocols {
		if p == token {
			return true
		}
		if p == "all" {
			for _, e := range HostInboundAllExpansionProtocols() {
				if e == token {
					return true
				}
			}
		}
	}
	return false
}

// validateHostInboundManagedRoutingMismatch emits the #4455 (HI-1) Component B
// commit-time WARN advisory: a managed FRR routing protocol — OSPFv2, OSPFv3, or
// RIP, which xpf renders into FRR (pkg/frr/policy_render.go) — is enabled on an
// interface whose security zone's EFFECTIVE `host-inbound-traffic protocols` set
// (the per-interface override where declared, which REPLACES the zone-level set
// — #6515, #3362; `all`-expanded) OMITS
// the matching token (ospf/ospf3/rip).
//
// This surfaces the ACTUAL silent multicast fail-open that the shipped
// validateHostInboundMulticastWarnings misses: that advisory fires only when a
// multicast token is PRESENT (the already-compliant case), so a zone running
// OSPF/RIP with NO matching token — the real #4455 parity gap — is invisible
// today. Component B closes that observability gap.
//
// WARN-only, ZERO dataplane surface: no nft change, no Rust change, no `iifname`
// predicate (the Component A DROP enforcement is PLAN-KILLed/deferred — the
// host-bound routing multicast is admitted PACKET-WIDE via the kernel
// input-chain `policy accept` fall-through regardless of the zone token). It
// never rejects or changes forwarding; the config is valid Junos. Mirrors the
// #3226/#4454 advisory doctrine and honors #1960 lenient-load.
//
// Scope: OSPFv2 (→ ospf), OSPFv3 (→ ospf3), RIP (→ rip), for both the global
// `protocols` stanza and each routing-instance's protocols. BGP/LDP/MSDP are
// unicast (no multicast group) and out of scope; PIM is unmanaged today
// (docs/feature-gaps.md) so it has no managed source to cross-check.
func validateHostInboundManagedRoutingMismatch(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	// Build interface-ref -> zone-name mirroring the dataplane's
	// buildInterfaceZoneMap (#3072): a bare zone member (`reth0`) claims the
	// physical key AND every configured unit (`reth0.10`), a unit-qualified entry
	// claims exactly that unit — via the zoneIfaceLogicalKeys SSOT — with
	// first-writer-wins over sorted zone names. This matches runtime zone
	// attribution, so an OSPF interface `reth0.10` under a zone listing bare
	// `reth0` resolves correctly (an exact-string map would miss it). An
	// interface not in any zone has no host-inbound dimension, so it is not
	// warned on (the lookup below simply misses).
	ifZone := make(map[string]string)
	znames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		znames = append(znames, name)
	}
	sort.Strings(znames)
	for _, zname := range znames {
		z := cfg.Security.Zones[zname]
		if z == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifEntry := range z.Interfaces {
			for _, key := range zoneIfaceLogicalKeys(cfg, ifEntry) {
				if _, seen := ifZone[key]; !seen {
					ifZone[key] = zname
				}
			}
		}
	}
	if len(ifZone) == 0 {
		return nil
	}

	type managedRP struct {
		proto  string // human label for the message
		token  string // host-inbound token to require
		ifaces []string
	}
	collect := func(ospf *OSPFConfig, ospfv3 *OSPFv3Config, rip *RIPConfig) []managedRP {
		var out []managedRP
		if ospf != nil {
			var ifs []string
			for _, a := range ospf.Areas {
				if a == nil {
					continue
				}
				for _, i := range a.Interfaces {
					if i != nil && i.Name != "" {
						ifs = append(ifs, i.Name)
					}
				}
			}
			if len(ifs) > 0 {
				out = append(out, managedRP{"ospf", "ospf", ifs})
			}
		}
		if ospfv3 != nil {
			var ifs []string
			for _, a := range ospfv3.Areas {
				if a == nil {
					continue
				}
				for _, i := range a.Interfaces {
					if i != nil && i.Name != "" {
						ifs = append(ifs, i.Name)
					}
				}
			}
			if len(ifs) > 0 {
				out = append(out, managedRP{"ospf3", "ospf3", ifs})
			}
		}
		if rip != nil && len(rip.Interfaces) > 0 {
			out = append(out, managedRP{"rip", "rip", append([]string(nil), rip.Interfaces...)})
		}
		return out
	}

	var all []managedRP
	all = append(all, collect(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.RIP)...)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			all = append(all, collect(ri.OSPF, ri.OSPFv3, ri.RIP)...)
		}
	}

	var warnings []string
	for _, rp := range all {
		for _, ifn := range rp.ifaces {
			zname, ok := ifZone[ifn]
			if !ok {
				continue
			}
			z := cfg.Security.Zones[zname]
			if z == nil {
				continue
			}
			// EFFECTIVE host-inbound protocols for this interface: the
			// per-interface override where declared (it REPLACES the zone-level
			// set, #6515) WITH #3720 physical-parent inheritance for a logical
			// unit — reuse the InterfaceHostInboundEffective SSOT so the
			// advisory matches the dataplane's admission resolution exactly (a
			// parent `reth0` override admitting ospf must cover unit `reth0.10`,
			// else this warns falsely).
			_, effProto, _ := z.InterfaceHostInboundEffective(ifn)
			if hostInboundAdmitsRoutingProtocol(effProto, rp.token) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"protocols %s is enabled on interface %q (security zone %q) but that "+
					"zone's host-inbound-traffic protocols set omits %q — the protocol's "+
					"host-bound multicast is currently admitted PACKET-WIDE via the kernel "+
					"input-chain accept fall-through (a known Junos-parity gap, #4455), not "+
					"scoped to the zone. Add `host-inbound-traffic protocols %s` to zone %q "+
					"(or the interface override) to make the admission explicit.",
				rp.proto, ifn, zname, rp.token, rp.token, zname))
		}
	}
	sort.Strings(warnings)
	return warnings
}

// validateDefaultPolicyLogWarnings emits a WARN-only commit-time message when
// `security policies default-policy-log session-init/session-close` is
// configured together with a default-DENY or default-REJECT verdict (#3534).
// The session-init/session-close RT_FLOW records fire only for a default-PERMIT
// verdict (which installs a session); a deny/reject verdict installs no session
// and is already logged via the policy-deny RT_FLOW record, so the flags are
// accepted-but-inert. It is never an error: the stanza is valid and a hard
// reject would brick a boot on a previously-committed value.
func validateDefaultPolicyLogWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	// #7422 row 13: the DECISION lives in DefaultPolicyLogFlagsInert so this
	// advisory and the three renderers that surface the flags cannot disagree
	// about which case is inert. The wording below stays here; only the
	// predicate is shared.
	if !DefaultPolicyLogFlagsInert(cfg) {
		return nil
	}
	var modes []string
	if cfg.Security.DefaultPolicyLogSessionInit {
		modes = append(modes, "session-init")
	}
	if cfg.Security.DefaultPolicyLogSessionClose {
		modes = append(modes, "session-close")
	}
	action := "deny-all"
	if cfg.Security.DefaultPolicy == PolicyReject {
		action = "reject-all"
	}
	return []string{fmt.Sprintf(
		"security policies default-policy-log `%s` is inert under default-policy "+
			"%s: a deny/reject verdict installs no session, so no RT_FLOW "+
			"session-init/session-close record is produced (the default verdict "+
			"is already logged via the policy-deny RT_FLOW record). These flags "+
			"take effect only with `default-policy permit-all`",
		strings.Join(modes, "/"), action)}
}

// validatePolicyLogInertOnDenyWarnings emits a WARN-only commit-time message
// for each NAMED or GLOBAL security policy whose terminal action is deny/reject
// yet configures `then log session-init` and/or `session-close` (#4373 E1,
// avo-review-007). This is the per-policy analog of the default-policy advisory
// above (validateDefaultPolicyLogWarnings, #3534).
//
// The confusion: an operator writes `then reject; then log session-close`
// expecting a close record when the flow is rejected. But a deny/reject verdict
// installs NO session, so the RT_FLOW SESSION_CREATE / SESSION_CLOSE records
// those flags request never fire — session-close has no session to close.
// The deny is instead logged unconditionally via the RT_FLOW policy-deny record
// (userspace-dp emit_policy_deny_event fires on EVERY non-permit verdict, never
// gated on a per-policy log flag), so `then log session-init` is redundant and
// `then log session-close` is inert. `then log` session records fire only for a
// `then permit` policy, whose admitted session the dataplane stamps the log
// flags onto at install (the #2508 per-policy path). Without this advisory the
// operator sees a policy that REPORTS session-close logging (REST/gRPC/CLI show
// the flag) yet produces no close record — a silent observability gap.
//
// WARN-only: `then log` on a deny/reject is valid Junos syntax and a hard
// reject would brick a previously-committed config (#1960 no-brick doctrine).
// The bare-`then log` gate (validatePolicyLogActionStrict, #3060) still applies
// independently. Iteration is over the ordered policy slices (zone-pair, then
// global), so the warnings are stable across commits.
func validatePolicyLogInertOnDenyWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	check := func(who string, pol *Policy) {
		if pol == nil || pol.Log == nil {
			return
		}
		if pol.Action != PolicyDeny && pol.Action != PolicyReject {
			return
		}
		if !pol.Log.SessionInit && !pol.Log.SessionClose {
			return
		}
		var modes []string
		if pol.Log.SessionInit {
			modes = append(modes, "session-init")
		}
		if pol.Log.SessionClose {
			modes = append(modes, "session-close")
		}
		action := "deny"
		if pol.Action == PolicyReject {
			action = "reject"
		}
		warnings = append(warnings, fmt.Sprintf(
			"security policy %s `then log %s` is inert under `then %s`: a "+
				"deny/reject verdict installs no session, so no RT_FLOW "+
				"session-init/session-close record is produced (the verdict is "+
				"already logged via the policy-deny RT_FLOW record). `then log` "+
				"session records fire only for a `then permit` policy (#4373)",
			who, strings.Join(modes, "/"), action))
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			check(fmt.Sprintf("%s->%s/%s", zpp.FromZone, zpp.ToZone, pol.Name), pol)
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		check(fmt.Sprintf("global/%s", pol.Name), pol)
	}
	return warnings
}

// junosHostPolicySourceScoped reports whether a policy match carries a genuine
// source-address restriction — i.e. it is narrower than "any source". A match
// with only the reserved wildcards (`any`/`any-ipv4`/`any-ipv6`/the empty
// token) is NOT scoped; a match naming a concrete address-book entry, literal
// prefix, or feed binding IS. `source-address-excluded` is inherently a
// restriction (permit/deny all EXCEPT the named sources) and so counts as
// scoped regardless of the token. Mirrors the wildcard set recognized by
// policyMatchAddressTokenRecognized (#3958) so the two agree on "any".
func junosHostPolicySourceScoped(m PolicyMatch) bool {
	if m.SourceAddressExcluded {
		return true
	}
	for _, a := range m.SourceAddresses {
		switch a {
		case "", "any", "any-ipv4", "any-ipv6":
			continue
		}
		return true
	}
	return false
}

// junosHostPolicyStricterThanCoarseGate reports whether a `to-zone junos-host`
// policy expresses a constraint the coarse kernel host-inbound gate cannot
// enforce on the direct host-bound path, and if so a short human label for the
// reason. The nft `xpf_hostinbound` chain (the PRIMARY enforcement for
// host-bound traffic the XDP shim shunts to the kernel) is permit-by-service
// only: it admits configured `system-services`/`protocols` to a firewall-local
// address from ANY source, with no per-source or per-application DENY. So a
// junos-host policy is stricter — and therefore silently unenforced on the
// direct path — when it:
//   - denies/rejects: the coarse gate cannot deny a service it permits, OR
//   - permits but restricts the source: the coarse gate admits any source.
//
// A plain `then permit` from any source only mirrors (or loosens) the coarse
// permit-by-service gate and adds no restriction the coarse gate lacks, so it
// does NOT warn — the conservative trigger the #4146 plan calls for (warn only
// on a genuinely stricter-than-coarse-gate junos-host policy, not every one).
// An application-only scope is deliberately not a standalone trigger: the
// coarse gate already filters by service/dport, so a narrow single-port
// application largely overlaps it; only the deny and the source restriction are
// dimensions the coarse gate has no expression for at all.
func junosHostPolicyStricterThanCoarseGate(action PolicyAction, m PolicyMatch) (bool, string) {
	switch action {
	case PolicyDeny:
		return true, "deny"
	case PolicyReject:
		return true, "reject"
	}
	if junosHostPolicySourceScoped(m) {
		return true, "source-restricted permit"
	}
	// #6612: a permit narrowed on DESTINATION is stricter for the same reason a
	// source-narrowed one is — the nft chain admits every configured
	// system-service to EVERY local address in the zone, so each firewall
	// address the permit does not name falls to the junos-host default deny
	// under Junos and is admitted here. Before #6612 such a permit produced no
	// warning at all, because this predicate asked about the source alone.
	//
	// #9504 changed what the warning is FOR, not whether it fires. The
	// projection now renders a destination-scoped permit (a return carrying its
	// `daddr` predicate), so it is no longer an unrendered policy. What stays
	// true is that no path applies an implicit junos-host default-deny, so the
	// addresses the permit does not name are admitted everywhere, and the
	// warning says that.
	if junosHostAddrScoped(m.DestinationAddresses) || m.DestinationAddressExcluded {
		return true, "destination-restricted permit"
	}
	return false, ""
}

// validateJunosHostDirectDeliveryWarnings emits a WARN-only commit-time message
// for each `to-zone junos-host` security policy — zone-pair or global — that is
// stricter than the coarse kernel host-inbound gate can enforce on the DIRECT
// host-bound path (#4146 H-1 slice c).
//
// The gap: ordinary traffic to a firewall interface IP is delivered by the
// Linux kernel (the XDP shim shunts local-destined packets to the kernel on a
// session miss — userspace-xdp/src/lib.rs is_local_destination →
// cpumap_or_pass), whose nft `xpf_hostinbound` chain has no junos-host
// awareness: it admits configured system-services from any source with no
// per-source / per-application deny. The fine `to-zone junos-host` restriction
// runs only on the userspace AF_XDP LocalDelivery path
// (junos_host_local_policy), which a direct host-bound packet never reaches.
// So a configured deny (or source-scoped permit) to junos-host is silently
// unenforced on the primary host-bound path — a false sense of security this
// warning surfaces at commit.
//
// It is never an error: the config is legal Junos, and the actual enforcement
// fix (withhold the IP from the local set / mirror the policy into nft) is a
// PLAN-DEFERRED availability-vs-security decision (#4146 directions a/b) — a
// hard reject would also brick a previously-committed config. Iteration is over
// the ordered policy slices (deterministic by config order), so the warnings
// are stable across commits.
func validateJunosHostDirectDeliveryWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	// #4146: the representable ordered DENY class is now ENFORCED on the direct
	// host-bound path by the kernel nft `xpf_hostinbound` chain
	// (BuildJunosHostDenyProjection). Suppress the parity warning for exactly the
	// policies that rendered an enforced kernel rule; every un-representable /
	// lifeline-only / unenforceable policy still warns (the documented
	// partial-coverage remainder). Rendered means: the policy applies only to
	// enforceable ingress zones and EVERY such zone's whole program is
	// representable (§3.3 / §8 inv-12).
	rendered := BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys
	var warnings []string
	msg := func(who, reason string) string {
		return fmt.Sprintf(
			"security policy %s expresses a %s to-zone junos-host that the kernel "+
				"host-inbound gate cannot enforce on the direct host-bound path: "+
				"traffic to a firewall interface IP is delivered by the kernel (the "+
				"XDP shim shunts local-destined packets to it on a session miss) and "+
				"nft xpf_hostinbound admits configured system-services from ANY "+
				"source with no per-source/per-application deny. The junos-host "+
				"restriction is enforced only on the userspace AF_XDP local-delivery "+
				"path (e.g. DNAT/static-NAT to a firewall-local address), so this "+
				"management-plane restriction may not fully apply to the direct path "+
				"(#4146, known vSRX-parity limitation — see "+
				"docs/host-inbound-service-matrix.md)",
			who, reason)
	}
	// #9504: a restricted PERMIT has nothing to enforce on any path. The runtime
	// applies no implicit junos-host default-deny (policy.rs
	// evaluate_junos_host_policy_l3_aware, policymatch.matchJunosHost), so what the
	// permit does not match is admitted by the zone's host-inbound-traffic on the
	// userspace path exactly as on the kernel path. msg tells the operator the
	// restriction holds on the userspace path, which is false for a permit.
	permitMsg := func(who, reason string) string {
		return fmt.Sprintf(
			"security policy %s is a %s to-zone junos-host, but no path applies an "+
				"implicit default-deny to host-bound traffic (the management lifeline): "+
				"whatever the permit does not match is still admitted by the ingress "+
				"zone's host-inbound-traffic, on the direct host-bound path and on the "+
				"userspace path alike. To refuse it, follow the permit with an explicit `then deny` "+
				"policy (#4146, #9504; see docs/host-inbound-service-matrix.md)",
			who, reason)
	}
	pick := func(a PolicyAction) func(string, string) string {
		if a == PolicyPermit {
			return permitMsg
		}
		return msg
	}
	// Zone-pair policies: `from-zone X to-zone junos-host { policy ... }`.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != "junos-host" {
			continue
		}
		for _, p := range zpp.Policies {
			if p == nil {
				continue
			}
			if rendered[JunosHostZonePairPolicyKey(zpp.FromZone, p.Name)] {
				continue // #4146: enforced on the direct path — no parity gap.
			}
			if stricter, reason := junosHostPolicyStricterThanCoarseGate(p.Action, p.Match); stricter {
				warnings = append(warnings, pick(p.Action)(fmt.Sprintf(
					"%q (from-zone %q)", p.Name, zpp.FromZone), reason))
			} else if p.Action == PolicyPermit {
				// #7374: the APPLICATION dimension. Checked separately because
				// it needs the zone's effective admit set, which the
				// action+match predicate above cannot see -- and because it is
				// a COMPARISON, not a token test: an application-narrowed
				// permit is only stricter when the gate admits something the
				// permit does not cover.
				if gap, reason := junosHostPermitApplicationGap(cfg, zoneByName(cfg, zpp.FromZone), p.Match); gap {
					warnings = append(warnings, permitMsg(fmt.Sprintf(
						"%q (from-zone %q)", p.Name, zpp.FromZone), reason))
				}
			}
		}
	}
	// Global policies with a `match to-zone junos-host` context (#3639). A
	// `match from-zone junos-host` global is already hard-rejected at commit
	// (validatePolicyZoneReferencesStrict), so it never reaches here.
	for _, p := range cfg.Security.GlobalPolicies {
		// #4626 M03: a host-inbound global scopes `to-zone junos-host` alone
		// (IsHostToZoneScope); a transit or all-zones global never does.
		if p == nil || !IsHostToZoneScope(p.Match.ToZones) {
			continue
		}
		if rendered[JunosHostGlobalPolicyKey(p.Name)] {
			continue // #4146: enforced on the direct path — no parity gap.
		}
		if stricter, reason := junosHostPolicyStricterThanCoarseGate(p.Action, p.Match); stricter {
			warnings = append(warnings, pick(p.Action)(fmt.Sprintf("global %q", p.Name), reason))
		} else if p.Action == PolicyPermit {
			// #7374: a global `to-zone junos-host` permit applies from EVERY
			// zone, so it has a gap if ANY zone's gate admits something it does
			// not cover. Zones are walked in sorted order so the first-reported
			// gap is deterministic.
			for _, zn := range sortedZoneNames(cfg) {
				if gap, reason := junosHostPermitApplicationGap(cfg, zoneByName(cfg, zn), p.Match); gap {
					warnings = append(warnings, permitMsg(fmt.Sprintf("global %q", p.Name), reason))
					break
				}
			}
		}
	}
	return warnings
}

// validatePreIDDefaultPolicyLogWarnings emits a WARN-only commit-time message
// when `security pre-id-default-policy then log session-init/session-close` is
// configured. The flags are parsed and stored but have no runtime consumer in
// the userspace dataplane (#2509) — there is no pre-identification
// session-admit path to stamp the log mode onto — so the logging action is
// accepted-but-inert. It is never an error: pre-id-default-policy is valid
// Junos and a hard reject would brick a boot on a previously-inert committed
// value.
func validatePreIDDefaultPolicyLogWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	p := cfg.Security.PreIDDefaultPolicy
	if p == nil || (!p.LogSessionInit && !p.LogSessionClose) {
		return nil
	}
	var modes []string
	if p.LogSessionInit {
		modes = append(modes, "session-init")
	}
	if p.LogSessionClose {
		modes = append(modes, "session-close")
	}
	return []string{fmt.Sprintf(
		"security pre-id-default-policy `then log %s` is accepted for "+
			"compatibility but is inert in the userspace dataplane (no "+
			"pre-identification session-admit path exists to emit the "+
			"RT_FLOW session log)",
		strings.Join(modes, "/"))}
}

// hostInboundTokenExpansion expands one host-inbound token to the set of NAMED
// tokens it stands for, so a coverage comparison is made on what is actually
// admitted rather than on the spelling. `all` is the only expanding token, and
// it expands differently per kind (HostInboundAllExpansionServices vs
// HostInboundAllExpansionProtocols), which is why the kind is a parameter rather
// than the caller picking a helper. Returned tokens are lower-cased, matching
// how the dataplane keys them.
func hostInboundTokenExpansion(token string, protocols bool) []string {
	t := strings.ToLower(strings.TrimSpace(token))
	if t == "" {
		return nil
	}
	if protocols {
		if t == "all" {
			out := make([]string, 0, len(HostInboundAllExpansionProtocols()))
			for _, p := range HostInboundAllExpansionProtocols() {
				out = append(out, strings.ToLower(p))
			}
			return out
		}
		return []string{t}
	}
	exp := HostInboundServiceTokenExpansion(t)
	out := make([]string, 0, len(exp))
	for _, e := range exp {
		out = append(out, strings.ToLower(strings.TrimSpace(e)))
	}
	return out
}

// hostInboundLostTokens returns the tokens from zoneToks that the interface's
// EFFECTIVE set no longer admits, in their authored order. A zone token is
// "kept" only when EVERY token it expands to is admitted by the effective set,
// so `all` at the zone level with a narrow interface stanza is reported (it is
// genuinely narrowed) while `ssh` at the zone level with `all` on the interface
// is not (the expansion covers it).
func hostInboundLostTokens(zoneToks, effToks []string, protocols bool) []string {
	if len(zoneToks) == 0 {
		return nil
	}
	admitted := make(map[string]bool, len(effToks)*2)
	for _, t := range effToks {
		for _, e := range hostInboundTokenExpansion(t, protocols) {
			admitted[e] = true
		}
	}
	var lost []string
	for _, zt := range zoneToks {
		exp := hostInboundTokenExpansion(zt, protocols)
		if len(exp) == 0 {
			continue
		}
		covered := true
		for _, e := range exp {
			if !admitted[e] {
				covered = false
				break
			}
		}
		if !covered {
			lost = append(lost, zt)
		}
	}
	return lost
}

// validateHostInboundOverrideReplaceWarnings emits the #6515 MIGRATION advisory:
// one warning per zone interface whose per-interface `host-inbound-traffic`
// stanza REPLACES a zone-level stanza that admitted more than it does.
//
// #6515 changed the zone↔interface combination from a union to a replace, to
// match Junos ("You can configure these parameters at the zone level, in which
// case they affect all interfaces of the zone, or at the interface level.
// (Interface configuration overrides that of the zone.)"). That is a NARROWING
// for any config authored against the previous additive behaviour: an interface
// stanza that was written to ADD `protocols ospf` to a zone admitting `ssh` now
// admits ospf and NOTHING ELSE on that interface. The services most likely to
// disappear are exactly the ones an operator cannot afford to lose silently —
// ssh, https/webmgmt, ike (ESP/AH are globally accepted but IKE udp/500,4500 is
// token-gated, so tunnels stop rekeying), and unicast bgp/ospf to the interface
// address.
//
// It is worse than "new connections are refused": the #5566 reconcile rebuilds
// its admit set from the same views and DELETES established kernel conntrack
// entries to a covered firewall-local address the new set no longer admits, so a
// narrowing commit drops the operator's LIVE session to a removed service. This
// advisory therefore names every lost token at `commit check`, BEFORE the commit
// that would remove it, and tells the operator the mechanical remedy: repeat the
// zone tokens in the interface stanza.
//
// WARN-only, never a reject: the config is valid Junos and the new behaviour IS
// the Junos behaviour. Rejecting it would refuse a config Junos accepts.
//
// Scope. Emitted per ZONE INTERFACE rather than per authored stanza, because a
// unit that merely INHERITS a physical-parent override (#3720) also loses the
// zone tokens and the operator needs to see the interface whose admission
// actually changed. Lifeline interfaces (fxp0 / em0 / fab* / the configured
// control + fabric links) are skipped: they are excluded from host-inbound deny
// scoping entirely, so nothing is lost on them and an advisory would be a false
// alarm. An effective set that full-admits (`any-service`) loses nothing and is
// skipped for the same reason.
func validateHostInboundOverrideReplaceWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []string
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.HostInboundTraffic == nil {
			continue // no zone-level stanza => nothing an override can replace
		}
		zoneSvc := zone.HostInboundTraffic.SystemServices
		zoneProto := zone.HostInboundTraffic.Protocols
		if len(zoneSvc) == 0 && len(zoneProto) == 0 {
			continue
		}
		refs := make([]string, 0, len(zone.Interfaces))
		seen := make(map[string]bool, len(zone.Interfaces))
		for _, ref := range zone.Interfaces {
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		for _, ref := range refs {
			if HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			effSvc, effProto, overridden := zone.InterfaceHostInboundEffective(ref)
			if !overridden {
				continue
			}
			fullAdmit := false
			for _, s := range effSvc {
				if HostInboundFullAdmitService(s) {
					fullAdmit = true
					break
				}
			}
			if fullAdmit {
				continue
			}
			lostSvc := hostInboundLostTokens(zoneSvc, effSvc, false)
			lostProto := hostInboundLostTokens(zoneProto, effProto, true)
			if len(lostSvc) == 0 && len(lostProto) == 0 {
				continue
			}
			var lost []string
			if len(lostSvc) > 0 {
				lost = append(lost, "system-services ["+strings.Join(lostSvc, " ")+"]")
			}
			if len(lostProto) > 0 {
				lost = append(lost, "protocols ["+strings.Join(lostProto, " ")+"]")
			}
			warnings = append(warnings, fmt.Sprintf(
				"zone %q interface %q: the per-interface host-inbound-traffic "+
					"stanza REPLACES the zone-level stanza on this interface "+
					"(Junos: \"Interface configuration overrides that of the "+
					"zone\"), so host-bound %s admitted by zone %q is DENIED "+
					"here. Repeat those tokens in the interface stanza to keep "+
					"admitting them. Established sessions to a removed service "+
					"are flushed at commit, not merely refused for new "+
					"connections (#6515, #5566).",
				name, ref, strings.Join(lost, " and "), name))
		}
	}
	return warnings
}

// validateHostInboundStanzaWarnings emits every commit-time advisory drawn by a
// `host-inbound-traffic` STANZA — the #3226 `any-service` breadth notice, the
// #3226 `system-services all` scoping/upgrade notice, and the unported-service
// denial notice — for the zone-level stanza and for each per-interface override
// (#3362).
//
// It was inline in ValidateConfig until #6640. It is the last member of the
// host-inbound advisory family to join its siblings in this file, and the move
// is a pure relocation: the body is byte-identical to the inline block, the
// three closures it defines were referenced from nowhere else, and the call
// site sits at the exact position the block occupied so the ORDER of
// ValidateConfig's returned slice is unchanged.
//
// The advisories reason about the EFFECTIVE view the dataplane enforces
// (config.ResolveInterfaceHostInbound), never the raw stanzas — see the
// comments inside, and docs/host-inbound-service-matrix.md.
func validateHostInboundStanzaWarnings(cfg *Config) []string {
	var warnings []string
	// #3226: `system-services any-service` is a packet-wide host-inbound
	// full-admit, NOT a union of the known system-service tokens. On BOTH
	// enforcement layers (the nft kernel mirror `hostInboundAllowsAll` →
	// `<fam> daddr <addrs> accept` with no catch-all drop, and the Rust AF_XDP
	// classifier `all_services` short-circuit) it accepts EVERY IP protocol/port
	// — GRE/ESP/AH/OSPF/PIM/VRRP and arbitrary future protocol numbers — to the
	// zone's local firewall addresses. Junos defines `any-service` as "all system
	// services on an entire port range including the system services that are not
	// defined", so it IS the documented escape hatch; xpf's packet-wide reading is
	// a superset of that. The breadth is deliberate, so this is a WARNING, never a
	// reject. `HostInboundFullAdmitService` is the SSOT for which tokens are
	// full-admit (pkg/config/host_inbound_tokens.go). Emitted for the zone-level
	// stanza AND every per-interface override (#3362); one advisory per stanza.
	//
	// The sibling `system-services all` NO LONGER lands here: #3226 scoped it to
	// the named-service union (HostInboundAllExpansionServices), matching the
	// Junos definition ("traffic from the defined system services available on the
	// Routing Engine") and the shape #3199 gave `protocols all`. It draws the
	// separate scoping advisory below instead.
	fullAdmitAdvice := func(where string, svcs []string) {
		for _, svc := range svcs {
			if !HostInboundFullAdmitService(svc) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"%s: system-services %q is a broad packet-wide full-admit that "+
					"accepts EVERY IP protocol/port "+
					"(GRE/ESP/AH/OSPF/PIM/VRRP/future proto numbers) to the "+
					"zone's local addresses — a superset of Junos's per-service "+
					"union; if you intend only specific services, list them "+
					"explicitly.", where, svc))
			return // one advisory per stanza
		}
	}
	// #3226 scoping advisory for `system-services all`. The token is valid Junos
	// and is now enforced with the Junos meaning, so this is purely an UPGRADE
	// notice: a deploy that leaned on the old packet-wide breadth to admit a
	// non-named protocol/port loses that admit, and the catch-all host-inbound
	// drop is now armed for the zone.
	//
	// It is gated on the stanza's zone owning at least one NON-lifeline
	// interface, because the narrowing can only change enforcement where the
	// zone actually contributes host-inbound addresses. Lifeline interfaces
	// (fxp0 + the configured cluster control/fabric interfaces, #3277) are
	// excluded from the deny address sets by BuildZoneHostInboundViews, so a
	// lifeline-only zone emits no rules at all and `all` vs the expansion is
	// indistinguishable there. Every shipped HA config puts `system-services
	// all` on exactly such a zone (the lifeline-only `control` zone — see
	// docs/ha-cluster-userspace.conf), so an ungated advisory would fire on
	// every cluster commit forever while flagging a guaranteed no-op.
	lifelines := HostInboundLifelineSet(cfg)
	allScopingAdvice := func(where string, svcs []string, enforcing bool) {
		if !enforcing {
			return
		}
		for _, svc := range svcs {
			if strings.ToLower(strings.TrimSpace(svc)) != "all" {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"%s: system-services \"all\" now expands to the union of the "+
					"named system-services (Junos parity, #3226) and no longer "+
					"admits every IP protocol/port — GRE, OSPF/PIM/VRRP, "+
					"unlisted TCP/UDP ports and future protocol numbers are now "+
					"DENIED to the zone's local addresses unless listed "+
					"explicitly under system-services / protocols; use "+
					"\"any-service\" for the previous packet-wide admit. "+
					"ESP/AH are NOT affected: they keep an unconditional "+
					"global accept (host-terminated IPsec is decrypted by XFRM "+
					"before any host-inbound deny), so no action is needed for "+
					"them — and there is no esp/ah token to list in any case.", where))
			return // one advisory per stanza
		}
	}
	// #3226 fold: for several services in Juniper's `system-services`
	// enumeration xpf has no authoritative listening tuple — r2cp, rpm,
	// tcp-encap, appqoe and high-availability
	// (config.HostInboundUnportedSystemServices). Junos would open whatever port
	// applies; xpf refuses to guess, because an invented port opens a port with
	// no listener while STILL denying the port actually in use. So these tokens
	// commit (they are real Junos services — rejecting them is the #3200 parity
	// gap) but synthesize no admit on either enforcement surface.
	//
	// That divergence is fail-CLOSED but it must not be SILENT: an operator who
	// went to the trouble of naming the service plainly expects it to work.
	// Warn at the moment they name it, and name a remedy that ACTUALLY WORKS.
	//
	// `any-service` is the ONLY remedy, and the advisory names nothing else.
	// Two earlier revisions got this wrong and the history is worth keeping:
	//
	//   r3 told operators to "admit the real port with a firewall filter". False
	//     on the AF_XDP local-delivery path: #3485 deliberately runs the
	//     host-inbound gate FIRST so a denied packet incurs none of the lo0
	//     filter's side-effects (counter, log, reject reply); on a deny the lo0
	//     filter is never evaluated at all.
	//   r4 narrowed that to "kernel path only", reasoning that xpf_lo0 (hook
	//     input priority 0) runs before xpf_hostinbound (priority 10) so an lo0
	//     `accept` terminates first. The PRIORITIES are right and the CONCLUSION
	//     is wrong: in nftables `accept` ends the current BASE CHAIN, not the
	//     hook. The nftables man page is explicit — "An accept verdict ... ends
	//     the evaluation of the current base chain. ... The packet advances to
	//     the next base chain", whereas only drop "immediately ends the
	//     evaluation of the whole ruleset". So the packet still traverses
	//     xpf_hostinbound at priority 10 and still hits its catch-all drop.
	//     There is no mark, no return-path exclusion, no bypass wiring between
	//     the two chains.
	//
	// So an lo0 filter accept rescues NOTHING on EITHER surface, and the remedy
	// is withdrawn rather than narrowed. Making it work would mean building a
	// real bypass — an explicit mark set in xpf_lo0 and tested in
	// xpf_hostinbound, or merging the chains — which is a new security mechanism
	// that deliberately lets an lo0 filter override the zone host-inbound
	// default-deny. That needs its own design and threat review, and it would
	// STILL not help on the AF_XDP path without also reordering #3485. Out of
	// scope here; see docs/host-inbound-service-matrix.md.
	//
	// Gated on explicit naming only. `system-services all` also covers these
	// tokens (contributing nothing), but warning there would fire on a large
	// fraction of commits — including every lifeline-only HA `control` zone —
	// while telling the operator nothing they asked about. The `all` case is
	// documented in docs/host-inbound-service-matrix.md instead.
	//
	// SUPPRESSED when the same stanza already carries a full-admit token. The
	// advisory's entire content is "this traffic is DENIED, use any-service" —
	// but with `any-service` present nothing IS denied (the full-admit
	// short-circuit means no catch-all drop is emitted at all, and the AF_XDP
	// classifier admits unconditionally), so the warning would be false on its
	// premise AND would advise adding a token the operator has already added.
	// The two advisory passes run independently, so without this gate a stanza
	// naming both `any-service` and `rpm` emitted one warning saying
	// `any-service` admits everything and another saying rpm is denied.
	unportedAdvice := func(where string, svcs []string) {
		for _, svc := range svcs {
			if HostInboundFullAdmitService(svc) {
				return
			}
		}
		var named []string
		seen := map[string]bool{}
		for _, svc := range svcs {
			tok := strings.ToLower(strings.TrimSpace(svc))
			if !HostInboundUnportedSystemServices[tok] || seen[tok] {
				continue
			}
			seen[tok] = true
			named = append(named, tok)
		}
		if len(named) == 0 {
			return
		}
		sort.Strings(named)
		// The two reason classes describe different operator situations, so they
		// get different wording. For an operator-configured port the operator
		// KNOWS their port and can act on it; for an unsourced service nobody
		// knows it, including xpf, and saying "the port is configurable" there
		// would be a lie.
		var configured, unsourced []string
		for _, tok := range named {
			if HostInboundNoAdmitReason[tok] == HostInboundNoPortOperatorConfigured {
				configured = append(configured, tok)
			} else {
				unsourced = append(unsourced, tok)
			}
		}
		var why []string
		if len(configured) > 0 {
			why = append(why, fmt.Sprintf(
				"[%s] have an operator-configured port with no platform default, so there "+
					"is no fixed port for xpf to admit", strings.Join(configured, " ")))
		}
		if len(unsourced) > 0 {
			why = append(why, fmt.Sprintf(
				"for [%s] xpf could not find an authoritative listening port and will not "+
					"guess one", strings.Join(unsourced, " ")))
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s: system-services [%s] accepted but NOT enforced — %s (a guessed port "+
				"opens an unused port while still denying the one actually in use). "+
				"Their traffic is DENIED to the zone's local addresses. The only remedy "+
				"is \"any-service\"; an lo0 input filter does NOT help, on either "+
				"enforcement path.",
			where, strings.Join(named, " "), strings.Join(why, "; ")))
	}
	hiZoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		hiZoneNames = append(hiZoneNames, name)
	}
	sort.Strings(hiZoneNames)
	// #8854: LOOP-INVARIANT. ResolveInterfaceHostInbound takes only cfg and
	// nothing in this loop mutates what it reads, so calling it per zone made
	// the tolerant compile O(Z^2 log Z) — it sorts every zone name on each
	// call. Measured on CompileConfigLenient before the hoist: 0.15s at 500
	// zones, 4.0s at 2000, 8.5s at 3000, 76s at 8000, with the resolver 86.7%
	// cumulative and slices.pdqsortOrdered 67.7% at Z=3000.
	//
	// This path is the TOLERANT one — boot and HA peer-sync — so the cost lands
	// where an operator cannot see it: a node taking 76 seconds to come up, or
	// a peer sync stalling, on a config that commits clean.
	//
	// The hoist is only safe because the resolved map does not change during
	// the loop. That was verified by instrumenting the loop to recompute the
	// map every iteration and compare against the first, then running
	// pkg/config, pkg/configstore and pkg/dataplane: zero divergences, with the
	// probe proved live by a positive control that mutated
	// zone.InterfaceHostInbound and did fire.
	//
	// Called through resolveInterfaceHostInboundFn so the ONCE-per-invocation
	// property is assertable — see
	// TestHostInboundResolverCalledOncePerValidate8854. A correctness cell
	// cannot see this: moving the call back inside the loop leaves every
	// existing test green and only the cost changes.
	resolvedHI := resolveInterfaceHostInboundFn(cfg)
	for _, name := range hiZoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		// True when the zone owns an interface that contributes host-inbound
		// addresses (i.e. is not a lifeline), so the #3226 narrowing is
		// observable on this zone.
		zoneEnforces := false
		for _, ifRef := range zone.Interfaces {
			if !HostInboundLifelineInterface(ifRef, lifelines) {
				zoneEnforces = true
				break
			}
		}
		// #3226 fold: every advisory below reasons about the EFFECTIVE token
		// set — via the shared EffectiveHostInboundTokens — because that is what
		// enforcement acts on. Reasoning per RAW STANZA made the advisories
		// contradict enforcement AND each other: a zone `any-service` with a
		// per-interface `rpm` warned that rpm was DENIED when the effective set
		// admits everything. Sharing the resolver removes the whole class rather
		// than special-casing each pair. Post-#6515 that resolver REPLACES the
		// zone level with a declared interface stanza rather than unioning them.
		var zoneSvcs []string
		if zone.HostInboundTraffic != nil {
			zoneSvcs = zone.HostInboundTraffic.SystemServices
		}
		// A full-admit token anywhere in an effective set makes the scoping and
		// unported advisories moot for that set: nothing is denied, so telling
		// the operator traffic is DENIED (and to add `any-service`) would be
		// false on its premise and would advise a change already made.
		effectiveFullAdmits := func(svcs []string) bool {
			for _, svc := range svcs {
				if HostInboundFullAdmitService(svc) {
					return true
				}
			}
			return false
		}
		// #6640: the advisories below reason about the SAME EFFECTIVE VIEW the
		// dataplane enforces, resolved by config.ResolveInterfaceHostInbound —
		// which the enforcement builders in pkg/dataplane/userspace now call
		// too. Before this they unioned the zone with each RAW interface stanza
		// and modelled no physical->unit layer at all, so the two reasoned about
		// different objects and the advisory contradicted enforcement on any
		// config that used both levels.
		//
		// The resolved map is keyed by the enforcement key — a canonical logical
		// unit, or a bare physical for a unit-less interface — and its value is
		// the physical-inherited override UNIONED with the unit-level one
		// (#3720), cross-zone quarantined (#3720 M01 / #5489).
		// hiKeysFor returns the enforcement keys a raw zone-interface REF
		// governs. It is deliberately not "the ref itself": a physical ref with
		// units never reaches the dataplane as a key — the per-unit snapshot
		// consumer looks up "<phy>.<unit>" — so an advisory keyed on the bare
		// physical would describe an object nothing enforces. A unit-less
		// physical IS its own key (see ResolveHostInboundIngressInterface).
		hiKeysFor := func(ref string) []string {
			canon := CanonicalInterfaceUnitRef(ref)
			if strings.Contains(canon, ".") {
				return []string{canon}
			}
			if ifCfg := cfg.Interfaces.Interfaces[canon]; ifCfg != nil && len(ifCfg.Units) > 0 {
				units := make([]string, 0, len(ifCfg.Units))
				for unitNum := range ifCfg.Units {
					units = append(units, fmt.Sprintf("%s.%d", canon, unitNum))
				}
				sort.Strings(units)
				return units
			}
			return []string{canon}
		}
		// hiEffectiveAt returns the effective system-service set the dataplane
		// admits on ONE enforcement key: the resolved override when one applies
		// (it REPLACES the zone level, #6515), else the zone-level set.
		hiEffectiveAt := func(key string) []string {
			ovr := resolvedHI[key]
			var is []string
			if ovr != nil {
				is = ovr.SystemServices
			}
			return EffectiveHostInboundTokens(zoneSvcs, is, ovr != nil)
		}
		// The zone-level stanza governs every enforcement key that does NOT
		// resolve to an interface-level override. #6515: an interface that
		// declares one REPLACES the zone set, so if EVERY key in the zone
		// resolves to an override, the zone-level tokens reach nothing and their
		// advisories are moot. A LIFELINE key is excluded as well: its host
		// traffic is served unconditionally (#3277), so the zone-level narrowing
		// is not observable there either — which is the false warning #6640
		// reproduced for a lifeline-only zone.
		//
		// The lookup is the RESOLVED map, not the raw stanza list, so a unit that
		// merely INHERITS a physical-parent override counts as covered. It is
		// covered: the dataplane enforces the inherited override on that unit and
		// never the zone set.
		//
		// A zone with NO interfaces keeps warning, exactly as before: the stanza
		// governs nothing yet, but the advisory is about what the operator
		// AUTHORED, and suppressing it would silence the #3226 advisory on the
		// commonest way to write one (a zone stanza authored before its
		// interfaces). Only a zone that HAS interfaces, none of which the
		// zone-level set can reach, is silenced.
		zoneObservable := !effectiveFullAdmits(zoneSvcs)
		if zoneObservable && len(zone.Interfaces) > 0 {
			reached := false
			for _, ifRef := range zone.Interfaces {
				if HostInboundLifelineInterface(ifRef, lifelines) {
					continue
				}
				for _, key := range hiKeysFor(ifRef) {
					if resolvedHI[key] == nil {
						reached = true
						break
					}
				}
				if reached {
					break
				}
			}
			zoneObservable = reached
		}
		if zone.HostInboundTraffic != nil {
			where := fmt.Sprintf("zone %q host-inbound-traffic", name)
			fullAdmitAdvice(where, zoneSvcs)
			allScopingAdvice(where, zoneSvcs, zoneEnforces && zoneObservable)
			if zoneObservable {
				unportedAdvice(where, zoneSvcs)
			}
		}
		// #3362: per-interface overrides carry the same token grammar and the
		// same packet-wide breadth, so warn on each of them too. Iterated via
		// the SSOT sorted-refs helper for deterministic advisory ordering.
		for _, ifRef := range zone.SortedInterfaceHostInboundRefs() {
			hi := zone.InterfaceHostInbound[ifRef]
			if hi == nil {
				continue
			}
			where := fmt.Sprintf("zone %q interface %q host-inbound-traffic", name, ifRef)
			// The full-admit notice stays keyed on the OVERRIDE's own tokens: it
			// reports what this stanza declares, and a zone-level `any-service`
			// already drew its own notice at the zone level.
			fullAdmitAdvice(where, hi.SystemServices)
			// #6640: the stanza's narrowing is OBSERVABLE only where the
			// dataplane acts on it, so walk the enforcement keys this ref
			// governs and ask whether ANY of them (a) is not a lifeline and
			// (b) does not full-admit once resolved. A physical stanza whose
			// unit unions an `any-service`, or a unit stanza sitting under a
			// physical `any-service`, resolves to a full admit and denies
			// nothing — the two false cases #6640 reproduced.
			//
			// The TOKEN LIST stays the stanza's OWN authored set, not the
			// resolved one. Under #6515 an interface override REPLACES the zone
			// level, so `EffectiveHostInboundTokens(zoneSvcs, hi.SystemServices,
			// true)` was already exactly hi.SystemServices here and this changes
			// no wording — but the resolved set also carries the tokens INHERITED
			// from a physical-level stanza, and naming those at the unit stanza
			// would report a service the unit stanza never accepted. That is the
			// same cry-wolf failure in a new place: one denial would draw two
			// advisories, one of them at a stanza that did not mention the
			// service.
			observable := false
			for _, key := range hiKeysFor(ifRef) {
				if HostInboundLifelineInterface(key, lifelines) {
					continue
				}
				if !effectiveFullAdmits(hiEffectiveAt(key)) {
					observable = true
					break
				}
			}
			// An override is scoped to the interface it names, so it is gated on
			// THAT interface's own lifeline status rather than the zone's — which
			// `observable` already carries, since every lifeline key is skipped
			// above.
			allScopingAdvice(where, hi.SystemServices, observable)
			if observable {
				unportedAdvice(where, hi.SystemServices)
			}
		}
	}
	return warnings
}

// resolveInterfaceHostInboundFn is the seam through which the host-inbound
// advisory pass reaches the resolver (#8854). Production always holds
// ResolveInterfaceHostInbound; the guard swaps it to COUNT calls, because the
// property being protected is "called once per invocation, not once per zone"
// and no correctness assertion can observe that. Same shape as the
// deriveKernelNameFn / directARPProbeFn seams in pkg/daemon.
var resolveInterfaceHostInboundFn = ResolveInterfaceHostInbound
