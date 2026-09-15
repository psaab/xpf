package config

import (
	"fmt"
	"sort"
	"strings"
)

// host_inbound_dhcp_scope_6519.go implements the #6519 parity advisory for the
// DHCP/BOOTP exception in Junos's host-inbound model.
//
// Juniper, Security Zones (security-zone-configuration): "All services (except
// DHCP and BOOTP) can be configured either per zone or per interface. A DHCP
// server is configured only per interface because the incoming interface must
// be known by the server to be able to send out DHCP replies."
//
// So `dhcp` and `bootp` are the two host-inbound system-services Junos does NOT
// accept at the zone level. xpf accepts them there and lets them authorize every
// member interface of the zone, which is an over-authorization relative to
// Junos: a single zone-level token opens udp/67-68 on firewall-local addresses
// the operator would have had to admit interface by interface.
//
// This file WARNS. The ENFORCEMENT half landed separately as #7490 and lives in
// host_inbound_dhcp_flip_7490.go: the zone-level authorization is now WITHHELD
// from an interface that runs a DHCP server or relay, and RETAINED everywhere
// else. The split of responsibilities matters —
//
//   - the flip decides what is admitted, gated on hostInboundDHCPRolesFor below,
//     which is why that classifier lives HERE and is shared rather than copied:
//     an enforcement gate that disagreed with the advice would tell an operator
//     to migrate one set of interfaces and withhold on a different one;
//   - this advisory decides what the operator is TOLD, and after #7490 it has
//     two things to say rather than one. On a withheld interface the token has
//     stopped working and the message is an upgrade notice. On a retained one
//     the deviation from Junos persists deliberately and the message says so.
//
// The retained half is not laziness. Junos does not accept these tokens at the
// zone level for ANY role, so withholding for every role would be the more
// faithful change; #7490 declined it because the vendor sentence is an argument
// about a SERVER needing ingress identity and says nothing about a client, and
// because #7489 established the token is load-bearing — the AF_XDP dataplane
// enforces host-inbound fail-closed on the local-delivery path, so a zoned,
// non-lifeline interface running the firewall's own DHCP client would lose
// udp/68, its unicast renewals, and with them its ADDRESS. The resulting
// per-role asymmetry is an xpf invention, not a Junos behaviour, and is
// documented as such in docs/host-inbound-service-matrix.md.

// hostInboundDHCPExceptionServices are the two `system-services` tokens Junos
// documents as per-INTERFACE only. `dhcpv6` is deliberately NOT here: the
// vendor sentence names DHCP and BOOTP, and extending it to the v6 token would
// be an inference, not a citation.
var hostInboundDHCPExceptionServices = []string{"dhcp", "bootp"}

// InterfaceHostInboundOverride returns the INTERFACE-LEVEL host-inbound tokens
// that apply to ref in this zone — the union of a physical-parent override and
// ref's own unit-level override (#3720, both are interface-level statements) —
// and whether ref declares any interface-level stanza at all.
//
// It is the interface-level half of what InterfaceHostInboundEffective resolves
// — that resolver CALLS this, so the #3720 physical∪unit walk exists once and not
// twice: a divergence between them would always be a bug. It is exposed on its
// own because a caller sometimes needs to know what the INTERFACE authorized as
// distinct from what the interface ends up admitting. #6519 is that caller: "the zone-level token is what authorizes DHCP here" is precisely
// "the effective set admits it and the interface's own stanza does not", and
// that predicate is correct whether the two levels union or the interface level
// replaces the zone level.
//
// declared is stanza PRESENCE, matching InterfaceHostInboundEffective's
// overridden: a present-but-empty stanza declares an interface-level policy (of
// admitting nothing) and returns declared=true with empty token lists.
func (z *ZoneConfig) InterfaceHostInboundOverride(ref string) (svc, proto []string, declared bool) {
	if z == nil {
		return nil, nil, false
	}
	// #9821: compiled stamps resolve through precomputed keys. Probe the
	// raw spelling, then its canonical Literal resolved through the STAMPED
	// declaration set (never the legacy first-dot cut): an alias query
	// (`p.0.001`) reaches the canonical unit key (`p.0.1`); raw-exact
	// precedence is preserved because the raw probe comes first, so a
	// padded declared name never aliases onto another interface.
	// A miss under a compiled stamp is authoritative ABSENT — every spelling
	// the runtime binds is stamped (construction invariant:
	// stampKeys ⊇ runtimeKeys per zone), so nothing governed is missed and
	// the method agrees with the runtime map on every query. A nil stamp
	// (hand-built cfgs bypassing compile) keeps the legacy walk below,
	// byte-identical.
	if z.ResolvedInterfaceOverrides != nil && z.ResolvedInterfaceDeclared != nil {
		if hib := z.ResolvedInterfaceOverrides[ref]; hib != nil {
			return UnionHostInboundTokens(hib.SystemServices, nil),
				UnionHostInboundTokens(hib.Protocols, nil), true
		}
		declared := z.ResolvedInterfaceDeclared
		isDeclared := func(s string) bool { return declared[s] }
		if lit := splitInterfaceRefWithDeclared(isDeclared, ref).Literal; lit != ref {
			if hib := z.ResolvedInterfaceOverrides[lit]; hib != nil {
				return UnionHostInboundTokens(hib.SystemServices, nil),
					UnionHostInboundTokens(hib.Protocols, nil), true
			}
		}
		return nil, nil, false
	}
	if base, unit, ok := strings.Cut(ref, "."); ok && unit != "" && base != "" {
		if phys := z.InterfaceHostInbound[base]; phys != nil {
			svc = UnionHostInboundTokens(svc, phys.SystemServices)
			proto = UnionHostInboundTokens(proto, phys.Protocols)
			declared = true
		}
	}
	if exact := z.InterfaceHostInbound[ref]; exact != nil {
		svc = UnionHostInboundTokens(svc, exact.SystemServices)
		proto = UnionHostInboundTokens(proto, exact.Protocols)
		declared = true
	}
	return svc, proto, declared
}

// stampResolvedInterfaceOverrides derives, per zone, the override closure
// InterfaceHostInboundOverride consults (#9821). Runs in resolveDerivedConfig
// where the whole *Config is available; the method itself cannot take one.
//
// Key discipline (sorted authored refs — the same deterministic discipline
// ResolveInterfaceHostInbound uses, so token order agrees too) is TARGET
// based, mirroring the runtime #18 arms exactly: BARE keys first-win
// (direct and alias writes alike skip an occupied key — occupant provenance
// does not matter: same-identity raw, co-authored alias, or fan-down from
// a dotted-nesting parent all lose to the first writer, as #18 does);
// UNIT keys union (parent∪child accumulates across identities on both
// sides). Every authored ref is stored under its RAW spelling (exact
// diagnostic queries keep working) AND its canonical Literal (alias queries
// and canonical consumers land together — Literal keys regardless of dot
// count, GLM-F1: multi-dot-only is retired FOR THE STAMP while the D3 gate
// keeps it); every bare ref fans its merged hib down onto each CONFIGURED
// unit (present-but-nil slots included, as the runtime does). Values are
// merged clones, never config aliases. No M01/#5489 guards here: the stamp
// preserves method semantics exactly and quarantine stays runtime-only
// (changing lenient quarantine is a separate behavior change, out of scope).
//
// D19 union completeness: each raw alias key carries what its canonical
// Literal resolved to — `p.0.01` and `p.0.1` BOTH map to union(parent-`p.0`,
// child), single-dot `p.01` and `p.1` likewise. The main loop leaves raw unit
// keys child-only (fan-down touches canonical keys only), so a second pass
// copies the resolved canonical value onto each authored raw alias. Bare
// aliases converge the same way (D20): authored `p.00` of declared `p.0`
// stamps {`p.00`, `p.0`, `p.0.N` fan-down} with the first-winner's value on
// the first two and inherit-unions on the units.
//
// Construction invariant (F-D19): stampKeys ⊇ runtimeKeys per zone — authored
// raws + Literals + bare fan-down over the SAME configured-unit set #18 fans
// — so a miss under a present stamp proves no governing override in EITHER
// map and the method returns authoritative ABSENT with no legacy walk.
func stampResolvedInterfaceOverrides(cfg *Config) {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return
	}
	declared := make(map[string]bool, len(cfg.Interfaces.Interfaces))
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil {
			declared[name] = true
		}
	}
	isDeclared := func(s string) bool { return declared[s] }
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		stamp := make(map[string]*HostInboundTraffic)
		refs := make([]string, 0, len(zone.InterfaceHostInbound))
		for ref := range zone.InterfaceHostInbound {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		type aliasKey struct{ raw, lit string }
		var aliases []aliasKey
		for _, ref := range refs {
			hib := zone.InterfaceHostInbound[ref]
			if ref == "" || hib == nil {
				continue
			}
			s := splitInterfaceRefWithDeclared(isDeclared, ref)
			merge := func(key string) {
				stamp[key] = MergeHostInboundTraffic(stamp[key], hib)
			}
			// Target-based discipline (review: exact runtime parity with
			// the #18 bare arm, which skips occupied Literals regardless
			// of occupant provenance): BARE keys first-win — a direct or
			// alias write skips when ANY earlier ref already wrote the
			// key, whether a same-identity raw, a co-authored alias, or
			// fan-down from a dotted-nesting parent. UNIT keys union —
			// parent∪child accumulates across identities on both sides.
			mergeFirstWins := func(key string) {
				if _, ok := stamp[key]; !ok {
					stamp[key] = MergeHostInboundTraffic(nil, hib)
				}
			}
			if !s.HasUnit {
				mergeFirstWins(ref)
				if s.Literal != ref {
					mergeFirstWins(s.Literal)
					aliases = append(aliases, aliasKey{ref, s.Literal})
				}
				if ifCfg := cfg.Interfaces.Interfaces[s.Base]; ifCfg != nil {
					for unitNum := range ifCfg.Units {
						merge(fmt.Sprintf("%s.%d", s.Base, unitNum))
					}
				}
			} else {
				merge(ref)
				if s.Literal != ref {
					merge(s.Literal)
					aliases = append(aliases, aliasKey{ref, s.Literal})
				}
			}
		}
		// D19/D20: the loop above leaves raw alias keys child-only (unit
		// fan-down lands on canonical keys only) or carrying only their own
		// direct value (a skipped bare-alias Literal merge). Each authored
		// raw alias instead carries what its canonical Literal resolved to
		// — parent∪child for units, the first-winner's value for bare
		// aliases (same-identity co-authors first-win on the canonical, so
		// the raw must see the winner, not a union) — so raw and canonical
		// queries agree exactly. Clones, never aliases. Unconfigured units
		// need no special case: their canonical holds child-only already
		// (no fan-down reached it), which is what the runtime binds too.
		for _, a := range aliases {
			if canon := stamp[a.lit]; canon != nil {
				stamp[a.raw] = MergeHostInboundTraffic(nil, canon)
			}
		}
		zone.ResolvedInterfaceOverrides = stamp
		zone.ResolvedInterfaceDeclared = declared
	}
}

// hostInboundSetAdmitsService reports whether an authored `system-services` list
// admits token, walking the `all` expansion so a zone that opened `all` is
// recognized as admitting dhcp exactly as the enforcement path does (`all`
// expands to the named-service union, which includes dhcp and bootp). Case
// -insensitive, matching every other host-inbound membership predicate.
func hostInboundSetAdmitsService(svcs []string, token string) bool {
	for _, s := range svcs {
		for _, e := range HostInboundServiceTokenExpansion(strings.ToLower(strings.TrimSpace(s))) {
			if strings.ToLower(strings.TrimSpace(e)) == token {
				return true
			}
		}
	}
	return false
}

// hostInboundZoneLevelDHCPTokens returns the DHCP-exception tokens a ZONE-LEVEL
// system-services list admits, each paired with how it got there — named
// outright, or pulled in by `all`. The distinction is what makes the advisory
// actionable: "you wrote dhcp at the zone level" and "your zone-level `all`
// silently includes dhcp" need different edits, and an advisory that reported
// only the first would leave the `all` case as a silent deviation.
func hostInboundZoneLevelDHCPTokens(zoneSvc []string) []string {
	named := make(map[string]bool, len(zoneSvc))
	viaAll := false
	for _, s := range zoneSvc {
		t := strings.ToLower(strings.TrimSpace(s))
		if t == "all" {
			viaAll = true
			continue
		}
		named[t] = true
	}
	var out []string
	for _, tok := range hostInboundDHCPExceptionServices {
		switch {
		case named[tok]:
			out = append(out, tok)
		case viaAll:
			out = append(out, tok+" (via `all`)")
		}
	}
	return out
}

// validateHostInboundZoneLevelDHCPWarnings emits the #6519 commit-time advisory:
// a zone whose ZONE-LEVEL host-inbound-traffic admits `dhcp` or `bootp` — named
// outright or via `all` — thereby authorizes DHCP/BOOTP on member interfaces
// that never asked for it, which Junos does not allow to be expressed at the
// zone level at all.
//
// One advisory per zone, naming the tokens and the member interfaces the
// zone-level authorization actually reaches. An interface is reached when its
// EFFECTIVE set admits the token but its OWN interface-level stanza does not —
// i.e. the zone-level token is the authorizer. Stating it that way keeps the
// advisory correct both while the two levels union and after #6515 makes the
// interface level replace the zone level, without asserting which rule is in
// force.
//
// Lifeline interfaces (fxp0 / em0 / fab* and the configured control + fabric
// links) are skipped: they are excluded from host-inbound deny scoping entirely,
// so no zone token decides anything on them and naming them would be a false
// alarm. A zone whose reached-interface set is empty draws no advisory.
//
// WARN-only. See the file header for why the enforcement flip is staged
// separately.
func validateHostInboundZoneLevelDHCPWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	serverRefs := hostInboundDHCPServerRefs(cfg)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []string
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.HostInboundTraffic == nil {
			continue
		}
		toks := hostInboundZoneLevelDHCPTokens(zone.HostInboundTraffic.SystemServices)
		if len(toks) == 0 {
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
		// #7490: ask the UNFILTERED question — "does the ZONE-LEVEL stanza name
		// this token for this interface" — and then split the answer by whether
		// the flip still lets it authorize.
		//
		// Reading the EFFECTIVE set here, as stages 1 and 1.5 did, would make
		// this advisory go SILENT on exactly the interfaces the flip just
		// narrowed: their effective set no longer admits the token, so the
		// operator whose DHCP server stopped receiving DISCOVER would be told
		// nothing. The advisory has to keep firing on those and say something
		// DIFFERENT, which is the whole upgrade path for this change.
		//
		// The predicate is now "the interface declares no stanza of its own AND
		// the zone-level list names the token". That asserts #6515's replace
		// rule, which stages 1/1.5 deliberately avoided asserting while the
		// combination rule was still in flight — it has landed, and
		// EffectiveHostInboundTokens implements replace unconditionally, so the
		// two forms are now equivalent and this one survives the filter.
		zoneSvc := zone.HostInboundTraffic.SystemServices
		var withheldRefs, retainedRefs []string
		var anyClient, anyIdle bool
		for _, ref := range refs {
			if HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			_, _, declared := zone.InterfaceHostInboundOverride(ref)
			if declared {
				continue
			}
			named := false
			for _, tok := range hostInboundDHCPExceptionServices {
				if hostInboundSetAdmitsService(zoneSvc, tok) {
					named = true
					break
				}
			}
			if !named {
				continue
			}
			// #6519 stage 1.5: name WHY the token is load-bearing here. The role
			// is the discriminator the #7490 flip turns on, so the advisory
			// computes it rather than leaving every reader to work it out per
			// interface.
			roles := hostInboundDHCPRolesFor(cfg, serverRefs, ref)
			entry := fmt.Sprintf("%s (%s)", ref, hostInboundDHCPRoleLabel(roles))
			if zone.WithholdsZoneLevelDHCPFor(ref) {
				withheldRefs = append(withheldRefs, entry)
				continue
			}
			anyClient = anyClient || roles.client
			anyIdle = anyIdle || (!roles.client && !roles.server)
			retainedRefs = append(retainedRefs, entry)
		}
		if len(withheldRefs) == 0 && len(retainedRefs) == 0 {
			continue
		}
		msg := fmt.Sprintf(
			"zone %q host-inbound-traffic: system-services %s %s configured at the "+
				"ZONE level, which Junos does not allow — DHCP and BOOTP are the "+
				"host-inbound services Junos accepts only per interface, because the "+
				"server must know the incoming interface to send replies.",
			name, strings.Join(toks, ", "), pluralIsAre(len(toks)))
		if len(withheldRefs) > 0 {
			// THE NARROWING — stated with the mechanism #8060 MEASURED, not the
			// one that reads more urgent.
			//
			// It is tempting to write "client DISCOVER is now DENIED". That is
			// FALSE, and it is the exact sentence #8060 was filed to remove from
			// this project's own reference config. DISCOVER/REQUEST never
			// depended on this token: the XDP shim hands the 255.255.255.255
			// broadcast straight to the kernel, and Kea's Dhcp4 runs in `raw`
			// mode so it receives on an AF_PACKET socket delivered BEFORE the
			// netfilter input hook — for a unicast to the interface's own
			// address as well as for the broadcast. An nft INPUT drop counted
			// the packet and Kea answered anyway (#6460, #7489, #8060).
			//
			// So for a dhcp-local-server this withdrawal is expected to be
			// INERT on the request path, and telling an operator their DHCP
			// just broke would send them to fix something that is not broken —
			// the "wrong reason reaches for the wrong remedy" failure #6460
			// exists to prevent. What the message must do instead is name what
			// stopped (a zone-level authorization of udp/67-68 on this
			// interface's firewall-local addresses), name what did not, and
			// name the cases that are NOT covered by the bypass argument.
			msg += fmt.Sprintf(
				" This token NO LONGER authorizes DHCP/BOOTP on %s (#7490): xpf now "+
					"withholds the zone-level authorization from an interface that "+
					"runs a DHCP server or relay, matching Junos. For a "+
					"`dhcp-local-server` this is expected to change nothing an "+
					"operator can observe — a client's DISCOVER/REQUEST reaches Kea on "+
					"an AF_PACKET socket ahead of netfilter and the XDP shim passes the "+
					"broadcast straight to the kernel, so that path never went through "+
					"this token (#6460, #8060). It is NOT covered for anything else on "+
					"the interface that needs udp/67-68 delivered to the host — a DHCP "+
					"relay's unicast leg, or the firewall's own DHCP client if one is "+
					"configured here later, whose RENEW unicast to a zone address IS "+
					"matched. To keep the authorization, restate it per interface: `set "+
					"security zones security-zone %s interfaces <if> "+
					"host-inbound-traffic system-services dhcp` — and note a "+
					"per-interface stanza REPLACES the zone stanza (#6515), so restate "+
					"the zone's other tokens there or they stop being admitted on that "+
					"interface.",
				strings.Join(withheldRefs, ", "), name)
		}
		if len(retainedRefs) > 0 {
			msg += fmt.Sprintf(
				" The zone-level token still authorizes DHCP/BOOTP on %s, which Junos "+
					"would require you to admit interface by interface. xpf retains it "+
					"there DELIBERATELY (#7490).",
				strings.Join(retainedRefs, ", "))
			if anyClient {
				msg += " An interface marked `DHCP client` runs the firewall's OWN " +
					"client, which needs udp/68 for its unicast renewals. The vendor " +
					"rule quoted above is about a DHCP SERVER knowing its incoming " +
					"interface and does not speak to the client, so on that interface " +
					"the token is holding up the interface's ADDRESS, not merely a " +
					"service — withdrawing it would cost the interface its lease."
			}
			if anyIdle {
				msg += " An interface marked `no DHCP configured` runs neither a DHCP " +
					"server/relay nor the firewall's own DHCP client, so the zone-level " +
					"token opens udp/67-68 there for nothing — removing it narrows " +
					"nothing in use."
			}
			// The parity remedy survives the flip for this half: Junos does
			// not accept the token at the zone level for ANY role, so an
			// operator who wants parity still migrates. The #6515 caveat has to
			// travel with the remedy wherever the remedy appears — following it
			// verbatim drops every other service the zone admitted there, and
			// the sibling #6515 advisory only says so on a LATER commit, after
			// the narrowing has already been authored.
			msg += " Keeping it is an xpf deviation from Junos, not Junos " +
				"behaviour. To match Junos, move the token to `interfaces <if> " +
				"host-inbound-traffic system-services ...` on the interfaces that " +
				"need it — and note a per-interface stanza REPLACES the zone stanza " +
				"(#6515), so restate the zone's other tokens there or they stop " +
				"being admitted on that interface."
		}
		warnings = append(warnings, msg)
	}
	return warnings
}

// pluralIsAre picks the verb for a token list of length n.
func pluralIsAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// hostInboundDHCPRoles records WHY an interface would need udp/67-68 admitted.
// The two halves are independent booleans rather than an enum because an
// interface can legitimately be both (a relay member that also runs the
// firewall's own client), and picking a winner would invent a precedence the
// config does not state.
type hostInboundDHCPRoles struct {
	server bool // dhcp-local-server / dhcpv6-local-server / dhcp-relay member
	client bool // family inet { dhcp; } — the firewall's OWN DHCP client
}

// hostInboundSameInterface reports whether two interface refs name the same
// interface for DHCP-role purposes. A bare physical ref and a unit ref under it
// are the same interface (`reth1` vs `reth1.0`) — the #3720 physical/unit
// relationship — but two DIFFERENT units are not (`reth1.0` vs `reth1.50`).
// Basing both sides on the physical would collapse those two, over-matching a
// sibling unit's DHCP role onto an interface that has none.
//
// #9821: identity resolves through the split (declared-first), not first-dot
// cuts. Same iff string-equal, or resolved owners equal with bare/bare or
// bare/unit status, or two unit refs with equal canonical unit numbers.
// Both-declared independence OUTRANKS textual nesting (`p.0` vs `p.0.2` with
// both declared are distinct interfaces even though one nests in the other).
// Canonical aliases of one unit (`p.0.01` vs `p.0.1`) ARE the same interface.
func hostInboundSameInterface(cfg *Config, a, b string) bool {
	if a == b {
		return true
	}
	if cfg == nil {
		return hostInboundSameInterfaceLegacy(a, b)
	}
	sa, sb := cfg.SplitInterfaceUnitRef(a), cfg.SplitInterfaceUnitRef(b)
	if sa.Base != sb.Base {
		return false
	}
	if !sa.HasUnit || !sb.HasUnit {
		// Bare/bare (same base) or bare/unit: the #3720 relationship — but
		// only when the bare side's base is actually that interface (split
		// bases already encode declared-ness, so no extra check is needed).
		return true
	}
	// Two unit refs: same only when their canonical unit numbers agree.
	// Sibling exclusion preserved: distinct units are distinct interfaces.
	na, _, errA := CanonicalLogicalUnit(sa.UnitTok)
	nb, _, errB := CanonicalLogicalUnit(sb.UnitTok)
	if errA != nil || errB != nil {
		return false
	}
	return na == nb
}

// hostInboundSameInterfaceLegacy is the pre-#9821 first-dot comparison,
// kept for nil-config callers. NOTE the bool-tuple subtlety the rewrite
// preserves: strings.Cut's third return is `found`, not the suffix, so
// `aUnit != bUnit` below means "exactly one side is bare".
func hostInboundSameInterfaceLegacy(a, b string) bool {
	if a == b {
		return true
	}
	aBase, _, aUnit := strings.Cut(a, ".")
	bBase, _, bUnit := strings.Cut(b, ".")
	if aBase != bBase {
		return false
	}
	// Equal bases: same interface only when exactly one side is the bare
	// physical. Two distinct units are distinct interfaces.
	return aUnit != bUnit
}

// hostInboundDHCPServerRefs collects every interface ref that receives DHCP on
// the firewall's behalf as a SERVER: dhcp-local-server and dhcpv6-local-server
// group members, and dhcp-relay group members. A relay counts because it too
// receives client DISCOVER on udp/67 and is the case the vendor rationale
// describes — the incoming interface must be known to send the reply back.
func hostInboundDHCPServerRefs(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var refs []string
	for _, srv := range []*DHCPLocalServerConfig{
		cfg.System.DHCPServer.DHCPLocalServer,
		cfg.System.DHCPServer.DHCPv6LocalServer,
	} {
		if srv == nil {
			continue
		}
		for _, g := range srv.Groups {
			if g != nil {
				refs = append(refs, g.Interfaces...)
			}
		}
	}
	if cfg.ForwardingOptions.DHCPRelay != nil {
		for _, g := range cfg.ForwardingOptions.DHCPRelay.Groups {
			if g != nil {
				refs = append(refs, g.Interfaces...)
			}
		}
	}
	return refs
}

// hostInboundIsDHCPClient reports whether ref runs the firewall's OWN DHCPv4
// client (`family inet { dhcp; }`). Only v4 is consulted: the tokens this
// advisory is about (`dhcp` / `bootp`) open udp/67-68, and `dhcpv6` is
// deliberately out of the vendor sentence's scope (see the file header).
//
// A bare physical ref answers for ANY unit beneath it, because the zone
// membership names the physical while the client is configured on a unit.
func hostInboundIsDHCPClient(cfg *Config, ref string) bool {
	if cfg == nil || ref == "" {
		return false
	}
	// #9821: resolve the stanza and unit through the split (declared-first):
	// a dotted child (`p.0.1`) looks under its declared parent (`p.0`), not
	// under the first-dot base (`p`). The unit match runs through
	// CanonicalLogicalUnit so padded spellings (`01`) match unit 1 (this also
	// fixes a pre-existing padded miss — pinned as intended).
	s := cfg.SplitInterfaceUnitRef(ref)
	ifc := cfg.Interfaces.Interfaces[s.Base]
	if ifc == nil {
		return false
	}
	if !s.HasUnit {
		// A bare physical ref answers for ANY unit beneath it, because the
		// zone membership names the physical while the client is configured
		// on a unit.
		for _, u := range ifc.Units {
			if u != nil && u.DHCP {
				return true
			}
		}
		return false
	}
	n, _, err := CanonicalLogicalUnit(s.UnitTok)
	if err != nil {
		return false
	}
	if u := ifc.Units[n]; u != nil && u.DHCP {
		return true
	}
	return false
}

// hostInboundDHCPRolesFor classifies one interface ref.
func hostInboundDHCPRolesFor(cfg *Config, serverRefs []string, ref string) hostInboundDHCPRoles {
	var r hostInboundDHCPRoles
	for _, s := range serverRefs {
		if hostInboundSameInterface(cfg, s, ref) {
			r.server = true
			break
		}
	}
	r.client = hostInboundIsDHCPClient(cfg, ref)
	return r
}

// hostInboundDHCPRoleLabel is the parenthetical the advisory appends to an
// interface name, naming which DHCP role makes the zone-level token load-bearing
// there. "no DHCP configured" is the operationally most useful of the three: it
// says the token authorizes udp/67-68 for nothing.
func hostInboundDHCPRoleLabel(r hostInboundDHCPRoles) string {
	switch {
	case r.server && r.client:
		return "DHCP server and client"
	case r.server:
		return "DHCP server"
	case r.client:
		return "DHCP client"
	default:
		return "no DHCP configured"
	}
}
