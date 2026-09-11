// policy_render.go renders Junos policy-options into FRR route-maps.
//
// After the #6424 split this file owns policy-statement -> route-map
// rendering (per-policy route-maps and composed chains), community-list
// regex classification, and the redistribute-alias collision guard. The
// other render aspects that used to share this file were moved, whole and
// unchanged, into cohesive sibling files:
//   - render_validate.go     value sanitization / validation belt
//   - redistribute.go        Junos export -> FRR redistribute resolution
//   - bgp_policy_chain.go    ordered BGP import/export chain resolution (#5277)
//   - bfd.go                 BFD profile/peer accumulator (#2550)
//   - protocols_render.go    OSPF/OSPFv3/BGP/RIP/IS-IS protocol stanzas
//   - prefix_list_render.go  ip|ipv6 prefix-list rendering
//
// Symbols:
//   - communityRegexChars, communityMemberIsRegex
//   - redistFailClosedRouteMap, redistAliasCollision
//   - policyNeedsRedistAlias, policyTrailingAction
//   - generatePolicyOptions, renderPolicyTermSequences
//   - renderRouteMapForPolicy, renderComposedRouteMap
package frr

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// communityRegexChars are the characters whose presence in a community
// member means it cannot be a plain literal ASN:VALUE (or well-known
// name) and therefore requires an FRR `expanded` community-list (POSIX
// regex) rather than a `standard` one. A standard list rejects any of
// these at config load, failing the whole frr-reload (#2643). The set
// includes the POSIX-ERE interval/bound braces `{` `}` — a Junos
// community member is a free-form verbatim string slot (no value
// validation; the compiler copies it straight through), so a legitimate
// bound operator like `65000:1{2,3}` must route to an expanded list too.
//
// #8449: this is now an ALIAS of the shared SSOT in pkg/config, not a second
// copy of the literal. The commit gate that rejects an uncompilable member has
// to make the SAME expanded/standard classification the renderer does, and two
// literals in two packages is exactly the pair that drifts. Kept as a named
// constant here so the existing pkg/frr tests that reference it keep binding
// the real value rather than being quietly decommissioned.
const communityRegexChars = config.CommunityRegexChars

// communityMemberIsRegex reports whether a Junos community member value
// contains regex / wildcard metacharacters and must be rendered into an
// FRR `expanded` community-list. A plain `ASN:VALUE` (digits:digits) or a
// well-known name ("no-export", "no-advertise", "internet", "local-AS")
// contains none of these and stays a `standard` member.
func communityMemberIsRegex(member string) bool {
	// #8449: delegate to the shared predicate so the render-side list-kind
	// decision and the commit gate cannot disagree about which members FRR
	// will run through regcomp.
	return config.CommunityMemberIsRegex(member)
}

// redistFailClosedRouteMap derives the per-use-site route-map name that IGP
// redistribute references for a policy that is ALSO applied as a BGP route-map
// in/out with no explicit default action. The base route-map keeps the Junos
// BGP default-accept trailing permit (#2998); this alias carries the fail-closed
// trailing deny the redistribute / forwarding-table context requires, so the
// BGP permit default never leaks into the IGP through FRR's single name-keyed
// route-map object (#4481). The config.ReservedRedistSuffix ("-xpf-redist") is
// RESERVED: the strict commit gate (validatePolicyReservedRedistNameStrict,
// pkg/config) rejects an operator policy-statement whose name ends in it, so the
// generated-alias namespace is injective by construction (#5116). The alias
// derivation here and that validator share the one constant so they cannot
// drift. redistAliasCollision below is the render-side belt: on the tolerant
// load / peer-sync path (where the strict gate only warns) it fails the apply
// CLOSED if an alias still collides with an operator policy-statement, so a
// leniently-loaded collision cannot silently leak.
func redistFailClosedRouteMap(name string) string {
	return name + config.ReservedRedistSuffix
}

// quarantineDenySeq is the single sequence number the #6807 quarantine
// route-map occupies. One sequence, always — it can never approach the FRR
// ceiling the quarantine exists to stay under.
const quarantineDenySeq = 10

// renderQuarantineDenyRouteMap emits a bounded, EXPLICIT deny route-map under
// name, for a policy whose real expansion cannot be rendered (#6807).
//
// The problem it solves: generatePolicyOptions and renderComposedRouteMap SKIP
// a policy whose Cartesian expansion would overflow FRR's route-map sequence
// ceiling (#5701/#5732), because emitting a `route-map <name> permit 70000`
// line makes FRR reject the command and poisons the WHOLE vtysh-batched
// frr-reload. That skip is correct. But BGP rendering emits the ATTACHMENT
// (`neighbor <ip> route-map <name> in|out`) independently, off the policy's
// presence in PolicyStatements — so the attachment survived while its
// definition did not.
//
// The surviving attachment is NOT harmless, and it is not permit-all. FRR
// stable/10.6 bgpd/bgp_route.c:
//
//	bgp_input_modifier:   rmap = route_map_lookup_by_name(rmap_name);
//	                      if (!rmap) return RMAP_DENY;
//	bgp_output_modifier:  if (!rmap_name) return RMAP_PERMIT;
//	                      rmap = route_map_lookup_by_name(rmap_name);
//	                      if (rmap == NULL) return RMAP_DENY;
//
// An attachment naming an UNDEFINED map denies every route it covers; only an
// ABSENT attachment permits. So the pre-#6807 behaviour was a silent deny-all
// on the affected neighbors — a routing outage — while the code comments here
// asserted the opposite (permit-all).
//
// Why an explicit deny rather than dropping the attachment: dropping it is the
// only alternative that renders, and it means NO policy at all — Junos BGP
// default-accept, i.e. advertising or accepting every route the operator's
// policy existed to filter. That is fail-OPEN on an authorization decision,
// which is the direction this project does not take (cf. #3333, #3392, #6790).
// Failing the whole render is not available either: this path exists precisely
// for the tolerant load / peer-sync / rollback config (#1960), which must not
// brick.
//
// So the outcome is unchanged (deny) and three things change: it is
// DELIBERATE, it is VISIBLE (an operator running `show route-map <name>` sees
// an explicit deny instead of nothing, which is the difference between
// diagnosing this in minutes and in hours), and it no longer depends on FRR's
// undefined-map semantics staying what they are today. It is also immune to a
// future "clean up the dangling reference" change silently converting the deny
// into a permit.
func renderQuarantineDenyRouteMap(name string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "route-map %s deny %d\n", frrName(name), quarantineDenySeq)
	b.WriteString("exit\n")
	return b.String()
}

// redistAliasCollision is the render-side defense-in-depth for #5116. For every
// policy-statement that generates a fail-closed redistribute alias
// (policyNeedsRedistAlias), it checks whether that derived alias name
// (redistFailClosedRouteMap) also exists as an operator-defined
// policy-statement. FRR keys route-maps by NAME in one global namespace and
// MERGES two same-named `route-map` definitions into a single object, so a
// colliding operator policy's (possibly permit-default) sequences would fuse
// with the generated fail-closed deny alias and could reintroduce the #4481
// BGP/IGP redistribution leak the alias exists to prevent.
//
// The strict commit gate (validatePolicyReservedRedistNameStrict, pkg/config)
// rejects a reserved-suffix operator name outright, so a committed config never
// reaches here with a collision. This belt covers the tolerant load / peer-sync
// / rollback path where that gate only warns (#1960): ApplyFull calls it before
// building the managed section and returns the error, failing the whole apply
// CLOSED (FRR keeps its last-good config, no new leak) instead of emitting a
// colliding route-map. Returns nil for the common non-colliding case, leaving
// render output byte-identical.
func redistAliasCollision(po *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool) error {
	if po == nil || po.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statement names in sorted order.
	names := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := po.PolicyStatements[name]
		if !policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
			continue
		}
		alias := redistFailClosedRouteMap(name)
		if _, ok := po.PolicyStatements[alias]; ok {
			return fmt.Errorf(
				"policy-statement %q generates the fail-closed redistribute "+
					"route-map alias %q (reserved %q suffix), which collides with "+
					"an operator-defined policy-statement of that exact name; FRR "+
					"merges same-named route-maps, so the collision could "+
					"reintroduce the #4481 BGP/IGP redistribution leak — refusing "+
					"to render (rename the operator policy off the reserved suffix)",
				name, alias, config.ReservedRedistSuffix)
		}
	}
	return nil
}

// policyNeedsRedistAlias reports whether policy-statement name renders a
// BGP-default-accept trailing permit that must NOT be shared with an IGP
// redistribute use of the same name (#4481). It is true only when the policy is
// applied as a BGP route-map in/out (bgpAcceptDefault carries these names, per
// collectBGPRouteMapPolicies) AND carries no explicit policy-level default
// action — the exact case in which policyTrailingAction returns "permit" for a
// route that matches no term. An explicit `then accept` / `then reject` renders
// the same trailing action in every context, so no alias is needed.
func policyNeedsRedistAlias(name string, ps *config.PolicyStatement, bgpAcceptDefault map[string]bool) bool {
	return ps != nil && bgpAcceptDefault[name] &&
		ps.DefaultAction != "accept" && ps.DefaultAction != "reject"
}

// policyTrailingAction resolves the trailing default-sequence action
// (permit/deny) for a policy-statement route-map, applying the #2998
// BGP-default-accept fallback:
//
//   - explicit `then accept`  → permit (Junos-explicit)
//   - explicit `then reject`  → deny   (Junos-explicit)
//   - no policy default + BGP route-map in/out context → permit
//     (BGP default-accept; bgpAcceptDefault carries these names)
//   - no policy default elsewhere (redistribute / forwarding-table export /
//     standalone) → deny (fail-closed, matches the OSPF/redistribute Junos
//     default and FRR's implicit deny)
func policyTrailingAction(name string, ps *config.PolicyStatement, bgpAcceptDefault map[string]bool) string {
	switch {
	case ps.DefaultAction == "accept":
		return "permit"
	case ps.DefaultAction == "reject":
		return "deny"
	case bgpAcceptDefault[name]:
		return "permit"
	default:
		return "deny"
	}
}

// generatePolicyOptions emits FRR prefix-list / route-map / community-list /
// as-path-access-list config from the typed Junos policy-options.
//
// The optional bgpAccept variadic carries the set of policy-statement names
// that are referenced as a BGP `route-map in`/`out` (built by
// collectBGPRouteMapPolicies at the GenerateConfig call site). A
// policy-statement in that set with NO explicit policy-level default action
// renders a terminating `permit` so an unmatched route follows the Junos BGP
// default-ACCEPT instead of being dropped by FRR's implicit deny (#2998).
// Direct/test callers omit the argument, preserving the historical
// fail-closed `deny` default for every policy.
func (m *Manager) generatePolicyOptions(po *config.PolicyOptionsConfig, bgpAccept ...map[string]bool) string {
	var bgpAcceptDefault map[string]bool
	if len(bgpAccept) > 0 {
		bgpAcceptDefault = bgpAccept[0]
	}
	var b strings.Builder

	// Generate FRR prefix-lists from Junos prefix-lists
	names := make([]string, 0, len(po.PrefixLists))
	for name := range po.PrefixLists {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pl := po.PrefixLists[name]
		for i, prefix := range pl.Prefixes {
			// #4482: sanitize the prefix so an embedded newline from a
			// leniently-loaded / peer-synced / rolled-back stored value cannot
			// inject an extra frr.conf line. #4097 added this render-side belt
			// to the community-list / as-path-list definitions but MISSED the
			// prefix-list slots and the route-map `set` clauses below, which
			// still rendered with a bare %s — a residual bypass on the tolerant
			// load path (the strict #1798 commit control-char gate rejects it,
			// but the peer-sync / rollback path only warns, #1960).
			if strings.Contains(prefix, ":") {
				fmt.Fprintf(&b, "ipv6 prefix-list %s seq %d permit %s\n", frrName(name), (i+1)*5, sanitizeFRRValue(prefix))
			} else {
				fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s\n", frrName(name), (i+1)*5, sanitizeFRRValue(prefix))
			}
		}
	}
	if len(po.PrefixLists) > 0 {
		b.WriteString("!\n")
	}

	// Generate FRR community-lists from Junos community definitions
	commNames := make([]string, 0, len(po.Communities))
	for name := range po.Communities {
		commNames = append(commNames, name)
	}
	sort.Strings(commNames)
	for _, name := range commNames {
		cd := po.Communities[name]
		// FRR standard community-lists only accept literal community
		// values (ASN:VALUE or well-known names); they REJECT regex /
		// wildcard members (e.g. "65000:*", ".*") at config load, which
		// fails the whole frr-reload of the managed section. An expanded
		// community-list accepts a POSIX regex per member. FRR does NOT
		// allow the same list NAME to be both standard and expanded, so
		// the decision is per-DEFINITION: if ANY member is a regex/
		// wildcard, the ENTIRE definition is rendered as `expanded`
		// (literal members are valid regexes that match themselves);
		// otherwise it stays `standard` (#2643).
		listKind := "standard"
		for _, member := range cd.Members {
			if communityMemberIsRegex(member) {
				listKind = "expanded"
				break
			}
		}
		// #8449 render-side belt, the community sibling of the #6686 as-path
		// belt below. A member that forces the expanded list kind but is not a
		// valid POSIX ERE fails FRR's regcomp — a CMD_WARNING_CONFIG_FAILED
		// that exits the whole vtysh add-batch non-zero and fails the ENTIRE
		// frr-reload, leaving every dynamic routing change stale. The strict
		// commit gate (validatePolicyCommunityRegexStrict) hard-rejects it, but
		// the tolerant Load / peer-sync paths only warn (#1960 no-brick), so the
		// renderer must keep a leniently-loaded definition out of frr.conf.
		//
		// Omitting the list is strictly better than poisoning the reload: FRR
		// resolves a `match community <name>` with no such list to NO MATCH,
		// which confines the damage to the terms that reference it instead of
		// stalling all of routing.
		//
		// The omission is per-DEFINITION, not per-member, because FRR does not
		// allow one list name to be both standard and expanded — a half-rendered
		// list would change the kind decision made above. Same predicate as the
		// commit gate: ValidCommunityMember is shared so the two cannot drift.
		unrenderable := false
		for _, member := range cd.Members {
			if err := config.ValidCommunityMember(member); err != nil {
				unrenderable = true
				break
			}
		}
		if unrenderable {
			continue
		}
		for _, member := range cd.Members {
			// #4097: sanitize the member so an embedded newline (from a
			// leniently-loaded / peer-synced / rolled-back stored value)
			// cannot inject an extra frr.conf line — parity with the auth
			// / description fields. The listKind decision above reads the
			// RAW members (a `\n` is not a regex metacharacter, so it does
			// not by itself flip standard→expanded; the exploit's `^`/`$`
			// do). The strict #1798 commit control-char gate rejects it outright.
			fmt.Fprintf(&b, "bgp community-list %s %s permit %s\n", listKind, frrName(name), sanitizeFRRValue(member))
		}
	}
	if len(po.Communities) > 0 {
		b.WriteString("!\n")
	}

	// Generate FRR as-path access-lists from Junos as-path definitions
	if len(po.ASPaths) > 0 {
		aspNames := make([]string, 0, len(po.ASPaths))
		for name := range po.ASPaths {
			aspNames = append(aspNames, name)
		}
		sort.Strings(aspNames)
		for _, name := range aspNames {
			ap := po.ASPaths[name]
			// #6686 render-side belt: an as-path whose regex is EMPTY or
			// not a valid POSIX ERE renders a line FRR rejects — an
			// incomplete command or a regcomp failure — and a single
			// CMD_WARNING_CONFIG_FAILED exits the whole vtysh add-batch
			// non-zero, failing the ENTIRE frr-reload and leaving every
			// dynamic routing change stale. The strict commit gate
			// (validatePolicyASPathRegexStrict, pkg/config) hard-rejects
			// it, but the tolerant load / peer-sync paths only warn (#1960
			// no-brick), so the renderer must keep a leniently-loaded
			// definition out of frr.conf entirely. Omitting the list is
			// strictly better than poisoning the reload: FRR resolves a
			// `match as-path <name>` with no such list to NO MATCH, which
			// confines the damage to the terms that reference it. Same
			// predicate as the commit gate — ValidASPathRegex is shared so
			// the two cannot drift. Mirrors validRouterID (render_validate.go).
			if err := config.ValidASPathRegex(ap.Regex); err != nil {
				slog.Warn("frr: omitting unrenderable as-path access-list",
					"as_path", name, "reason", err)
				continue
			}
			// #4097: sanitize the regex so an embedded newline cannot
			// inject an extra frr.conf line — parity with the auth /
			// description fields. FRR takes the regex as a rest-of-line
			// token, so a legitimate space (multi-AS path) survives; only
			// control chars (incl. the newline injection vector) collapse
			// to a space. The strict #1798 commit control-char gate rejects it.
			fmt.Fprintf(&b, "bgp as-path access-list %s permit %s\n", frrName(name), sanitizeFRRValue(ap.Regex))
		}
		b.WriteString("!\n")
	}

	// Generate FRR route-maps from Junos policy-statements
	psNames := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		psNames = append(psNames, name)
	}
	sort.Strings(psNames)
	for _, name := range psNames {
		ps := po.PolicyStatements[name]
		// #5701 render-side belt: a policy whose per-term Cartesian expansion
		// exceeds the FRR route-map sequence-number ceiling would render a
		// `route-map <name> <action> <seq>` line past seq 65535, which FRR
		// rejects (CMD_WARNING_CONFIG_FAILED) — poisoning the WHOLE
		// vtysh-batched frr-reload, not just this policy. The strict commit gate
		// (config.validatePolicyRouteMapSequenceBoundStrict) rejects it; this
		// belt covers the tolerant load / peer-sync / rollback path (#1960)
		// where that gate only warns: do not render the oversized EXPANSION, so
		// the rest of the managed section still reloads.
		//
		// #6807: the expansion is still skipped, but the NAME is no longer left
		// undefined. BGP rendering emits `neighbor <ip> route-map <name> in|out`
		// independently of this loop (off the policy's presence in
		// PolicyStatements), so skipping outright left a live attachment naming
		// a map FRR cannot resolve — which FRR DENIES (bgp_input_modifier /
		// bgp_output_modifier return RMAP_DENY on a failed
		// route_map_lookup_by_name; verified against stable/10.6, the deployed
		// line). Every route on the attached neighbors was silently withdrawn
		// while the comment here claimed permit-all. Emit a bounded explicit
		// deny instead: same outcome, but deliberate, visible in `show
		// route-map`, and independent of FRR's undefined-map behaviour. See
		// renderQuarantineDenyRouteMap for why deny and not "drop the
		// attachment".
		if n := config.RouteMapSequenceCount(po, ps); n > config.MaxRouteMapSequences {
			slog.Warn("oversized route-map policy: expansion would overflow FRR sequence numbers "+
				"and poison the reload; rendering an explicit DENY under this name instead — "+
				"routes matched by its attachments are withdrawn until the policy is reduced",
				"policy", name, "sequences", n, "max", config.MaxRouteMapSequences)
			m.noteQuarantined(name)
			b.WriteString(renderQuarantineDenyRouteMap(name))
			b.WriteString("!\n")
			// The redistribute alias is derived from the SAME policy, so it is
			// oversized too and resolveRedistribute may still reference it.
			// Quarantine it under the same rule; its normal trailing action is
			// already `deny`, so this is its fail-closed intent unchanged.
			if policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
				m.noteQuarantined(redistFailClosedRouteMap(name))
				b.WriteString(renderQuarantineDenyRouteMap(redistFailClosedRouteMap(name)))
				b.WriteString("!\n")
			}
			continue
		}
		// Base route-map: Junos BGP default-accept (#2998) vs the fail-closed
		// redistribute/forwarding-table default, resolved per use context.
		b.WriteString(m.renderRouteMapForPolicy(po, name, ps, policyTrailingAction(name, ps, bgpAcceptDefault)))
		b.WriteString("!\n")
		// #4481: FRR route-maps are keyed by NAME — one object shared by every
		// use site. A policy applied as a BGP route-map in/out with no explicit
		// default renders a trailing PERMIT (Junos BGP default-accept, #2998).
		// If the SAME policy is also used for an IGP redistribute, that permit
		// would leak every non-matching route into the IGP. Emit a per-use-site
		// fail-closed alias for the redistribute contexts; resolveRedistribute
		// references it instead of the shared permit-default map.
		if policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
			b.WriteString(m.renderRouteMapForPolicy(po, redistFailClosedRouteMap(name), ps, "deny"))
			b.WriteString("!\n")
		}
	}

	return b.String()
}

// renderPolicyTermSequences renders policy-statement ps's TERM sequences (NO
// trailing default) into a fresh buffer under FRR route-map name routeMapName,
// deriving inline route-filter prefix-list names from plPrefix, starting at
// sequence startSeq. It returns the rendered text and the next unused sequence.
//
// Splitting the route-map NAME (route-map header) from the prefix-list PREFIX
// lets renderComposedRouteMap emit several policies' term sequences into ONE
// route-map (all sharing routeMapName) while keeping each policy's inline
// prefix-lists in a distinct namespace (plPrefix carries the policy name), so a
// term name reused across chained policies cannot fuse two prefix-lists (#5277).
// renderRouteMapForPolicy passes routeMapName == plPrefix == emitName, keeping
// the single-policy render byte-identical to master.
func (m *Manager) renderPolicyTermSequences(po *config.PolicyOptionsConfig, routeMapName, plPrefix string, ps *config.PolicyStatement, startSeq int) (string, int) {
	var b strings.Builder
	seq := startSeq
	for _, term := range ps.Terms {
		action := "permit"
		if term.Action == "reject" {
			action = "deny"
		}

		// Junos evaluates a policy's terms sequentially and a term that
		// carries NO terminating action (no `then accept`/`then reject`,
		// i.e. term.Action == "") APPLIES its modifications and FALLS
		// THROUGH to the next term. FRR, by contrast, stops a route-map
		// after the first sequence whose match clauses pass and that is a
		// `permit` — once the `set` clauses run the route-map evaluation
		// ends. Without an explicit continuation a Junos policy whose early
		// terms do non-terminating set work (community add, local-preference,
		// ...) and rely on a later term to accept/reject is silently
		// TRUNCATED — the later terms never execute (#2451).
		//
		// FRR's `on-match next` makes a permit sequence run its `set`
		// clauses and then CONTINUE evaluating the following sequences,
		// which is exactly Junos fall-through. We emit it for every
		// non-terminating term (rendered as `permit` above). A terminating
		// term — `then accept` (permit, stop) or `then reject` (deny, stop)
		// — must NOT get `on-match next`, so its FRR semantics match Junos
		// terminating semantics. The `on-match next` line is written after
		// the term's match/set clauses, immediately before `exit`, below.
		//
		// `on-match next` only fires on a MATCHED sequence: if a term's
		// match clauses fail, FRR moves to the next sequence regardless, so
		// emitting it on a non-terminating term never changes the behavior
		// of a non-matching term. Falling off the end of all terms still
		// hits the policy's default-action sequence (emitted after this
		// loop), preserving the overall default behavior.
		nonTerminating := term.Action != "accept" && term.Action != "reject"

		// emitTermBody renders one route-map SEQUENCE for this term: the
		// header, this term's family-specific route-filter match line, the
		// family-agnostic match clauses (source-protocol/community/as-path),
		// the optional `from prefix-list` clause, the `set`/then actions,
		// and `on-match next`/`exit`. seqFam scopes which family-specific
		// clauses are emitted:
		//   - ""   single (unsplit) sequence — the term has homogeneous or
		//          no route-filters; ALL clauses emit (byte-identical to the
		//          pre-#2607 render).
		//   - "v4" / "v6" one half of a SPLIT mixed-family route-filter
		//          term — only that family's route-filter entries + match
		//          line are emitted, and `from prefix-list` is emitted only
		//          when the referenced list's family matches seqFam.
		//
		// Why split rather than emit both `match ip` and `match ipv6` in
		// ONE sequence: FRR ANDs match clauses of DIFFERENT types within a
		// single route-map index (lib/routemap.c route_map_apply_match
		// invokes EVERY match rule with no AF pre-filter; `match ip
		// address` and `match ipv6 address` are different rule types). A
		// route is exclusively v4 or v6, so a v4 route NOMATCHes the ipv6
		// clause and a v6 route NOMATCHes the ip clause → MATCH + NOMATCH =
		// NOMATCH AND's the index to a silent deny for BOTH families. Two
		// SEPARATE sequences (one per family, each carrying the full term
		// body) is the only structure where each family's routes hit a
		// sequence they can satisfy (#2607; the same AND finding that
		// drove #2071's single-matcher decision).
		emitTermBody := func(seqFam string, seqNum int, rfs []indexedRouteFilter, plName string, fromPL fromPrefixListRef, fromCommunity, fromASPath string) {
			fmt.Fprintf(&b, "route-map %s %s %d\n", frrName(routeMapName), action, seqNum)

			// rfMatchEmitted / rfMatchV6 record whether THIS sequence emitted a
			// route-filter "match ip|ipv6 address prefix-list" line and its
			// family, so the from-prefix-list branch below can detect a
			// same-family, same-type collision (#5730) and render the
			// from-prefix-list as a DISTINCT-type access-list match instead of a
			// second (colliding) prefix-list match.
			rfMatchEmitted := false
			rfMatchV6 := false

			// Inline prefix-list for this sequence's route-filters.
			if len(term.RouteFilters) > 0 {
				// matchV6 selects the address family of the
				// "match ip/ipv6 address prefix-list" line. For a split
				// sequence the family is fixed by seqFam. For a single
				// sequence it is taken from the first EMITTED entry, else
				// the first parseable route-filter (a #2103-skipped /32
				// longer still names a real family), else v4 — mirroring
				// the term.PrefixList branch's "unknown/empty defaults to
				// IPv4". The match line is ALWAYS emitted (fail-closed
				// against an undefined list, see below).
				matchV6 := seqFam == "v6"
				matchFamilyKnown := seqFam != ""
				// emitted counts the prefix-list entries actually written.
				// A #2103-skipped (/32 longer, empty set) or #2105-malformed
				// entry writes NO "ip prefix-list" line, so the list may end
				// up with zero entries — and we intentionally never
				// materialise a count==0 list (FRR treats a count==0
				// prefix-list as PREFIX_PERMIT / match-ALL). The match line
				// still references the (then-undefined) list name: FRR
				// resolves an undefined prefix-list to NULL → RMAP_NOMATCH
				// (DENY), so an all-skipped term matches NOTHING and stays
				// fail-closed. Suppressing the match line would leave a bare
				// "route-map … permit <seq>" with no match clauses, which
				// FRR treats as match-ALL — flipping "/32 longer" from the
				// empty set to permit-everything (Copilot #2110).
				emitted := 0
				for _, irf := range rfs {
					// Family hint for the single-sequence case: the first
					// PARSEABLE route-filter sets it (even if later skipped),
					// the first EMITTED entry overrides. For a split sequence
					// seqFam already fixed it.
					if seqFam == "" && !matchFamilyKnown {
						if _, _, err := net.ParseCIDR(irf.rf.Prefix); err == nil {
							matchV6 = strings.Contains(irf.rf.Prefix, ":")
							matchFamilyKnown = true
						}
					}
					if renderRouteFilterEntry(&b, plName, irf.idx, irf.rf) {
						if emitted == 0 && seqFam == "" {
							matchV6 = strings.Contains(irf.rf.Prefix, ":")
							matchFamilyKnown = true
						}
						emitted++
					}
				}
				if matchV6 {
					fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", frrName(plName))
				} else {
					fmt.Fprintf(&b, " match ip address prefix-list %s\n", frrName(plName))
				}
				rfMatchEmitted = true
				rfMatchV6 = matchV6
			}

			if fromPL.name != "" {
				// The address family of THIS `from prefix-list` match is fixed
				// by the typed ref (fromPrefixListRef.matchKW): a mixed v4+v6
				// referenced list is expanded UPSTREAM (fromPrefixListRefs) into
				// two refs — one "ip", one "ipv6" — each emitted in its own
				// route-map sequence, so BOTH families bind their own `match
				// ip|ipv6 address` line and neither family's routes silently
				// fail the term (#2607). A single-family or undefined/empty list
				// yields exactly one ref, byte-identical to the pre-#2607 render.
				// FRR keeps `ip` and `ipv6` prefix-lists in independent
				// namespaces, so `match ip address prefix-list PL` resolves to PL's
				// v4 entries and `match ipv6 address prefix-list PL` to its v6
				// entries even though both share the name PL.
				//
				// In a SPLIT mixed-route-filter term (seqFam != "") this
				// `from prefix-list` match is ANDed with this sequence's
				// route-filter match. When the ref's family is the OPPOSITE of the
				// route-filter's, the match line MUST STILL be emitted: it names a
				// different FRR match type than the `match ip/ipv6 address
				// <route-filter>`, so the two coexist and the sequence
				// AND-NOMATCHes every route — exactly the intended Junos semantics
				// ("(route-filter) AND (off-family prefix-list)" is unsatisfiable
				// for this family, so the term is non-matching for it). Dropping
				// the off-family match instead (the pre-#5702 behavior) silently
				// LOOSENED the term to its route-filter half — a fail-open
				// policy-semantics change (#5702). This is a DIFFERENT-type
				// coexistence, NOT the #2071/#5730 same-type collision: a v4
				// route-filter is `match ip` and a v6 prefix-list is `match ipv6`,
				// so neither replaces the other.
				//
				// A referenced list is ONE entry of a possibly multi-valued
				// `from prefix-list` set (#2642), and a mixed list adds its own
				// per-family OR-dimension (#2607). Both are the SAME structure:
				// FRR's route_map_add_match REPLACES a same-type rule
				// (lib/routemap.c), so OR is expressed by one route-map SEQUENCE
				// per (list, family) value — the dispatch loop below — each
				// carrying the full term body.
				plObj := po.PrefixLists[fromPL.name]
				matchKW := fromPL.matchKW
				// #5730: when THIS sequence ALSO emitted a same-family
				// route-filter "match ip|ipv6 address prefix-list" line, a
				// second same-type "match ... prefix-list" for the
				// from-prefix-list COLLIDES — FRR's route_map_add_match REPLACES
				// a same-type rule (keeps the LAST), silently dropping the
				// route-filter constraint and loosening "(route-filter) AND
				// (prefix-list)" to prefix-list-only. Render the from-prefix-list
				// as an ACCESS-LIST match — a DISTINCT FRR rule type — so FRR
				// ANDs the two constraints. A DIFFERENT-family route-filter (the
				// #5702 off-family fail-closed coexistence) is already a distinct
				// FRR type, so it keeps the prefix-list match unchanged.
				if rfMatchEmitted && rfMatchV6 == (matchKW == "ipv6") {
					// #5872: a bounded, namespaced, deterministically-hashed
					// access-list name (routeFilterACLName, naming.go) — NOT the
					// pre-#5872 `fromPrefixList + "_rf"` concatenation, which had no
					// length bound (FRR-identifier overflow) and no collision
					// namespace (two long same-prefix names truncate-collide → FRR
					// merges the access-lists → silent policy widen/narrow). The
					// SAME value backs the definition and the reference below, so
					// they always agree; routeFilterACLNameCollision (wired into
					// ApplyFull) fails the apply CLOSED on any residual collision.
					aclName := routeFilterACLName(fromPL.name, matchKW)
					renderFromPrefixListACL(&b, aclName, matchKW, plObj)
					fmt.Fprintf(&b, " match %s address %s\n", matchKW, aclName)
				} else {
					fmt.Fprintf(&b, " match %s address prefix-list %s\n", matchKW, frrName(fromPL.name))
				}
			}

			// Junos "from protocol [ bgp ospf static ]" matches ANY listed
			// protocol. FRR's "match source-protocol" only accepts a single
			// protocol per line, but repeated lines within one route-map entry
			// are OR'd, so render one line per protocol.
			for _, proto := range term.FromProtocols {
				if proto == "direct" {
					proto = "connected"
				}
				// #4498: sanitize the protocol token — the same #4097/#4482
				// render-side belt the other route-map free-text slots use.
				// A tolerant-load / peer-synced / rolled-back FromProtocols
				// value with an embedded newline must not inject an extra
				// frr.conf line (the strict #1798 commit gate rejects it, but
				// the lenient load path only warns, #1960).
				fmt.Fprintf(&b, " match source-protocol %s\n", sanitizeFRRValue(proto))
			}

			// fromCommunity / fromASPath are ONE entry of a possibly
			// multi-valued `from community` / `from as-path` set (#2642).
			// Junos OR's repeated same-type matches; FRR can hold only one
			// `match community` / `match as-path` rule per route-map index
			// (route_map_add_match replaces same-type), so OR is expressed
			// by emitting one SEQUENCE per entry (dispatch loop below).
			if fromCommunity != "" {
				fmt.Fprintf(&b, " match community %s\n", frrName(fromCommunity))
			}

			if fromASPath != "" {
				fmt.Fprintf(&b, " match as-path %s\n", frrName(fromASPath))
			}

			// then actions
			if term.NextHop != "" {
				if term.NextHop == "peer-address" {
					// Junos "next-hop peer-address" → FRR. The session AF is not
					// known here, so emit both forms; FRR applies each only to
					// the matching address family of the carrying BGP session.
					fmt.Fprintf(&b, " set ip next-hop peer-address\n")
					fmt.Fprintf(&b, " set ipv6 next-hop peer-address\n")
				} else if term.NextHop == "self" {
					// Junos `then next-hop self` sets the advertised next-hop to
					// THIS router's own session address for ONLY the routes that
					// match this term. FRR has no literal `set ... next-hop self`
					// (the parser rejects it and takes the whole route-map down),
					// but in an OUTBOUND route-map `set ip next-hop peer-address`
					// resolves to the local end of the BGP session — i.e. self —
					// and is evaluated per-route, so it rewrites exactly this
					// term's routes and leaves every other term's routes intact.
					// A BGP export policy is always rendered as `route-map <name>
					// out`, so this always evaluates in the outbound direction.
					//
					// This lowering REPLACES the pre-#5115 neighbor-wide
					// `neighbor <peer> next-hop-self force` knob, which ran after
					// route selection and rewrote EVERY route advertised to the
					// peer — including routes accepted by OTHER terms that never
					// requested self (the #5115 semantic widening). A term with
					// no `from` match still renders a match-all sequence, so a
					// genuinely neighbor-wide `then next-hop self` keeps its
					// neighbor-wide effect. Like the old `force`, an outbound
					// `set` overrides the next-hop on iBGP / route-reflector-
					// reflected routes too, so the #2977 iBGP blackhole stays
					// fixed — now correctly scoped to the term's routes.
					//
					// The session AF is unknown at render time; emit both forms
					// and FRR applies each only to its matching address family
					// (mirrors the `peer-address` branch above).
					fmt.Fprintf(&b, " set ip next-hop peer-address\n")
					fmt.Fprintf(&b, " set ipv6 next-hop peer-address\n")
				} else if strings.Contains(term.NextHop, ":") {
					// IPv6 literal next-hop. FRR rejects "set ip next-hop" for a
					// v6 address (whole route-map fails to parse); v6 uses the
					// dedicated "set ipv6 next-hop global" form. Mirror the
					// AF detection used by the prefix-list renderer above.
					fmt.Fprintf(&b, " set ipv6 next-hop global %s\n", sanitizeFRRValue(term.NextHop))
				} else {
					// #4498: sanitize the next-hop — an IP-typed slot, but on
					// the tolerant load / peer-sync / rollback path a stored
					// malformed value with an embedded newline reaches the
					// renderer (the strict #1798 commit gate does not cover
					// those paths, #1960). Parity with the #4482 set-clause belt.
					fmt.Fprintf(&b, " set ip next-hop %s\n", sanitizeFRRValue(term.NextHop))
				}
			}

			if term.LoadBalance != "" {
				// FRR handles ECMP load balancing via forwarding-table export
				// The route-map just needs to be a permit
			}

			// Emit on PRESENCE, not value: local-preference 0 is a
			// valid BGP value (maximally deprioritize a route within
			// the AS). Gating on LocalPreference > 0 silently dropped
			// `set local-preference 0` (#2857).
			if term.HasLocalPreference {
				fmt.Fprintf(&b, " set local-preference %d\n", term.LocalPreference)
			}
			// Emit on PRESENCE, not value: metric/MED 0 is a valid
			// traffic-engineering value (advertise a highly preferred
			// route). Gating on Metric > 0 silently dropped `set metric
			// 0` (#2847).
			if term.HasMetric {
				fmt.Fprintf(&b, " set metric %d\n", term.Metric)
			}
			if term.MetricType == 1 || term.MetricType == 2 {
				fmt.Fprintf(&b, " set metric-type type-%d\n", term.MetricType)
			}
			// BGP community operations (#2848). Junos/vSRX supports
			// append/delete/strip in addition to whole-attribute replace;
			// emitting only the replace clause wiped upstream-set
			// communities. Map each Junos operation to its FRR route-map
			// set clause. #4482: every free-text value below (set community,
			// set comm-list delete name, set as-path prepend, and the match
			// community / as-path names) is routed through sanitizeFRRValue —
			// the same #4097 render-side belt the community-list / as-path-list
			// definitions use — so a tolerant-load / peer-synced / rolled-back
			// value with an embedded newline cannot inject an extra frr.conf
			// line regardless of load path. #4498 extended the belt to the
			// three remaining bare-%s route-map slots the #4482 sweep missed:
			// `set ip/ipv6 next-hop`, `set origin`, and `match
			// source-protocol` (all rendered above).
			//   - add    → `set community <v> additive` (append)
			//   - delete → `set comm-list <name> delete` (strip by list)
			//   - none   → `set community none` (strip all)
			//   - set/"" → `set community <v>` (replace; legacy bare form)
			switch term.CommunityOp {
			case "none":
				b.WriteString(" set community none\n")
			case "add":
				if term.CommunityAdd != "" {
					fmt.Fprintf(&b, " set community %s additive\n", sanitizeFRRValue(term.CommunityAdd))
				}
			case "delete":
				// FRR's `set comm-list <name> delete` strips ONE
				// community-list per line, so a multi-list
				// `then community delete [ listA listB ]` emits one clause
				// per referenced list — every name in order (#2902).
				for _, name := range term.CommunityDelete {
					if name != "" {
						fmt.Fprintf(&b, " set comm-list %s delete\n", frrName(name))
					}
				}
			default: // "" or "set" — whole-attribute replace
				if term.Community != "" {
					fmt.Fprintf(&b, " set community %s\n", sanitizeFRRValue(term.Community))
				}
			}
			// AS-path prepend (#2892). Junos `then as-path-prepend
			// "<asn> <asn> ..."` → FRR `set as-path prepend <asn> <asn>
			// ...`. The repeated ASNs lengthen the advertised AS_PATH so
			// peers prefer a shorter alternate path. Emit every ASN in
			// order (repetition is the mechanism) on a single clause; skip
			// entirely when no ASNs were configured.
			if len(term.ASPathPrepend) > 0 {
				fmt.Fprintf(&b, " set as-path prepend %s\n", sanitizeFRRValue(strings.Join(term.ASPathPrepend, " ")))
			}
			if term.Origin != "" && validBGPOrigin(term.Origin) {
				// #4919: skip an invalid origin (fail-closed) — a non-control
				// typo like `igpp` or a leniently-loaded / peer-synced bad
				// value would fail the FRR route-map grammar and poison the
				// reload. Only igp | egp | incomplete are valid. #4498:
				// sanitize the accepted token too (defense-in-depth; a valid
				// origin has no control chars, so it is a no-op on the happy
				// path).
				fmt.Fprintf(&b, " set origin %s\n", sanitizeFRRValue(term.Origin))
			}

			// Non-terminating term: fall through to the next sequence after
			// running this term's set clauses (Junos fall-through; #2451).
			// In a SPLIT term BOTH per-family sequences carry on-match next
			// for a non-terminating term — each is its own permit sequence
			// and must continue to later terms. A terminating term gets none
			// in either half (the v4-route case stops at the v4 sequence; the
			// v6-route case stops at the v6 sequence).
			if nonTerminating {
				b.WriteString(" on-match next\n")
			}

			b.WriteString("exit\n")
		}

		// Decide single vs split. A term splits ONLY when its route-filters
		// genuinely mix families (at least one v4 AND one v6 prefix). A
		// homogeneous or empty route-filter set renders as today — ONE
		// sequence, ONE plName, byte-identical output (no churn for the
		// common case).
		// Two independent OR-dimensions can each multiply the number of
		// emitted sequences:
		//   (a) route-filters that genuinely mix families (#2607) - one
		//       sequence per family; and
		//   (b) repeated same-type `from prefix-list` / `from community`
		//       / `from as-path` matches (#2642) - Junos OR's them, but
		//       FRR holds only one rule of each match TYPE per route-map
		//       index (route_map_add_match replaces same-type), so OR is
		//       expressed as one sequence per value.
		// Different match types must AND, the same type must OR. The
		// correct structure is the CARTESIAN PRODUCT of the OR-sets: each
		// emitted sequence carries exactly one prefix-list, one community,
		// one as-path (plus its family's route-filter match, all
		// source-protocol lines, and all set actions). A route that
		// satisfies (any prefix-list) AND (any community) AND (any as-path)
		// reaches at least one sequence it fully matches - the Junos
		// "(p1|p2) AND (c1|c2) AND ..." semantics.
		//
		// The common single-valued / no-match case collapses to ONE
		// sequence with the historical plName, byte-identical to master:
		// each OR-set defaults to a single "" sentinel.
		plName := plPrefix + "-" + term.Name
		v4rf, v6rf := partitionRouteFiltersByFamily(term.RouteFilters)
		mixedFamily := len(term.RouteFilters) > 0 && len(v4rf) > 0 && len(v6rf) > 0

		// orElseEmpty yields the OR-set to iterate: the field's values, or
		// a single "" sentinel so a missing match still emits one sequence
		// (the per-clause guards skip the empty value).
		orElseEmpty := func(vs []string) []string {
			if len(vs) == 0 {
				return []string{""}
			}
			return vs
		}

		// emitVariants emits the cross-product of the from-* OR sets for one
		// route-filter family group (seqFam/rfs/famPL), advancing seq by 10 per
		// sequence. The iteration order (prefix-list, then its per-family refs,
		// then community, then as-path) is fixed, so output is deterministic.
		// Each referenced prefix-list expands into one ref per family it holds
		// (fromPrefixListRefs): a single-family list yields one ref (unchanged
		// output), a mixed v4+v6 list yields an ip ref and an ipv6 ref so BOTH
		// families bind a family-correct match line (#2607).
		emitVariants := func(seqFam string, rfs []indexedRouteFilter, famPL string) {
			for _, plName := range orElseEmpty(term.PrefixList) {
				for _, plRef := range fromPrefixListRefs(po, plName) {
					for _, comm := range orElseEmpty(term.FromCommunity) {
						for _, asp := range orElseEmpty(term.FromASPath) {
							emitTermBody(seqFam, seq, rfs, famPL, plRef, comm, asp)
							seq += 10
						}
					}
				}
			}
		}

		if mixedFamily {
			// Mixed-family route-filters: split into a v4 group and a v6
			// group (#2607), each carrying its own family's route-filter
			// entries into a per-family prefix-list (plName_v4 / plName_v6 -
			// FRR `ip` vs `ipv6` prefix-lists are separate namespaces anyway,
			// but the distinct NAME keeps the two match lines referencing
			// disjoint single-family lists). Within each group the from-* OR
			// cross-product is emitted; v4 first.
			emitVariants("v4", v4rf, plName+"_v4")
			emitVariants("v6", v6rf, plName+"_v6")
		} else {
			// Homogeneous or no route-filters: one family group. Pass the
			// full (possibly empty) indexed route-filter set and the
			// historical plName. With no repeated from-* matches this is a
			// single sequence, byte-identical to master.
			all := make([]indexedRouteFilter, len(term.RouteFilters))
			for i, rf := range term.RouteFilters {
				all[i] = indexedRouteFilter{i, rf}
			}
			emitVariants("", all, plName)
		}
	}

	return b.String(), seq
}

// renderRouteMapForPolicy renders ONE FRR route-map for policy-statement ps
// under emitName, appending the caller-supplied trailing default action. The
// body — terms, match/set clauses, and inline route-filter prefix-lists whose
// names derive from emitName — is identical across use sites; only the header
// name and the trailing default differ. That lets a BGP-default-accept policy
// ALSO be rendered under a fail-closed per-use-site alias for redistribute
// without leaking its permit default across FRR's name-keyed route-map object
// (#4481 / #2998 / #2607 / #2642).
func (m *Manager) renderRouteMapForPolicy(po *config.PolicyOptionsConfig, emitName string, ps *config.PolicyStatement, trailingAction string) string {
	body, seq := m.renderPolicyTermSequences(po, emitName, emitName, ps, 10)
	var b strings.Builder
	b.WriteString(body)

	// Trailing default action, resolved by the caller — Junos BGP
	// default-accept (#2998) or the fail-closed redistribute /
	// forwarding-table default — and passed in so the SAME body can render
	// under a per-use-site alias with a different trailing default, never
	// mutating FRR's name-keyed shared route-map object (#4481). See
	// policyTrailingAction for the case matrix.
	fmt.Fprintf(&b, "route-map %s %s %d\n", frrName(emitName), trailingAction, seq)
	b.WriteString("exit\n")
	return b.String()
}

// renderComposedRouteMap composes an ordered Junos BGP policy CHAIN (>= 2
// DEFINED policy-statements, e.g. `export [ A B C ]`) into a SINGLE FRR
// route-map named composedName, preserving Junos policy-chain semantics that
// the pre-#5277 lastNonEmpty collapse violated by rendering only the final
// policy:
//
//   - Each policy's terms evaluate IN ORDER (A, then B, then C). A term's
//     terminating `then accept`/`then reject` wins immediately (permit/deny,
//     stop); a non-terminating term applies its set clauses and falls through
//     (on-match next), exactly as the single-policy render does.
//   - A policy with an EXPLICIT policy-level default (`then accept`/`then
//     reject`) TERMINATES the chain with a match-all permit/deny — later
//     policies are unreachable (Junos: the default action is terminating).
//   - A policy with NO explicit default FALLS THROUGH to the next policy
//     (Junos next-policy), so a route BLOCK-PRIVATE would reject is caught by
//     BLOCK-PRIVATE before ALLOW-CUSTOMER ever runs.
//   - If the route falls off the end of EVERY policy, the Junos BGP
//     default-ACCEPT applies (#2998). A composed chain only ever renders in a
//     BGP `route-map in`/`out` context, so that fall-off default is permit.
//
// Sequence numbers run continuously across the chain; each policy's inline
// prefix-lists are namespaced by composedName+"-"+policyName so a term name
// reused across policies cannot fuse two prefix-lists.
func (m *Manager) renderComposedRouteMap(po *config.PolicyOptionsConfig, composedName string, chain []string) string {
	// #5732 render-side belt: this composed route-map numbers its members'
	// sequences with ONE running counter, so a chain whose members each pass the
	// per-policy #5701 bound can still SUM past the FRR ceiling and emit a
	// `route-map` line past seq 65535 — poisoning the whole vtysh-batched
	// frr-reload. The strict commit gate
	// (config.validateBGPComposedChainSequenceBoundStrict) rejects it; this belt
	// covers the tolerant load / peer-sync / rollback path (#1960) where that
	// gate only warns: do not render the oversized EXPANSION. The gate and this
	// belt consult the SAME config.ComposedChainSequenceCount predicate, so they
	// can never disagree on what overflows.
	//
	// #6807: return a bounded explicit DENY under composedName rather than the
	// empty string. The neighbor's `route-map <composedName> in|out` is emitted
	// by BGP rendering regardless of what this function returns, so an empty
	// return left that attachment naming an unresolvable map — which FRR denies
	// (RMAP_DENY on a failed route_map_lookup_by_name, stable/10.6), not
	// permits as the previous comment claimed. Same tradeoff as the
	// single-policy site (#5701); see renderQuarantineDenyRouteMap.
	if n := config.ComposedChainSequenceCount(po, po.PolicyStatements, chain); n > config.MaxRouteMapSequences {
		slog.Warn("oversized composed BGP policy-chain route-map: expansion would overflow FRR "+
			"sequence numbers and poison the reload; rendering an explicit DENY under this name "+
			"instead — routes on neighbors carrying this chain are withdrawn until it is reduced",
			"route-map", composedName, "sequences", n, "max", config.MaxRouteMapSequences)
		m.noteQuarantined(composedName)
		return renderQuarantineDenyRouteMap(composedName)
	}
	var b strings.Builder
	seq := 10
	terminated := false
	for _, name := range chain {
		ps := po.PolicyStatements[name]
		if ps == nil {
			// Defensive: chain is pre-filtered to defined policy-statements.
			continue
		}
		body, next := m.renderPolicyTermSequences(po, composedName, composedName+"-"+name, ps, seq)
		b.WriteString(body)
		seq = next
		switch ps.DefaultAction {
		case "accept":
			fmt.Fprintf(&b, "route-map %s permit %d\n", frrName(composedName), seq)
			b.WriteString("exit\n")
			seq += 10
			terminated = true
		case "reject":
			fmt.Fprintf(&b, "route-map %s deny %d\n", frrName(composedName), seq)
			b.WriteString("exit\n")
			seq += 10
			terminated = true
		}
		if terminated {
			break
		}
	}
	if !terminated {
		// Fell off the end of every policy in the chain → Junos BGP
		// default-ACCEPT (#2998): permit the (accumulated-modified) route.
		fmt.Fprintf(&b, "route-map %s permit %d\n", frrName(composedName), seq)
		b.WriteString("exit\n")
	}
	return b.String()
}
