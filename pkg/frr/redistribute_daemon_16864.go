package frr

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #16864 (R3-B07-01): per-(policy, source, consuming daemon/AF)
// redistribute maps.
//
// #12065 derived one map per (policy, source) and rendered it
// daemon-agnostically. vtysh dispatches each `match` line only to the
// daemons that installed that command, so a clause the CONSUMING
// daemon did not install silently vanished from its copy of the map
// and the sequence became match-all:
//
//   - ospfd, ospf6d, ripd and isisd do not install `match community`
//     or `match as-path` (bgpd-only): a community-scoped BGP->OSPF
//     export redistributed every BGP route, and a community reject
//     withdrew every route instead of only its own.
//   - ospfd/ripd do not install `match ipv6 ...`; ospf6d does not
//     install `match ip ...`: in a dual-stack policy shared by ospf
//     and ospf3, the other family's accept terms leaked every route
//     of the source and its reject terms withdrew all redistribution.
//
// The fix renders, for every IGP-referenced (policy, source), one
// variant per consuming daemon/AF actually referencing it, named
// `<policy>-<proto>-xpf-redist-<variant>` with variant in
// {ospf, ospf6, rip, isis-v4, isis-v6}. Each variant keeps only the
// clauses its daemon evaluates (see redistVariantTerm16864):
// off-family terms are omitted (they can never match a local route),
// bgpd-only conditions on a BGP source omit accepts and render
// rejects as bare denies, and every omission warns — never an
// empty-match permit.
//
// BGP is the evaluating daemon for community/as-path, so maps
// attached under `router bgp` / `address-family ipv6 unicast` keep
// the historical unsuffixed per-source render byte-identically (the
// empty variant). A policy referenced by both BGP and an IGP gets
// the unsuffixed BGP map plus each IGP variant. IS-IS is dual-AF in
// one daemon, so it gets one variant per AF and isisRedistributeLines
// names the variant matching the line's AF. A policy referenced by
// no IGP (BGP-only or unreferenced) renders only the unsuffixed map,
// exactly as before.
//
// QNH metric maps (xpf-qnh-*) are NOT split: they attach only as
// `redistribute static` replacements and their metric sequences are
// already daemon-scoped by qnhMetricScopeForDaemon11447; splitting
// them is a residual (docs/log/16864.md).

// redistVariantContext16864 is one consuming context. The empty
// variant is the daemon-agnostic (BGP / direct-caller) context.
type redistVariantContext16864 struct {
	variant string // "", "ospf", "ospf6", "rip", "isis-v4", "isis-v6"
	daemon  string // slog label
	v6      bool   // routes evaluated here are IPv6
	isis    bool   // one of the two IS-IS AF contexts
}

var (
	redistVariantOSPF16864  = redistVariantContext16864{variant: "ospf", daemon: "ospfd"}
	redistVariantOSPF616864 = redistVariantContext16864{variant: "ospf6", daemon: "ospf6d", v6: true}
	redistVariantRIP16864   = redistVariantContext16864{variant: "rip", daemon: "ripd"}
	redistVariantISIS416864 = redistVariantContext16864{variant: "isis-v4", daemon: "isisd", isis: true}
	redistVariantISIS616864 = redistVariantContext16864{variant: "isis-v6", daemon: "isisd", v6: true, isis: true}
	// redistVariantBGP16864 is the evaluating (unsuffixed) context.
	redistVariantBGP16864 = redistVariantContext16864{variant: "", daemon: "bgpd"}
)

// redistVariantForNode16864 maps a (self, node) render pair — the
// vocabulary of redistributeEntriesAt / redistReferencedNodes14380 —
// to its variant context. ok=false for the BGP nodes and unknown
// nodes, which keep the unsuffixed render. IS-IS returns its v4
// context as representative; callers needing per-AF names use the
// entry's isis flag (see isisRedistributeLines).
func redistVariantForNode16864(self, node string) (redistVariantContext16864, bool) {
	switch node {
	case "ospf":
		return redistVariantOSPF16864, true
	case "ospf6":
		return redistVariantOSPF616864, true
	case "rip":
		return redistVariantRIP16864, true
	case "isis":
		return redistVariantISIS416864, true
	}
	return redistVariantBGP16864, false
}

// redistVariantsForNodes16864 returns the distinct IGP variant
// contexts a policy's referencing nodes require, in deterministic
// order. BGP nodes contribute nothing (unsuffixed map).
func redistVariantsForNodes16864(nodes [][2]string) []redistVariantContext16864 {
	seen := make(map[string]bool)
	var out []redistVariantContext16864
	add := func(ctx redistVariantContext16864) {
		if !seen[ctx.variant] {
			seen[ctx.variant] = true
			out = append(out, ctx)
		}
	}
	for _, nd := range nodes {
		switch nd[1] {
		case "ospf":
			add(redistVariantOSPF16864)
		case "ospf6":
			add(redistVariantOSPF616864)
		case "rip":
			add(redistVariantRIP16864)
		case "isis":
			add(redistVariantISIS416864)
			add(redistVariantISIS616864)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].variant < out[j].variant })
	return out
}

// redistVariantRouteMapName16864 names a variant map. The unsuffixed
// (BGP) name is exactly redistProtocolRouteMapName.
func redistVariantRouteMapName16864(policy, proto string, ctx redistVariantContext16864) string {
	base := redistProtocolRouteMapName(policy, proto)
	if ctx.variant == "" {
		return base
	}
	return base + "-" + ctx.variant
}

// redistVariantChainRouteMapName16864 names a composed (#15156)
// variant map.
func redistVariantChainRouteMapName16864(chain []string, proto string, ctx redistVariantContext16864) string {
	base := redistChainRouteMapName15156(chain, proto)
	if ctx.variant == "" {
		return base
	}
	return base + "-" + ctx.variant
}

// redistVariantSuffixes16864 lists every variant suffix, for the
// collision guards' generated-name enumeration.
var redistVariantSuffixes16864 = []string{"ospf", "ospf6", "rip", "isis-v4", "isis-v6"}

// redistProtoFitsVariant16864 reports whether a source protocol can
// be redistributed into ctx at all: for IS-IS the source's AF must
// cover the variant's family; for the single-AF daemons the existing
// node grammar filter decides.
func redistProtoFitsVariant16864(proto string, ctx redistVariantContext16864) bool {
	proto = normalizedRedistProtocol(proto)
	if ctx.isis {
		afi, known := frrRedistSourceAFI[proto]
		if !known {
			return true
		}
		if ctx.v6 {
			return afi&afiV6 != 0
		}
		return afi&afiV4 != 0
	}
	switch ctx.variant {
	case "ospf":
		return redistSourceFitsNode(proto, "ospf")
	case "ospf6":
		return redistSourceFitsNode(proto, "ospf6")
	case "rip":
		return redistSourceFitsNode(proto, "rip")
	}
	return true
}

// --- term / statement filtering ------------------------------------

// redistVariantTerm16864 classifies one per-source term (FromProtocols
// already cleared by redistPolicyForProtocol; proto is that source)
// for ctx. It returns the term to render (nil to omit it), whether
// anything was dropped or converted, and whether the returned term
// is a bare deny-all conversion.
//
// Rules (Junos: a term matches only if ALL its from conditions
// match; an IPv4 filter never matches an IPv6 route):
//
//   - community/as-path on a non-BGP source can never match (only
//     BGP routes carry those attributes): omit for every action.
//   - community/as-path on a BGP source cannot be evaluated by any
//     IGP daemon: accept and non-terminating terms are omitted
//     (fail closed, never an empty-match permit); a terminating
//     reject or a `next policy` term becomes a bare deny — its match
//     set is unknowable here, and the deny superset is the only
//     sound fail-closed render (the #9881/#10822 dangling rule).
//   - Route-filters / prefix-list refs exclusively of the other
//     family can never match a local route: omit for every action.
//     A reject here governs no local route, so a bare deny would
//     wrongly withdraw the other family's routes (the s1 mirror).
//   - A dangling (undefined/empty) prefix-list with no same-family
//     defined ref is unknowable, not off-family: reject becomes a
//     bare deny, accept/modify are omitted (the #14136 rule).
//   - Mixed-family route-filters are trimmed to ctx's family;
//     mixed prefix-lists keep their name and are family-restricted
//     by redistVariantPO16864 at render.
//   - A term with no conditions at all (authored match-all) is kept
//     verbatim: an empty-match sequence is then the operator's own
//     semantics, not a dropped-clause artifact.
func redistVariantTerm16864(po *config.PolicyOptionsConfig, term *config.PolicyTerm, proto string, ctx redistVariantContext16864) (keep *config.PolicyTerm, dropped bool, denyAll bool) {
	if term == nil {
		return nil, false, false
	}
	if ctx.variant == "" {
		c := *term
		return &c, false, false
	}
	// The verb the generic renderer assigns this term.
	actionDeny := (term.Action == "reject" && !term.NextPolicy) || (term.NextPolicy && term.Action != "")

	if len(term.FromCommunity) > 0 || len(term.FromASPath) > 0 {
		if proto != "bgp" {
			return nil, true, false
		}
		if actionDeny || term.NextPolicy {
			return &config.PolicyTerm{Name: term.Name, Action: "reject"}, true, true
		}
		return nil, true, false
	}

	v4rf, v6rf := partitionRouteFiltersByFamily(term.RouteFilters)
	if len(term.RouteFilters) > 0 {
		local := v4rf
		if ctx.v6 {
			local = v6rf
		}
		if len(local) == 0 {
			return nil, true, false
		}
	}

	// Prefix-list dimension: OR across names and per-family refs.
	plSame, plDangling := false, false
	var keptLists []string
	for _, name := range term.PrefixList {
		_, defined := po.PrefixLists[name]
		if defined && po.PrefixLists[name] != nil && len(po.PrefixLists[name].Prefixes) == 0 {
			defined = false
		}
		same := false
		for _, ref := range fromPrefixListRefs(po, name) {
			if ref.name != "" && (ref.matchKW == "ipv6") == ctx.v6 {
				same = true
			}
		}
		if !defined {
			plDangling = true
			// An undefined list yields the default ip ref; keep the
			// name only where that ref is same-family so the generic
			// renderer's own dangling rule can fire there.
			if same {
				keptLists = append(keptLists, name)
				plSame = true
			}
			continue
		}
		if same {
			plSame = true
			keptLists = append(keptLists, name)
		}
	}
	if len(term.PrefixList) > 0 && !plSame {
		if plDangling {
			if actionDeny || term.NextPolicy {
				return &config.PolicyTerm{Name: term.Name, Action: "reject"}, true, true
			}
			return nil, true, false
		}
		return nil, true, false
	}

	c := *term
	if len(term.RouteFilters) > 0 && len(v4rf) > 0 && len(v6rf) > 0 {
		src := v4rf
		if ctx.v6 {
			src = v6rf
		}
		c.RouteFilters = make([]*config.RouteFilter, len(src))
		for i, irf := range src {
			c.RouteFilters[i] = irf.rf
		}
	}
	if len(term.PrefixList) > 0 {
		c.PrefixList = keptLists
	}
	return &c, false, false
}

// redistPolicyForVariant16864 filters a per-source statement for
// ctx, preserving authored term order (deny-all conversions stay in
// place as bare rejects).
func redistPolicyForVariant16864(po *config.PolicyOptionsConfig, ps *config.PolicyStatement, proto string, ctx redistVariantContext16864) (filtered *config.PolicyStatement, dropped int, denyAlls int) {
	if ps == nil {
		return nil, 0, 0
	}
	out := *ps
	out.Terms = nil
	for _, term := range ps.Terms {
		keep, wasDropped, isDenyAll := redistVariantTerm16864(po, term, proto, ctx)
		if isDenyAll {
			denyAlls++
			dropped++
			out.Terms = append(out.Terms, keep)
			continue
		}
		if wasDropped {
			dropped++
			continue
		}
		if keep != nil {
			out.Terms = append(out.Terms, keep)
		}
	}
	return &out, dropped, denyAlls
}

// redistVariantPO16864 returns a render view of po whose prefix-lists
// hold only ctx's family entries, so fromPrefixListRefs expands a
// mixed referenced list to the local family only. The global
// prefix-list definitions are rendered elsewhere from the original
// po; FRR keeps ip/ipv6 lists in separate namespaces, so the local
// `match ip|ipv6 address prefix-list <name>` still resolves.
func redistVariantPO16864(po *config.PolicyOptionsConfig, ctx redistVariantContext16864) *config.PolicyOptionsConfig {
	if po == nil || ctx.variant == "" || po.PrefixLists == nil {
		return po
	}
	out := *po
	lists := make(map[string]*config.PrefixList, len(po.PrefixLists))
	for name, pl := range po.PrefixLists {
		if pl == nil {
			lists[name] = nil
			continue
		}
		cp := *pl
		cp.Prefixes = nil
		for _, p := range pl.Prefixes {
			if strings.Contains(p, ":") == ctx.v6 {
				cp.Prefixes = append(cp.Prefixes, p)
			}
		}
		lists[name] = &cp
	}
	out.PrefixLists = lists
	return &out
}

// logRedistVariantDrop16864 warns once per rendered variant that
// dropped or converted terms — the operator-visible signal the issue
// requires instead of the pre-fix silence.
func logRedistVariantDrop16864(policy, proto string, ctx redistVariantContext16864, dropped, denyAlls int) {
	if dropped == 0 {
		return
	}
	slog.Warn("frr: redistribute map variant omits terms the consuming daemon cannot evaluate; accepts fail closed, rejects render deny-all (#16864)",
		"policy", policy, "protocol", proto, "daemon", ctx.daemon,
		"variant", ctx.variant, "dropped_terms", dropped, "deny_all_terms", denyAlls)
}

// --- variant rendering ----------------------------------------------

// renderRedistributeVariantMapCluster16864 renders one
// (policy, source, daemon/AF) variant map. The BGP context delegates
// to the historical renderer, byte-identically.
func renderRedistributeVariantMapCluster16864(m *Manager, po *config.PolicyOptionsConfig, policy string, ps *config.PolicyStatement, proto string, ctx redistVariantContext16864, clusterMode bool) string {
	if ctx.variant == "" {
		return renderRedistributePolicyMapCluster15158(m, po, policy, ps, proto, clusterMode)
	}
	routeMap := redistVariantRouteMapName16864(policy, proto, ctx)
	source := redistPolicyForProtocol(ps, proto)
	vpo := redistVariantPO16864(po, ctx)
	filtered, dropped, denyAlls := redistPolicyForVariant16864(po, source, proto, ctx)
	logRedistVariantDrop16864(policy, proto, ctx, dropped, denyAlls)
	if n := config.RouteMapSequenceCount(vpo, filtered); n > config.MaxRouteMapSequences {
		slog.Warn("oversized redistribute route-map variant: expansion would overflow FRR sequence numbers; rendering an explicit deny instead (#16864)",
			"policy", policy, "protocol", proto, "variant", ctx.variant, "sequences", n, "max", config.MaxRouteMapSequences)
		m.noteQuarantined(routeMap)
		return renderQuarantineDenyRouteMap(routeMap) + "!\n"
	}
	body := m.renderRouteMapForPolicyWithFallback(
		vpo, routeMap, filtered, policyTrailingAction(policy, filtered, nil), "deny", false)
	if clusterMode && proto == "static" {
		body = clusterTagDeny15158(routeMap) + body
	}
	return body + "!\n"
}

// redistVariantMapCollision16864 refuses (fail-closed) a variant map
// name that collides with an operator policy-statement or another
// generated variant — FRR merges same-named route-maps. It mirrors
// redistProtocolMapCollisionFiltered over the referenced-node
// variant names generatePolicyOptions actually emits.
func redistVariantMapCollision16864(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	po := fc.PolicyOptions
	nodesByPolicy := redistReferencedNodes14380(fc)
	names := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	operatorNames := make(map[string]string, len(names))
	for _, name := range names {
		normalized := frrName(name)
		if _, exists := operatorNames[normalized]; !exists {
			operatorNames[normalized] = name
		}
	}
	generated := make(map[string]string)
	for _, policy := range names {
		ctxs := redistVariantsForNodes16864(nodesByPolicy[policy])
		if len(ctxs) == 0 {
			continue
		}
		for _, proto := range redistReferencedProtocols14380(po.PolicyStatements[policy], nodesByPolicy[policy]) {
			for _, ctx := range ctxs {
				if !redistProtoFitsVariant16864(proto, ctx) {
					continue
				}
				routeMap := redistVariantRouteMapName16864(policy, proto, ctx)
				final := frrName(routeMap)
				if operator, ok := operatorNames[final]; ok {
					return fmt.Errorf(
						"policy-statement %q generates redistribute route-map %q, which collides with operator policy-statement %q; FRR merges same-named route-maps — refusing to render (#16864)",
						policy, routeMap, operator)
				}
				identity := policy + "\x00" + proto + "\x00" + ctx.variant
				if previous, ok := generated[final]; ok && previous != identity {
					return fmt.Errorf(
						"policy-statements generate the same redistribute route-map %q (%q vs %q); FRR merges same-named route-maps — refusing to render (#16864)",
						final, previous, identity)
				}
				generated[final] = identity
			}
		}
	}
	return nil
}
