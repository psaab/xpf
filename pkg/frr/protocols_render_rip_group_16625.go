package frr

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #16625 (R3-A12-03): per-group RIP export rendering.
//
// ripd evaluates, for each outbound interface, the redistribution
// route-maps to build the candidate set, then applies
// `distribute-list prefix <list> out <if>` as a final prefix gate.
// A prefix-list cannot express source-protocol or policy-term
// conditions, so per-group filtering is rendered as:
//
//  1. The UNION of every enrolled group's export chain is
//     redistributed once (router-global), exactly as the legacy
//     path did for Redistribute — this builds the superset
//     candidate pool with full policy fidelity (route-maps,
//     composed chains #15156, cluster guards #15158).
//  2. For each distinct export chain among enrolled groups, the
//     set of prefixes that chain ACCEPTS is computed
//     (ripGroupAcceptedPrefixes16625) and rendered as
//     ip/ipv6 prefix-lists at top level.
//  3. Each group interface gets distribute-list bindings for
//     both families, confining the union pool to its group's
//     accepted set.
//
// #16866 (R3-B07-03) extends the gate to every enrolled
// interface and to ripd's native candidates: `network <if>`
// originates connected subnets and re-advertises RIP-learned
// routes, which Junos advertises only through an export policy.
// Interfaces with no export boundary (no group, empty group
// export, or a group-less render) carry the empty chain and
// render deny-all. `redistribute rip` is never rendered
// (FRR-invalid self-source); connected enrols only through
// the ordinary composed redistribution chain, and the prefix
// gate confines every candidate per interface.
//
// Fail closed, never leak: a chain that is not expressible as
// finite prefix sets (bare protocol token such as `static`, or
// an accepting term that is not purely prefix-matched, or an
// undefined policy on the tolerant path) renders a DENY-ALL
// list for its interfaces plus a loud warning. A missing or
// empty FRR prefix-list can mean permit-all, so deny-all is an
// explicit `deny 0.0.0.0/0 le 32` / `deny ::/0 le 128` entry and
// every generated list carries at least that entry when its
// permit set is empty.
//
// Naming is per-RIP-instance-index: renderRIP16125 does not know
// whether it renders the global instance or which VRF, so the
// caller (generateProtocols) stamps a unique index onto each
// RIPConfig render via the manager field ripGroupIndex16625 —
// see protocols_render.go. Both the definition site (inside
// renderRIP16125, before `router rip`) and the binding site use
// the same index, so they cannot disagree.

type ripChainGroup16625 struct {
	chain  []string
	ifaces []string
}

// ripGroupChains16625 groups enrolled interfaces by distinct
// export chain (order-preserved, deduped), sorted by first
// interface for determinism.
//
// #16866: interfaces with NO export boundary are grouped too,
// under the empty chain, which renders deny-all: enrolled but
// in no group (grouped config), or in a group with no export.
// Junos advertises nothing to a neighbor without an export
// policy, so an empty chain is a real boundary, not the absence
// of one. Only enrolled interfaces are considered — contested
// interfaces were already withheld by the caller.
func ripGroupChains16625(rip *config.RIPConfig, enrolled []string) []ripChainGroup16625 {
	enrolledSet := make(map[string]bool, len(enrolled))
	for _, iface := range enrolled {
		enrolledSet[iface] = true
	}
	byKey := make(map[string]*ripChainGroup16625)
	var order []*ripChainGroup16625
	for _, g := range rip.Groups {
		if g == nil {
			continue
		}
		var ifaces []string
		seenIface := make(map[string]bool)
		for _, iface := range g.Interfaces {
			if enrolledSet[iface] && !seenIface[iface] {
				seenIface[iface] = true
				ifaces = append(ifaces, iface)
			}
		}
		if len(ifaces) == 0 {
			continue
		}
		key := config.RIPGroupExportKey16625(g.Export)
		cg, ok := byKey[key]
		if !ok {
			seen := make(map[string]bool)
			var chain []string
			for _, e := range g.Export {
				if e != "" && !seen[e] {
					seen[e] = true
					chain = append(chain, e)
				}
			}
			cg = &ripChainGroup16625{chain: chain}
			byKey[key] = cg
			order = append(order, cg)
		}
		cg.ifaces = append(cg.ifaces, ifaces...)
	}
	// #16866: enrolled interfaces claimed by no group carry the
	// empty (deny-all) chain.
	claimed := make(map[string]bool)
	for _, cg := range order {
		for _, iface := range cg.ifaces {
			claimed[iface] = true
		}
	}
	var unclaimed []string
	for _, iface := range enrolled {
		if !claimed[iface] {
			unclaimed = append(unclaimed, iface)
		}
	}
	if len(unclaimed) > 0 {
		key := config.RIPGroupExportKey16625(nil)
		cg, ok := byKey[key]
		if !ok {
			cg = &ripChainGroup16625{}
			byKey[key] = cg
			order = append(order, cg)
		}
		cg.ifaces = append(cg.ifaces, unclaimed...)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].ifaces[0] < order[j].ifaces[0] })
	out := make([]ripChainGroup16625, 0, len(order))
	for _, cg := range order {
		out = append(out, *cg)
	}
	return out
}

func ripGroupListName16625(instanceIdx, chainIdx int, v6 bool) string {
	if v6 {
		return fmt.Sprintf("%s%d-grp-%d-v6", config.ReservedRIPGatePrefix, instanceIdx, chainIdx)
	}
	return fmt.Sprintf("%s%d-grp-%d", config.ReservedRIPGatePrefix, instanceIdx, chainIdx)
}

func (m *Manager) nextRIPGroupIndex16625() int {
	idx := m.ripGroupIdx16625
	m.ripGroupIdx16625++
	return idx
}

// renderRIPPerGroup16625 renders prefix-list definitions (to be
// emitted BEFORE `router rip`, at top level) plus the router-rip
// body lines (union redistribution + distribute-list bindings).
//
// #16866: EVERY enrolled interface gets a binding. The empty
// chain (no group, or a group with no export) renders deny-all —
// Junos advertises nothing without an export policy, while
// ripd's `network` otherwise originates connected subnets and
// re-advertises RIP-learned routes ungated.
//
// Native candidates: ripd cannot `redistribute rip` (FRR
// 10.7.1 rejects the self-source, exit 2 — verified), and
// interface routes skip redistribute route-maps, so connected /
// RIP-learned candidates are enforced ONLY by the per-interface
// prefix gate. That gate is exact only for the policy shapes
// ripGroupAcceptedPrefixes16625 admits; everything else renders
// deny-all (fail closed, no leak of native routes). Connected
// enrolment itself comes from the ordinary union chain above
// (resolveRedistributeChainCluster15158 on rip.Redistribute).
// #17688: grouped redistribution is the UNION of independently
// evaluated group export chains, not a single ordered chain. The
// compiler also preserves top-level exports separately so their
// legacy chain remains independent from group exports. With no
// groups, Redistribute keeps its existing ordered-chain semantics.
func (m *Manager) renderRIPGroupPool17688(rip *config.RIPConfig, po *config.PolicyOptionsConfig, clusterMode bool, metrics *qnhMetricScope11447) string {
	if len(rip.Groups) == 0 {
		return m.resolveRedistributeChainCluster15158(rip.Redistribute, po, "rip", clusterMode, qnhMetricScopeForDaemon11447(metrics, "rip"))
	}
	pool := m.ripGroupPool17688(rip, po, qnhMetricScopeForDaemon11447(metrics, "rip"))
	for i := range pool.entries {
		pool.entries[i].clusterMode = clusterMode
	}
	return formatRedistEntries(pool.entries)
}

func (m *Manager) renderRIPPerGroup16625(rip *config.RIPConfig, enrolled []string, policyOptions *config.PolicyOptionsConfig, clusterMode bool, qnhMetrics *qnhMetricScope11447, instanceIdx int) (defs string, body string) {
	var db, bb strings.Builder
	bb.WriteString(m.renderRIPGroupPool17688(rip, policyOptions, clusterMode, qnhMetrics))
	chains := ripGroupChains16625(rip, enrolled)
	for idx, cg := range chains {
		var v4, v6 []string
		if len(cg.chain) > 0 {
			var ok bool
			v4, v6, ok = ripGroupAcceptedPrefixes16625(cg.chain, policyOptions)
			if !ok {
				slog.Warn("frr: rip group export is not expressible as a per-interface prefix filter (bare protocol token or non-prefix accept condition); advertising NOTHING on those interfaces rather than leaking the union (#16625)",
					"chain", cg.chain, "interfaces", cg.ifaces)
			}
		}
		name4 := ripGroupListName16625(instanceIdx, idx, false)
		name6 := ripGroupListName16625(instanceIdx, idx, true)
		writeRIPGroupPrefixList16625(&db, name4, false, v4)
		writeRIPGroupPrefixList16625(&db, name6, true, v6)
		for _, iface := range cg.ifaces {
			// router rip is IPv4-only (RIPng is separate); only
			// the v4 list binds here. The v6 definition is
			// retained harmlessly for symmetry/future RIPng.
			fmt.Fprintf(&bb, " distribute-list prefix %s out %s\n", name4, iface)
		}
	}
	if db.Len() > 0 {
		db.WriteString("!\n")
	}
	return db.String(), bb.String()
}

func writeRIPGroupPrefixList16625(b *strings.Builder, name string, v6 bool, prefixes []string) {
	kind := "ip"
	denyAll := "0.0.0.0/0 le 32"
	if v6 {
		kind = "ipv6"
		denyAll = "::/0 le 128"
	}
	if len(prefixes) == 0 {
		fmt.Fprintf(b, "%s prefix-list %s seq 5 deny %s\n", kind, name, denyAll)
		return
	}
	for i, p := range prefixes {
		action := "permit"
		if strings.HasPrefix(p, "deny\x00") {
			action = "deny"
			p = strings.TrimPrefix(p, "deny\x00")
		}
		fmt.Fprintf(b, "%s prefix-list %s seq %d %s %s\n", kind, name, (i+1)*5, action, p)
	}
}

// ripGroupAcceptedPrefixes16625 computes the v4/v6 FRR
// prefix-list entry strings (e.g. "192.168.50.0/24",
// "10.0.0.0/8 le 32") a redistribution export chain accepts.
// ok=false when inexpressible (see file header).
//
// Chain semantics (first terminal action wins, #5277/#15156):
// policies evaluate in chain order; within a policy, terms in
// order. A prefix is accepted iff the first matching terminal
// term is accept. We compute this symbolically over the union of
// all route-filter / prefix-list entries mentioned by accepting
// and rejecting terms, in evaluation order: earlier entries
// claim their prefix space; later entries only add space not
// already claimed. Overlapping entries with ge/le qualifiers
// make exact set subtraction inexpressible in one prefix-list —
// but a prefix-list is itself an ordered first-match list, so
// we emit entries in evaluation order with permit/deny actions
// mirroring the terms, and let FRR's own first-match semantics
// reproduce the policy decision for the redistribute pool. The
// pool only contains prefixes the union chain accepted, so a
// deny entry here can only remove leaked union prefixes — the
// desired confinement.
func ripGroupAcceptedPrefixes16625(chain []string, po *config.PolicyOptionsConfig) (v4 []string, v6 []string, ok bool) {
	if po == nil {
		// No policy-options at all: any policy name is undefined
		// and any token is bare — inexpressible. The caller
		// renders deny-all (#16866): Junos advertises nothing
		// (no connected subnet, no RIP-learned route) without
		// an export policy that accepts it, so deny-all is the
		// faithful render, not a loss.
		return nil, nil, false
	}
	type entry = struct {
		text string
		v6   bool
	}
	var entries []entry
	seenText := make(map[string]bool)
	add := func(text string, is6 bool) {
		if seenText[text] {
			return
		}
		seenText[text] = true
		entries = append(entries, entry{text, is6})
	}
	hasLaterAccept := func(policyIdx, termIdx int, boundary string) bool {
		boundaryBase, boundaryLen := parseRouteFilterPrefix16762(strings.TrimPrefix(boundary, "boundary\x00"))
		if boundaryBase == nil {
			// The boundary came from a validated route-filter, so this
			// is unreachable. If its host cannot be parsed, stay closed.
			return true
		}
		termCanMatchBoundary := func(term *config.PolicyTerm) bool {
			if term == nil {
				return false
			}
			if len(term.PrefixList) > 0 && len(term.RouteFilters) > 0 {
				return true
			}
			if len(term.PrefixList) > 0 {
				for _, name := range term.PrefixList {
					pl, found := po.PrefixLists[name]
					if !found || pl == nil {
						return true
					}
					for _, prefix := range pl.Prefixes {
						normalized, ok := config.NormalizePrefixListEntry(prefix)
						if !ok {
							return true
						}
						base, _ := parseRouteFilterPrefix16762(normalized)
						if sameRouteFilterBase16762(base, boundaryBase) {
							return true
						}
					}
				}
				return false
			}
			if len(term.RouteFilters) == 0 {
				// No destination match means the term can match any
				// route, including this host.
				return true
			}
			mostSpecificBaseLen := -1
			matchesMostSpecific := false
			for _, rf := range term.RouteFilters {
				if rf == nil {
					continue
				}
				base, baseLen := parseRouteFilterPrefix16762(rf.Prefix)
				if base == nil {
					return true
				}
				if !routeFilterContains16762(base, boundaryBase.IP, boundaryLen) || baseLen < mostSpecificBaseLen {
					continue
				}
				matches := false
				switch rf.MatchType {
				case "exact":
					matches = sameRouteFilterBase16762(base, boundaryBase)
				case "", "orlonger":
					matches = true
				case "longer":
					matches = baseLen < boundaryLen
				case "upto":
					matches = baseLen <= boundaryLen && rf.UptoLen >= boundaryLen
				case "prefix-length-range":
					matches = rf.RangeLow > baseLen && rf.RangeLow <= boundaryLen && rf.RangeHigh >= boundaryLen
				default:
					// An unsupported shape may still match the host;
					// do not weaken the existing fail-closed behavior.
					return true
				}
				if baseLen > mostSpecificBaseLen {
					mostSpecificBaseLen = baseLen
					matchesMostSpecific = matches
				} else if matches {
					matchesMostSpecific = true
				}
			}
			return matchesMostSpecific
		}
		for i := policyIdx; i < len(chain); i++ {
			later, defined := po.PolicyStatements[chain[i]]
			if !defined || later == nil {
				continue
			}
			start := 0
			if i == policyIdx {
				start = termIdx + 1
			}
			for _, laterTerm := range later.Terms[start:] {
				if laterTerm != nil && (laterTerm.Action == "accept" || laterTerm.NextPolicy) && termCanMatchBoundary(laterTerm) {
					return true
				}
			}
			if later.DefaultAction == "accept" {
				return true
			}
			if later.DefaultAction == "reject" {
				// Explicit reject default terminates the chain
				// (same rule as the statement default below):
				// policies after this one are unreachable, so
				// their accepts cannot override the boundary.
				return false
			}
		}
		return false
	}
	for chainIdx, name := range chain {
		if name == "" {
			continue
		}
		ps, defined := po.PolicyStatements[name]
		if !defined || ps == nil {
			// Bare protocol token (static/connected/...) or an
			// undefined policy (tolerant path): the accepted set
			// is a whole protocol table — inexpressible.
			return nil, nil, false
		}
		if len(ps.UnknownFrom) > 0 || len(ps.UnknownTo) > 0 {
			return nil, nil, false
		}
		// Explicit statement-level reject terminates the chain
		// (#16866 re-review F1): later policies are unreachable
		// for candidates this statement rejects, so the chain
		// must stop here. The composed route-map renderer emits
		// a terminating deny for the same shape
		// (redistribute.go renderRedistComposedMapVariant16864).
		// A `next policy` term anywhere in the statement makes
		// the default unreachable for matched candidates, in
		// which case fall-through is correct.
		for termIdx, term := range ps.Terms {
			if term == nil {
				continue
			}
			if len(term.UnknownFrom) > 0 || len(term.UnknownTo) > 0 || len(term.UnknownThen) > 0 {
				return nil, nil, false
			}
			if term.NextPolicy {
				// `then next policy` (F2, gate2 B1): matched
				// candidates skip the remaining terms and this
				// statement's default. A destination-only list
				// cannot decide whether the jump fires for a
				// native candidate: no prefix entries means
				// match-ALL (no from) or a source-only subset —
				// both fire for some candidate class — and an
				// empty prefix-list's Junos match semantics are
				// unproven. `len(entries)==0` therefore proves
				// nothing. ANY NextPolicy term makes the chain
				// inexpressible here: fail closed.
				return nil, nil, false
			}
			isAccept := term.Action == "accept"
			isReject := term.Action == "reject"
			if !isAccept && !isReject {
				// Non-terminal term (e.g. only sets metric):
				// it can fall through. If it has prefix matches
				// its prefixes are decided by later terms; if it
				// has NO matches at all it matches everything and
				// falls through — still decidable later. Skip:
				// only terminal terms decide.
				continue
			}
			// Non-prefix conditions make matching depend on
			// more than the prefix. A prefix-list decides by
			// destination alone, so it cannot reproduce
			// source-protocol, community, as-path or next-hop
			// predicates for ripd's NATIVE candidates: interface
			// routes skip redistribute route-maps entirely
			// (FRR 10.7.1 ripd excludes RIP_ROUTE_INTERFACE) and
			// RIP-learned routes have no `redistribute rip` verb
			// to carry one. Permitting a static-only term's
			// prefixes here would leak connected/RIP routes in
			// the same range (#16866 F2). Fail closed.
			if len(term.FromProtocols) > 0 || len(term.FromCommunity) > 0 || len(term.FromASPath) > 0 || term.NextHop != "" {
				if isAccept {
					return nil, nil, false
				}
				// A reject with extra conditions rejects a
				// SUBSET of its prefix set; emitting a deny for
				// the full prefix set would over-deny (loss, not
				// leak). Conservative: inexpressible.
				return nil, nil, false
			}
			// Collect this term's prefix entries with Junos
			// longest-match lowering for its route-filters
			// (F3): overlapping filters in one term decide by
			// longest containing base, not by walkup/OR.
			termEntries, termOK := ripTermEntries16625(term, po)
			if !termOK {
				return nil, nil, false
			}
			if len(termEntries) == 0 {
				// Terminal term matching EVERYTHING.
				if isAccept {
					// A match-all accept is exactly representable:
					// retain prior terminal denies/permits, then
					// permit the rest of each address family.
					add("0.0.0.0/0 le 32", false)
					add("::/0 le 128", true)
					return ripSplitEntries16625(entries)
				}
				// Reject-all: truncates the chain. Entries so
				// far stand; nothing later can accept (first
				// terminal wins and this matches all). Done.
				return ripSplitEntries16625(entries)
			}
			for _, e := range termEntries {
				// This marker means the term has no matching route:
				// continue evaluating the policy chain.
				if strings.HasPrefix(e.text, "nomatch\x00") {
					continue
				}
				// An empty max-length `longer` boundary is a
				// representable exact-host exclusion from a
				// sibling broader permit in this accept term.
				// Keep it as a deny before that permit; other
				// longest-match stops still require term fallthrough
				// that this destination-only list cannot express.
				if strings.HasPrefix(e.text, "boundary\x00") {
					if !isAccept || hasLaterAccept(chainIdx, termIdx, e.text) {
						return nil, nil, false
					}
					add("deny\x00"+strings.TrimPrefix(e.text, "boundary\x00"), e.v6)
					continue
				}
				// Entries arrive pre-tagged: "deny\x00" marks a
				// longest-match stop or a reject term's set.
				if isAccept && !strings.HasPrefix(e.text, "deny\x00") {
					add(e.text, e.v6)
					continue
				}
				if isAccept {
					// Longest-match stop inside an accept term
					// (gate2 R2): candidates under it fail THIS
					// term and continue to LATER terms/policies,
					// which may accept them. A single ordered
					// list cannot express "term no-match, keep
					// evaluating" — promoting the stop to a
					// chain deny over-denies later accepts, and
					// omitting it over-permits. Inexpressible:
					// fail closed for the whole chain.
					return nil, nil, false
				}
				if isReject && strings.HasPrefix(e.text, "deny\x00") {
					// A rejecting term's longest-match stop is
					// inexpressible (gate3 Astra R2): a
					// candidate failing the longest match does
					// NOT match this term at all and must fall
					// through to later terms — copying the stop
					// into the chain deny over-denies them.
					// Only stop-tagged entries trigger this;
					// plain reject entries fall through to the
					// deny emission below.
					return nil, nil, false
				}
				if isReject {
					add("deny\x00"+e.text, e.v6)
				}
			}
		}
		// Statement default action.
		if ps.DefaultAction == "accept" {
			add("0.0.0.0/0 le 32", false)
			add("::/0 le 128", true)
			return ripSplitEntries16625(entries)
		}
		if ps.DefaultAction == "reject" {
			// F1: explicit reject terminates the chain —
			// entries so far stand, later policies never run.
			// No next-policy carve-out (gate2 B2): any
			// NextPolicy term already failed the chain closed
			// above, so no live jump can suppress termination.
			break
		}
		// Implicit reject (no statement default): the chain
		// continues to the next policy (a policy that does not
		// accept falls through, #5277 chain semantics).
	}
	return ripSplitEntries16625(entries)
}

// ripTermEntries16625 collects one terminal term's prefix
// entries (prefix-list refs expanded, route-filters lowered),
// ok=false when the term is inexpressible at a destination-only
// gate. Junos ANDs distinct `from` types in one term (the
// route-map renderer keeps them as separate ANDed matches,
// policy_render.go from-prefix-list arm), so a term carrying
// BOTH prefix-list refs and route-filters cannot be lowered to
// one union list — inexpressible, fail closed (gate3 B1).
// Prefix-list entries are normalised through
// config.NormalizePrefixListEntry + sanitizeFRRValue exactly
// like the canonical renderer (policy_render.go): a malformed
// entry would otherwise break the whole vtysh reload (exit 2)
// and a newline-bearing entry would inject frr.conf lines
// (gate3 B2, #10823/#4482). Any unrenderable entry fails the
// term closed. Route-filters of one term are lowered with
// Junos longest-match semantics (#16762): permits sort by
// descending base length, and after each distinct base that a
// broader renderable filter contains, a deny stop is emitted.
// Ordinary stops are pre-tagged "deny\x00"; empty max-length
// `longer` boundaries use a distinct marker so an accepting
// sibling broader permit can retain a bare exact-host exclusion.
func ripTermEntries16625(term *config.PolicyTerm, po *config.PolicyOptionsConfig) (entries []struct {
	text string
	v6   bool
}, ok bool) {
	type entry = struct {
		text string
		v6   bool
	}
	if len(term.PrefixList) > 0 && len(term.RouteFilters) > 0 {
		return nil, false
	}
	for _, plName := range term.PrefixList {
		pl, found := po.PrefixLists[plName]
		if !found || pl == nil {
			return nil, false
		}
		for _, p := range pl.Prefixes {
			normalized, normOK := config.NormalizePrefixListEntry(p)
			if !normOK {
				return nil, false
			}
			entries = append(entries, entry{sanitizeFRRValue(normalized), strings.Contains(normalized, ":")})
		}
	}
	// Route-filters: collect renderable permits with bases.
	type rfEntry struct {
		text  string
		base  string
		v6    bool
		ipnet *net.IPNet
		plen  int
	}
	var rfs []rfEntry
	emptyBoundary := false
	for _, rf := range term.RouteFilters {
		if rf == nil {
			continue
		}
		text, is6, rendered := ripRouteFilterEntryText16625(rf)
		if !rendered {
			return nil, false
		}
		if text == "" {
			emptyBoundary = true
		}
		ipnet, plen := parseRouteFilterPrefix16762(rf.Prefix)
		rfs = append(rfs, rfEntry{text: text, base: rf.Prefix, v6: is6, ipnet: ipnet, plen: plen})
	}
	// Longest-match order: descending base length, stable.
	sort.SliceStable(rfs, func(i, j int) bool { return rfs[i].plen > rfs[j].plen })
	for i, e := range rfs {
		if e.text != "" {
			entries = append(entries, entry{e.text, e.v6})
		}
		if e.ipnet == nil || e.plen <= 0 {
			continue
		}
		// Stop needed only when a BROADER renderable filter
		// could otherwise catch a failed candidate.
		canStillMatch := false
		for _, o := range rfs {
			if o.text == "" {
				continue
			}
			if o.ipnet == nil {
				canStillMatch = true
				break
			}
			if routeFilterBaseContains16762(o.ipnet, e.ipnet) {
				canStillMatch = true
				break
			}
		}
		if !canStillMatch {
			continue
		}
		lastOfBase := true
		for j := i + 1; j < len(rfs); j++ {
			if rfs[j].ipnet != nil && sameRouteFilterBase16762(e.ipnet, rfs[j].ipnet) {
				lastOfBase = false
				break
			}
		}
		if !lastOfBase {
			continue
		}
		maxLen := 32
		if e.v6 {
			maxLen = 128
		}
		// The stop body names the BASE prefix (authored text
		// before any ge/le), mirroring #16762's layout.
		if e.plen == maxLen {
			// A bare deny is exactly the host prefix and avoids
			// FRR-invalid `le` equal to the base length.
			stopPrefix := "deny\x00"
			if e.text == "" {
				// Unlike a normal longest-match stop, this empty
				// boundary can be represented as an exact host
				// exclusion before its sibling broader permit.
				stopPrefix = "boundary\x00"
			}
			entries = append(entries, entry{stopPrefix + sanitizeFRRValue(e.base), e.v6})
		} else {
			entries = append(entries, entry{"deny\x00" + fmt.Sprintf("%s le %d", sanitizeFRRValue(e.base), maxLen), e.v6})
		}
	}
	if len(entries) == 0 && emptyBoundary {
		// A lone valid empty boundary matches no route; preserve that
		// fact so the caller can continue to a later policy term.
		entries = append(entries, entry{"nomatch\x00", false})
	}
	return entries, true
}

func ripSplitEntries16625(entries []struct {
	text string
	v6   bool
}) (v4 []string, v6 []string, ok bool) {
	// Rebuild permit/deny ordered lists per family, suppressing
	// a permit whose exact text was denied earlier, and render
	// denies as deny entries placed before permits so FRR
	// first-match reproduces the decision order.
	denied := make(map[string]bool)
	type oe struct {
		text string
		deny bool
		v6   bool
	}
	var ordered []oe
	for _, e := range entries {
		if strings.HasPrefix(e.text, "deny\x00") {
			t := strings.TrimPrefix(e.text, "deny\x00")
			denied[t] = true
			ordered = append(ordered, oe{t, true, e.v6})
		} else {
			if denied[e.text] {
				continue
			}
			ordered = append(ordered, oe{e.text, false, e.v6})
		}
	}
	// Render per family preserving order: permits and denies
	// interleaved by sequence. The caller writes seq by index
	// per family, so return strings prefixed with action.
	for _, o := range ordered {
		s := o.text
		if o.deny {
			s = "deny\x00" + s
		}
		if o.v6 {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	return v4, v6, true
}

// ripRouteFilterEntryText16625 renders one RouteFilter as an
// FRR prefix-list entry body ("10.0.0.0/8", "10.0.0.0/8 le 32",
// "10.0.0.0/8 ge 25 le 32"). rendered=false mirrors the
// match-nothing skips in renderRouteFilterEntry.
func ripRouteFilterEntryText16625(rf *config.RouteFilter) (string, bool, bool) {
	is6 := strings.Contains(rf.Prefix, ":")
	if _, _, err := net.ParseCIDR(rf.Prefix); err != nil {
		return "", is6, false
	}
	maxLen := 32
	if is6 {
		maxLen = 128
	}
	_, ipnet, _ := net.ParseCIDR(rf.Prefix)
	baseLen, _ := ipnet.Mask.Size()
	switch rf.MatchType {
	case "exact":
		return rf.Prefix, is6, true
	case "orlonger", "":
		// "" (unset) is rendered by the existing renderer as
		// orlonger (default le max).
		return fmt.Sprintf("%s le %d", rf.Prefix, maxLen), is6, true
	case "longer":
		if baseLen+1 > maxLen {
			// A max-length `longer` is a valid empty set, but its
			// base remains a longest-match boundary. The caller
			// emits a bare exact-host deny only if a broader permit
			// could otherwise accept that host route.
			return "", is6, true
		}
		return fmt.Sprintf("%s ge %d le %d", rf.Prefix, baseLen+1, maxLen), is6, true
	case "upto":
		if rf.UptoLen <= baseLen || rf.UptoLen > maxLen {
			// Mirrors renderRouteFilterEntry guards: invalid
			// upto renders match-nothing there.
			if baseLen >= maxLen {
				return "", is6, false
			}
			return "", is6, false
		}
		return fmt.Sprintf("%s le %d", rf.Prefix, rf.UptoLen), is6, true
	case "prefix-length-range":
		if rf.RangeLow > baseLen && rf.RangeLow <= rf.RangeHigh && rf.RangeHigh <= maxLen {
			return fmt.Sprintf("%s ge %d le %d", rf.Prefix, rf.RangeLow, rf.RangeHigh), is6, true
		}
		return "", is6, false
	default:
		return "", is6, false
	}
}
