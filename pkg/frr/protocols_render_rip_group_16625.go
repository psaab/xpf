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
//     accepted set. Interfaces enrolled only globally (no group)
//     get NO binding: they receive the union, which is the only
//     expressible reading of a global neighbor under a grouped
//     config (Junos: put the interface in a group for isolation).
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
	sort.Slice(order, func(i, j int) bool { return order[i].ifaces[0] < order[j].ifaces[0] })
	out := make([]ripChainGroup16625, 0, len(order))
	for _, cg := range order {
		out = append(out, *cg)
	}
	return out
}

func ripGroupListName16625(instanceIdx, chainIdx int, v6 bool) string {
	if v6 {
		return fmt.Sprintf("xpf-rip-%d-grp-%d-v6", instanceIdx, chainIdx)
	}
	return fmt.Sprintf("xpf-rip-%d-grp-%d", instanceIdx, chainIdx)
}

func (m *Manager) nextRIPGroupIndex16625() int {
	idx := m.ripGroupIdx16625
	m.ripGroupIdx16625++
	return idx
}

// renderRIPPerGroup16625 renders prefix-list definitions (to be
// emitted BEFORE `router rip`, at top level) plus the router-rip
// body lines (union redistribution + distribute-list bindings).
// Empty-export groups are skipped (no boundary authored).
func (m *Manager) renderRIPPerGroup16625(rip *config.RIPConfig, enrolled []string, policyOptions *config.PolicyOptionsConfig, clusterMode bool, qnhMetrics *qnhMetricScope11447, instanceIdx int) (defs string, body string) {
	var db, bb strings.Builder
	bb.WriteString(m.resolveRedistributeChainCluster15158(rip.Redistribute, policyOptions, "rip", clusterMode, qnhMetricScopeForDaemon11447(qnhMetrics, "rip")))
	chains := ripGroupChains16625(rip, enrolled)
	for idx, cg := range chains {
		if len(cg.chain) == 0 {
			continue
		}
		v4, v6, ok := ripGroupAcceptedPrefixes16625(cg.chain, policyOptions)
		if !ok {
			slog.Warn("frr: rip group export is not expressible as a per-interface prefix filter (bare protocol token or non-prefix accept condition); advertising NOTHING on those interfaces rather than leaking the union (#16625)",
				"chain", cg.chain, "interfaces", cg.ifaces)
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
		// and any token is bare — inexpressible unless the chain
		// is empty (accepts nothing via redistribute; the
		// interface still gets connected/direct routes, which
		// distribute-list also gates — an empty chain means the
		// group exports nothing redistributed, but Junos RIP
		// still advertises direct routes. A deny-all list would
		// withdraw those too. Empty chain = no export statement:
		// Junos default is to advertise direct + RIP-learned
		// only, which the prefix-list cannot express either.
		// Fail closed is WRONG here (it withdraws direct
		// routes the operator never restricted). Signal
		// inexpressible; caller warns + deny-all. This matches
		// the issue's fail-closed direction for an authored
		// export that cannot be honoured; a group with NO
		// export has no boundary to leak, handled by caller
		// skipping empty chains before calling here.
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
	for _, name := range chain {
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
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			if len(term.UnknownFrom) > 0 || len(term.UnknownTo) > 0 || len(term.UnknownThen) > 0 {
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
			// more than the prefix.
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
			// Collect this term's prefix entries.
			var termEntries []entry
			for _, plName := range term.PrefixList {
				pl, found := po.PrefixLists[plName]
				if !found || pl == nil {
					if isAccept {
						return nil, nil, false
					}
					return nil, nil, false
				}
				for _, p := range pl.Prefixes {
					termEntries = append(termEntries, entry{p, strings.Contains(p, ":")})
				}
			}
			for _, rf := range term.RouteFilters {
				if rf == nil {
					continue
				}
				text, is6, rendered := ripRouteFilterEntryText16625(rf)
				if !rendered {
					if isAccept {
						return nil, nil, false
					}
					return nil, nil, false
				}
				termEntries = append(termEntries, entry{text, is6})
			}
			if len(termEntries) == 0 {
				// Terminal term matching EVERYTHING.
				if isAccept {
					return nil, nil, false
				}
				// Reject-all: truncates the chain. Entries so
				// far stand; nothing later can accept (first
				// terminal wins and this matches all). Done.
				return ripSplitEntries16625(entries)
			}
			for _, e := range termEntries {
				if isAccept {
					add(e.text, e.v6)
				}
				// Reject entries: prefixes rejected here must
				// NOT be added by later accepts for the SAME
				// exact entry text. Track denied texts so a
				// later identical accept entry is suppressed.
				// (Overlapping-but-not-identical ranges are
				// ordered correctly by FRR first-match only if
				// we emit deny entries too — we do, below.)
				if isReject {
					add("deny\x00"+e.text, e.v6)
				}
			}
		}
		// Statement default action.
		if ps.DefaultAction == "accept" {
			return nil, nil, false
		}
		// reject / implicit reject: chain continues to next
		// policy (next-policy semantics for redistribution
		// chains: a policy that does not accept falls through
		// to the next policy in the export chain).
	}
	return ripSplitEntries16625(entries)
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
			return "", is6, false
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
