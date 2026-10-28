// prefix_list_render.go renders FRR `ip|ipv6 prefix-list` output for
// Junos route-filters and `from prefix-list` references.
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - renderRouteFilterEntry, renderFromPrefixListACL
//   - indexedRouteFilter, partitionRouteFiltersByFamily
//   - fromPrefixListRef, fromPrefixListRefs
package frr

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderRouteFilterEntry is the historical single-entry seam: it
// renders one route-filter's permit line into list plName at seq slot
// (idx+1)*5. It delegates to routeFilterDerivation16762.emit so the
// term-level layout (renderRouteFilterListGroup, #16762) renders the
// very same permit at longest-match sequence slots without a second
// derivation. Family selection (the namespace `ip` vs `ipv6`) is
// intrinsic to the prefix, so a single mixed-family route-filter slice
// can be rendered correctly by calling this per entry.
func renderRouteFilterEntry(b *strings.Builder, plName string, idx int, rf *config.RouteFilter) (emitted bool) {
	return routeFilterDerivation16762{isV6: strings.Contains(rf.Prefix, ":"), plName: plName}.emit(b, idx, rf)
}

// routeFilterDerivation16762 carries the destination (plName) and family
// (isV6) renderRouteFilterEntry formerly re-derived from its
// arguments, so emit can render a permit line at ANY sequence slot.
// The term-level layout (#16762) re-sequences entries after Junos'
// longest-match ordering instead of the original (idx+1)*5 slot, so
// emit takes the slot explicitly rather than reading a field.
type routeFilterDerivation16762 struct {
	isV6   bool
	plName string // empty for body-only derivations (routeFilterPermitLine)
}

// emit writes `ip|ipv6 prefix-list <plName> seq <(seq+1)*5> permit
// <entry>` for rf when plName is non-empty, else just the entry body
// (`permit <prefix>[ ge/le]` plus a trailing newline). It applies the
// per-match-type ge/le derivation and returns emitted=false, writing
// nothing, for the skip cases (a max-length `longer` empty set, a
// malformed prefix, an out-of-range `prefix-length-range`, or an
// unhandled match-type) - see the per-arm comments for the
// FRR-validity / fail-closed reasoning (#2072/#2103/#2105/#2525).
func (p routeFilterDerivation16762) emit(b *strings.Builder, seq int, rf *config.RouteFilter) (emitted bool) {
	matchStr := "le 32"
	if p.isV6 {
		matchStr = "le 128"
	}
	// skipEntry suppresses this route-filter's prefix-list line entirely
	// (match-nothing for this entry) rather than emitting an FRR-invalid
	// line. Set by the #2103 max-length "longer" guard and the #2105
	// malformed-prefix belt below.
	skipEntry := false
	// #2105/#5576 render-side belt-and-suspenders: a malformed prefix must
	// NEVER reach an FRR line. The commit-time key validator
	// (ValidateRouteFilterArgPositional) rejects these on the strict path
	// — including a match-type keyword mistakenly placed in the prefix
	// slot (`route-filter longer exact`, #5576) — but the lenient-on-load
	// path (Store.Load / SyncApply, #1960) can still feed a stored
	// pre-gate garbage prefix to the renderer. Use the SAME net.ParseCIDR
	// check as the commit validator so the belt's coverage matches it
	// exactly.
	if _, _, err := net.ParseCIDR(rf.Prefix); err != nil {
		skipEntry = true
	}
	switch rf.MatchType {
	case "exact":
		matchStr = ""
	case "longer":
		// longer = strictly more specific (the prefix itself EXCLUDED).
		// For a max-length prefix (/32 v4, /128 v6) there are no
		// more-specifics, so "longer" is the EMPTY set — skip the entry
		// rather than emit an FRR-invalid "ge plen+1 le maxLen" line
		// (e.g. "ge 33 le 32"). Mirrors the upto plen>=maxLen guard
		// (#2102) and closes #2103. Boundary: plen+1 > maxLen skips ONLY
		// plen==maxLen — /31 still emits "ge 32 le 32".
		parts := strings.SplitN(rf.Prefix, "/", 2)
		if len(parts) == 2 {
			if plen, err := strconv.Atoi(parts[1]); err == nil {
				maxLen := 32
				if p.isV6 {
					maxLen = 128
				}
				if plen+1 > maxLen {
					skipEntry = true
				} else {
					matchStr = fmt.Sprintf("ge %d le %d", plen+1, maxLen)
				}
			}
		}
	case "orlonger":
		// orlonger = this prefix or any more specific (default le 32/128)
	case "prefix-length-range":
		// prefix-length-range /low-/high = match any route whose prefix
		// length is in [low, high] and that falls under the base prefix.
		// FRR expresses a bounded length range directly as "ge low le
		// high" (#2525). validateRouteFilterMatchTypesStrict has already
		// rejected an inverted / out-of-range / at-or-below-base range on
		// the commit path; this arm is the lenient-path belt: it emits
		// "ge low le high" ONLY when the bounds are present and FRR-valid,
		// else skips (match-nothing, fail-closed) rather than fall through
		// to the open-ended "le maxLen" default (the #2525 bug). FRR
		// requires "len < ge-value", so RangeLow must be > baseLen.
		maxLen := 32
		if p.isV6 {
			maxLen = 128
		}
		baseLen := 0
		if _, ipnet, err := net.ParseCIDR(rf.Prefix); err == nil {
			baseLen, _ = ipnet.Mask.Size()
		}
		if rf.RangeLow > baseLen && rf.RangeLow <= rf.RangeHigh && rf.RangeHigh <= maxLen {
			matchStr = fmt.Sprintf("ge %d le %d", rf.RangeLow, rf.RangeHigh)
		} else {
			skipEntry = true
		}
	case "through":
		// through <prefix2> has no lossless FRR equivalent: Junos
		// "through" matches a two-prefix radix-tree containment path, not
		// a length range. validateRouteFilterMatchTypesStrict rejects it
		// at commit; only the tolerant load/peer-sync path can reach the
		// renderer with it. Skip (match-nothing, fail-closed) rather than
		// emit a wrong / open-ended line (#2525).
		skipEntry = true
	default:
		// Any match-type not handled above is rejected at the strict gate
		// for flat, hierarchical, compact, and term-line syntax (#12538).
		// A value that reaches the renderer via the tolerant path
		// MUST NOT fall through to an open-ended default; skip the entry
		// instead (match-nothing is fail-closed, #2525).
		skipEntry = true
	case "upto":
		// upto /N = this prefix or any more specific, but no longer than
		// /N. FRR renders this as a bare "le N". FRR requires len <
		// le-value, so this arm computes matchStr from scratch and never
		// keeps an invalid value — including the inherited default le
		// 32/128, which is itself invalid when plen == maxLen (#2102, the
		// /32 upto /31 case). See the original generatePolicyOptions
		// comment block for the full rule table (#2072).
		parts := strings.SplitN(rf.Prefix, "/", 2)
		if len(parts) == 2 {
			if plen, err := strconv.Atoi(parts[1]); err == nil {
				maxLen := 32
				if strings.Contains(rf.Prefix, ":") {
					maxLen = 128
				}
				switch {
				case rf.UptoLen <= 0:
					if plen >= maxLen {
						matchStr = ""
					} else {
						matchStr = fmt.Sprintf("le %d", maxLen)
					}
				case plen >= maxLen:
					matchStr = ""
				case rf.UptoLen == plen:
					matchStr = ""
				case rf.UptoLen > plen && rf.UptoLen <= maxLen:
					matchStr = fmt.Sprintf("le %d", rf.UptoLen)
				default:
					// A nonsensical upto length — below the base prefix
					// (UptoLen < plen: an EMPTY length range) or above the
					// family max (UptoLen > maxLen) — has no valid Junos
					// meaning. The earlier #2072/#2102 code degraded this to
					// the open-ended "le maxLen", which silently WIDENS the
					// match to an orlonger-style permit of the base prefix and
					// every more-specific (#4484 L-12): fail-OPEN on a
					// route-filter that gates route accept/redistribute. Skip
					// the entry instead (match-nothing, fail-CLOSED), matching
					// the #2525 posture the sibling invalid match-types
					// (prefix-length-range / through / unknown) already use.
					// Skip emits no line — an FRR-legal seq gap, never the
					// invalid "le <plen" the #2102 degrade was avoiding — so
					// the frr-reload-brick concern does not apply.
					skipEntry = true
				}
			}
		}
	}
	if skipEntry {
		// #2103/#2105: emit no prefix-list line for this entry. Its seq
		// slot (seq+1)*5 is simply not used; gaps in seq are FRR-legal.
		return false
	}
	if p.plName != "" {
		if p.isV6 {
			fmt.Fprintf(b, "ipv6 prefix-list %s seq %d permit %s", frrName(p.plName), (seq+1)*5, sanitizeFRRValue(rf.Prefix))
		} else {
			fmt.Fprintf(b, "ip prefix-list %s seq %d permit %s", frrName(p.plName), (seq+1)*5, sanitizeFRRValue(rf.Prefix))
		}
	} else {
		fmt.Fprintf(b, "permit %s", sanitizeFRRValue(rf.Prefix))
	}
	if matchStr != "" {
		fmt.Fprintf(b, " %s", matchStr)
	}
	b.WriteString("\n")
	return true
}

// routeFilterPermitLine computes the FRR prefix-list permit line body
// (without the `ip|ipv6 prefix-list <name> seq <n>` header) for one
// route-filter of the given family, applying renderRouteFilterEntry's
// per-match-type ge/le derivation. emitted=false mirrors
// renderRouteFilterEntry's skip cases (see its comments). Computing the
// string up front — rather than writing straight into the builder as
// renderRouteFilterEntry does — lets the term-level layout in
// renderRouteFilterListGroup capture the permit for re-sequencing after
// Junos' longest-match ordering (#16762) without parsing rendered text.
func routeFilterPermitLine(isV6 bool, rf *config.RouteFilter) (string, bool) {
	var b strings.Builder
	d := routeFilterDerivation16762{isV6: isV6}
	if !d.emit(&b, 0, rf) {
		return "", false
	}
	return b.String(), true
}

// --- #16762: Junos longest-match layout for one term's route-filters ---
//
// Junos' default route-filter evaluation is a longest-match lookup over
// ALL of a term's route-filters: the most specific filter whose prefix
// contains the route decides — even when its match type then fails (the
// route does NOT fall through to a broader filter; only the opt-in
// `walkup` qualifier, which xpf does not model, changes that). FRR
// prefix-lists are ordered first-match, so authoring-order permits gave
// walkup/OR semantics instead (#16762). This layout restores
// longest-match: only groups with strict base containment need a new
// layout. For those groups, sort permits by descending base-prefix length
// (stable, so equal-length filters keep authoring order) and, after each
// distinct prefix P, interpose a deny covering P through the family
// maximum (`deny P le <max>`, or bare `deny P` when P is already /32 or
// /128 because `le max` on those bases is redundant: the bare deny is
// the same match set. FRR accepts `le == plen` under its
// `mask <= ge <= le` rule; omitting `le` here is brevity, not a validity
// requirement). The deny is emitted only when some other renderable
// filter's base CONTAINS P, i.e. only when a route under P that failed
// P's match type could otherwise fall through to that broader permit.
// The failed route then first-matches the deny and stops, exactly as
// Junos' failed longest match fails the term's route-filter condition.
// Disjoint bases cannot fall through to one another, so groups without
// strict containment preserve authored order and their historical
// sequence slots byte-for-byte. The family root never gets a stop (no
// broader filter can contain it). Single, disjoint, and same-base lists
// therefore retain their historical render.

// routeFilterLayoutEntry16762 is one renderable route-filter or a valid
// empty max-length `longer` boundary whose prefix still participates in
// longest-match selection.
type routeFilterLayoutEntry16762 struct {
	rf            *config.RouteFilter
	idx           int        // original term index, used by unchanged lists
	ipnet         *net.IPNet // parsed base prefix (nil when unparsable)
	plen          int        // base prefix length, -1 when unknown
	permit        string     // routeFilterPermitLine body, empty only for a boundary
	canStillMatch bool       // a broader/nil permit base could catch a failed match
}

// parseRouteFilterPrefix16762 parses a route-filter's base CIDR once.
// nil, -1 when unparsable — the permit derivation still renders valid
// prefixes, so callers that already hold a permit may rely on a parsed
// base, but same-prefix / containment helpers tolerate nil.
func parseRouteFilterPrefix16762(s string) (*net.IPNet, int) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, -1
	}
	plen, _ := ipnet.Mask.Size()
	return ipnet, plen
}

// sameRouteFilterBase16762 reports whether two prefixes share the same
// base network ADDRESS and prefix length (192.168.100.0/24 vs itself,
// not vs 192.168.100.128/25). netip mask-normalisation plus the plen
// comparison keeps host-bits variants (192.168.100.1/24 from a lenient
// load) in one class, matching FRR's own prefix normalisation.
func sameRouteFilterBase16762(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	aa, aok := routeFilterBasePrefix16762(a)
	bb, bok := routeFilterBasePrefix16762(b)
	return aok && bok && aa == bb
}

// routeFilterBasePrefix16762 normalises a parsed base CIDR to its
// masked netip prefix (host bits cleared), so base comparisons and
// containment test the NETWORK, not the authored address.
func routeFilterBasePrefix16762(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := routeFilterAddr16762(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	plen, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, plen).Masked(), true
}

func routeFilterAddr16762(ip net.IP) (netip.Addr, bool) {
	// net.ParseCIDR returns a 4-byte IP for v4; a 16-byte IP may be
	// v4-in-v6, so slices must be taken AFTER To4/To16, never from the
	// raw IP (slicing the 16-byte form would read the mapped prefix).
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte(ip4)), true
	}
	if ip16 := ip.To16(); ip16 != nil {
		return netip.AddrFrom16([16]byte(ip16)), true
	}
	return netip.Addr{}, false
}

// routeFilterContains16762: does base prefix a contain route address
// addr with length rplen? Containment of another route-filter base b in
// a is routeFilterContains16762(a, b.IP, plen(b)).
func routeFilterContains16762(a *net.IPNet, addr net.IP, rplen int) bool {
	if a == nil {
		return false
	}
	ap, aok := routeFilterBasePrefix16762(a)
	ra, rok := routeFilterAddr16762(addr)
	if !aok || !rok || ap.Addr().Is4() != ra.Is4() {
		return false
	}
	aplen, _ := a.Mask.Size()
	return aplen <= rplen && ap.Contains(ra)
}

// routeFilterBaseContains16762 reports whether outer's base NETWORK
// strictly contains inner's base network (outer broader, inner inside
// it) — the only shape in which a route under inner can fall through
// to outer.
func routeFilterBaseContains16762(outer, inner *net.IPNet) bool {
	if outer == nil || inner == nil {
		return false
	}
	oplen, _ := outer.Mask.Size()
	iplen, _ := inner.Mask.Size()
	return oplen < iplen && routeFilterContains16762(outer, inner.IP, iplen)
}

// renderRouteFilterListGroup renders the FINAL prefix-list entries for
// one term-family group (or single-family term) into definitions and
// reports how many permits it emitted, plus the match family of the FIRST
// emitted entry for the single-sequence case. The per-entry permits come
// from the SAME routeFilterDerivation16762 seam as renderRouteFilterEntry,
// so every historical skip rule (#2072 / #2103 / #2105 / #2525) is judged
// here, never re-derived. A valid empty max-length `longer` is retained
// as a boundary even though that seam correctly emits no permit for it.
func renderRouteFilterListGroup(definitions *strings.Builder, plName string, rfs []indexedRouteFilter, seqFam string) (emitted int, firstIsV6 bool) {
	if len(rfs) == 0 {
		return 0, false
	}
	isV6Group := seqFam == "v6"
	var entries []routeFilterLayoutEntry16762
	for _, irf := range rfs {
		isV6 := isV6Group
		if seqFam == "" {
			isV6 = strings.Contains(irf.rf.Prefix, ":")
		}
		body, ok := routeFilterPermitLine(isV6, irf.rf)
		ipnet, plen := parseRouteFilterPrefix16762(irf.rf.Prefix)
		if !ok {
			maxLen := 32
			if isV6 {
				maxLen = 128
			}
			// A max-length `longer` is a valid empty match set, but its
			// prefix remains the longest matching boundary. Keep it in
			// the layout so the stop-deny below prevents fall-through to
			// any broader permit. All other skipped entries remain
			// absent: malformed/unhandled entries must never create a
			// boundary or affect valid siblings.
			if irf.rf.MatchType != "longer" || ipnet == nil || plen != maxLen {
				continue
			}
		}
		permit := ""
		if ok {
			permit = strings.TrimSuffix(body, "\n")
		}
		entries = append(entries, routeFilterLayoutEntry16762{
			rf: irf.rf, idx: irf.idx, ipnet: ipnet, plen: plen, permit: permit,
		})
	}
	if len(entries) == 0 {
		return 0, false
	}
	firstIsV6 = strings.Contains(entries[0].rf.Prefix, ":")
	// Precompute whether each entry could fall through to a broader
	// renderable base. Only such a group needs longest-match reordering
	// and interposed stops; otherwise retain its authored order and
	// original sequence slots to preserve the historical bytes.
	hasContainment := false
	for i := range entries {
		if entries[i].ipnet == nil {
			continue
		}
		for j := range entries {
			if i == j || entries[j].permit == "" {
				continue
			}
			if entries[j].ipnet == nil || routeFilterBaseContains16762(entries[j].ipnet, entries[i].ipnet) {
				entries[i].canStillMatch = true
				hasContainment = true
				break
			}
		}
	}
	if hasContainment {
		// Junos longest-match order: descending base length, stable.
		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].plen > entries[j].plen
		})
	}
	seq := 0
	for i := range entries {
		e := entries[i]
		kind := "ip"
		maxLen := 32
		if strings.Contains(e.rf.Prefix, ":") {
			kind = "ipv6"
			maxLen = 128
		}
		entrySeq := e.idx
		if hasContainment {
			entrySeq = seq
		}
		if e.permit != "" {
			fmt.Fprintf(definitions, "%s prefix-list %s seq %d %s\n", kind, frrName(plName), (entrySeq+1)*5, e.permit)
			if hasContainment {
				seq++
			}
			emitted++
		}
		if e.ipnet == nil || e.plen <= 0 || !e.canStillMatch {
			continue
		}
		// Only the LAST entry of each distinct base group can be
		// followed by the deny: earlier same-base permits are sibling
		// length-window slices whose union decides the base.
		lastOfBase := true
		for j := i + 1; j < len(entries); j++ {
			if entries[j].ipnet != nil && sameRouteFilterBase16762(e.ipnet, entries[j].ipnet) {
				lastOfBase = false
				break
			}
		}
		if !lastOfBase {
			continue
		}
		if e.plen == maxLen {
			// An `le max` on a /32 or /128 base is redundant: the
			// bare deny is exactly the same match set (the base
			// prefix itself). FRR accepts `le == plen` under its
			// `mask <= ge <= le` rule; omitting `le` is brevity,
			// not a validity requirement. This stop is needed for
			// a max-length `longer` boundary with an empty set.
			fmt.Fprintf(definitions, "%s prefix-list %s seq %d deny %s\n", kind, frrName(plName), (seq+1)*5, sanitizeFRRValue(e.rf.Prefix))
		} else {
			fmt.Fprintf(definitions, "%s prefix-list %s seq %d deny %s le %d\n", kind, frrName(plName), (seq+1)*5, sanitizeFRRValue(e.rf.Prefix), maxLen)
		}
		seq++
	}
	return emitted, firstIsV6
}

// routeFilterEntrySkipped reports whether renderRouteFilterEntry would
// skip rf as INVALID (failClosedInheritedInvalidRouteFilters12687's set,
// widened to bad prefixes): a malformed prefix, an unknown or `through`
// match-type, a malformed / out-of-range / at-or-below-base
// prefix-length-range, or an invalid upto. It is the single source of
// truth for "this entry's match set is unknowable", shared by the config
// quarantine and the FRR term rule (#14137) so the two cannot drift.
// A max-length `longer` is NOT skipped here: it is a valid route-filter
// with an honestly empty match set, not an invalid entry or deny-all.
// renderRouteFilterEntry still writes no line for it; the term-level
// longest-match layout may retain its base solely as a stop boundary
// when it is nested under a broader permit. A lone empty entry therefore
// keeps the undefined-list NOMATCH behavior for both actions.
func routeFilterEntrySkipped(rf *config.RouteFilter) bool {
	return config.RouteFilterEntrySkipped(rf)
}

// renderFromPrefixListACL writes an FRR access-list DEFINITION mirroring the
// matchKW-family entries of Junos from-prefix-list pl into access-list aclName,
// so the caller can reference it with a `match ip|ipv6 address <aclName>`
// clause. It exists to break the #5730 collision: when one route-map sequence
// carries BOTH a route-filter and a SAME-FAMILY `from prefix-list`, both would
// otherwise render as `match ip|ipv6 address prefix-list`, and FRR's
// route_map_add_match REPLACES a same-type rule (keeps the LAST) — silently
// dropping the route-filter constraint and loosening "(route-filter) AND
// (prefix-list)" to prefix-list-only (a fail-open policy-semantics change). An
// access-list match is a DISTINCT FRR rule type (`route_match_ip_address`
// vs `route_match_ip_address_prefix_list`), so FRR ANDs the two constraints
// instead of replacing. Entries use `exact-match` to mirror Junos `from
// prefix-list` (and the prefix-list renderer's bare-permit) exact semantics.
// Only the matchKW-family entries are emitted, mirroring the single-family
// match the prefix-list branch derives (a mixed v4+v6 list selects the IPv6
// matcher — the same #2071 homogeneous-family limitation). An empty family set
// (or nil list) emits NO definition: the undefined access-list then NOMATCHes
// every route (fail-closed), matching an undefined prefix-list. The prefix is
// sanitized as a #4482-style belt against a leniently-loaded stored value.
// These unindented definition lines are collected separately from route-map
// bodies so the caller can emit them before the first route-map header.
func renderFromPrefixListACL(b *strings.Builder, aclName, matchKW string, pl *config.PrefixList) {
	if pl == nil {
		return
	}
	v6 := matchKW == "ipv6"
	seqn := 5
	for _, prefix := range pl.Prefixes {
		if strings.Contains(prefix, ":") != v6 {
			continue
		}
		// #10823: policy-options prefix-list entries are also copied into
		// inline access-lists when a route-filter and from-prefix-list share
		// a route-map term. Keep malformed entries out of this second FRR
		// emission path as well as the top-level prefix-list definition.
		// #15012: the shared normaliser also renders a bare host with its
		// /32 or /128 mask instead of omitting it.
		normalized, ok := config.NormalizePrefixListEntry(prefix)
		if !ok {
			slog.Warn("frr: omitting malformed prefix-list entry from inline access-list",
				"list", pl.Name, "prefix", prefix)
			continue
		}
		if v6 {
			fmt.Fprintf(b, "ipv6 access-list %s seq %d permit %s exact-match\n", aclName, seqn, sanitizeFRRValue(normalized))
		} else {
			fmt.Fprintf(b, "access-list %s seq %d permit %s exact-match\n", aclName, seqn, sanitizeFRRValue(normalized))
		}
		seqn += 5
	}
}

// indexedRouteFilter carries a route-filter together with its ORIGINAL
// index in the term's route-filter slice so the FRR prefix-list entry
// seq slot ((idx+1)*5) stays stable when the slice is partitioned by
// family. Holding the original index keeps a split mixed-family term's
// per-family entries at the same seq numbers they would have had in the
// single combined list (gaps where the other family's entries sit are
// FRR-legal).
type indexedRouteFilter struct {
	idx int
	rf  *config.RouteFilter
}

// partitionRouteFiltersByFamily splits a term's route-filters into IPv4
// and IPv6 buckets by the prefix's family (`:` → v6), preserving each
// entry's original index. A route-filter whose prefix is malformed
// (fails net.ParseCIDR) is classified by the same `strings.Contains(":")`
// heuristic the renderer already uses for the family decision — it will
// be skipped at entry-render time anyway, so its bucket only affects
// which (possibly empty) sequence references an undefined list,
// preserving the existing fail-closed behavior.
func partitionRouteFiltersByFamily(rfs []*config.RouteFilter) (v4, v6 []indexedRouteFilter) {
	for i, rf := range rfs {
		if strings.Contains(rf.Prefix, ":") {
			v6 = append(v6, indexedRouteFilter{i, rf})
		} else {
			v4 = append(v4, indexedRouteFilter{i, rf})
		}
	}
	return v4, v6
}

// fromPrefixListRef is one referenced Junos `from prefix-list` bound to a SINGLE
// FRR address family. A mixed v4+v6 referenced list expands into TWO refs (ip +
// ipv6) so each family binds its own `match ip|ipv6 address` line in a
// family-correct route-map sequence — otherwise the collapsed single-family
// match silently drops the other family's routes (#2607 referenced-prefix-list
// residual). A single-family or undefined/empty list yields exactly one ref,
// byte-identical to the pre-#2607 selection.
type fromPrefixListRef struct {
	name    string // referenced prefix-list name ("" = no from-prefix-list)
	matchKW string // "ip" | "ipv6" — the family this ref binds
}

// fromPrefixListRefs expands one referenced prefix-list NAME into its per-family
// refs. The "" sentinel (no from-prefix-list on this term) yields a single empty
// ref so the from-* OR cross-product still emits exactly one sequence. A mixed
// v4+v6 list is exactly the Junos OR "(in the list's v4 half) OR (in its v6
// half)", so expanding it into two family refs reuses the SAME #2642 one-
// sequence-per-OR-value mechanism the community / as-path / multi-prefix-list
// sets already use — no new family model.
func fromPrefixListRefs(po *config.PolicyOptionsConfig, name string) []fromPrefixListRef {
	if name == "" {
		return []fromPrefixListRef{{}}
	}
	fams := prefixListFamilies(po.PrefixLists[name])
	refs := make([]fromPrefixListRef, len(fams))
	for i, kw := range fams {
		refs[i] = fromPrefixListRef{name: name, matchKW: kw}
	}
	return refs
}
