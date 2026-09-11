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
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderRouteFilterEntry writes the single FRR `ip|ipv6 prefix-list`
// entry line for one route-filter into list plName at seq slot
// (idx+1)*5, applying the per-match-type ge/le derivation. It returns
// emitted=true when a line was written, emitted=false when the entry was
// skipped (a max-length `longer` empty set, a malformed prefix, an
// out-of-range `prefix-length-range`, or an unhandled match-type) — see
// the per-arm comments for the FRR-validity / fail-closed reasoning
// (#2072/#2103/#2105/#2525). Family selection (the namespace `ip` vs
// `ipv6`) is intrinsic to the prefix, so a single mixed-family
// route-filter slice can be rendered correctly by calling this per entry.
func renderRouteFilterEntry(b *strings.Builder, plName string, idx int, rf *config.RouteFilter) (emitted bool) {
	isV6 := strings.Contains(rf.Prefix, ":")
	matchStr := "le 32"
	if isV6 {
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
				if isV6 {
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
		if isV6 {
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
		// Any match-type admitted by the schema but not handled above (a
		// future keyword, or a value that slipped past validation on a
		// tolerant path) MUST NOT fall through to the pre-switch
		// open-ended "le maxLen" default — that silently degrades a
		// constrained match to an orlonger-style permit (#2525). Skip the
		// entry instead: match-nothing is fail-closed.
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
		// slot (idx+1)*5 is simply not used; gaps in seq are FRR-legal.
		return false
	}
	if isV6 {
		fmt.Fprintf(b, "ipv6 prefix-list %s seq %d permit %s", frrName(plName), (idx+1)*5, sanitizeFRRValue(rf.Prefix))
	} else {
		fmt.Fprintf(b, "ip prefix-list %s seq %d permit %s", frrName(plName), (idx+1)*5, sanitizeFRRValue(rf.Prefix))
	}
	if matchStr != "" {
		fmt.Fprintf(b, " %s", matchStr)
	}
	b.WriteString("\n")
	return true
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
// Mirrors renderRouteFilterEntry's inline-definition style: the unindented
// `access-list` line is emitted into the route-map body builder and processed
// by FRR at the config node, exactly like the route-filter prefix-lists.
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
		if v6 {
			fmt.Fprintf(b, "ipv6 access-list %s seq %d permit %s exact-match\n", aclName, seqn, sanitizeFRRValue(prefix))
		} else {
			fmt.Fprintf(b, "access-list %s seq %d permit %s exact-match\n", aclName, seqn, sanitizeFRRValue(prefix))
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
