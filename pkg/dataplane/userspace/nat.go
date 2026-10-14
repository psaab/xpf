package userspace

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// natCounterID returns the compiler-assigned per-rule translation hit counter
// ID for the type-namespaced "natType/rulesetName/ruleName" key (#2218). The
// natType MUST match the type the compiler stamped (dataplane.NATCounterKey),
// otherwise same-named SNAT/DNAT/static rules collide. A nil map or a missing
// key yields 0 ("no counter"), preserving the legacy behavior where the
// snapshot carried no per-rule counter attribution. The ID is the stable
// key-derived hash assigned by the compiler (#2255), so it is u32-wide.
func natCounterID(ids map[string]uint32, natType, ruleSet, rule string) uint32 {
	if ids == nil {
		return 0
	}
	return ids[dataplane.NATCounterKey(natType, ruleSet, rule)]
}

const natUnresolvedAddressNamePrefix = "unresolved-address-name:"

// resolveNATAddressNamePrefixes resolves a NAT `match {source,destination}-
// address-name` reference into concrete prefixes using the SAME feed-aware
// recursive address-book expander the security-policy path uses
// (expandBookNameRecursive, policies_addrbook.go). feedOverlay maps a
// `security dynamic-address address-name ... profile <feed>` binding to its
// live feed-backed CIDR strings (resolved by the daemon from
// feeds.Manager.SnapshotForBindings).
//
// A direct feed reference unions its live prefixes with a usable same-named
// static address/set closure, matching policy book rows. If that static closure
// is poisoned, the ready direct feed stands alone instead of exposing a
// partial static subset. Nested feed members also contribute ready prefixes
// alongside static members (#4925). A present-EMPTY overlay for a declared
// fail-mode drop binding is the exception: it is the binding's match-none
// intent and takes precedence over the same-named static closure (#12965),
// keeping NAT in book-row parity with the #12961 policy resolver.
//
// Before #4925 this helper called the STATIC resolveUserspaceAddressBookEntry
// expander, which never consulted feedOverlay for nested members and POISONED
// the whole set on an unresolvable feed member (feedOverlay is keyed by the
// direct feed name, e.g. "bad-feed", NOT by the containing set "bad-set"). A NAT
// rule scoped to a set with an unresolvable feed member therefore resolved to no
// prefixes and silently matched nothing — diverging from the feed-aware
// security-policy path. #4925 reuses that same SSOT expander for ready feed
// members, closing the nested-feed under-resolution without changing the
// whole-closure quarantine described below.
//
// Fail-closed is preserved for the WHOLE closure: any member not resolved by
// a static book entry or ready feed overlay (e.g. an empty unbound nested
// set, a dangling reference without a ready feed, an unusable static address
// without a ready feed value, or an unready feed binding) poisons the name.
// SNAT promotes any poisoned selector name to a whole-rule drop using its
// existing LenientMatchDropped marker. DNAT has no corresponding poison field,
// so it retains per-name filtering until the snapshot contract is changed.
// All NAT append helpers use the fixed non-address prefix for fallback tokens,
// preventing CIDR-shaped names from becoming literal prefixes (#12626).
//
// The output is sorted + deduped to match the static resolver's shape (so the
// already-green #2416 exact-slice pins stay byte-identical); the NAT consumer
// treats the list as an unordered prefix set (duplicates contribute no extra
// table entry, ordering is irrelevant), so this canonicalization is inert.
func resolveNATAddressNamePrefixes(cfg *config.Config, feedOverlay map[string][]string, name string) []string {
	out, poisoned := resolveNATAddressNamePrefixesStatus(cfg, feedOverlay, name)
	if poisoned || len(out) == 0 {
		return nil
	}
	return out
}

// resolveNATAddressNamePrefixesStatus distinguishes valid present-empty feeds
// from unresolved closures. A ready direct feed is a fallback only when a
// same-named static closure is poisoned; otherwise static and feed values are
// unioned, as they are in the policy address-book row.
func resolveNATAddressNamePrefixesStatus(cfg *config.Config, feedOverlay map[string][]string, name string) ([]string, bool) {
	if cfg == nil || name == "" {
		return nil, false
	}
	ab := cfg.Security.AddressBook
	if ab != nil {
		if _, collision := ab.CollidingNames[name]; collision {
			return nil, true
		}
	}
	feeds, directFeedReady := feedOverlay[name]
	visited := make(map[string]bool)
	out, unknownMember := expandBookNameRecursive(
		ab, feedOverlay, cfg.Security.DynamicAddress.AddressBindings, name, visited, 0)
	if unknownMember {
		if !directFeedReady {
			return nil, true
		}
		// Policy representability accepts the direct feed reference even when
		// its same-named static closure is unusable. Do not publish a subset.
		out = append([]string(nil), feeds...)
	}
	sort.Strings(out)
	return slices.Compact(out), false
}

// appendNATAddressNames resolves one selector side and reports whether any
// reference poisoned its closure. SNAT uses that status to clear the affected
// side and attach its existing whole-rule drop marker.
func appendNATAddressNames(cfg *config.Config, feedOverlay map[string][]string, addrs []string, names []string) ([]string, bool) {
	addrs, poisonedName := appendNATAddressNamesPoisoned(cfg, feedOverlay, addrs, names)
	return addrs, poisonedName != ""
}

// appendNATAddressNamesPoisoned is appendNATAddressNames but also returns the
// first name whose closure poisoned the side, for operator diagnostics.
func appendNATAddressNamesPoisoned(cfg *config.Config, feedOverlay map[string][]string, addrs []string, names []string) ([]string, string) {
	for _, name := range names {
		if name == "" {
			continue
		}
		values, poisoned := resolveNATAddressNamePrefixesStatus(cfg, feedOverlay, name)
		if poisoned {
			return nil, name
		}
		if len(values) == 0 {
			addrs = append(addrs, natUnresolvedAddressNamePrefix+name)
		} else {
			addrs = append(addrs, values...)
		}
	}
	return addrs, ""
}

// appendNATSourceAddressName resolves a DNAT rule's `match source-address-name
// <book-entry>` into source prefixes for the destination-translation key
// (#2416). A direct feed reference unions its live prefixes with a usable
// same-named static closure, or uses the feed alone if that closure is poisoned.
// This matches policy representability; nested static-set expansion still
// includes ready feed members (#4925).
//
// On an unresolved name, the prefixed token is appended so the source list
// stays NON-EMPTY (source_constrained stays true on the Rust side). The fixed
// non-address prefix keeps CIDR-shaped names from matching literal prefixes
// (#12626). Commit validation rejects the reference on the strict path.
func appendNATSourceAddressName(cfg *config.Config, feedOverlay map[string][]string, sourceAddrs []string, name string) []string {
	if name == "" {
		return sourceAddrs
	}
	if values := resolveNATAddressNamePrefixes(cfg, feedOverlay, name); len(values) > 0 {
		return append(sourceAddrs, values...)
	}
	// Keep the source constraint non-empty with a prefixed, unparseable fallback.
	return append(sourceAddrs, natUnresolvedAddressNamePrefix+name)
}

// appendNATDestinationAddressName resolves a DNAT rule's
// `match destination-address-name <book-entry>` into destination prefixes
// (#3229). A direct feed reference unions its live prefixes with a usable
// same-named static closure, or uses the feed alone if that closure is poisoned.
// This matches policy representability; nested static-set expansion still
// includes ready feed members (#4925).
//
// On an unresolved name, the prefixed token is appended so the destination
// list stays NON-EMPTY (the rule does not collapse to no destination = skip).
// The fixed non-address prefix keeps CIDR-shaped names from becoming a
// translation prefix (#12626). Commit validation rejects the reference on the
// strict path.
func appendNATDestinationAddressName(cfg *config.Config, feedOverlay map[string][]string, destAddrs []string, name string) []string {
	if name == "" {
		return destAddrs
	}
	if values := resolveNATAddressNamePrefixes(cfg, feedOverlay, name); len(values) > 0 {
		return append(destAddrs, values...)
	}
	// Keep the destination list non-empty with a prefixed, unparseable fallback.
	return append(destAddrs, natUnresolvedAddressNamePrefix+name)
}

// natNeverMatchPortRange is an impossible inclusive range (Low > High): no L4
// port satisfies `p >= 1 && p <= 0`, so a rule carrying it matches NOTHING
// (#3429). It is the fail-CLOSED sentinel emitted when a destination-port (or an
// application's destination-port) constraint WAS configured but every value is
// unrepresentable / out of the valid 1..65535 range. Without it, coalescing to
// an EMPTY range list would be read downstream as "no port constraint" = match
// any port — re-introducing the exact fail-OPEN widening #3429 closes (AGY
// finding on PR #3471). The Rust matcher PRESERVES a Low>High range (it never
// matches) rather than dropping it, so the sentinel survives the wire. The
// strict commit gate (#3386) already rejects an out-of-range port at commit;
// this hardens the lenient / tolerant-load / peer-sync path.
var natNeverMatchPortRange = NatPortRangeWire{Low: 1, High: 0}

// coalescePortRanges collapses a list of individual L4 ports (the expanded
// output of parseDNATPortList / appPortsFromSpec) into a minimal set of
// inclusive [Low,High] wire ranges (#3429). Any value outside the valid
// 1..65535 range is skipped (a bad/wrapping value never becomes a wrong u16
// match). The result is sorted, deduplicated, and run-merged so a
// `destination-port 20000 to 20003` carries one range, not four entries.
//
// This is a pure utility: it returns an EMPTY slice both for "no ports given"
// AND for "ports given but none representable" — the two are indistinguishable
// here and an empty result means "unconstrained" downstream. Callers that must
// fail CLOSED on an all-out-of-range constraint (rather than widen to match-any)
// MUST go through sourceNATDestPortRanges / the app-term guard, which substitute
// natNeverMatchPortRange when the input was non-empty but coalesced to nothing.
func coalescePortRanges(ports []int) []NatPortRangeWire {
	if len(ports) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(ports))
	uniq := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}
	if len(uniq) == 0 {
		return nil
	}
	sort.Ints(uniq)
	var ranges []NatPortRangeWire
	lo, hi := uniq[0], uniq[0]
	for _, p := range uniq[1:] {
		if p == hi+1 {
			hi = p
			continue
		}
		ranges = append(ranges, NatPortRangeWire{Low: uint16(lo), High: uint16(hi)})
		lo, hi = p, p
	}
	ranges = append(ranges, NatPortRangeWire{Low: uint16(lo), High: uint16(hi)})
	return ranges
}

// appPortRangesFromSpec returns exactly what
// coalescePortRanges(appPortsFromSpec(spec)) returns, WITHOUT materializing the
// intermediate per-port slice (#5250, A6-b2 F3).
//
// A port spec is a single value or ONE contiguous inclusive range, so its
// coalesced form is always zero or one wire range — there is nothing for
// coalescePortRanges to merge. The old path nonetheless appended every port
// from lo..hi into a []int first, so `destination-port 1-65535` allocated ~65k
// ints (512 KiB on a 64-bit build) purely to have them collapsed back into one
// {Low:1,High:65535} entry on the very next line, once per application and
// again for every member of an application-set — a commit-time allocation
// spike on the same goroutine that services the control socket.
//
// Equivalence with the composition it replaces, arm by arm (pinned by
// TestAppPortRangesFromSpecMatchesCoalescedSlice, which asserts the two agree
// across a spec corpus rather than trusting this comment):
//   - "" / parse failure / reversed range (#3726) -> both yield no range.
//   - lo == hi -> the slice path yields []int{lo}, which coalesces to
//     {lo,lo} when lo >= 1 and to nothing when lo == 0.
//   - lo < hi  -> the slice path yields lo..hi, and coalescePortRanges drops
//     only the sub-1 values, so the result is {max(lo,1), hi}. hi <= 65535 is
//     guaranteed by the ParseUint bit width, so no high-side clamp is needed.
func appPortRangesFromSpec(spec string) []NatPortRangeWire {
	lo, hi, ok := appPortSpecBounds(spec)
	if !ok {
		return nil
	}
	// coalescePortRanges skips every value below 1; for a contiguous range that
	// is exactly a low-side clamp.
	if lo < 1 {
		lo = 1
	}
	if hi < lo {
		// Either a single port 0, or a range whose only members were sub-1.
		return nil
	}
	return []NatPortRangeWire{{Low: uint16(lo), High: uint16(hi)}}
}

// appPortSpecBounds parses a port spec into its inclusive [lo,hi] bounds. ok is
// false for an empty spec, a malformed number, or a REVERSED range (#3726 —
// "200-100" can never match, and must not be narrowed to an exact match on the
// low port). It is the shared parse behind appPortsFromSpec and
// appPortRangesFromSpec so the two cannot drift.
func appPortSpecBounds(spec string) (lo, hi uint64, ok bool) {
	if spec == "" {
		return 0, 0, false
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, 0, false
		}
		hi, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return 0, 0, false
		}
		if hi < lo {
			// #3726: a REVERSED range ("200-100", lo>hi) is invalid — it can
			// never match any port. Report "no bounds" (not lo..lo) so the
			// caller treats it as "configured but unrepresentable" and fails
			// CLOSED via the never-match sentinel, rather than silently
			// narrowing the NAT rule to an exact match on the low port. Strict
			// commit already rejects lo>hi (pkg/config range validation); this
			// hardens the #1960 tolerant-load / peer-sync backstop. hi==lo is a
			// legitimate single exact port.
			return 0, 0, false
		}
		return lo, hi, true
	}
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return 0, 0, false
	}
	return p, p, true
}

// appPortsFromSpec parses a port specification like "80", "1024-65535" into a
// list of port numbers. Mirrors the logic in pkg/dataplane/compiler.go.
func appPortsFromSpec(spec string) []int {
	lo, hi, ok := appPortSpecBounds(spec)
	if !ok {
		return nil
	}
	ports := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		ports = append(ports, int(p))
	}
	return ports
}
