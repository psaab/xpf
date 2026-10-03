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

// resolveNATAddressNamePrefixes resolves a NAT `match {source,destination}-
// address-name` reference into concrete prefixes using the SAME feed-aware
// recursive address-book expander the security-policy path uses
// (expandBookNameRecursive, policies_addrbook.go). feedOverlay maps a
// `security dynamic-address address-name ... profile <feed>` binding to its
// live feed-backed CIDR strings (resolved by the daemon from
// feeds.Manager.SnapshotForBindings).
//
// The expander merges feedOverlay at the top level AND at every nested
// address-set MEMBER, so one operator-authored address object resolves to the
// same prefixes across NAT and policy:
//   - a DIRECT `match ...-address-name <feed-name>` reference resolves its live
//     feed prefixes (the #3303 NAT-side gap),
//   - a reference to an address-SET whose member is feed-backed now resolves the
//     nested member's feed prefixes too (#4925) — feed-only members AND mixed
//     static+feed sets,
//   - a name that is BOTH a static address and a feed binding accumulates both.
//
// Before #4925 this helper called the STATIC resolveUserspaceAddressBookEntry
// expander, which never consulted feedOverlay for nested members and POISONED
// the whole set on an unresolvable feed member (feedOverlay is keyed by the
// direct feed name, e.g. "bad-feed", NOT by the containing set "bad-set"). A NAT
// rule scoped to a set with a feed member therefore resolved to no prefixes and
// silently matched nothing — diverging from the feed-aware security-policy path
// (#3294 closed the nested-member case there via expandBookNameRecursive; the
// NAT path was left as a tracked residual). #4925 reuses that same SSOT expander
// so the divergence is gone.
//
// Fail-closed is preserved. A set with NO resolvable member (an empty set, or a
// set whose only member is a genuinely unresolvable NON-feed token) yields NO
// prefixes here; the append helpers then keep the constraint non-empty with the
// raw book-name token so the rule matches NOTHING — it never widens to match-any.
//
// The output is sorted + deduped to match the static resolver's shape (so the
// already-green #2416 exact-slice pins stay byte-identical); the NAT consumer
// treats the list as an unordered prefix set (duplicates contribute no extra
// table entry, ordering is irrelevant), so this canonicalization is inert.
func resolveNATAddressNamePrefixes(cfg *config.Config, feedOverlay map[string][]string, name string) []string {
	if cfg == nil || name == "" {
		return nil
	}
	visited := make(map[string]bool)
	out, unknownMember := expandBookNameRecursive(cfg.Security.AddressBook, feedOverlay, name, visited, 0)
	if unknownMember || len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// appendNATSourceAddressName resolves a NAT rule's `match source-address-name
// <book-entry>` into concrete source prefixes and appends them to the rule's
// source list (#2416). It reuses resolveNATAddressNamePrefixes — the same
// feed-aware recursive expander the security-policy snapshot path uses
// (expandBookNameRecursive), which unions the static address book with the
// dynamic-address feed overlay at the top level AND at nested address-set
// members (#3303 direct feed, #4925 nested-set feed member) — so a name-scoped
// NAT rule carries the entry's prefixes (static AND feed-backed) into the #2394
// source constraint instead of publishing an empty (match-any) source list.
//
// Fail-closed on an unknown / unresolvable name: the raw token is appended so
// the source list stays NON-EMPTY (source_constrained stays true on the Rust
// side) while the token itself fails IpAddr/IpNet parse and contributes no
// prefix — the rule then matches NOTHING rather than collapsing to match-any.
// This mirrors the policy path's behavior for an unresolved address reference
// and is backstopped at commit by validateNATSourceAddressNameReferencesStrict.
func appendNATSourceAddressName(cfg *config.Config, feedOverlay map[string][]string, sourceAddrs []string, name string) []string {
	if name == "" {
		return sourceAddrs
	}
	if values := resolveNATAddressNamePrefixes(cfg, feedOverlay, name); len(values) > 0 {
		return append(sourceAddrs, values...)
	}
	// Unknown / empty book entry: keep the constraint non-empty but
	// unmatchable (fail-closed). The raw name cannot parse as an IP.
	return append(sourceAddrs, name)
}

// appendNATDestinationAddressName resolves a NAT rule's `match
// destination-address-name <book-entry>` into concrete destination prefixes and
// appends them to the rule's destination list (#3229). It is the destination
// twin of appendNATSourceAddressName and shares the same expander
// (resolveNATAddressNamePrefixes) the security-policy and source-address-name
// paths use — the feed-aware recursive expandBookNameRecursive, static address
// book unioned with the dynamic-address feed overlay at the top level and at
// nested address-set members (#3303 direct feed, #4925 nested-set feed member) —
// so a name-scoped destination matches the same prefixes a literal `match
// destination-address` would, including feed-backed members nested in a set.
//
// Fail-closed on an unknown / unresolvable name: the raw token is appended so
// the destination list stays NON-EMPTY (the rule does not collapse to no
// destination = skip), while the token itself fails IP parse downstream and
// contributes no installed table entry — the rule then matches NOTHING rather
// than broadening. Backstopped at commit by
// validateNATSourceAddressNameReferencesStrict, which also gates
// destination-address-name.
func appendNATDestinationAddressName(cfg *config.Config, feedOverlay map[string][]string, destAddrs []string, name string) []string {
	if name == "" {
		return destAddrs
	}
	if values := resolveNATAddressNamePrefixes(cfg, feedOverlay, name); len(values) > 0 {
		return append(destAddrs, values...)
	}
	// Unknown / empty book entry: keep the list non-empty but unmatchable
	// (fail-closed). The raw name cannot parse as an IP.
	return append(destAddrs, name)
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
