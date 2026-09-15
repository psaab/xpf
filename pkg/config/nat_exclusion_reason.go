package config

import (
	"net"
	"strings"
)

// Shared "will the dataplane actually install this NAT object?" predicates.
//
// #6534: every fail-closed snapshot exclusion in pkg/dataplane/userspace has a
// show surface that renders the excluded object straight from config, with no
// indication that it is not enforced. The operator reads `show security nat
// ...`, sees the rule they wrote, and concludes the box is translating traffic
// it is silently forwarding untranslated.
//
// The fix is NOT an applied-set readback. Every one of these exclusions is
// decided by the GO SNAPSHOT BUILDER, at build time, as a deterministic
// function of the committed config — the dataplane does not "decide at runtime"
// that the object is not installed, it merely honors a verdict the builder
// already reached (for source NAT, the `pool_unusable` wire flag). There is no
// runtime fact to read back. What the renderer is missing is the PREDICATE, not
// a data path.
//
// So these live here, next to NPTv6ScopeUnsupported and
// SourceNATPoolUnusableReason, and BOTH the snapshot builder and the show
// surface call them. That is the same shape nptv6_scope.go already argues for:
// two copies of a predicate drift, and the two drift directions fail
// differently — a builder that drops what the renderer calls armed lies to the
// operator, and a renderer that annotates what the builder installs cries wolf
// on a working rule.
//
// The reason strings are operator-facing and are rendered verbatim, so they are
// part of the contract. They deliberately do NOT match the source-NAT wire
// reasons (SourceNATPoolUnusableReason): those cross the wire and are decoded
// Rust-side by source_nat_failure_reason_from_snapshot, these never leave Go.
//
// Every exclusion here is a LENIENT-PATH backstop. The strict commit gates
// (validateStaticNATInetTargetStrict, validateDNATPoolStrict) reject these
// configs outright, so a freshly committed config cannot reach a state where
// one of these returns non-empty. They are reachable through Store.Load at boot
// and Store.SyncApply on HA peer-sync (opts.lenientFirewallRefs, #1960
// no-brick) — which is exactly when an operator is reading show output to work
// out why traffic is not flowing.

// StaticNATRuleExcludedReason reports why the userspace snapshot builder DROPS
// a static NAT rule, or "" when the rule is installed.
//
// Callers (they must not drift — see the file header):
//
//  1. buildStaticNATSnapshots (pkg/dataplane/userspace/nat_static.go) drops the
//     rule, and
//  2. natshow.RenderStatic / RenderStaticRule annotate it as not installed.
//
// NPTv6 rules are NOT this predicate's business: buildStaticNATSnapshots routes
// them to buildNPTv6Snapshots before reaching here, and their own exclusion
// predicate is NPTv6ScopeUnsupported. A nil rule reports "" — both callers skip
// nils first, and "installed" is the direction that cannot make a renderer
// annotate a rule that is in fact armed.
func StaticNATRuleExcludedReason(rule *StaticNATRule) string {
	if rule == nil || rule.IsNPTv6 {
		return ""
	}
	// #5859: `then static-nat inet` is the Junos NAT64 keyword, but this
	// same-family static_nat table stores an IP address in InternalIP. The
	// literal "inet" makes the Rust parse_nat_prefix fail, so the rule
	// installs nothing. The supported path is `security nat nat64`.
	if rule.Then == "inet" {
		return "nat64 target not representable in the static-nat table (use `security nat nat64`)"
	}
	// #5101: a PRESENT but out-of-range port must not reach clampPort —
	// clamping to 0 collapses the rule to the whole-address wildcard, which
	// installs a 1:1 mapping exposing EVERY port (a fail-OPEN broadening), so
	// the builder drops it instead. Genuine-absent (0) is a valid 1:1 shape.
	if staticNATPortOutOfRange(rule.MatchDestinationPort) || staticNATPortOutOfRange(rule.MappedPort) {
		return "destination-port / mapped-port outside 1-65535"
	}
	return ""
}

// staticNATPortOutOfRange reports whether a PRESENT static-NAT port is outside
// the representable range. Zero means "absent" (a plain whole-address 1:1
// rule), not "invalid".
func staticNATPortOutOfRange(p int) bool {
	return p != 0 && (p < 1 || p > 65535)
}

// DestinationNATRuleExcludedReason reports why the userspace snapshot builder
// DROPS a destination NAT rule, or "" when the rule is installed.
//
// Callers (they must not drift — see the file header):
//
//  1. buildDestinationNATSnapshotsWithFeeds
//     (pkg/dataplane/userspace/nat_destination.go) drops the rule, and
//  2. natshow.RenderDestRuleDetail annotates it as not installed.
//
// A `then destination-nat off` rule is the #3844 no-NAT exemption: it names no
// pool, installs as an exemption entry, and is never excluded. A nil rule or
// nil DNAT config reports "" for the same reason StaticNATRuleExcludedReason
// does.
func DestinationNATRuleExcludedReason(dnat *DestinationNATConfig, rule *NATRule) string {
	if dnat == nil || rule == nil {
		return ""
	}
	// #9874: a rule whose authored `match` constrains nothing publishes no
	// entry — the builder skips it before the pool checks. FIRST, and in
	// particular before the #3844 `off` exemption below: an empty-match
	// exemption has no destination key either, so it installs nothing no
	// matter what it carries. The builder reaches the same verdict through
	// its own loop-top check (which also covers the `off` shape this
	// predicate's builder call site does not reach); this clause is what the
	// show and structured surfaces read.
	if rule.LenientMatchDropped {
		return "the authored match constrains nothing, so the rule publishes " +
			"no entry (a commit would reject it, #9874)"
	}
	// #3844: the no-NAT exemption resolves without a pool. Decided by `off`,
	// not by an empty pool name.
	if rule.Then.Off {
		return ""
	}
	pool, ok := dnat.Pools[rule.Then.PoolName]
	if !ok || pool == nil || pool.Address == "" {
		// #6823: an ACTIONLESS rule names no pool at all, and saying it
		// "references undefined or address-less pool \"\"" asserts a
		// reference it does not carry — the destination twin of the
		// `Action: interface` defect #7640 fixed on the source side, on
		// exactly the rule shape an operator is trying to find. Worse than
		// cosmetic: it mis-attributes the CAUSE, sending someone off to
		// define a pool when the rule carries no translation action for a
		// pool to belong to.
		//
		// The PREDICATE is deliberately untouched — this is the same branch
		// under the same condition, returning a different string. #6534
		// shares this function with buildDestinationNATSnapshotsWithFeeds so
		// the builder and the renderer cannot disagree about which rules are
		// armed; moving the condition would be the #6534 defect with the
		// polarity reversed.
		if rule.Then.PoolName == "" {
			return "names no translation action (neither `pool` nor `off`)"
		}
		return "references undefined or address-less pool " + quoteName(rule.Then.PoolName)
	}
	// #3450: a non-host pool address would be coerced to its network base, and
	// a configured-but-invalid port would wrap on the uint16 cast or collapse
	// to preserve-destination-port. Both publish NO entry so the rule matches
	// nothing rather than translating to the wrong place.
	if _, hostOK := DNATPoolHostIP(pool.Address); !hostOK {
		return "pool " + quoteName(rule.Then.PoolName) + " address is not a single host address"
	}
	if pool.PortRaw != "" && (pool.Port < 1 || pool.Port > 65535) {
		return "pool " + quoteName(rule.Then.PoolName) + " port outside 1-65535"
	}
	return ""
}

// DNATPoolHostIP resolves a destination-NAT pool address to the single host IP
// the dataplane installs, reporting false when the address is not a single host
// (unparseable, or a prefix wider than /32 or /128 that would silently coerce
// to its network base).
//
// Exported so the snapshot builder and DestinationNATRuleExcludedReason share
// ONE answer: a builder that installs an address the renderer calls
// unrepresentable is the #6534 defect with the polarity reversed.
func DNATPoolHostIP(addr string) (string, bool) {
	if addr == "" {
		return "", false
	}
	if strings.IndexByte(addr, '/') == -1 {
		ip := net.ParseIP(addr)
		if ip == nil {
			return "", false
		}
		return ip.String(), true
	}
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", false
	}
	if ones, bits := ipNet.Mask.Size(); ones != bits {
		return "", false // non-host prefix — would coerce to the network base
	}
	return ip.String(), true
}

// quoteName renders a config name for an operator-facing reason string,
// making an EMPTY name visible as "" rather than vanishing mid-sentence.
func quoteName(s string) string {
	return `"` + s + `"`
}

// SourceNATPoolDisarmedReason reports the WIRE reason the userspace snapshot
// builder marks a pool-mode source-NAT rule unusable (the `pool_unusable_reason`
// the Rust side decodes in source_nat_failure_reason_from_snapshot), or "" when
// the rule translates.
//
// This composes the two clauses the builder applies in order, with the builder's
// precedence: the pool's own DEFINITION verdict first (SourceNATPoolUnusableReason,
// which reports "missing_pool" for a nil pool — so an unresolvable name resolves
// here too), and only then the #6812 aggregate cardinality budget. Getting that
// order wrong would relabel a specifically-diagnosed pool as merely over-budget.
//
// overBudget is SourceNATAggregateOverBudgetPools(cfg). It is a parameter rather
// than recomputed here because the walk is per-CONFIG, not per-rule; a renderer
// looping over rules must hoist it or pay the walk once per rule.
//
// Callers: buildSourceNATSnapshots (via its inline clauses, pinned to this
// function by the #6534 agreement test) and natshow.RenderSourceRuleDetail.
// Interface-mode source NAT has no pool — callers must gate on a non-empty
// pool name, exactly as the builder does.
func SourceNATPoolDisarmedReason(pool *NATPool, poolName string, overBudget map[string]bool) string {
	if reason := SourceNATPoolUnusableReason(pool); reason != "" {
		return reason
	}
	if overBudget[poolName] {
		return "aggregate_over_budget"
	}
	return ""
}

// SourceNATDisarmReasonText renders a `pool_unusable_reason` wire token as the
// operator-facing prose the show surfaces print. An UNKNOWN token is echoed
// verbatim rather than swallowed: a reason added to the builder but not here
// must still reach the operator, because printing nothing is the #6534 defect
// this whole file exists to close.
func SourceNATDisarmReasonText(reason string) string {
	switch reason {
	case "":
		return ""
	case "missing_pool":
		return "references an undefined pool"
	case "empty_pool":
		return "pool has no usable addresses"
	case "invalid_pool":
		return "pool has a member the dataplane cannot expand (unparseable, malformed mask, or over-capacity prefix)"
	case "invalid_port_range":
		return "pool port range is invalid"
	case "zone_scoped_pool_address":
		return "pool has a zone-qualified address the dataplane cannot represent"
	case "aggregate_over_budget":
		return "pool does not fit the aggregate pool-cardinality budget"
	default:
		return reason
	}
}
