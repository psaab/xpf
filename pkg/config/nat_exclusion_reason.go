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
//     rule,
//  2. buildNptv6Snapshots (pkg/dataplane/userspace/nat_nptv6.go) drops it, and
//  3. natshow.RenderStatic / RenderStaticRule annotate it as not installed.
//
// NPTv6 rules reach this predicate ONLY for the #9877 unknown-leaf clause:
// buildStaticNATSnapshots routes IsNPTv6 rules to buildNPTv6Snapshots, whose
// scope verdict stays NPTv6ScopeUnsupported, and the plain-only clauses below
// (#5859/#5101) sit behind the IsNPTv6 early return. A nil rule reports "" —
// all callers skip nils first, and "installed" is the direction that cannot
// make a renderer annotate a rule that is in fact armed.
func StaticNATRuleExcludedReason(rule *StaticNATRule) string {
	if rule == nil {
		return ""
	}
	// #9877: dropped match leaves disarm BOTH plain and NPTv6 rules, so this
	// clause precedes the IsNPTv6 early return. A typo'd scope leaf on an
	// NPTv6 rule would otherwise evade the #5818 drop and install a zone-wide
	// rewrite the correctly-spelled config would have had refused.
	if reason := unknownNATMatchLeavesReason(rule.UnknownMatchLeaves); reason != "" {
		return reason
	}
	// #9988: an unparseable destination-port is preserved separately from
	// MatchDestinationPort, whose zero value is the legitimate whole-address
	// wildcard. Drop the rule before clampPort can turn the invalid token into
	// an installed wildcard on the lenient load / peer-sync path.
	if len(rule.InvalidDestinationPorts) > 0 {
		return "destination-port contains non-numeric token(s) [" +
			quoteNATLeafKeywords(rule.InvalidDestinationPorts) + "]"
	}
	if rule.IsNPTv6 {
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
// pool and installs as an exemption entry. It is excluded only when #9877
// leaves it unkeyable (below). A nil rule or nil DNAT config reports "" for
// the same reason StaticNATRuleExcludedReason does.
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
		// #9877: an exemption whose destination key was dropped is unkeyable —
		// the builder skips rules with no destination entries whether or not
		// they are exemptions — so report it rather than render it armed. A
		// keyable exemption (destination survives) still installs: skipping
		// one would translate traffic the operator said not to translate.
		if len(rule.UnknownMatchLeaves) > 0 && !dnatRuleHasDestinationKey(rule) {
			return "exemption match dropped unknown leaves [" + quoteNATLeafKeywords(rule.UnknownMatchLeaves) + "] leaving no destination key; the exemption cannot be keyed so it is not installed (fail-closed)"
		}
		return ""
	}
	// #9877: match-content loss is asked before the pool clauses: the match is
	// the rule's own authoring, the pool its referenced object, and the
	// builder skips on this verdict before any pool lookup.
	if reason := unknownNATMatchLeavesReason(rule.UnknownMatchLeaves); reason != "" {
		return reason
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

// quoteNATLeafKeywords renders dropped match-leaf keywords for an
// operator-facing reason string (#9877).
func quoteNATLeafKeywords(leaves []string) string {
	quoted := make([]string, len(leaves))
	for i, l := range leaves {
		quoted[i] = `"` + l + `"`
	}
	return strings.Join(quoted, ", ")
}

// unknownNATMatchLeavesReason formats the shared #9877 verdict: the rule's
// match lost leaves the compiler does not read, so installing it would match
// a different (wider) set than authored. "" when no leaves were dropped.
func unknownNATMatchLeavesReason(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	return "match dropped unknown leaves [" + quoteNATLeafKeywords(leaves) + "]; installing it would match a different set than authored, so the rule is not installed (fail-closed)"
}

// dnatRuleHasDestinationKey reports whether a destination NAT rule configures
// any destination criterion (literal or name). It mirrors the builder's
// destination-presence read (literals plus configured names) closely enough
// to decide the #9877 unkeyable-exemption verdict: configured-empty implies
// the builder resolves nothing and skips. A configured-but-UNRESOLVABLE name
// still resolves per-entry at emit time — that pre-existing unknown-name lie
// class is gate-warned, not grown here.
func dnatRuleHasDestinationKey(rule *NATRule) bool {
	m := rule.Match
	return len(m.DestinationAddresses) > 0 || m.DestinationAddress != "" ||
		len(m.DestinationAddressNames) > 0 || m.DestinationAddressName != ""
}

// SourceNATRuleExcludedReason reports why the userspace snapshot builder DROPS
// a source NAT rule, or "" when the rule is installed.
//
// Callers (they must not drift — see the file header):
//
//  1. buildSourceNATSnapshotsWithFeeds
//     (pkg/dataplane/userspace/nat_source.go) drops the rule, and
//  2. SourceNATRuleNotInstalledReason (nat_not_installed_7473.go) plus
//     natshow's source renderer annotate it as not installed.
//
// Unlike the pool verdicts below (which travel on the wire as `pool_unusable`
// for Rust to honor), a match-content verdict is decided by a Go-side skip:
// Rust cannot re-derive a dropped leaf from a snapshot — the leaf left no
// trace — so any tombstone would have to originate here anyway, and a skip
// with a shared-predicate annotation is the identical dataplane outcome with
// no wire churn. A `then source-nat off` exemption is never excluded (the
// #3844 structure): skipping one would translate traffic the operator said
// not to translate.
//
// Overlap with #9874 (parent ruling: DISARM-WINS): a rule carrying BOTH
// markers (a typo-only match is also unconstrained) is NOT skipped — it
// ships as the #9874 fail-closed drop tombstone. Unknown operator intent
// fails closed (deny: drop + stop) rather than falling through to
// subsequent rules, which a skip would allow.
func SourceNATRuleExcludedReason(rule *NATRule) string {
	if rule == nil || rule.Then.Off {
		return ""
	}
	if rule.LenientMatchDropped {
		return ""
	}
	return unknownNATMatchLeavesReason(rule.UnknownMatchLeaves)
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
