package config

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// validateNATMatchApplicationsStrict hard-rejects a source- or
// destination-NAT rule's `match application <name>` token that resolves to
// NONE of: a predefined junos-* application, a user-defined `applications
// application <name>`, or a non-empty user-defined `applications
// application-set <name>` (#3434, Codex audit 095 H07/H08). It is the NAT
// analog of validatePolicyMatchApplicationsStrict (#3144/#3146).
//
// A NAT `match application` consumes the referenced application's
// protocol/port the same way a policy match does (the SNAT/DNAT snapshot
// builders in pkg/dataplane/userspace/nat.go resolve it via
// ResolveApplication / ExpandApplicationSet). When the token is a typo /
// dangling reference (H07) or a defined-but-EMPTY application-set (H08), the
// reference resolves to ZERO application terms — and the DNAT builder then
// fell THROUGH to its explicit-match fallback (protocol="" + destination-port
// 0), publishing the pool VIP for EVERY flow to the destination (a fail-open
// wildcard translation). The dataplane backstop now substitutes a never-match
// term on that path (the source-NAT buildSourceNATAppTerms natProtoNever term,
// and the destination-NAT natNeverMatchPortRange source-port sentinel), but
// the operator still got a green commit for a NAT rule that quietly fails
// closed. Failing the unresolved reference at commit turns that silent break
// into an operator-visible error.
//
// Resolution mirrors the snapshot builders EXACTLY (ResolveApplication, which
// checks user apps then the predefined table, plus ResolveApplicationSet +
// ExpandApplicationSet) so the commit gate and the dataplane cannot diverge.
// The `any` keyword and the empty token are always accepted (they mean
// "unconstrained" and the builders short-circuit them to no terms). Static NAT
// carries no application match, so only source and destination NAT rule-sets
// are walked.
//
// Strict on commit / commit-check (hard reject naming the NAT kind, rule-set,
// rule, and the undefined app); lenient on load / peer-sync (warn — #1960; the
// dataplane independently fails the rule closed, so a leniently-loaded bad
// config is no worse off, now flagged). Same doctrine as
// lenientPolicyMatchApplications.
func validateNATMatchApplicationsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// appRefError returns nil if the token resolves, or a tailored reject.
	// Resolution mirrors the SNAT/DNAT snapshot builders: a name resolves only
	// if it is a predefined / user application OR an application-set that
	// EXPANDS to >= 1 member. A defined-but-EMPTY application-set resolves by
	// NAME but expands to zero members -> the builder produces a never-match
	// term (H08).
	appRefError := func(natKind, ruleSet, ruleName, name string) error {
		switch name {
		case "", "any":
			return nil
		}
		if _, ok := ResolveApplication(name, cfg.Applications.Applications); ok {
			return nil
		}
		if _, ok := ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
			expanded, err := ExpandApplicationSet(name, &cfg.Applications)
			if err == nil && len(expanded) == 0 {
				return natMatchEmptyAppSetError(natKind, ruleSet, ruleName, name)
			}
			return nil
		}
		return natMatchApplicationError(natKind, ruleSet, ruleName, name)
	}
	checkRuleSet := func(natKind string, rs *NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #3431: validate EVERY application in a bracket list / repeated
			// `match application [ a b ]`, not just the first. The parser used
			// to collapse the list to one value, so a trailing typo was never
			// reached by this gate.
			for _, app := range rule.Match.ApplicationList() {
				if err := appRefError(natKind, rs.Name, rule.Name, app); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, rs := range cfg.Security.NAT.Source {
		if err := checkRuleSet("source", rs); err != nil {
			return err
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if err := checkRuleSet("destination", rs); err != nil {
				return err
			}
		}
	}
	return nil
}

// natMatchApplicationError formats the #3434 H07 reject for a NAT rule whose
// `match application` names neither a predefined/user application nor an
// application-set.
func natMatchApplicationError(natKind, ruleSet, ruleName, app string) error {
	return fmt.Errorf(
		"%s NAT rule-set %q rule %q match application %q resolves to no "+
			"predefined application, user-defined application, or "+
			"application-set (a typo or undefined application disarms the NAT "+
			"match and the dataplane falls open to a wildcard translation) — "+
			"define the application or fix the reference (#3434)",
		natKind, ruleSet, ruleName, app)
}

// natMatchEmptyAppSetError formats the #3434 H08 reject for a NAT rule
// referencing a DEFINED but EMPTY application-set. The set exists by name but
// expands to zero members, so the snapshot builder produces a never-match term
// and the rule quietly matches nothing — the NAT sibling of #3146.
func natMatchEmptyAppSetError(natKind, ruleSet, ruleName, name string) error {
	return fmt.Errorf(
		"%s NAT rule-set %q rule %q match application %q is a defined but "+
			"EMPTY application-set (it expands to zero applications) — the rule "+
			"commits but the dataplane installs a never-match term so the "+
			"translation never fires — add at least one `applications "+
			"application-set %q application <name>` member or remove the "+
			"reference (#3434)",
		natKind, ruleSet, ruleName, name, name)
}

// validateDestinationNATAddressesStrict (#2396(c)) hard-rejects a
// destination-NAT rule whose `match destination-address` resolves to NO
// parseable host IP — i.e. the rule HAS a destination match (singular or
// bracket-list) but EVERY configured token fails to parse as a bare IP after
// any CIDR mask is stripped.
//
// The DNAT snapshot builder (buildDestinationNATSnapshots, #2395) strips the
// CIDR suffix from each destination and SKIPS any token where
// `net.ParseIP(stripped) == nil`; the Rust DNAT table (DnatTable::from_snapshots)
// independently `continue`s on a destination it cannot parse. So a rule whose
// destinations are all malformed emits NO table entry and silently translates
// NOTHING — it compiled and committed, but is inert, with no operator feedback.
// This is the #2396(c) silent-drop. Surfacing it at commit / commit-check turns
// a fat-fingered "the only destination is a typo" into a visible error.
//
// Acceptance MUST match the builder's exactly: a token is "good" iff, after
// stripping a trailing `/mask`, the remainder parses with net.ParseIP. A rule
// with NO destination match at all is out of scope (it never reaches the
// builder's per-destination loop). A rule with at least one good destination is
// fine even if others are malformed (the builder emits entries for the good
// ones and skips the rest — partial, but not a silent total no-op).
//
// Reported deterministically: rule-sets are walked in sorted name order and
// rules in their configured order, so the first-reported offender is stable.
// The caller downgrades the error to a warning on the tolerant load / peer-sync
// path (#1960 no-brick): a config persisted before this gate existed still
// boots, and the dataplane drops the inert rule on its own.
func validateDestinationNATAddressesStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return nil
	}
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Destination.RuleSets...)
	sort.SliceStable(rulesets, func(i, j int) bool {
		if rulesets[i] == nil || rulesets[j] == nil {
			return rulesets[i] != nil
		}
		return rulesets[i].Name < rulesets[j].Name
	})
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// Mirror the builder's destination-address gathering: prefer the
			// bracket-list form, fall back to the singular match value.
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			if len(destAddrs) == 0 {
				// No destination match at all — out of scope.
				continue
			}
			// #3228: reject the rule if ANY listed destination-address is
			// unparseable, not just when they ALL are. The snapshot builder
			// (buildDestinationNATSnapshots) strips the CIDR suffix and then
			// per-entry `continue`s past any token that is empty or fails
			// net.ParseIP — silently dropping it from the installed DNAT
			// table. A mixed list such as `[ 192.0.2.1 web-server ]` would
			// otherwise commit clean (the old anyGood break) while
			// `web-server` never translates. Mirror the builder's exact skip
			// predicate (CIDR strip via natCIDRIPPart, then empty/ParseIP
			// check) so the validator rejects precisely what the builder
			// would drop: validator and dataplane view agree, and an
			// all-valid list still compiles byte-identical.
			for _, raw := range destAddrs {
				ipPart := natCIDRIPPart(raw)
				if ipPart == "" || net.ParseIP(ipPart) == nil {
					return fmt.Errorf(
						"destination-nat rule-set %q rule %q: match destination-address "+
							"%q is not a valid IP/CIDR; the rule would commit but the "+
							"dataplane silently drops the malformed entry, leaving traffic "+
							"to it untranslated (full list: %s)",
						rs.Name, rule.Name, raw, strings.Join(destAddrs, ", "))
				}
			}
			// #3164: a DNAT `match destination-address` that is a MULTI-HOST
			// prefix (a CIDR with a non-host mask, e.g. 198.51.100.0/24) is now
			// HONORED. The snapshot builder (buildDestinationNATSnapshots) carries
			// the canonical prefix to the wire (DestinationPrefix) and the Rust
			// DnatTable installs a longest-prefix-match entry so every host in the
			// block is translated to the rule's pool. The #3029 reject that
			// previously fired here (fail-closed against silent narrowing) is gone
			// — the narrowing no longer exists. Block-mapping semantics (1:1
			// offset host-N->host-N) remain out of scope: a prefix destination is
			// a many:1 match to the configured pool, matching the documented
			// scope of #3164.
		}
	}
	return nil
}

// dnatProtocolResolvable reports whether a DNAT `match protocol` token is one
// the userspace dataplane can resolve for the DNAT match path. The DNAT path
// emits the token VERBATIM (no junos-* pre-resolution); normalization (trim +
// lower-case) matches proto_number exactly.
//
// This is a deliberately-tighter SSOT than the Rust ip_proto::proto_number
// resolver — it is NOT a 1:1 mirror of it. It is tighter in TWO ways:
//
//  1. junos-* aliases: proto_number resolves them (for the filter/application
//     paths), but the raw DNAT match-protocol path never pre-resolves them, so
//     accepting a junos-* token here would re-introduce the #2396 silent drop.
//
//  2. ipv6 (IANA protocol 41): proto_number was widened in #3393 to resolve the
//     "ipv6" name (so a firewall filter's `from protocol ipv6` round-trips),
//     but DNAT match-protocol intentionally EXCLUDES it — matching on the IPv6
//     encapsulation protocol number is not a meaningful DNAT destination-rule
//     selector here. So `match protocol ipv6` is rejected at commit even though
//     proto_number would resolve it. (filterProtocolResolvable / the appid
//     SSOT accept "ipv6"; DNAT does not — that divergence is by design.)
//
// Empty ("" = any protocol) is the IP-only wildcard and is always resolvable.
func dnatProtocolResolvable(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "",
		"tcp", "udp",
		"icmp", "icmp6", "icmpv6",
		"gre", "ospf", "ipip",
		"egp", "igmp", "pim",
		"ah", "esp", "sctp", "vrrp":
		return true
	default:
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil && n >= 0 && n < 256 {
			return true
		}
		return false
	}
}

// DNATProtocolResolvable exposes dnatProtocolResolvable for a cross-package
// drift-guard test that pins this acceptance set to its documented,
// deliberately-tighter relationship to the Rust proto_number SSOT (it excludes
// the junos-* aliases and "ipv6"/41 that proto_number resolves — see
// dnatProtocolResolvable). TEST seam, not a runtime coupling.
func DNATProtocolResolvable(token string) bool {
	return dnatProtocolResolvable(token)
}

// validateDestinationNATProtocolStrict (#2396 (a)/(3)) hard-rejects a DNAT rule
// whose `match protocol <token>` is not resolvable by the dataplane
// (dnatProtocolResolvable / proto_number). The token reaches the snapshot
// verbatim and the Rust table drops an unresolvable one with no apply failure,
// so an operator typo (`match protocol grre`) or a junos-* alias the DNAT path
// does not pre-resolve committed cleanly and silently translated nothing.
//
// Only the raw `match protocol` token is gated here. A protocol that comes from
// a resolved `match application` is validated separately by
// validateApplicationSpecsStrict (the application's own `protocol` leaf), so it
// is not re-checked. Rule-sets are walked in sorted name order and rules in
// configured order for a deterministic first-reported offender. The caller
// downgrades the error to a warning on the tolerant load / peer-sync path
// (#1960 no-brick).
func validateDestinationNATProtocolStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return nil
	}
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Destination.RuleSets...)
	sort.SliceStable(rulesets, func(i, j int) bool {
		if rulesets[i] == nil || rulesets[j] == nil {
			return rulesets[i] != nil
		}
		return rulesets[i].Name < rulesets[j].Name
	})
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// The raw match-protocol token is only emitted when the rule has no
			// application override (the builder prefers app terms). But gating it
			// regardless is correct: an unresolvable token can never be a valid
			// DNAT protocol, application override or not.
			//
			// #3431: validate EVERY protocol of a bracket list / repeated
			// `match protocol [ tcp udp ]`. The parser used to keep only the
			// first, so a bad trailing protocol committed silently AND only the
			// first protocol was ever published.
			for _, proto := range rule.Match.ProtocolList() {
				if !dnatProtocolResolvable(proto) {
					return fmt.Errorf(
						"destination-nat rule-set %q rule %q: match protocol %q is not a "+
							"resolvable protocol (known name or 0-255 number); the rule would "+
							"commit but never translate any traffic",
						rs.Name, rule.Name, proto)
				}
			}
		}
	}
	return nil
}

// validateNATMatchDestinationPortStrict (#3446) hard-rejects a source- or
// destination-NAT rule whose `match destination-port` carries a value the
// dataplane cannot honor: 0, a negative or >65535 number, or a non-numeric
// token (`http`). Static NAT already validates its typed `destination-port`
// leaf (#2491 / validateNATHostMaskStrict 1..65535); this closes the same gap
// for the source/destination NAT match grammar, whose parser used a bare
// strconv.Atoi with no bound check and whose builders cast straight to uint16
// (so 70000 wrapped to 4464, -1 to 65535) or collapsed an unparseable list to
// the wildcard port (translating EVERY port instead of failing closed).
//
// The compiled match carries two signals: DestinationPorts (every numeric
// token, including out-of-range ones) and InvalidDestinationPorts (the raw
// tokens that did not parse as integers — preserved by parseDNATPortList for
// exactly this gate). A 0/out-of-range number or any invalid token is an
// operator error that can never become a valid L4 port match.
//
// Strict on commit / commit-check (hard reject so the bad port is
// operator-visible); the compiler downgrades this to a warning on the tolerant
// load / peer-sync path (#1960 no-brick) — the snapshot builders independently
// fail CLOSED (coalescePortRanges / sourceNATDestPortRanges emit a never-match
// sentinel; the DNAT builder drops the rule rather than wildcarding), so a
// leniently-loaded bad rule installs nothing rather than over-translating.
// Rule-sets are walked in sorted name order, rules in configured order, for a
// deterministic first-reported offender.
func validateNATMatchDestinationPortStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(kind string, rulesets []*NATRuleSet) error {
		sorted := append([]*NATRuleSet(nil), rulesets...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i] == nil || sorted[j] == nil {
				return sorted[i] != nil
			}
			return sorted[i].Name < sorted[j].Name
		})
		for _, rs := range sorted {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil {
					continue
				}
				for _, p := range rule.Match.DestinationPorts {
					if p < 1 || p > 65535 {
						return fmt.Errorf(
							"%s-nat rule-set %q rule %q: match destination-port %d is out "+
								"of range (1-65535); the rule would commit but the dataplane "+
								"cannot install it as an L4 port match (the value wraps on a "+
								"uint16 cast or collapses to the wildcard port, translating "+
								"the wrong port or every port)",
							kind, rs.Name, rule.Name, p)
					}
				}
				if len(rule.Match.InvalidDestinationPorts) > 0 {
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q: match destination-port %q is not a "+
							"numeric port (1-65535); the rule would commit but the bad token "+
							"is dropped and the port match collapses to the wildcard port "+
							"(translating every port instead of failing closed)",
						kind, rs.Name, rule.Name, rule.Match.InvalidDestinationPorts[0])
				}
				// #4422: a reversed range (high < low, e.g. `destination-port
				// 4000 to 3000`) is malformed — the parser splits it into its two
				// discrete endpoints, silently matching only those two ports
				// instead of the contiguous range the operator wrote. Reject it so
				// the miscompile is operator-visible at commit.
				if len(rule.Match.ReversedDestinationPortRanges) > 0 {
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q: match destination-port %q is a "+
							"reversed range (low is greater than high); the rule would commit "+
							"but the parser splits it into the two discrete endpoints, matching "+
							"only those ports instead of the contiguous range — swap the "+
							"endpoints so low <= high",
						kind, rs.Name, rule.Name, rule.Match.ReversedDestinationPortRanges[0])
				}
			}
		}
		return nil
	}
	if err := check("source", cfg.Security.NAT.Source); err != nil {
		return err
	}
	if cfg.Security.NAT.Destination != nil {
		if err := check("destination", cfg.Security.NAT.Destination.RuleSets); err != nil {
			return err
		}
	}
	return nil
}

// validateDNATPoolStrict (#3450) hard-rejects a destination-NAT pool whose
// translated `port` or `address` the dataplane cannot honor as configured:
//
//   - M03/M04 port: the pool `port` parser used a bare strconv.Atoi with no
//     bound check and the snapshot builder cast straight to uint16, so `port
//     70000` wrapped to 4464 and `-1` to 65535 (translating to an unintended
//     backend port), while `port 0` / `port httpp` collapsed to Port==0 — which
//     the Rust DNAT path treats as "preserve the destination port", silently
//     no-op'ing the requested rewrite. PortRaw distinguishes a configured port
//     (which must be 1..65535) from no `port` leaf at all (Port==0 = the
//     legitimate preserve-port mode, left untouched).
//
//   - M05/M06 address: the builder strips any CIDR suffix and the Rust
//     DnatTable parses the remainder as a single host IpAddr, `continue`-ing
//     past anything it cannot parse. So `address 10.0.0.0/24` was coerced to
//     the network base 10.0.0.0 (no pool/range semantics — M05) and `address
//     web-server` (an address-book name) installed NO table entry, leaving the
//     VIP silently untranslated (M06). A DNAT pool address must therefore be a
//     single host the dataplane can install: a bare IP, /32, or /128
//     (isHostMaskAddress — the same predicate static NAT uses). An empty pool
//     address is also rejected: the builder skips it, so the rule is inert.
//
// Strict on commit / commit-check (hard reject so the bad value is operator-
// visible); the compiler downgrades this to a warning on the tolerant load /
// peer-sync path (#1960 no-brick) — the snapshot builder independently fails
// CLOSED (it skips the rule rather than wrapping the port or coercing the
// address), so a leniently-loaded bad pool installs nothing rather than
// translating wrongly. Pools are walked in sorted name order for a
// deterministic first-reported offender.
func validateDNATPoolStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return nil
	}
	pools := cfg.Security.NAT.Destination.Pools
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pool := pools[name]
		if pool == nil {
			continue
		}
		// Port: only validate when a `port` leaf was actually configured.
		// No leaf (PortRaw == "") leaves Port == 0 = preserve-destination-port,
		// which is legitimate and untouched.
		if pool.PortRaw != "" {
			n, err := parseCanonicalPort(pool.PortRaw)
			if err != nil {
				return fmt.Errorf(
					"destination-nat pool %q: port %q is not a numeric port (1-65535); "+
						"the rule would commit but the bad token is dropped and the pool "+
						"port collapses to 0 (preserve destination port), silently "+
						"no-op'ing the requested rewrite",
					name, pool.PortRaw)
			}
			if n < 1 || n > 65535 {
				return fmt.Errorf(
					"destination-nat pool %q: port %d is out of range (1-65535); the rule "+
						"would commit but the value wraps on a uint16 cast (e.g. 70000->4464, "+
						"-1->65535) or collapses to 0 (preserve destination port), translating "+
						"to an unintended backend port or silently no-op'ing the rewrite",
					name, n)
			}
		}
		// Address: the dataplane needs a single host (bare IP, /32, or /128).
		if pool.Address == "" {
			return fmt.Errorf(
				"destination-nat pool %q: no translated address configured; the rule "+
					"would commit but the dataplane installs no entry, leaving matching "+
					"traffic untranslated", name)
		}
		if host, _ := isHostMaskAddress(pool.Address); !host {
			return fmt.Errorf(
				"destination-nat pool %q: address %q is not a single host address "+
					"(a bare IP, /32, or /128); the rule would commit but the dataplane "+
					"coerces a non-host CIDR to its network base (no pool/range semantics) "+
					"or drops an unparseable token (e.g. an address-book name), leaving "+
					"matching traffic translated to the wrong address or untranslated",
				name, pool.Address)
		}
	}
	return nil
}

// validateSourceNATPoolStrict (#3906) hard-rejects a source-NAT pool whose
// `port range <low> to <high>` the dataplane cannot honor as configured:
//
//   - a REVERSED range (low > high) — the Rust allocator marks the pool
//     unusable (SourceNatFailureReason::InvalidPortRange) and drops the rule at
//     runtime, so the config commits green then silently stops translating; and
//   - an OUT-OF-RANGE endpoint (low < 1 or high > 65535) — a port cannot live
//     outside 1..65535, and the u16 wire slot would wrap it.
//
// Before #3906 the pool `port range <low> to <high>` was parsed with the wrong
// keyword shape and silently ignored (the pool defaulted to 1024-65535 PAT), so
// an operator narrowing the pool to a specific range got the full default range
// and a reversed range was never caught. Only an EXPLICITLY configured range is
// validated: a pool with no `port` leaf keeps PortLow==0/PortHigh==0 (defaulted
// to 1024/65535 downstream) and is left untouched. A `port no-translation` pool
// preserves the source port and ignores the range entirely, so its (defaulted)
// range is not an error.
//
// #5457: parseSourcePoolPortRange now FAILS CLOSED on a non-canonical token, an
// endpoint outside 1..65535 (0 included), or a reversed range — it leaves
// PortLow/PortHigh at the default and records the raw spec in
// PortRangeInvalidSpec. That marker (checked first below) is the primary reject
// signal; the stamped low/high checks remain as a backstop. This closes the
// pre-#5457 residual where a 0-valued endpoint escaped as the "unconfigured"
// sentinel and silently widened to the default PAT range.
//
// Strict on commit / commit-check (hard-reject so the bad value is operator-
// visible); the compiler downgrades this to a warning on the tolerant load /
// peer-sync path (#1960 no-brick) — the snapshot builder independently fails
// CLOSED (sourceNATPoolPortRange returns !valid, marking the pool unusable), so
// a leniently-loaded bad range installs nothing rather than translating wrongly.
// Pools are walked in sorted name order for a deterministic first-reported
// offender.
func validateSourceNATPoolStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pools := cfg.Security.NAT.SourcePools
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pool := pools[name]
		if pool == nil {
			continue
		}
		// #5457: an explicit `port [range]` leaf whose value the parser rejected
		// (a non-canonical token, an endpoint outside 1..65535 including 0, or a
		// reversed range). parseSourcePoolPortRange failed closed and left
		// PortLow/PortHigh at their default, recording the raw offending spec
		// here — so this is the ONLY signal a bad range survives. Hard-reject
		// (downgraded to a warning on the tolerant path) so the operator sees the
		// bad value instead of the pool silently PAT-translating over the
		// defaulted 1024-65535 range; the snapshot builder independently marks the
		// pool unusable when this is set.
		if pool.PortRangeInvalidSpec != "" {
			return fmt.Errorf(
				"source-nat pool %q: port range %q is invalid; source-pool ports "+
					"must be 1-65535 and the range non-decreasing — the rule would "+
					"commit but the dataplane marks the pool unusable and drops it at "+
					"runtime, silently stopping translation",
				name, pool.PortRangeInvalidSpec)
		}
		// Only validate an EXPLICITLY configured range. No `port` leaf leaves
		// PortLow/PortHigh at 0 (defaulted to 1024/65535 downstream) — the
		// legitimate default-PAT mode, untouched. These stamped-value checks are
		// a belt-and-suspenders backstop: after #5457 parseSourcePoolPortRange
		// never stamps an out-of-range/reversed value (it sets
		// PortRangeInvalidSpec above instead), so they guard only a future path
		// that writes PortLow/PortHigh directly.
		low := pool.PortLow
		high := pool.PortHigh
		if low == 0 && high == 0 {
			continue
		}
		if low < 1 || low > 65535 || high < 1 || high > 65535 {
			return fmt.Errorf(
				"source-nat pool %q: port range %d to %d is out of range (1-65535); "+
					"the rule would commit but the dataplane marks the pool unusable and "+
					"drops the rule at runtime, silently stopping translation",
				name, low, high)
		}
		if low > high {
			return fmt.Errorf(
				"source-nat pool %q: port range low %d is greater than high %d "+
					"(reversed); the rule would commit but the dataplane marks the pool "+
					"unusable and drops the rule at runtime, silently stopping translation",
				name, low, high)
		}
	}
	return nil
}

// #6041: validateSourceNATPersistentNoTranslationStrict (the #5819 fail-closed
// reject of `persistent-nat` + `port no-translation`) was REMOVED here. The
// userspace dataplane now implements an address-only persistent lease
// (reserve_address_only_persistent, userspace-dp/src/nat/allocator.rs) that
// pins a public pool ADDRESS across the configured permit scope without
// consuming a translated pool port, so the combination is supported and no
// longer silently degrades. The paired snapshot fail-closed marker
// ("persistent_nat_no_translation" in pkg/dataplane/userspace/nat_source.go)
// was removed with it.

// validateNATPoolReferencesStrict (#5626) hard-rejects a source- or
// destination-NAT rule whose `then ... pool <name>` names a pool that is NOT
// defined under `security nat source pool <name>` (SNAT) or `security nat
// destination pool <name>` (DNAT).
//
// A rule referencing an undefined pool committed cleanly — the only feedback
// was a warn-only advisory (formerly ValidateConfig, now subsumed by this
// gate) — and then behaved incorrectly at runtime in an ORDER-DEPENDENT way.
// The SNAT snapshot builder (pkg/dataplane/userspace/nat_source.go) marks the
// rule poolUnusable with reason "missing_pool" and the DNAT builder
// (nat_destination.go) drops the rule outright (the pool lookup misses), so
// the requested translation silently never fires and matching traffic falls
// through to whatever a later rule or the no-NAT default does. The operator
// got a green commit for a NAT rule that quietly does nothing.
//
// Pool-reference resolution mirrors the snapshot builders EXACTLY: an SNAT
// `then source-nat pool` name must key cfg.Security.NAT.SourcePools; a DNAT
// `then destination-nat pool` name must key
// cfg.Security.NAT.Destination.Pools. A rule with no pool reference (`then ...
// interface`, `then ... off`, or an empty then) carries PoolName == "" and is
// out of scope. Static NAT (`then static-nat prefix`) takes a literal address,
// not a pool reference, so it has nothing to resolve here.
//
// Strict on commit / commit-check (hard reject naming the NAT kind, rule-set,
// rule, and the undefined pool); lenient on load / peer-sync (warn — #1960
// no-brick; the snapshot builders independently fail CLOSED — SNAT marks the
// rule unusable, DNAT drops it — so a leniently-loaded config that references a
// dangling pool installs nothing rather than mis-translating). Shares the
// lenientDestNATAddresses flag (same NAT silent-drop doctrine as the sibling
// pool-value gates). Rule-sets are walked in sorted name order (source-first,
// then destination) for a deterministic first-reported offender. Mirrors
// validateSourceNATPoolStrict / validateNATSourceAddressNameReferencesStrict.
func validateNATPoolReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(kind string, rulesets []*NATRuleSet, pools map[string]*NATPool) error {
		sorted := append([]*NATRuleSet(nil), rulesets...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i] == nil || sorted[j] == nil {
				return sorted[i] != nil
			}
			return sorted[i].Name < sorted[j].Name
		})
		for _, rs := range sorted {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil || rule.Then.PoolName == "" {
					continue
				}
				if _, ok := pools[rule.Then.PoolName]; !ok {
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q references undefined pool %q; "+
							"define `security nat %s pool %s ...` in the same commit — "+
							"otherwise the rule commits but the dataplane fails the "+
							"translation closed (the pool lookup misses, so the rule is "+
							"dropped / marked unusable) and matching traffic is silently "+
							"left untranslated, falling through to a later rule or the "+
							"no-NAT default",
						kind, rs.Name, rule.Name, rule.Then.PoolName, kind, rule.Then.PoolName)
				}
			}
		}
		return nil
	}
	if err := check("source", cfg.Security.NAT.Source, cfg.Security.NAT.SourcePools); err != nil {
		return err
	}
	if cfg.Security.NAT.Destination != nil {
		if err := check("destination", cfg.Security.NAT.Destination.RuleSets, cfg.Security.NAT.Destination.Pools); err != nil {
			return err
		}
	}
	return nil
}

// MaxSourceNATPoolPrefixHosts mirrors the userspace-dp
// MAX_POOL_PREFIX_HOSTS constant (`userspace-dp/src/nat/source.rs`, #3049):
// the upper bound on how many host addresses ONE source-NAT pool prefix is
// expanded into by the Rust SNAT allocator. A pool member CIDR whose host
// count exceeds this cap (an over-broad `/15`, `/8`, or any v6 prefix shorter
// than `/112`) makes `expand_pool_address` return false, and the allocator
// marks the WHOLE pool `InvalidPool`. The Go strict validator uses the same
// bound so a pool the dataplane cannot honor is rejected at commit, not after
// apply. A `/16` (exactly 65536 hosts) is at the cap and accepted, matching
// the Rust `count > MAX_POOL_PREFIX_HOSTS` comparison exactly.
const MaxSourceNATPoolPrefixHosts = 65536

// sourceNATPoolAddressReason validates one source-NAT pool address member
// against the live Rust pool grammar (`expand_pool_address`,
// `userspace-dp/src/nat/source.rs`) and returns a human-readable reason when
// the member is NOT honorable (ok=false), or ("", true) when it is.
//
// The live grammar accepts exactly two shapes:
//
//   - a bare IP (no `/`), parsed as a single host; and
//   - a CIDR (`a.b.c.d/n`), enumerated over its FULL prefix range, valid only
//     when the host count `1 << (addrbits - n)` does not exceed
//     MaxSourceNATPoolPrefixHosts.
//
// Anything else — an unparseable token (`not-an-ip`), a malformed mask
// (`203.0.113.1/garbage`), or an over-capacity prefix (`/15`, `10.0.0.0/8`, a
// v6 prefix shorter than `/112`) — makes the Rust allocator return false for
// the member and mark the pool `InvalidPool`, so the Go grammar must reject it
// too. netip.ParsePrefix accepts a non-canonical prefix with host bits set; the
// runtime masks to the network base, so the Go side counts hosts off the prefix
// LENGTH exactly as Rust does.
//
// GRAMMAR PARITY (#6812 F1 round 3). "Mirrors expand_pool_address" is a claim
// about two PARSERS agreeing, and it is not established by sharing this
// predicate between two Go call sites — that only makes the two GO sites agree.
// A measured differential over both real parsers found the two sides disagreed
// on six inputs, in both directions:
//
//   - `010.0.0.0/24` and its siblings (a leading-zero IPv4 octet inside a CIDR,
//     including the embedded-v4 form `::ffff:010.0.0.0/120`). netip rejects a
//     leading-zero octet; the Rust CIDR branch used to parse via `IpNet`, whose
//     hand-rolled octet reader accepts up to three digits with any leading
//     zeros, so the dataplane expanded a working 256-address allocator for a
//     pool this predicate stamped `invalid_pool`. Closed in the RUNTIME (round
//     3): expand_pool_address now parses its address half with the same
//     `std::net::IpAddr` its bare branch always used, so the ambiguous spelling
//     is InvalidPool on both sides — the verdict this predicate already gave.
//     Widening Go instead would have blessed an octal-confusion spelling at
//     commit, and mirrored a third-party crate's accident as policy.
//   - `fe80::1%eth0` (a zone qualifier on a BARE member). netip.ParseAddr
//     carries a zone; std::net::IpAddr has no zone model and refuses it. Closed
//     HERE, by the zone check below: the CIDR form was already refused (netip
//     .ParsePrefix rejects a zone outright), so only the bare form diverged.
//     The pool-level reason is unchanged — SourceNATPoolUnusableReason writes
//     the specific #5875 `zone_scoped_pool_address` after this clause — and so
//     is the strict message, because validateSourceNATPoolAddressScopeStrict is
//     registered BEFORE the grammar gate in both runUniformGates and the
//     peer-effective SNAT gate set.
//
// The table that decides both is ONE file — userspace-dp/tests/fixtures/
// snat_pool_grammar_v1.json — read by TestPoolAddressGrammarMatchesDataplane_6812
// here and by nat_pool_grammar_parity_fixture (userspace-dp/src/nat/
// tests_aggregate_budget.rs) through the real expand_pool_address. Neither side
// keeps a copy, so the next divergence reds a test instead of surviving to a
// review round.
func sourceNATPoolAddressReason(addr string) (string, bool) {
	if strings.Contains(addr, "/") {
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			if hint := canonicalPoolAddressHint(addr); hint != "" {
				return leadingZeroPoolAddressReason(addr, hint), false
			}
			return "is not a valid CIDR (the dataplane cannot expand it and marks the pool unusable)", false
		}
		addrBits := 32
		if p.Addr().Is6() {
			addrBits = 128
		}
		hostBits := addrBits - p.Bits()
		// Mirror the Rust arithmetic: reject when the enumerated host count
		// exceeds the cap. The hostBits >= 64 guard both matches the Rust v6
		// early-out and prevents a 1<<hostBits shift overflow (Go defines an
		// over-wide shift as 0, which would otherwise UNDER-count and wrongly
		// accept an astronomically large prefix).
		if hostBits >= 64 || uint64(1)<<uint(hostBits) > MaxSourceNATPoolPrefixHosts {
			return fmt.Sprintf(
				"expands to more than %d host addresses, over the pool cap (the "+
					"dataplane rejects the prefix and marks the pool unusable)",
				MaxSourceNATPoolPrefixHosts), false
		}
		return "", true
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		if hint := canonicalPoolAddressHint(addr); hint != "" {
			return leadingZeroPoolAddressReason(addr, hint), false
		}
		return "is not a valid IP address (the dataplane cannot parse it and marks the pool unusable)", false
	}
	// #6812 F1 round 3: netip carries an IPv6 zone (`fe80::1%eth0`) that
	// std::net::IpAddr — the parser expand_pool_address's bare branch uses —
	// cannot represent, so accepting it here would claim a member is honorable
	// that the dataplane refuses. The scoped CIDR form already failed above.
	if a.Zone() != "" {
		return "carries an IPv6 zone qualifier the dataplane cannot represent (it marks the pool unusable)", false
	}
	return "", true
}

// validateSourceNATPoolAddressGrammarStrict (#5627) hard-rejects a source-NAT
// pool, REFERENCED by a pool-mode `then source-nat pool <name>` rule, whose
// address membership the live Rust dataplane cannot honor as configured —
// closing a commit-vs-apply grammar divergence (codex-review-181 M15 /
// A3-b00-F02).
//
// The prior strict path (validateSourceNATPoolStrict) validated only a pool's
// `port range`; it left the pool's ADDRESS members completely unchecked. The
// snapshot builder (pkg/dataplane/userspace/nat_source.go) copies the raw
// address strings onto the wire, and the Rust allocator
// (`expand_pool_address` / `parse_source_nat_rules`,
// `userspace-dp/src/nat/source.rs`) then rejects a malformed member, an
// over-capacity prefix (host count > MaxSourceNATPoolPrefixHosts), or an empty
// pool — marking the rule `InvalidPool` / `EmptyPool` and DROPPING it. So a
// pool referencing `not-an-ip`, `203.0.113.1/garbage`, `10.0.0.0/8`, an
// over-cap `/15`, or no addresses at all committed green then silently stopped
// translating after apply: a single bad member poisons an otherwise usable
// pool, producing a persistent NAT outage visible only at runtime.
//
// The gate iterates only pools that a pool-mode source-NAT rule actually
// references (the exact set the dataplane snapshot expands — an unreferenced
// pool never reaches the Rust grammar), in sorted rule-set / declaration order
// for a deterministic first-reported offender. An UNDEFINED reference is
// validateNATPoolReferencesStrict's (#5626) domain and is skipped here. Host
// counting is O(pool address entries) with no enumeration — the invariant the
// audit requires (do not expand up to 65,536 hosts in Go).
//
// Strict on commit / commit-check (hard-reject so the un-honorable pool is
// operator-visible); the call site downgrades this to a warning on the
// tolerant load / peer-sync path (opts.lenientDestNATAddresses — the shared
// NAT silent-drop / wrong-translate doctrine, as validateNATPoolReferencesStrict
// and validateSourceNATPoolStrict use) so an already-persisted or peer-synced
// config carrying such a pool still BOOTS (#1960 no-brick) — the snapshot
// builder independently marks the pool unusable, installing nothing rather
// than translating wrongly. Mirrors validateSourceNATPoolStrict.
func validateSourceNATPoolAddressGrammarStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pools := cfg.Security.NAT.SourcePools
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Source...)
	sort.SliceStable(rulesets, func(i, j int) bool {
		if rulesets[i] == nil || rulesets[j] == nil {
			return rulesets[i] != nil
		}
		return rulesets[i].Name < rulesets[j].Name
	})
	seen := make(map[string]bool)
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			name := rule.Then.PoolName
			if seen[name] {
				continue
			}
			seen[name] = true
			pool, ok := pools[name]
			if !ok || pool == nil {
				// Undefined reference — validateNATPoolReferencesStrict (#5626).
				continue
			}
			// Mirror the snapshot builder's live address set: the DNAT-compat
			// single Address (unused by source pools today, but included for
			// parity) plus the source pool Addresses.
			var addrs []string
			if pool.Address != "" {
				addrs = append(addrs, pool.Address)
			}
			addrs = append(addrs, pool.Addresses...)
			if len(addrs) == 0 {
				return fmt.Errorf(
					"source-nat pool %q (referenced by rule-set %q rule %q) has no "+
						"pool addresses; the rule commits but the dataplane marks the "+
						"pool unusable (EmptyPool) and drops it at runtime, silently "+
						"stopping translation",
					name, rs.Name, rule.Name)
			}
			for _, a := range addrs {
				if reason, ok := sourceNATPoolAddressReason(a); !ok {
					return fmt.Errorf(
						"source-nat pool %q (referenced by rule-set %q rule %q): "+
							"address %q %s; a single malformed or over-capacity member "+
							"poisons the whole pool — the rule commits but the dataplane "+
							"marks the pool unusable (InvalidPool) and drops it at runtime, "+
							"silently stopping translation",
						name, rs.Name, rule.Name, a, reason)
				}
			}
		}
	}
	return nil
}

// PoolAddressHasZoneScope reports whether a source-NAT pool address literal
// carries an IPv6 zone/scope qualifier (`%<zone>`), e.g. `fe80::1%eth0`
// (#5875). The Junos lexer permits the `%`-qualified text (lexer.go isIdentChar
// admits `%`) and Go's netip.ParseAddr accepts a zone, so a scoped literal
// passes the source-pool address grammar gate. But the live Rust allocator
// parses each pool member as std::net::IpAddr (`expand_pool_address`,
// userspace-dp/src/nat/source.rs), which has NO zone model, so the scoped form
// fails to parse and the whole pool is marked InvalidPool and dropped at apply.
//
// No legitimate source-NAT pool address ever carries a `%zone` suffix — a
// global SNAT pool address needs no interface scope, and `%` is not part of any
// IPv4/IPv6/CIDR literal — so a `%` anywhere in the member is unambiguously the
// zone qualifier. Detection is a plain substring test so it also catches a
// scoped-CIDR (`fe80::1%eth0/64`) form that netip.ParsePrefix would reject with
// a less specific message. Shared by the strict validator
// (validateSourceNATPoolAddressScopeStrict) and the userspace snapshot builder
// (pkg/dataplane/userspace/nat_source.go) so both fail closed identically.
func PoolAddressHasZoneScope(addr string) bool {
	return strings.Contains(addr, "%")
}

// validateSourceNATPoolAddressScopeStrict (#5875) hard-rejects a source-NAT
// pool, referenced by a pool-mode `then source-nat pool <name>` rule, whose
// address membership carries an IPv6 zone/scope qualifier (`%<zone>`) that the
// live Rust dataplane cannot represent — a NEW representability constraint
// alongside validateSourceNATPoolAddressGrammarStrict (#5627).
//
// A scoped literal such as `fe80::1%eth0` passes the grammar gate because Go's
// netip.ParseAddr accepts a zone identifier, and the snapshot builder copies
// the raw string onto the wire. But Rust parses pool members as
// std::net::IpAddr (no scope model), so `expand_pool_address` returns false,
// the allocator marks the whole pool InvalidPool, and the rule silently stops
// translating after apply — a commit-vs-apply divergence. Rejecting the scoped
// form is safe: a global SNAT pool address never needs an interface scope, and
// stripping the `%zone` silently would change the modeled address, so the fix
// rejects rather than rewrites (per the issue's "do not strip %zone silently").
//
// Mirrors validateSourceNATPoolAddressGrammarStrict's scoping exactly: only
// pools a pool-mode rule references are checked (an unreferenced pool never
// reaches the Rust grammar), in sorted rule-set / declaration order for a
// deterministic first-reported offender. Dispatched BEFORE the grammar gate so
// a `%zone`-scoped member (including a scoped-CIDR the grammar gate would
// otherwise reject with a generic invalid-CIDR message) gets this precise,
// actionable scope diagnostic. Strict on commit / commit-check
// (hard-reject so the un-representable pool is operator-visible); the call site
// (runUniformGates) downgrades it to a warning on the tolerant load / peer-sync
// path (#1960 no-brick) — the snapshot builder independently marks the pool
// unusable (reason "zone_scoped_pool_address"), installing nothing rather than
// shipping the unparseable string. Because it is registered in the SNAT strict
// set, the #5876 peer-effective SNAT gate runs it against the peer view too.
func validateSourceNATPoolAddressScopeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pools := cfg.Security.NAT.SourcePools
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Source...)
	sort.SliceStable(rulesets, func(i, j int) bool {
		if rulesets[i] == nil || rulesets[j] == nil {
			return rulesets[i] != nil
		}
		return rulesets[i].Name < rulesets[j].Name
	})
	seen := make(map[string]bool)
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			name := rule.Then.PoolName
			if seen[name] {
				continue
			}
			seen[name] = true
			pool, ok := pools[name]
			if !ok || pool == nil {
				// Undefined reference — validateNATPoolReferencesStrict (#5626).
				continue
			}
			var addrs []string
			if pool.Address != "" {
				addrs = append(addrs, pool.Address)
			}
			addrs = append(addrs, pool.Addresses...)
			for _, a := range addrs {
				if PoolAddressHasZoneScope(a) {
					return fmt.Errorf(
						"source-nat pool %q (referenced by rule-set %q rule %q): "+
							"address %q carries an IPv6 zone/scope qualifier (%%zone), "+
							"which the dataplane cannot represent — Rust parses pool "+
							"members as an unscoped IP address, so the rule commits but "+
							"the dataplane marks the pool unusable (InvalidPool) and "+
							"drops it at runtime, silently stopping translation; remove "+
							"the %%zone suffix (a global SNAT pool address needs no scope)",
						name, rs.Name, rule.Name, a)
				}
			}
		}
	}
	return nil
}

// validateNATSourceAddressNameReferencesStrict hard-rejects a source or
// destination NAT rule whose `match source-address-name <name>` OR `match
// destination-address-name <name>` (#3229) names an address-book entry that
// either is not defined under `security address-book` (#2416) OR is defined
// but does not resolve to >= 1 concrete address (#3425).
//
// The name is resolved to concrete prefixes at snapshot-build time
// (appendNATSourceAddressName → resolveNATAddressNamePrefixes →
// expandBookNameRecursive, the feed-aware recursive expander since #4925). Two
// distinct failures both translate to a rule that matches NOTHING (fail-closed
// but SILENT):
//
//   - a wholly UNDEFINED name (a typo) — neither an address-book entry nor a
//     dynamic-address feed binding; and
//   - a DEFINED-but-UNRESOLVABLE name (#3425) — a defined `address` with no
//     prefix (empty Value), a defined-but-EMPTY `address-set`, or a set with a
//     dangling / member-less expansion. expandBookNameRecursive returns an
//     empty prefix list for these, so the builder appends the raw (unparseable)
//     token to keep the constraint non-empty and the rule translates no
//     traffic — exactly the policy-address fail-open class #3149 closes for
//     security policies, here for NAT.
//
// This gate makes BOTH visible at commit, consistent with the policy-address
// representability gate (validatePolicyMatchAddressSetMembersStrict) and the
// NAT match-application gate (validateNATMatchApplicationsStrict).
//
// Feed carve-out (#3303 / #3294): a DIRECT `match ...-address-name <feed-name>`
// reference to a `security dynamic-address address-name <name> profile <feed>`
// binding is ACCEPTED — the static book expansion is empty but
// resolveNATAddressNamePrefixes unions the live feed overlay at runtime, so the
// rule does carry prefixes. Mirrors validatePolicyMatchAddressesStrict's
// AddressBindings carve-out; deliberately scoped to the DIRECT reference. At
// THIS strict commit gate a feed member NESTED in an address-set is NOT covered
// by the carve-out: nested membership is judged by the static
// policyMatchAddressBookResolves check (which never consults the feed overlay),
// so a set whose only resolvable content is a feed member is still rejected at
// commit — the anti-Option-C guardrail, identical to the policy path.
//
// This paragraph describes the STRICT-COMMIT gate behavior ONLY. Since #4925 the
// LENIENT runtime resolver (resolveNATAddressNamePrefixes ->
// expandBookNameRecursive, pkg/dataplane/userspace/nat.go) DOES feed-resolve
// nested set members via the policy SSOT expander, so at RUNTIME a mixed
// static+feed set partially resolves (it carries the resolvable members'
// prefixes) instead of being poisoned whole. The commit gate is intentionally
// stricter than the runtime path; this comment does not change that behavior.
//
// On the tolerant load / peer-sync paths the call site downgrades to a warning
// (opts.lenientFirewallRefs) so an already-persisted or peer-synced config
// still BOOTS (#1960); the dataplane then fails closed for the unresolved
// reference. Rule-sets are walked source-first then destination, in slice
// order, for a deterministic first error.
func validateNATSourceAddressNameReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	feedBinding := func(name string) bool {
		if name == "" {
			return false
		}
		_, ok := cfg.Security.DynamicAddress.AddressBindings[name]
		return ok
	}
	defined := func(name string) bool {
		if name == "" || ab == nil {
			return false
		}
		if _, ok := ab.Addresses[name]; ok {
			return true
		}
		_, ok := ab.AddressSets[name]
		return ok
	}
	// nameError returns nil when the reference is valid, or the strict
	// rejection error otherwise. field is "source-address-name" /
	// "destination-address-name" and scope is "source scope" / "destination
	// scope" for the operator-facing message.
	nameError := func(natType, ruleSet, ruleName, field, scope, name string) error {
		if name == "" || feedBinding(name) {
			return nil
		}
		if !defined(name) {
			return fmt.Errorf(
				"%s NAT rule-set %q rule %q references undefined "+
					"%s %q (define `security address-book "+
					"address %s` / `address-set %s`, or fix the name — the "+
					"%s would otherwise be silently lost and the "+
					"rule would match no traffic)",
				natType, ruleSet, ruleName, field, name, name, name, scope)
		}
		// #3425: a DEFINED name that the runtime resolver cannot expand to >= 1
		// literal address (empty address, empty/dangling set). The builder
		// appends the raw token → the rule is non-empty but unmatchable. Reject
		// it so the operator sees the dead scope at commit.
		if cause := policyMatchAddressBookResolves(ab, name); cause != nil {
			return fmt.Errorf(
				"%s NAT rule-set %q rule %q match %s %q does not resolve to "+
					"any address: %w — the rule commits but the dataplane "+
					"installs a match-nothing %s so the translation never "+
					"fires (add at least one resolvable member / a prefix to "+
					"the address, or remove the reference) (#3425)",
				natType, ruleSet, ruleName, field, name, cause, scope)
		}
		return nil
	}
	check := func(natType string, rs *NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #3431: validate EVERY name in a bracket list / repeated
			// `match source-address-name [ a b ]`, not just the first.
			for _, name := range rule.Match.SourceAddressNameList() {
				if err := nameError(natType, rs.Name, rule.Name,
					"source-address-name", "source scope", name); err != nil {
					return err
				}
			}
			// #3229: destination-address-name is the destination twin of
			// source-address-name and resolves through the same address-book
			// expander (appendNATDestinationAddressName). A dangling or
			// unresolvable reference installs no destination = the rule matches
			// nothing (fail-closed but silent); gate it here so the problem is
			// operator-visible at commit, exactly like the source name above.
			// #3431: validate every value of a bracket list / repeated leaf.
			for _, name := range rule.Match.DestinationAddressNameList() {
				if err := nameError(natType, rs.Name, rule.Name,
					"destination-address-name", "destination scope", name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, rs := range cfg.Security.NAT.Source {
		if err := check("source", rs); err != nil {
			return err
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if err := check("destination", rs); err != nil {
				return err
			}
		}
	}
	return nil
}

// validatePoolUtilizationAlarm is the #2079 strict-vs-lenient gate for the
// `security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// thresholds. Junos requires only raise-threshold; clear-threshold is optional
// and, when omitted, is defaulted at parse time to a hysteresis margin below
// raise (defaultPoolAlarmClearThreshold, #4077) so a raise-only alarm both
// commits and runs. This gate therefore only ever sees a zero/invalid
// clear-threshold when the operator EXPLICITLY provided one. A bare
// `pool-utilization-alarm;` compiles to raise=0/clear=0 (an always-firing
// alarm) and inverted/equal thresholds make hysteresis meaningless. Strict
// (commit / commit-check): hard-reject. Lenient (load / peer-sync, #1979
// doctrine): return the message as a warning so a config committed before this
// gate existed still boots (#1960 fail-closed-on-compile-failure would
// otherwise brick the daemon on restart). The runtime monitor treats raise<=0
// as disabled, so a leniently loaded bad config is inert, not always-firing.
func validatePoolUtilizationAlarm(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	a := cfg.Security.NAT.PoolUtilizationAlarm
	if a == nil {
		return nil, nil
	}
	var msg string
	switch {
	case a.RaiseThreshold <= 0 || a.RaiseThreshold > 100:
		msg = fmt.Sprintf("pool-utilization-alarm: raise-threshold must be in 1..100, got %d", a.RaiseThreshold)
	case a.ClearThreshold <= 0 || a.ClearThreshold >= a.RaiseThreshold:
		msg = fmt.Sprintf("pool-utilization-alarm: clear-threshold must be in 1..raise-threshold-1 (0 < clear < raise), got clear=%d raise=%d", a.ClearThreshold, a.RaiseThreshold)
	default:
		return nil, nil
	}
	if lenient {
		return []string{msg + " (ignored: alarm disabled until corrected)"}, nil
	}
	return nil, fmt.Errorf("%s", msg)
}

// isNAT64PoolHostAddress reports whether addr is an IPv4 host route the
// NAT64 source pool can install. It mirrors EXACTLY the Rust parse_pool_v4
// gate (userspace-dp/src/nat64.rs): the NAT64 pool holds IPv4 source
// addresses, so it accepts ONLY a bare IPv4 address or an IPv4 /32 — an
// IPv6 address (bare or any mask, INCLUDING the IPv4-mapped ::ffff:x.x.x.x
// form that Ipv4Addr::from_str rejects) and a non-host IPv4 mask are all
// silently dropped by parse_pool_v4, so the commit gate must reject them
// too or the gate and the dataplane disagree. Family is keyed on
// natAddrFamily (textual, colon == v6) to match Ipv4Addr::from_str. The
// second return value reports whether addr parsed as an IP at all (so a
// non-IP address-book token is left to existing handling); a parseable
// non-IPv4 address returns (host=false, parsed=true) — it parsed, but is
// not an installable pool address.
func isNAT64PoolHostAddress(addr string) (host bool, parsed bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam := natAddrFamily(ipPart)
	if fam == "" {
		return false, false
	}
	if fam != "v4" {
		// Parsed, but not an IPv4 pool address — reject (parse_pool_v4 drops).
		return false, true
	}
	if slash < 0 {
		return true, true
	}
	// Only an IPv4 /32 is an installable pool host address.
	return addr[slash+1:] == "32", true
}

// nptv6PrefixHasHostBits reports whether the CIDR text `cidr` carries any
// bit set beyond its prefix length — i.e. the raw address is not equal to
// its own network (masked) address. `parsed` is the *net.IPNet returned by
// net.ParseCIDR(cidr) (its .IP is already masked); the comparison parses the
// raw IP part of the original text and re-masks it under the same mask. The
// second return value is false when the raw IP cannot be parsed (the caller
// has already proven cidr parses via ParseCIDR, so this is defensive only).
// #2380: net.ParseCIDR silently masks, so this surfaces the discarded bits.
func nptv6PrefixHasHostBits(cidr string, parsed *net.IPNet) (host bool, ok bool) {
	if parsed == nil {
		return false, false
	}
	raw := net.ParseIP(natCIDRIPPart(cidr))
	if raw == nil {
		return false, false
	}
	// Mask the raw address with the prefix's mask and compare to the raw
	// address. If they differ, host/subnet bits were set beyond the prefix.
	masked := raw.Mask(parsed.Mask)
	if masked == nil {
		// Mask width does not match the address family — should not happen
		// for an IPv6 prefix that already parsed, but treat as no host bits.
		return false, true
	}
	return !masked.Equal(raw), true
}

// validateNATHostMaskStrict is the #2173 strict-vs-lenient gate that
// rejects a static-NAT match/prefix or a NAT64 source-pool address whose
// mask is not a host route (/32 for v4, /128 for v6; a bare address is a
// host too). #2132 made the Rust dataplane TOLERATE the canonical host
// mask, and PR #2167 then hardened the Rust parser to REJECT a non-host
// mask — so today a misconfigured /24 static-NAT match or pool address is
// SILENTLY DROPPED at the dataplane (the rule is parsed-out, never
// installed) with no operator feedback. This commit-time check surfaces
// the misconfiguration at `commit`/`commit check` instead.
//
// Scope mirrors what the Rust host-mask gate covers:
//   - static-NAT rules' `match destination-address` (-> ExternalIP) and
//     `then static-nat prefix` (-> InternalIP). NPTv6 (`nptv6-prefix`) and
//     NAT64 (`static-nat inet`) rules are EXEMPT: NPTv6 is a genuine prefix
//     translation (RFC 6296), and an `inet` rule's match is the NAT64
//     well-known prefix (e.g. 64:ff9b::/96) with translation driven by the
//     separate NAT64 snapshot, not the static_nat table.
//   - NAT64 source-pool addresses (the IPv4 pool referenced by a
//     `nat64 rule-set ... source-pool` — parse_pool_v4 host-mask gate).
//
// Strict (commit / commit-check): hard-reject. Lenient (load / peer-sync,
// #1960 / #1979 doctrine): return the message as a warning so a config
// committed before this gate existed still boots (fail-closed-on-compile-
// failure would otherwise brick the daemon on restart); the dataplane
// independently drops the bad entry, so a leniently-loaded config is
// already inert for that rule, not mis-installed.
func validateNATHostMaskStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	// emitSuffix returns a violation as an error (strict) or appends it to the
	// lenient warning list with a dataplane-effect suffix. The suffix differs
	// by case: a static-NAT IP failure drops the WHOLE rule (parse_nat_addr
	// returns None for the rule's match/then), whereas a NAT64 source-pool
	// entry is dropped individually by filter_map(parse_pool_v4) — the rest of
	// the pool/rule stays installed. Keep the load-path text precise so the
	// operator does not over-read the impact.
	emitSuffix := func(msg, suffix string) error {
		if lenient {
			warnings = append(warnings, msg+suffix)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	// ruleDropped records whether ANY check in the static-NAT rule currently
	// being validated has already reported a cause that drops the WHOLE rule.
	// Reset at the top of each rule; read only when resolving the deferred
	// emitMatchAddr suffixes at the end of that rule.
	//
	// #6673: it is set by `emit` itself rather than by a hand-maintained list
	// of causes. `emit` IS the rule-dropped closure — its suffix is "rule
	// dropped by dataplane until corrected" — so every present and future
	// caller of it marks the rule automatically, and a check that reports a
	// NARROWER effect correctly does not. The previous spelling mirrored the two
	// match-side loops by hand and was wrong by three causes: the then-side
	// parse, the then-side host-mask, and the /0 block-pair loop each drop the
	// rule without touching a match address, so a warning about a non-selected
	// match value announced that the selected value "stays active" while the
	// rule was in fact dropped. Observing the emissions cannot drift the way
	// mirroring them did.
	//
	// #6673 fold: "every caller of emit participates" is only worth as much as
	// the ROUTING of each check, and two whole-rule-dropping checks were routed
	// through emitSuffix instead — the block-pair-plus-port gate (#3202) and the
	// out-of-range `match destination-port` gate (#5101). Both were worded as
	// port-scoped and both really discard the entire rule, so "stays active" was
	// emitted for a rule the dataplane installs nothing for. They now go through
	// emit. The complete routing of the static-NAT rule loop, enumerated from
	// the two lowering stages rather than from the messages:
	//
	//	WHOLE-RULE DROP -> emit (marks the rule)
	//	  match destination-address unparseable   Rust parse_nat_prefix(external)
	//	  then static-nat prefix unparseable      Rust parse_nat_prefix(internal)
	//	  match destination-address non-host      Rust host/length/family check
	//	  then static-nat prefix non-host         Rust host/length/family check
	//	  /0 block pair                           Rust zero-length reject (#5658)
	//	  block pair + any port                   Rust block-branch port reject (#3202)
	//	  match destination-port out of range     Go buildStaticNATSnapshots (#5101)
	//	NARROWER -> emitSuffix (does NOT mark the rule)
	//	  match destination-port without mapped-port  installs port-scoped 1:1
	//	  mapped-port present-but-malformed           installs plain 1:1, port dropped
	//	  mapped-port without match destination-port  installs plain 1:1, port dropped
	//	  nat64 source-pool non-host address          that pool entry only
	//
	// The three narrower port cases are Rust `(0,_)/(m,0)` folds in the host
	// branch of from_snapshots, which build an entry rather than `continue`;
	// each is argued at its own call site. `then static-nat inet` and IsNPTv6
	// rules drop too, but the loop `continue`s past them before any emit, so no
	// claim about them is ever made here.
	//
	// RESIDUAL — an inventory, not an example, because "one exception" invited
	// the reader to assume the rest were covered. ruleDropped observes what THIS
	// validator emits, so a rule-breaking cause it does not itself report leaves
	// "stays active" standing. Both known cases, measured:
	//
	//   - EMPTY `then static-nat` target (a misspelled / unhandled target
	//     keyword). rule.Then == "" so the then-side checks here are guarded off,
	//     the Go lowering emits InternalIP: "" and Rust parse_nat_prefix("")
	//     drops the whole mapping (pinned by tests_static.rs "a static-NAT rule
	//     with an unparseable internal-ip must be dropped"). It IS reported — by
	//     validateStaticNATThenTargetStrict (#4290), a SIBLING validator whose
	//     emissions this flag cannot see. Not the "not checked at all" kind.
	//   - CROSS-FAMILY host pair: `match destination-address 192.0.2.1/32` with
	//     `then static-nat prefix 2001:db8::1/128`. Both sides parse and both are
	//     host routes, so nothing here complains and the Rust host branch builds
	//     an entry from a v4 external and a v6 internal. This one genuinely is
	//     not checked at all, by any validator.
	//
	// Closing either needs a cross-validator verdict channel or a new rejection,
	// not a wording change, so both are stated rather than papered over.
	// selectedMatchInvalid narrows that: the rule-dropping cause was the
	// SELECTED match address failing one of the match-side checks, so the
	// complaint about another slot can name it as invalid rather than pointing
	// vaguely at a different error. Set only by the emitMatchAddr addr ==
	// selected path, and likewise observed rather than recomputed.
	ruleDropped, selectedMatchInvalid := false, false
	emit := func(msg string) error {
		ruleDropped = true
		return emitSuffix(msg, " (ignored: rule dropped by dataplane until corrected)")
	}
	// emitMatchAddr is emit for a complaint whose operand is ONE authored
	// `match destination-address` value out of the list #6659 made visible.
	//
	// #6673: the plain `emit` suffix — "rule dropped by dataplane until
	// corrected" — is FALSE for a value the compiler did not select. Only ONE
	// value is ever lowered (rule.Match, the value nodeVal took from the last
	// authored statement); a malformed value in any other slot never reaches
	// the dataplane, so nothing is dropped and the rule installs and translates
	// normally on rule.Match. Reporting it as a dropped rule tells the operator
	// their published service is down when it is up, and the reverse mistake —
	// staying silent — is what #6659 was fixing. Name the actual effect per
	// value: the selected one really does drop the rule, a non-selected one is
	// ignored on its own.
	//
	// #6673 follow-up: whether a non-selected value's complaint may promise that
	// the selected value "stays active" depends on whether ANYTHING ELSE drops
	// the rule — and some of those causes are checked AFTER these loops run.
	// Without accounting for them the two loops contradicted each other on the
	// same rule: with `destination-address bad-old; destination-address
	// bad-selected;` the warning for bad-old announced that bad-selected "stays
	// active", and the very next warning — for bad-selected, the value that IS
	// selected — correctly said the dataplane drops the rule.
	//
	// So a non-selected complaint is emitted in place (preserving warning
	// order) but with its suffix left BLANK, and the suffix is patched in at
	// the end of the rule, once ruleDropped is final. That is what lets the
	// verdict be OBSERVED from the emissions rather than mirrored by hand.
	// Strict mode never defers: emitSuffix discards the suffix entirely when
	// !lenient, and the first violation returns as the error, so deferring
	// there would only risk changing which error is reported.
	type deferredMatchAddrSuffix struct {
		warningIdx int
		selected   string
	}
	var deferredSuffixes []deferredMatchAddrSuffix
	emitMatchAddr := func(addr, selected, msg string) error {
		if addr == selected {
			selectedMatchInvalid = true
			return emit(msg)
		}
		if !lenient {
			// Suffix is discarded in strict mode; report the violation now.
			return emitSuffix(msg, "")
		}
		warnings = append(warnings, msg)
		deferredSuffixes = append(deferredSuffixes, deferredMatchAddrSuffix{
			warningIdx: len(warnings) - 1,
			selected:   selected,
		})
		return nil
	}
	// matchAddrSuffix words the effect of a complaint about a match value the
	// compiler did NOT select, given the rule's final verdict.
	matchAddrSuffix := func(selected string, dropped, selectedInvalid bool) string {
		// #6673: an authored-but-EMPTY slot can be the SELECTED value —
		// `destination-address [ "" bogus ]` blanks the match, and nodeVal
		// selects the blank. The "%q is, and it stays active" wording then
		// renders as `"" is, and it stays active`, which translates nothing and
		// reassures the operator about a rule that does not exist: rule.Match
		// == "" lowers ExternalIP: "" and the Rust parse_nat_prefix("") returns
		// None, so from_snapshots drops the whole mapping. Neither of the other
		// two suffixes is true here — this value still is not the one that
		// installs, but there is no surviving rule to keep active. Checked
		// first because an empty selection names no value to quote.
		if selected == "" {
			return " (ignored: this value is not the one the rule " +
				"installs — the selected match destination-address is EMPTY, so " +
				"the rule is dropped by the dataplane regardless of this value)"
		}
		if selectedInvalid {
			return fmt.Sprintf(
				" (ignored: this value is not the one the rule installs — %q is, "+
					"but that value is invalid too, so the rule is dropped by the "+
					"dataplane regardless of this value)", selected)
		}
		if dropped {
			// The selected match value is fine; something else about the rule
			// — a then-side parse or host-mask failure, a /0 block pair — drops
			// it. Do NOT blame the selected value here, and do not promise it
			// stays active either. The cause is in another warning on the same
			// rule.
			return fmt.Sprintf(
				" (ignored: this value is not the one the rule installs — %q is, "+
					"but this rule is dropped by the dataplane anyway for a "+
					"separate reason reported alongside this warning)", selected)
		}
		return fmt.Sprintf(
			" (ignored: this value is not the one the rule installs — %q is, "+
				"and it stays active; correct or remove the unused value)",
			selected)
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// `then static-nat inet` is a NAT64 translation, not host-1:1
			// static NAT: its `match destination-address` is the NAT64
			// well-known prefix (e.g. 64:ff9b::/96, a legitimate non-host
			// prefix), so the host-mask check does not apply. The keyword is
			// itself rejected at strict commit by validateStaticNATInetTarget-
			// Strict (#5859) — no dataplane lowering exists, and emitting the
			// literal "inet" left the rule silently inert — so this exemption
			// only avoids a misleading second (host-mask) error on the same
			// rule; the inet gate is the authoritative rejection. Exempt the
			// whole rule.
			if rule.Then == "inet" {
				continue
			}
			// #3206: a `match destination-address` / `then static-nat
			// prefix` that is not a parseable literal IP or CIDR (an
			// address-book name, or a typo'd prefix) is NOT caught by the
			// host-mask check below — that check fires only when the value
			// parses (`parsed && !host`). An unparseable value falls all the
			// way through to the Rust dataplane, where `parse_nat_prefix`
			// returns None and `from_snapshots` does `continue`, SILENTLY
			// dropping the entire static-NAT mapping with no commit error or
			// runtime feedback (the operator authored a rule that simply does
			// not exist at runtime). Static NAT takes literal IP/CIDR
			// endpoints, not address-book references, so reject an
			// unparseable value at commit. `natStaticPrefixInfo` mirrors the
			// Rust `parse_nat_prefix` classification; its `parsedIP == false`
			// is precisely the silently-dropped case. Run this BEFORE the
			// blockPair / host-mask checks so an unparseable value reports its
			// own (clearer) error rather than being skipped as "not a block
			// pair".
			// #6659: validate EVERY authored destination-address, not just the
			// first. Before #6659 the compiler read this leaf with nodeVal, so
			// only one value existed to check. It now accumulates into
			// MatchAddresses, and reading only the scalar rule.Match here would
			// leave the tail unvalidated.
			//
			// WHAT THIS BUYS, stated precisely because the obvious rationale is
			// FALSE and a false rationale talks the next reader out of checking:
			// this loop is NOT the last line of defence in front of the Rust
			// dataplane. Only ONE value is ever lowered — the userspace
			// snapshot builder sets `ExternalIP: rule.Match`
			// (pkg/dataplane/userspace/nat_static.go), rule.Match is the value
			// nodeVal selected from the LAST authored statement
			// (compiler_nat_static.go) — NOT MatchAddresses[0]; the two differ
			// whenever a bracketed list precedes a repeated sibling. MatchAddresses has
			// NO consumer outside these validators. A malformed value in slot 2
			// is therefore dropped by the Go lowering and never reaches
			// `parse_nat_prefix` at all.
			//
			// What it buys is DIAGNOSTIC COMPLETENESS on the TOLERANT load /
			// peer-sync path, where validateStaticNATMatchAddressesStrict
			// downgrades the multi-value rejection to a warning and the config
			// LOADS with only slot 1 in effect. The remedy that warning
			// prescribes is "author one rule per external prefix" — so the
			// operator needs to know that slot 2 is ALSO malformed now, not on
			// the next commit after they have split the list. At strict commit
			// the multi-value gate rejects the list outright and fires first, so
			// the tail is unreachable there. Fall back to the scalar when the
			// plural is empty so a typed config produced by an older binary
			// (peer sync, a restored DB) is still checked.
			matchAddrs := rule.MatchAddresses
			if len(matchAddrs) == 0 && rule.Match != "" {
				matchAddrs = []string{rule.Match}
			}
			// #6659 follow-up: the block-pair classification below is what
			// EXEMPTS an address from the host-route requirement, so a
			// match-side check cannot be widened to the tail without widening
			// the classification with it — a tail block prefix classified
			// against slot 1 lands in neither branch and escapes silently
			// (`[ 192.0.2.1/32 198.51.100.0/24 ]` produced no host-mask
			// complaint at all while `198.51.100.0/24` alone did).
			//
			// blockPairFor answers the question the multi-value warning's own
			// remedy asks: if this address were split into its own rule against
			// the same `then` prefix, would that rule be a legal block-to-block
			// map? That keeps the match-side diagnosis per-address.
			//
			// It is deliberately NOT hoisted into an "any address forms a block
			// pair" flag for the THEN-side and rule-level checks below. Those
			// describe the ONE pair that actually installs — (rule.Match,
			// rule.Then) — so an "any" flag would SUPPRESS a true complaint
			// about the installed pair: `match [ 192.0.2.1/32 198.51.100.0/24 ]
			// then 10.0.0.1/24` installs host-vs-block, and the Then host-route
			// complaint that catches it today would vanish because slot 2
			// happens to pair with the target. Widening a check is only correct
			// where the operand is the value being widened.
			blockPairFor := func(matchAddr string) bool {
				return isStaticBlockPair(matchAddr, rule.Then)
			}
			// #6673: a complaint about some OTHER slot must not promise that the
			// selected value "stays active" when the rule does not survive. The
			// selected value is the one that lowers to
			// StaticNATRuleSnapshot.ExternalIP, and the dataplane drops the
			// whole rule when it cannot parse it — but so do the then-side and
			// /0 verdicts, which is why this is no longer a hand-written mirror
			// of the two match-side loops. ruleDropped is set by `emit` itself,
			// so it accumulates EVERY rule-dropping cause reported for this
			// rule, including ones added later; the deferred suffixes below are
			// resolved from it once the rule is fully validated.
			ruleDropped, selectedMatchInvalid = false, false
			deferredSuffixes = deferredSuffixes[:0]
			for _, addr := range matchAddrs {
				if addr == "" {
					continue
				}
				if _, _, _, parsedIP := natStaticPrefixInfo(addr); !parsedIP {
					if err := emitMatchAddr(addr, rule.Match, fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q is not a valid IP address or CIDR prefix (static NAT requires a literal address or prefix, not an address-book name or a typo'd value)",
						rs.Name, rule.Name, addr)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" {
				if _, _, _, parsedIP := natStaticPrefixInfo(rule.Then); !parsedIP {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q is not a valid IP address or CIDR prefix (static NAT requires a literal address or prefix, not an address-book name or a typo'd value)",
						rs.Name, rule.Name, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #3031: a valid block-to-block (subnet) static-NAT rule —
			// equal-length non-host prefixes of the same family — is now
			// installed by the dataplane (offset-preserving 1:1 remap), so do
			// NOT reject it as a non-host mask. Only the genuinely-invalid
			// non-host cases (host-vs-block, mismatched length, mixed family,
			// malformed mask) fall through to the host-route rejection below.
			// The rule-level / then-side classification: the pair that actually
			// installs. See blockPairFor above for why this one stays scalar.
			blockPair := blockPairFor(rule.Match)
			// #5658: a valid block pair whose prefix length is ZERO (`/0` on
			// both sides — isStaticBlockPair already requires equal length) maps
			// the ENTIRE address family 1:1. The dataplane host mask for a /0 is
			// all-ones, so every address matches and the equal-length offset
			// remap preserves all host bits — an identity translation that,
			// installed in the ordered block scan, SHADOWS every narrower
			// static/DNAT rule while claiming to translate. Reject it at strict
			// commit-check with an operator-facing error (downgraded to a warning
			// on the tolerant load / peer-sync path — the Rust backstop drops the
			// whole rule and records a bounded NAT parse error). This is a
			// zero-length reject ONLY, not an arbitrary non-zero floor: a
			// legitimate large-but-intentional block (`/8`, `/64`, …) still
			// commits, preserving documented subnet static-NAT parity. Applies to
			// IPv4 (0.0.0.0/0) and IPv6 (::/0) identically (natStaticPrefixInfo is
			// family-agnostic on the length). Runs BEFORE the #3202 port check so
			// the whole-family identity NAT is the primary reported error.
			// #6659 follow-up: the operand here is a MATCH address, so it runs
			// per authored value — a /0 block pair authored in the tail is
			// reported against its own address rather than being classified
			// against slot 1 and skipped.
			//
			// #6673: and because the operand is a match value, the effect must
			// be worded per value like its two sibling loops — this one was
			// widened to iterate matchAddrs but kept the scalar `emit`, whose
			// suffix says the rule is "dropped by dataplane until corrected".
			// For a /0 pair in a slot the compiler did not select that is two
			// falsehoods at once: the quoted pair is not the pair that installs
			// (rule.Match <-> rule.Then is), and the rule is not dropped — it
			// installs and translates on the selected value.
			for _, addr := range matchAddrs {
				if addr == "" || !blockPairFor(addr) {
					continue
				}
				if _, bits, _, _ := natStaticPrefixInfo(addr); bits == 0 {
					if err := emitMatchAddr(addr, rule.Match, fmt.Sprintf(
						"security nat static rule-set %q rule %q maps a block-to-block subnet with a zero-length (/0) prefix (match destination-address %q <-> then static-nat prefix %q); a /0 mapping remaps the ENTIRE address family 1:1 (an identity translation that shadows every narrower static/DNAT rule) — use a specific subnet prefix",
						rs.Name, rule.Name, addr, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #3202: a block-to-block (subnet) static-NAT rule that ALSO
			// carries a `match destination-port` or a `then static-nat
			// mapped-port` is not representable in the dataplane. The Rust
			// `StaticNatBlock` (static_nat.rs `from_snapshots`) stores only the
			// address prefixes and performs an offset-preserving, ALL-PORT 1:1
			// remap — it has no `match_dst_port`/`mapped_port` fields. So the
			// port match/mapping is SILENTLY discarded and "NAT only port 80 of
			// this /24, remap to 8080" degrades to "NAT every port of the /24"
			// (over-broad NAT / policy bypass). This also matches Junos: a
			// `static-nat prefix` is an address-only 1:1 subnet map; per-port
			// translation is a host-scope construct (`static-nat ... mapped-port`
			// on a /32). Reject the combination at strict commit-check so the
			// operator authors a host static-NAT rule for the port forward, or
			// drops the port tokens for a whole-subnet 1:1. (#3031 added the
			// address-only block map; it did not add this rejection.)
			//
			// #6673 fold: this reports a WHOLE-RULE drop, so it goes through
			// `emit` and marks the rule. The message's "the port mapping is
			// silently dropped" described the pre-#3202 hazard the gate was
			// written to prevent, not what the dataplane does today: from_snapshots
			// `continue`s on `snap.match_destination_port != 0 || snap.mapped_port
			// != 0` inside the block-pair branch, dropping the ENTIRE rule (pinned
			// by static_nat_block_with_port_is_dropped and
			// static_nat_block_with_match_port_only_is_dropped in
			// userspace-dp/src/nat/tests_static.rs). Routed through emitSuffix with
			// a port-scoped suffix it left ruleDropped false, so a complaint about
			// a non-selected match value on the same rule announced that the
			// selected value "stays active" while the rule installed nothing.
			if blockPair && (rule.MatchDestinationPort != 0 || rule.MappedPort != 0) {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q maps a subnet (block-to-block prefix) but also specifies a port (match destination-port / then static-nat mapped-port); subnet static NAT is address-only 1:1 and the dataplane cannot translate per-port for a block, so the whole rule is dropped (use a /32 host match+prefix for a port forward, or drop the port tokens for a whole-subnet 1:1)",
					rs.Name, rule.Name)); err != nil {
					return nil, err
				}
			}
			// #6659 follow-up: the operand here is a MATCH address, so it runs
			// per authored value with a per-address block-pair exemption.
			// Reading only the scalar, a non-host prefix in slot 2 escaped this
			// check entirely (the reviewer's verified case:
			// `[ 192.0.2.1/32 198.51.100.0/24 ]` warned about nothing while
			// `198.51.100.0/24` alone warned).
			//
			// #6673: report the effect per value via emitMatchAddr. A non-host
			// mask in a slot the compiler did not select is not "silently
			// dropped by the dataplane" as a rule — it never reaches the
			// dataplane at all, and the rule keeps translating on rule.Match.
			for _, addr := range matchAddrs {
				if addr == "" || blockPairFor(addr) {
					continue
				}
				if host, parsed := isHostMaskAddress(addr); parsed && !host {
					if err := emitMatchAddr(addr, rule.Match, fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, addr)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" && !blockPair {
				if host, parsed := isHostMaskAddress(rule.Then); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #2491: port-mapped static NAT. The `mapped-port` token rides
			// inside the children:nil static-nat leaf, so the schema's
			// value-slot validator never sees it; range-check it here. An
			// out-of-range port would truncate to a wrong u16 in the snapshot,
			// so reject it. A `mapped-port` requires a matching `match
			// destination-port`: without an external port to match, the port
			// rewrite has no inbound trigger and the reverse SNAT cannot
			// recover the original port.
			//
			// #6673 fold: this too reports a WHOLE-RULE drop, so it goes through
			// `emit`. buildStaticNATSnapshots (pkg/dataplane/userspace/nat_static.go,
			// #5101) `continue`s on staticNATPortOutOfRange(rule.MatchDestinationPort)
			// — the rule never reaches a snapshot at all, let alone the dataplane,
			// because clamping an invalid port to 0 would fail OPEN onto the
			// whole-address wildcard. Measured: `destination-port 70000` yields 0
			// snapshots. The port-scoped suffix understated that and, worse, left
			// ruleDropped false so a non-selected match value was told the selected
			// one "stays active" for a rule that installs nothing.
			if rule.MatchDestinationPort != 0 && (rule.MatchDestinationPort < 1 || rule.MatchDestinationPort > 65535) {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-port %d is out of range (1-65535)",
					rs.Name, rule.Name, rule.MatchDestinationPort)); err != nil {
					return nil, err
				}
			}
			// #2769: a `match destination-port` WITHOUT a `then static-nat
			// mapped-port` is a port-scoped 1:1 (no port translation). The
			// dataplane scopes the reverse SNAT to that one port — but the
			// half-config is almost always an operator mistake (the intent is
			// usually a full port-forward with mapped-port). Reject it at
			// strict commit-check, mirroring the existing mapped-port-without-
			// match-port rejection below, so the operator must either drop the
			// port match (whole-address 1:1) or add a mapped-port (port
			// forward). The dataplane backstop (static_nat.rs) keeps the
			// reverse SNAT scoped to the matched port if the rule slips through
			// the lenient load / peer-sync path.
			//
			// #6479 fold: guard on !MappedPortPresent so this fires ONLY on a
			// TRUE absence. A PRESENT-but-malformed mapped-port (`mapped-port
			// 0`/``/bare/`notaport`) also lands at MappedPort==0, but it is the
			// presence gate below that owns that case (naming the bad token).
			// Without this guard both gates fire — two warnings in lenient mode,
			// and in strict the misleading "requires a mapped-port" message
			// (emitted first) wins over the accurate "not a valid port number".
			if rule.MatchDestinationPort != 0 && rule.MappedPort == 0 && !rule.MappedPortPresent {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-port %d requires a matching `then static-nat mapped-port` (a port match without a port translation either broadens or scopes the reverse source-NAT in a non-obvious way; drop the port match for a whole-address 1:1, or add a mapped-port for a port forward)",
					rs.Name, rule.Name, rule.MatchDestinationPort),
					" (ignored: port match dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			// C179-038 + fold: a PRESENT `then static-nat mapped-port <token>`
			// rides inside the children:nil static-nat leaf, bypassing the
			// schema value validator. The compiler records an explicit presence
			// signal (MappedPortPresent) plus the parsed port (MappedPort, 0
			// when absent OR malformed) and the raw token (MappedPortRaw). This
			// ONE gate rejects every present-but-not-1-65535 sibling the earlier
			// string/int sentinels let slip: a non-numeric token ("notaport"),
			// an empty operand (`mapped-port ""`), a bare keyword with no
			// operand, the literal "0", and an out-of-range number ("70000").
			// All previously collapsed to MappedPort==0-or-out-of-range with no
			// diagnostic under the old `MappedPortRaw != ""` / `MappedPort != 0`
			// gates (MappedPort==0 conflated "absent" with "present-but-
			// malformed"; MappedPortRaw=="" conflated "absent" with "present-
			// but-empty"), so the value silently degraded to "no port
			// translation" even though a WELL-FORMED value in the same position
			// without a `match destination-port` IS rejected. The lenient load /
			// peer-sync path (#1960 no-brick) downgrades this to a warning and
			// the dataplane installs a plain 1:1 (MappedPort==0, no bogus port).
			// MappedPortPresent is compile-only (json:"-") and never reaches the
			// dataplane.
			//
			// #6673 fold: this stays on emitSuffix — it is genuinely NARROWER —
			// even though its sibling `match destination-port` check above now
			// drops the rule for the arithmetically identical fault. The
			// asymmetry is in the COMPILER, not in the gate:
			// combineMappedPortOperands folds ANY malformed mapped-port operand
			// (empty, bare, non-numeric, out-of-range) to MappedPort == 0 and
			// records the offending token separately, whereas the
			// `destination-port` arm stores whatever Atoi returned verbatim
			// (compiler_nat_static.go). So the value that reaches
			// buildStaticNATSnapshots is 0, staticNATPortOutOfRange(0) is FALSE
			// (0 is the legitimate "port absent" sentinel), and the rule lowers
			// and installs as a plain 1:1 with no port translation — measured:
			// `mapped-port 70000` yields 1 snapshot with mapped=0, while
			// `destination-port 70000` yields 0 snapshots. The reported effect
			// really is "the port translation is dropped", not the rule.
			//
			// The bound this rests on: MappedPort is only ever 0 or a valid
			// 1-65535 on every path that reaches here, because both compile
			// entry points build it through combineMappedPortOperands and
			// MappedPortPresent is json:"-" so a peer-synced / restored typed
			// config cannot arrive with the flag set at all. If either of those
			// ever changes, a PRESENT non-zero out-of-range MappedPort WOULD hit
			// the #5101 drop and this call must move to `emit`.
			if rule.MappedPortPresent && (rule.MappedPort < 1 || rule.MappedPort > 65535) {
				token := "(missing value)"
				if rule.MappedPortRaw != "" {
					token = fmt.Sprintf("%q", rule.MappedPortRaw)
				}
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat mapped-port %s is not a valid port number (1-65535)",
					rs.Name, rule.Name, token),
					" (ignored: port translation dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			// A VALID in-range mapped-port still requires a matching `match
			// destination-port`: without an external port to match, the port
			// rewrite has no inbound trigger and the reverse SNAT cannot recover
			// the original port. Guarded on MappedPort != 0 so it does not
			// double-fire on a malformed mapped-port (MappedPort==0), which the
			// presence gate above already rejected.
			if rule.MappedPort != 0 && rule.MatchDestinationPort == 0 {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat mapped-port %d requires a matching `match destination-port`",
					rs.Name, rule.Name, rule.MappedPort),
					" (ignored: port translation dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			// #6673: every rule-dropping cause for THIS rule has now been
			// reported, so ruleDropped is final — word the non-selected match
			// value complaints held open above. Patching in place keeps the
			// warnings in emission order. Only reachable on the lenient path;
			// strict returned at the first violation.
			for _, d := range deferredSuffixes {
				warnings[d.warningIdx] += matchAddrSuffix(d.selected, ruleDropped, selectedMatchInvalid)
			}
		}
	}

	// NAT64 source-pool addresses are discrete IPv4 host source IPs: the Rust
	// parse_pool_v4 (nat64.rs) accepts ONLY a bare IPv4 or an IPv4 /32 and
	// silently drops everything else (an IPv6 address, a non-host IPv4 mask).
	// Range-expanded pool entries are always /32 by construction
	// (expandAddressRange), so only an operator-authored single
	// `pool address <X>` can trip this.
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.SourcePool == "" {
			continue
		}
		pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]
		if !ok || pool == nil {
			continue
		}
		addrs := pool.Addresses
		if pool.Address != "" {
			addrs = append([]string{pool.Address}, addrs...)
		}
		for _, a := range addrs {
			if a == "" {
				continue
			}
			if host, parsed := isNAT64PoolHostAddress(a); parsed && !host {
				if err := emitSuffix(fmt.Sprintf(
					"security nat source pool %q address %q is referenced by nat64 rule-set %q source-pool and must be an IPv4 host route (a bare IPv4 address or /32); a non-host or IPv6 address is silently dropped by the dataplane",
					pool.Name, a, rs.Name),
					" (ignored: only this pool address is dropped by the dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
		}
	}

	return warnings, nil
}

// validateNPTv6Strict is the #2240/#2241 strict-vs-lenient gate for NPTv6
// (RFC 6296) static-NAT rules (`then static-nat nptv6-prefix`).
//
// #2240 (fail-closed validation): the dataplane compiler
// (`pkg/dataplane/compiler_nat.go` compileNPTv6) historically logged a warning
// and `continue`d past any per-rule validation failure (unparseable prefix,
// mismatched /48-vs-/64 lengths, an unsupported length, a non-IPv6 prefix),
// then unconditionally called `DeleteStaleNPTv6(written)` over only the VALID
// subset — so editing one previously-good rule into an invalid one TORE DOWN
// its working translation entry with no replacement installed, silently
// disabling a working translation. The Rust helper mirrored the silent skip.
// In a retired-eBPF world (#1373) the userspace helper is the enforcement
// plane, so this is a fail-OPEN regression: a typo silently changes
// reachability and source/destination identity while the commit still reports
// success. This commit-time gate surfaces the misconfiguration loudly.
//
// #2241 (overlap rejection): NPTv6 supports both /48 and /64 rules. The runtime
// resolves a match by FIRST hit in insertion order with no longest-prefix
// match, so a broad /48 configured before a nested /64 shadows the /64 and
// reordering the same rules changes the translation identity. Reject any
// overlapping pair (in either direction) so resolution is deterministic.
//
// Strict (commit / commit-check): hard-reject. Lenient (load / peer-sync, #1960
// / #1979 doctrine): return the messages as warnings so a config committed
// before this gate existed (or peer-synced) still boots. The "previous state is
// kept" impact note in the lenient warning is scoped to the userspace
// apply/preflight, not asserted as a general validator guarantee: the Rust
// helper's own #2240/#2241 backstop (`Nptv6State::try_from_snapshots`) rejects
// the whole snapshot at apply, so the apply preflight keeps the previous live
// forwarding state and a leniently-loaded bad config never installs a
// torn-down or nondeterministic NPTv6 runtime. The validator itself only
// classifies the rule as invalid; it is the helper preflight that preserves
// the prior forwarding state.
func validateNPTv6Strict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NPTv6 rule is invalid; on a userspace-dataplane apply/preflight"+
					" the helper rejects the whole NPTv6 snapshot and the previous state is kept,"+
					" so the rule will not take effect until corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	// Track already-validated prefixes per direction to reject overlaps (#2241).
	// Outbound matches on the internal prefix; inbound matches on the external
	// (match) prefix. Each direction is checked independently.
	type seenPrefix struct {
		net         *net.IPNet
		ones        int
		ruleSetName string
		ruleName    string
	}
	var internalSeen, externalSeen []seenPrefix

	// overlaps reports whether two IPv6 prefixes overlap — i.e. one contains
	// the other's network address (the shorter prefix is a prefix of the
	// longer). This covers identical /48-/48, identical /64-/64, and a /48
	// nesting a /64 (the case that makes first-match resolution order-
	// dependent).
	overlaps := func(a, b *net.IPNet) bool {
		return a.Contains(b.IP) || b.Contains(a.IP)
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}

			// #5523/#6479: NPTv6 (RFC 6296) translates the IPv6 address prefix
			// and has NO transport-port concept, so a `then static-nat
			// nptv6-prefix <p6> mapped-port <p>` is invalid in EVERY shape
			// (collapsed keys, hierarchical nptv6-prefix child, or a distinct
			// `mapped-port` sibling). The host-mask loop skips nptv6 rules
			// entirely (`IsNPTv6` continue), so WITHOUT this gate a mapped-port
			// on an nptv6 rule reached no validator at all: a malformed operand
			// was silently accepted (the C179-038 class for the nptv6 shape) and
			// a well-formed one was silently ignored. recordNPTv6MappedPort-
			// Presence stamps MappedPortPresent whenever the keyword appears, so
			// reject on PRESENCE alone — the value is irrelevant on nptv6, even a
			// well-formed 1-65535 port is meaningless. This runs BEFORE the
			// prefix-parse/length checks so it fires even when the prefixes are
			// otherwise valid (the pure silent-accept case). No `continue`: on the
			// lenient no-brick path the prefix diagnostics still accumulate, and
			// the nptv6 prefix translation itself still applies (MappedPort==0),
			// so this warning is scoped to the dropped mapped-port, not the rule.
			if rule.MappedPortPresent {
				msg := fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix does not support mapped-port (NPTv6 translates the address prefix per RFC 6296, not transport ports); remove the mapped-port",
					rs.Name, rule.Name)
				if lenient {
					warnings = append(warnings, msg+
						" (ignored: mapped-port dropped by dataplane; the nptv6 prefix translation still applies)")
				} else {
					return nil, fmt.Errorf("%s", msg)
				}
			}

			// External prefix = `match destination-address`. The family is
			// classified from the original CIDR text (natCIDRIPPart +
			// natAddrFamily below), not the parsed net.IP, so the parsed IP
			// values are intentionally discarded.
			_, extNet, errExt := net.ParseCIDR(rule.Match)
			// Internal prefix = `then static-nat nptv6-prefix`.
			_, intNet, errInt := net.ParseCIDR(rule.Then)

			if errExt != nil {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-address %q is not a valid IPv6 prefix for nptv6-prefix translation",
					rs.Name, rule.Name, rule.Match)); err != nil {
					return nil, err
				}
				continue
			}
			if errInt != nil {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix %q is not a valid IPv6 prefix",
					rs.Name, rule.Name, rule.Then)); err != nil {
					return nil, err
				}
				continue
			}

			extOnes, _ := extNet.Mask.Size()
			intOnes, _ := intNet.Mask.Size()

			if extOnes != intOnes {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefix lengths must match (match %q is /%d, nptv6-prefix %q is /%d)",
					rs.Name, rule.Name, rule.Match, extOnes, rule.Then, intOnes)); err != nil {
					return nil, err
				}
				continue
			}
			if extOnes != 48 && extOnes != 64 {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefix length /%d is unsupported (only /48 and /64 are allowed)",
					rs.Name, rule.Name, extOnes)); err != nil {
					return nil, err
				}
				continue
			}
			// Family classification MUST be textual (natAddrFamily), not
			// net.IP.To4(): Go folds an IPv4-mapped IPv6 literal
			// (::ffff:1.2.3.4) so its parsed .To4() is non-nil, but Rust's
			// Ipv6Addr::from_str (parse_prefix in userspace-dp/src/nptv6.rs)
			// accepts the same text as a valid IPv6 address and APPLIES the
			// rule. A To4()-based check here would warn-skip on the lenient
			// load path while the dataplane installs the rule — a Go<->Rust
			// divergence (#2247 item 2). Classifying on the original text
			// (colon == v6) matches the helper exactly, so an IPv4-mapped form
			// is treated as IPv6 here too. We split the IP part off the CIDR
			// (the same idiom as isHostMaskAddress); ParseCIDR already proved
			// these parse, so a missing slash cannot happen, but the helper is
			// robust either way.
			if natAddrFamily(natCIDRIPPart(rule.Match)) != "v6" ||
				natAddrFamily(natCIDRIPPart(rule.Then)) != "v6" {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefixes must be IPv6 (match %q, nptv6-prefix %q)",
					rs.Name, rule.Name, rule.Match, rule.Then)); err != nil {
					return nil, err
				}
				continue
			}

			// #2380: host-bits-zero strictness. net.ParseCIDR masks the
			// address to the prefix length silently, so a prefix with bits
			// set beyond the prefix length (e.g. 2001:db8:1:2::/48) parses
			// as a DIFFERENT prefix (2001:db8:1::/48) than the operator
			// wrote, and the Rust parse_prefix (nptv6.rs) discards the extra
			// words identically. Both planes agree on the masked result, so
			// there is no traffic-correctness bug — but the operator gets a
			// rule that does not match what they typed, with no feedback.
			// Junos rejects host bits set on a prefix; mirror that here. This
			// is the same class as isHostMaskAddress for static-NAT host
			// masks. The masked network address is extNet.IP / intNet.IP; the
			// raw address is the IP part of the original CIDR text. A mismatch
			// means host/subnet bits were set.
			if host, ok := nptv6PrefixHasHostBits(rule.Match, extNet); ok && host {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-address %q has host bits set beyond the /%d prefix (Junos rejects this; write the masked prefix explicitly)",
					rs.Name, rule.Name, rule.Match, extOnes)); err != nil {
					return nil, err
				}
				continue
			}
			if host, ok := nptv6PrefixHasHostBits(rule.Then, intNet); ok && host {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix %q has host bits set beyond the /%d prefix (Junos rejects this; write the masked prefix explicitly)",
					rs.Name, rule.Name, rule.Then, intOnes)); err != nil {
					return nil, err
				}
				continue
			}

			// #2241: overlap rejection. Check the internal (outbound) and
			// external (inbound) prefixes independently against prior rules.
			//
			// #4339: a rule is NEVER compared against itself. A single NPTv6
			// rule in a rule-set with MULTIPLE from-scopes (`from zone A; from
			// zone B`, or several interfaces) is scope-expanded by
			// compileNATStatic into one StaticNATRuleSet entry PER scope, all
			// sharing the rule-set name AND the rule name (they are one logical
			// rule; only the from-scope differs). The seen lists span every
			// rule-set, so the second scope-expansion's prefixes matched the
			// first's exactly and the rule was reported as overlapping ITSELF —
			// blocking ANY NPTv6 mapping whose rule-set had more than one
			// from-scope. Skip the same (rule-set, rule) identity so only
			// DISTINCT rules are compared for a genuine, order-dependent overlap.
			sameRule := func(prev seenPrefix) bool {
				return prev.ruleSetName == rs.Name && prev.ruleName == rule.Name
			}
			overlapFound := false
			for _, prev := range internalSeen {
				if sameRule(prev) {
					continue
				}
				if overlaps(prev.net, intNet) {
					overlapFound = true
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q nptv6-prefix %q overlaps rule-set %q rule %q (outbound/internal prefixes overlap; first-match resolution would be order-dependent)",
						rs.Name, rule.Name, rule.Then, prev.ruleSetName, prev.ruleName)); err != nil {
						return nil, err
					}
					break
				}
			}
			for _, prev := range externalSeen {
				if sameRule(prev) {
					continue
				}
				if overlaps(prev.net, extNet) {
					overlapFound = true
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q overlaps rule-set %q rule %q (inbound/external prefixes overlap; first-match resolution would be order-dependent)",
						rs.Name, rule.Name, rule.Match, prev.ruleSetName, prev.ruleName)); err != nil {
						return nil, err
					}
					break
				}
			}
			if overlapFound {
				// Do not register an overlapping rule as a baseline for
				// subsequent comparisons; the snapshot is already rejected.
				continue
			}

			internalSeen = append(internalSeen, seenPrefix{net: intNet, ones: intOnes, ruleSetName: rs.Name, ruleName: rule.Name})
			externalSeen = append(externalSeen, seenPrefix{net: extNet, ones: extOnes, ruleSetName: rs.Name, ruleName: rule.Name})
		}
	}

	return warnings, nil
}

// validateNPTv6ScopeStrict is the #5818 fail-closed gate for NPTv6 (RFC 6296)
// static-NAT rules that carry a match-scope dimension the NPTv6 dataplane does
// NOT yet honor.
//
// The config model retains the full static-NAT match scope: a rule-set `from
// interface` / `from routing-instance` scope (StaticNATRuleSet.FromInterface /
// FromRoutingInstance, #3096) and a per-rule `match source-address`
// (StaticNATRule.SourceAddress / SourceAddresses, #3435). But NPTv6 compilation
// discards every constraint except `from zone`: buildNptv6Snapshots
// (pkg/dataplane/userspace/nat_nptv6.go) emits only name + from-zone + the two
// prefixes, Nptv6RuleSnapshot has no interface / routing-instance / source-
// prefix field, and the Rust helper (userspace-dp/src/nptv6.rs) matches on
// ingress/egress zone only. An NPTv6 rule scoped to a specific interface, VRF,
// or client source prefix was therefore installed as a broader zone/global
// prefix rewrite: traffic that CANNOT match the configured rule (wrong
// interface/VRF/source) was still translated and routed — the same security-
// widening class #5176 fixed for `from zone`, for the remaining scope
// dimensions.
//
// Carrying and evaluating those dimensions end-to-end (typed scope union +
// canonical source-prefix list on the Go and Rust wire, stable logical-
// interface / routing-instance identity at both lookup points, symmetric
// outbound interpretation for stateless NPTv6, and overlap-registry
// partitioning) is a substantial wire+dataplane change. It was tracked as #6043
// and is PLAN-KILLED: `from zone`-only NPTv6 (#5176) is fully honored and is the
// RFC 6296 deployment shape, so full scoped support is a demand-gated enhancement
// whose price includes a helper capability/protocol gate to stop a newer manager
// handing a constrained rule to an older helper that would install it globally.
// This reject is therefore the TERMINAL disposition, not an interim one: refuse
// the unsupported-scope NPTv6 rule LOUDLY at commit rather than silently install
// an over-broad rewrite. The acceptance matrix in #5818 is preserved and remains
// the correct starting point if a real operator request ever revives it.
//
// Reject condition (precise): an NPTv6 rule-set (one containing >= 1 nptv6-prefix
// rule) whose FromInterface != "" OR FromRoutingInstance != "", or any NPTv6 rule
// carrying a `match source-address`. A `from zone`-only or fully-unscoped/global
// NPTv6 rule is UNAFFECTED (the #5176-correct path). An ordinary (non-NPTv6)
// static-NAT rule carrying the SAME dimensions is ALSO unaffected: from-interface
// / from-routing-instance scope (#3096) and match source-address (#3435) ARE
// honored for static NAT, so those rule-sets are skipped here.
//
// Strict (commit / commit-check): hard-reject naming the rule-set/rule and the
// unsupported constraint. Lenient (load / peer-sync, #1960 / #1979 doctrine):
// return the message as a warning so a config committed before this gate existed
// (or peer-synced) still boots — the snapshot builder (buildNptv6Snapshots)
// independently EXCLUDES the scope-carrying rule so nothing installs rather than
// a widened rewrite. Mirrors the #5859 static-nat `then inet` and #5819
// persistent-nat + no-translation fail-closed patterns. Uses the same
// opts.lenientNPTv6 flag as validateNPTv6Strict.
func validateNPTv6ScopeStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NPTv6 rule is excluded from the dataplane snapshot so it"+
					" installs nothing rather than a broader zone/global rewrite; it will"+
					" not take effect until the unsupported constraint is removed or full"+
					" scoped NPTv6 support lands)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		// Scope only applies to NPTv6 rule-sets. A rule-set with NO nptv6-prefix
		// rule is ordinary static NAT, whose interface/RI scope and source-address
		// match ARE honored — leave it untouched.
		hasNptv6 := false
		for _, rule := range rs.Rules {
			if rule != nil && rule.IsNPTv6 {
				hasNptv6 = true
				break
			}
		}
		if !hasNptv6 {
			continue
		}

		// Rule-set FromInterface scope. Reported before FromRoutingInstance and
		// the per-rule source match for a deterministic first offender.
		if rs.FromInterface != "" {
			if err := emit(fmt.Sprintf(
				"security nat static rule-set %q is an NPTv6 (nptv6-prefix) rule-set "+
					"scoped `from interface %q`, but the NPTv6 dataplane honors only "+
					"`from zone`; the interface constraint would be dropped and the "+
					"prefix rewrite installed over a broader scope, translating traffic "+
					"the interface scope excludes — remove the interface scope until "+
					"scoped NPTv6 support lands (#5818)",
				rs.Name, rs.FromInterface)); err != nil {
				return nil, err
			}
		}
		if rs.FromRoutingInstance != "" {
			if err := emit(fmt.Sprintf(
				"security nat static rule-set %q is an NPTv6 (nptv6-prefix) rule-set "+
					"scoped `from routing-instance %q`, but the NPTv6 dataplane honors "+
					"only `from zone`; the routing-instance constraint would be dropped "+
					"and the prefix rewrite installed over a broader scope, translating "+
					"traffic the routing-instance scope excludes — remove the routing-"+
					"instance scope until scoped NPTv6 support lands (#5818)",
				rs.Name, rs.FromRoutingInstance)); err != nil {
				return nil, err
			}
		}

		// Per-rule `match source-address`. Prefer the full bracket-list
		// (SourceAddresses); fall back to the singular SourceAddress for an
		// older typed config, mirroring buildNptv6Snapshots' fail-closed check.
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}
			srcAddrs := append([]string(nil), rule.SourceAddresses...)
			if len(srcAddrs) == 0 && rule.SourceAddress != "" {
				srcAddrs = append(srcAddrs, rule.SourceAddress)
			}
			if len(srcAddrs) > 0 {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q is an NPTv6 (nptv6-prefix) "+
						"rule carrying `match source-address %s`, but the NPTv6 dataplane "+
						"honors only `from zone` and does not evaluate a source-address "+
						"constraint; the source match would be dropped and the prefix "+
						"rewrite applied to every source — remove the source-address match "+
						"until scoped NPTv6 support lands (#5818)",
					rs.Name, rule.Name, strings.Join(srcAddrs, ", "))); err != nil {
					return nil, err
				}
			}
			// Per-rule `match destination-port` (#5818 review residual): the port
			// scope is schema-permitted and the compiler records it, but the NPTv6
			// snapshot carries only from-zone + prefixes, so the port constraint is
			// dropped and the rewrite applied to EVERY port — the same
			// security-widening class as the source match. (The ordinary
			// destination-port strict gate skips NPTv6 rules, so this is the only
			// place that catches it.) MappedPort can never attach to an
			// nptv6-prefix then-branch, so destination-port is the sole remaining
			// reachable narrowing dimension.
			if rule.MatchDestinationPort != 0 {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q is an NPTv6 (nptv6-prefix) "+
						"rule carrying `match destination-port %d`, but the NPTv6 dataplane "+
						"honors only `from zone` and does not evaluate a destination-port "+
						"constraint; the port match would be dropped and the prefix rewrite "+
						"applied to every port — remove the destination-port match until "+
						"scoped NPTv6 support lands (#5818)",
					rs.Name, rule.Name, rule.MatchDestinationPort)); err != nil {
					return nil, err
				}
			}
		}
	}

	return warnings, nil
}

// validateNAT64PrefixStrict is the #3886 strict-vs-lenient gate for a NAT64
// rule-set's `prefix` (`security nat nat64 rule-set <r> prefix <p>`).
//
// The prefix is read verbatim into NAT64RuleSnapshot.Prefix
// (compiler_nat.go:compileNAT64 -> buildNAT64Snapshots) and parsed at
// dataplane apply by Nat64State::try_from_snapshots (userspace-dp/src/nat64.rs).
// That /96-integrity check REQUIRES the prefix to be `<ipv6-address>/96`: it
// splits on '/', the token after the first '/' MUST parse as a decimal /96
// (only /96 is supported by the translator), and the address token before the
// '/' MUST parse as an IPv6 address. Anything else (a non-/96 length, a missing
// or garbage mask, a non-IPv6 / malformed address) makes try_from_snapshots
// return a SnapshotIntegrityError, which propagates via `?` out of
// build_reconcile_forwarding and ABORTS the whole forwarding rebuild WITHOUT
// publishing a snapshot. The dataplane is then frozen at the last-good state:
// every later commit (new sessions, policy, NAT) silently stops reaching the
// dataplane with no operator feedback. Without this gate a single bad NAT64
// prefix COMMITS GREEN and wedges the entire control->dataplane pipeline.
//
// This mirrors the Rust /96-integrity check EXACTLY so anything that would
// abort the rebuild at runtime is rejected at commit — no commit-accept ->
// runtime-abort gap. An empty/absent prefix is deliberately OUT OF SCOPE: the
// Go builder (buildNAT64Snapshots) skips an empty-prefix rule, so it is never
// emitted on the wire and never reaches the Rust check, so it cannot freeze the
// rebuild.
//
// Strict (commit / commit-check): hard-reject a non-/96 or malformed prefix.
// Lenient (load / peer-sync, #1960 / #1979 doctrine): return the message as a
// warning so a config committed before this gate existed (or peer-synced) still
// BOOTS — fail-closed-on-compile-failure would otherwise brick the daemon on
// restart. The Rust helper's own try_from_snapshots backstop keeps the previous
// live forwarding state on the leniently-loaded config, so the bad rule never
// installs. Same doctrine as validateNPTv6Strict.
func validateNAT64PrefixStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NAT64 rule is invalid; on a userspace-dataplane apply/preflight"+
					" the helper's Nat64State::try_from_snapshots rejects the whole forwarding"+
					" snapshot and the previous live state is kept, so this rule — and every"+
					" later config change — will not reach the dataplane until it is corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		// Mirror the Rust loader Nat64State::from_snapshots
		// (userspace-dp/src/nat64.rs) EXACTLY. It splits on '/' (`split('/')`)
		// and requires EXACTLY two parts — `<ipv6>/96`: `if parts.len() != 2 {
		// ...; continue }` SKIPS any rule whose prefix does not split into
		// exactly two slash-separated parts (pinned by the Rust
		// `extra_slash_prefix_skips_rule` test). So a trailing extra slash
		// ("64:ff9b::/96/garbage" → three parts) is NOT ignored by the runtime —
		// the whole rule is silently dropped from the forwarding snapshot. If we
		// accepted it here (the pre-#5517 `len(parts) >= 2` loose split, which
		// indexed [0]/[1] and disregarded the rest), commit would SUCCEED but the
		// NAT64 rule would never install: a silent IPv6→IPv4 blackhole with no
		// error. Require exactly two parts so the commit gate rejects precisely
		// what the runtime skips (#5517).
		parts := strings.Split(rs.Prefix, "/")
		// The token after the first '/' must parse as a decimal /96. A missing
		// mask (no '/'), an empty mask, a non-numeric mask, an EXTRA '/' segment
		// (more than two parts), or any length other than 96 is rejected — only
		// an exact `<ipv6>/96` is supported by the translator.
		mask96 := false
		if len(parts) == 2 {
			if m, err := strconv.ParseUint(parts[1], 10, 8); err == nil && m == 96 {
				mask96 = true
			}
		}
		if !mask96 {
			if err := emit(fmt.Sprintf(
				"security nat nat64 rule-set %q prefix %q must be an IPv6 prefix of length /96 (RFC 6052: the well-known 64:ff9b::/96 or a /96 network-specific prefix); any other length, a missing/garbage mask, or an extra '/' segment is rejected by the dataplane, which aborts the entire forwarding rebuild",
				rs.Name, rs.Prefix)); err != nil {
				return nil, err
			}
			continue
		}
		// The address token before the first '/' must parse as an IPv6 address.
		// natAddrFamily keys the family on the un-parsed text (colon == v6) so
		// an IPv4-mapped literal (::ffff:1.2.3.4) is classified V6, matching
		// Rust's Ipv6Addr::from_str exactly (a dotted-quad or a non-IP token is
		// NOT V6 and is rejected).
		if natAddrFamily(parts[0]) != "v6" {
			if err := emit(fmt.Sprintf(
				"security nat nat64 rule-set %q prefix %q has an address part %q that is not a valid IPv6 address; the dataplane rejects it and aborts the entire forwarding rebuild",
				rs.Name, rs.Prefix, parts[0])); err != nil {
				return nil, err
			}
			continue
		}
	}

	return warnings, nil
}

// validateStaticNATThenTargetStrict rejects a static-NAT rule that would install
// with an EMPTY translation target (#4290). Two causes both leave Then=="":
//
//   - an unresolvable `then static-nat prefix-name <name>` (undefined /
//     multi-member / prefix-less address-book entry — resolveStaticNATThen-
//     PrefixNames could not fill Then); and
//   - a bare / misspelled `then static-nat` target keyword (a typo the free-form
//     static-nat leaf accepted — the then switch matched no case).
//
// Both previously committed cleanly and installed a static NAT with no
// translation (silent broken 1:1). NPTv6 rules are skipped (their Then holds the
// nptv6 prefix and buildStaticNATSnapshots handles them on a separate path).
// Strict on commit / commit-check (hard reject); the call site downgrades to a
// warning on the tolerant load / peer-sync path (#1960) where the dataplane then
// fails closed (the empty prefix does not parse as an IP → no translation).
// Rule-sets are walked in slice order for a deterministic first error.
func validateStaticNATThenTargetStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 || rule.Then != "" {
				continue
			}
			if rule.ThenPrefixName != "" {
				return fmt.Errorf(
					"static NAT rule-set %q rule %q references `then static-nat "+
						"prefix-name %q`, which does not resolve to a single "+
						"address-book prefix (define `security address-book "+
						"global address %s <prefix>`, or fix the name — the "+
						"translation target would otherwise be silently empty "+
						"and the 1:1 NAT would install with no target) (#4290)",
					rs.Name, rule.Name, rule.ThenPrefixName, rule.ThenPrefixName)
			}
			return fmt.Errorf(
				"static NAT rule-set %q rule %q has an empty `then static-nat` "+
					"translation target (an unhandled or misspelled target "+
					"keyword — expected prefix | prefix-name | nptv6-prefix | "+
					"inet) — the rule would otherwise install with no "+
					"translation and silently forward the packet untranslated "+
					"(#4290)",
				rs.Name, rule.Name)
		}
	}
	return nil
}

// validateStaticNATInetTargetStrict rejects a static-NAT rule whose translation
// target is the Junos NAT64 keyword `then static-nat inet` (#5859).
//
// The compiler ACCEPTS the keyword (compileNATStatic records rule.Then=="inet"),
// but the userspace snapshot builder emits it as the LITERAL string "inet" in
// the same-family static_nat table's InternalIP address slot. The Rust dataplane
// (static_nat.rs) calls parse_nat_prefix on "inet", the parse fails, and the
// rule is SILENTLY SKIPPED — a strict-valid config claims NAT64 translation but
// is INERT (a security-relevant NAT rule that installs nothing). The dataplane
// has no lowering of `static-nat inet` into the native NAT64 IR; the only
// supported IPv6->IPv4 path is the native `security nat nat64` rule-set
// (buildNAT64Snapshots reads cfg.Security.NAT.NAT64, NOT static-NAT rules).
//
// Until that lowering exists (a separate, larger design change: match scope,
// source pool, routing-instance, counters, fragments, reverse BIB, HA sync),
// fail CLOSED: hard-reject at strict commit so the operator sees a loud error
// instead of a silently inert rule, and name the native rule-set as the
// supported alternative. NPTv6 rules are skipped (Then holds the nptv6 prefix,
// handled on a separate path). Rule-sets are walked in slice order for a
// deterministic first error.
//
// Strict on commit / commit-check (hard reject); the call site downgrades to a
// warning on the tolerant load / peer-sync path (#1960 no-brick), where the
// snapshot builder (buildStaticNATSnapshots) independently DROPS the rule so the
// unparseable "inet" sentinel never reaches the Rust static_nat table.
func validateStaticNATInetTargetStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			if rule.Then == "inet" {
				return fmt.Errorf(
					"static NAT rule-set %q rule %q uses `then static-nat "+
						"inet` (NAT64), which is not yet representable in the "+
						"dataplane and would install as a silently inert rule "+
						"(the literal \"inet\" cannot parse as a translation "+
						"address); author the native `security nat nat64` "+
						"rule-set instead (#5859)",
					rs.Name, rule.Name)
			}
		}
	}
	return nil
}

// validateStaticNATMatchAddressesStrict (#6659) hard-rejects a static-NAT rule
// whose `match destination-address` carries MORE THAN ONE prefix.
//
// Before #6659 the compiler read this leaf with nodeVal, so a bracket / block
// list silently kept only the FIRST prefix. Two things went wrong at once:
//
//   - the rule translated only one of the authored external prefixes, and the
//     others fell through static NAT entirely, with no diagnostic; and
//   - the dropped prefixes never reached prefix validation, so a MALFORMED
//     entry in any slot but the first committed CLEAN — a validation fail-open.
//
// The compiler now accumulates every value into MatchAddresses (so all of them
// are visible to validation), and this gate rejects the multi-valued case. It
// is a rejection rather than a fan-out because a static-NAT rule lowers to ONE
// dataplane row — StaticNATRuleSnapshot.ExternalIP is a single address in the
// Rust static_nat table — so N prefixes have no representable meaning without
// inventing rule-fanout semantics (which external prefix pairs with the single
// `then static-nat prefix`?). Junos likewise takes one prefix here. Rejecting
// makes the previously-silent collapse loud and fails CLOSED; the operator
// writes one rule per external prefix. Widening static NAT to fan a rule across
// several external prefixes is a separate semantic change, tracked as #6674.
//
// Strict on commit / commit-check (hard reject); the call site downgrades to a
// warning on the tolerant load / peer-sync path (#1960 no-brick), where Match
// still carries the SELECTED prefix so behaviour is exactly pre-#6659.
//
// #6673: "selected", not "first". compileNATStatic runs
// `rule.Match = nodeVal(m)` once per `destination-address` sibling, so the LAST
// authored statement wins outright — `destination-address 192.0.2.1/32;` then
// `destination-address 198.51.100.1/32;` installs 198.51.100.1/32, not the
// first. Only WITHIN a single bracket/block list is the selected value that
// statement's first, which is why the error below quotes rule.Match rather than
// addrs[0]. That value can also be an authored blank, handled separately.
func validateStaticNATMatchAddressesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #6673: count only NON-EMPTY values. MatchAddresses records every
			// authored value slot including the empty ones, because nodeVal
			// selects an empty slot and the list has to contain what installs
			// (see multiLeafAuthoredValues). An empty slot is a selection, not a
			// second external prefix — `destination-address 192.0.2.1/32`
			// followed by `destination-address [ ]` authors ONE prefix and
			// blanks it, which master accepted, so counting raw length here
			// would invent a rejection this gate was never meant to make.
			//
			// #6673 fold: and count only DISTINCT ones, for exactly the same
			// reason the empty slot is spared. A REPEATED prefix —
			// `destination-address 192.0.2.1/32;` written twice, `[ 192.0.2.1/32
			// 192.0.2.1/32 ]`, two `match {}` stanzas carrying the same prefix,
			// or `192.0.2.1` beside `192.0.2.1/32` — authors ONE external
			// prefix. Master accepted every one of those and compiled a
			// byte-identical rule.Match; the raw count rejected them at commit,
			// and the message ("only %q would take effect and the rest would be
			// silently ignored") was false because "the rest" IS the selected
			// value. Nothing is ignored and nothing is lost. staticNATMatchAddrKey
			// collapses only values that lower to the SAME dataplane row, so the
			// #6659 rejection for genuinely distinct prefixes is untouched.
			// #6673 fold: the identity a value is deduped on is the
			// CONSUMER's. Plain static NAT masks a prefix to its length, so two
			// masked-equal spellings install the same row and count once; NPTv6
			// REJECTS host bits instead of masking (nptv6.rs parse_prefix,
			// #4519), so for an NPTv6 rule a host-bits value is NOT the same
			// prefix as its masked form and must not collapse into it — that
			// collapse was how `destination-address [ 2001:db8:1::/48
			// 2001:db8:1:2::/48 ]` committed clean with the invalid tail
			// visible to no gate at all. See staticNATMatchAddrKeyFor.
			addrs := dedupeValuesBy(nonEmptyValues(rule.MatchAddresses),
				staticNATMatchAddrKeyFor(rule.IsNPTv6))
			if len(addrs) > 1 {
				// #6673: the selected slot can itself be the authored BLANK —
				// `destination-address [ "" 192.0.2.1/32 198.51.100.1/32 ];`
				// counts two prefixes but nodeVal selects the empty one, so
				// ExternalIP lowers as "" and the Rust parse drops the whole
				// mapping. "only %q would take effect" printed `only ""` and
				// implied one of the two still translates.
				if rule.Match == "" {
					return fmt.Errorf(
						"static NAT rule-set %q rule %q declares %d `match "+
							"destination-address` prefixes (%v); a static-NAT rule "+
							"translates exactly ONE external prefix to the single "+
							"`then static-nat prefix` target and the selected value "+
							"is EMPTY, so NONE of them takes effect and the "+
							"dataplane drops the rule — author one rule per "+
							"external prefix (#6659)",
						rs.Name, rule.Name, len(addrs), addrs)
				}
				return fmt.Errorf(
					"static NAT rule-set %q rule %q declares %d `match "+
						"destination-address` prefixes (%v); a static-NAT rule "+
						"translates exactly ONE external prefix to the single "+
						"`then static-nat prefix` target, so only %q would take "+
						"effect and the rest would be silently ignored — author "+
						"one rule per external prefix (#6659)",
					rs.Name, rule.Name, len(addrs),
					addrs, rule.Match)
			}
		}
	}
	return nil
}

// validateProxyARPAddressesStrict (#6659 follow-up) hard-rejects a
// `security nat proxy-arp interface <if> address <addr>` value that the
// dataplane cannot parse.
//
// This gate exists because #6659 WIDENED THE READ. Before it, the compiler took
// this leaf with nodeVal and kept only the first address; `address
// [ 192.0.2.1 bogus ]` compiled to one entry and the malformed tail was never
// materialised. #6659 made the arm accumulate every value, so `bogus` now
// reaches ProxyARPEntry.Addresses as "bogus/32" — and proxyarp.go's installer
// does `netip.ParsePrefix(cidr)`, logs a bounded warning and `continue`s, so the
// address answers no ARP/ND and inbound traffic to it is never drawn to this
// firewall. Widening a read without widening its validator converts a
// value-drop into a silently-inert entry, so the validator is widened here in
// the same change.
//
// Note the check is NOT tail-only: a malformed address in the FIRST slot
// committed clean before #6659 too (verified), because proxy-ARP addresses
// carried no commit-time validator at all. Every slot is checked.
//
// That first-slot arm is a DELIBERATE NEW COMMIT GATE, not a consequence of the
// widening, and the paragraph above does not justify it — say so plainly rather
// than let the causal framing carry it. Measured on both trees with an identical
// corpus: `address bogus` (one value, first slot) is STRICT=OK on master and
// STRICT=REJECT here, while the COMPILED result is byte-identical on both
// ("bogus/32"). The widening never touched slot 1; this arm closes a hole that
// predates it.
//
// Operator-visible consequence, and the reason this is stated here instead of
// only in a commit message: an appliance whose ACTIVE config already carries a
// malformed proxy-ARP address keeps booting (the tolerant path warns), but its
// operator can no longer `commit` ANY change -- including a fix for an unrelated
// outage -- until that line is corrected. The gate is still the right call, since
// the entry was silently inert rather than working, but it is a behaviour change
// against an existing config and belongs in the release notes.
//
// The parse is netip.ParsePrefix — deliberately the SAME call the installer
// makes (pkg/dataplane/proxyarp.go), so "accepted at commit" and "installed at
// runtime" cannot diverge. The reported value is the COMPILED form: an address
// authored without a prefix length has "/32" appended by the compiler, so
// `address bogus` is reported as "bogus/32".
//
// Strict on commit / commit-check (hard reject so the inert entry is
// operator-visible); the call site downgrades to a warning on the tolerant load
// / peer-sync path (#1960 no-brick — an already-persisted config with a bad
// proxy-ARP address must still boot, and the installer already skips exactly
// that entry, so a leniently-loaded config is no worse than before this gate).
func validateProxyARPAddressesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, entry := range cfg.Security.NAT.ProxyARP {
		if entry == nil {
			continue
		}
		// #6714: a statement whose range keyword neither range branch consumed.
		// Reported BEFORE the per-address parse below, because the addresses
		// this entry does carry are the single-value fallback — they parse
		// fine, and reporting only them would name the one address that DID
		// survive while staying silent about the ones that did not.
		for _, spec := range entry.MalformedRangeSpecs {
			return fmt.Errorf(
				"security nat proxy-arp interface %q address %q is not a valid "+
					"address statement: it carries the `to` range keyword in a "+
					"position neither `address <low> to <high>` nor a plain "+
					"address list can consume — a list MIXING discrete addresses "+
					"with a range, a range with a missing or misplaced endpoint, "+
					"or a range nested inside a block. The compiler installs only "+
					"the FIRST value of such a statement and discards the rest, "+
					"so the firewall answers ARP/ND for one address of the "+
					"authored set and inbound traffic to the others is never "+
					"drawn to it. Author each range as its own `address <low> to "+
					"<high>` statement and the discrete addresses as another "+
					"(#6714)",
				entry.Interface, spec)
		}
		for _, addr := range entry.Addresses {
			if addr == "" {
				continue
			}
			if _, err := netip.ParsePrefix(addr); err != nil {
				return fmt.Errorf(
					"security nat proxy-arp interface %q address %q is not a valid "+
						"IP address or CIDR prefix; the dataplane parses every "+
						"proxy-ARP address with netip.ParsePrefix and SKIPS the ones "+
						"that fail, so this address would answer no ARP/ND and inbound "+
						"traffic to it would never be drawn to this firewall (#6659)",
					entry.Interface, addr)
			}
		}
	}
	return nil
}

// validateStaticNATSingleTargetStrict (#6483) hard-rejects a static-NAT rule
// that declares MORE THAN ONE translation target. A Junos static-nat rule maps
// to EXACTLY ONE of `prefix <ip>` | `prefix-name <name>` | `nptv6-prefix <p6>` |
// `inet`; authoring two or more (e.g. `then static-nat prefix <ip>` plus `then
// static-nat prefix-name <pool>`, or an `inet` sibling alongside a `prefix`
// sibling) is invalid.
//
// The compiler otherwise silently ACCEPTED such a rule: the compileNATStatic
// child loop honors the FIRST target it matches by a fixed priority
// (nptv6-prefix > prefix-name > prefix > inet) and drops the rest, and because
// prefix / inet / nptv6-prefix all land in the shared Then field a later target
// simply overwrites an earlier one — so the rule compiled to a single arbitrary
// target with no operator feedback (`inet` + `prefix` even installs as a plain
// prefix rule, evading the #5859 inet reject). Dropping a target this way also
// dropped any `mapped-port` that rode ONLY on the discarded target — the
// #6479/C179-038 residual — because that target's node was never the one whose
// modifier the mapped-port fold read. Rejecting the multi-target rule outright is
// the correct Junos-faithful closure and forecloses that residual as a side
// effect (the rule never compiles, so no dropped-target modifier can slip).
//
// ThenTargetCount is taken from the AST during compile (staticNATThenTargetCount)
// BEFORE the fields collapse, so it sees every declared target regardless of
// shape (flat-set targets collapse onto one static-nat node's children; the
// hierarchical `then { static-nat {…} static-nat {…} }` shape spreads them across
// siblings) and regardless of the last-wins overwrite. A count of exactly one is
// the well-formed case; zero is the empty-target gate's domain
// (validateStaticNATThenTargetStrict, #4290) and is not re-diagnosed here.
//
// Strict on commit / commit-check (hard reject so the malformed rule is
// operator-visible); the call site downgrades to a warning on the tolerant load
// / peer-sync path (opts.lenientFirewallRefs, #1960 no-brick) — a config an older
// binary persisted, or a peer authored, before this gate existed still boots, and
// the dataplane is no worse off than before the gate (the compiler still lowers
// the single honored target). Rule-sets are walked in slice order for a
// deterministic first-reported offender, mirroring the sibling static-NAT target
// gates.
func validateStaticNATSingleTargetStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.ThenTargetCount > 1 {
				return fmt.Errorf(
					"static NAT rule-set %q rule %q declares %d static-nat "+
						"translation targets (prefix/prefix-name/nptv6-prefix/inet); a "+
						"static-nat rule has exactly one — the compiler would otherwise "+
						"honor one target and silently drop the rest (and any mapped-port "+
						"riding only on a dropped target, the #6479 residual). Keep a "+
						"single target per rule",
					rs.Name, rule.Name, rule.ThenTargetCount)
			}
		}
	}
	return nil
}

// natThenTerminalActionCount returns how many mutually-exclusive NAT-terminal
// translation actions a resolved NATThen carries: source-nat `interface`,
// `off`, or a `pool <name>` for source NAT; `off` or a `pool <name>` for
// destination NAT (destination NAT never sets Interface). Exactly one of these
// is the well-formed case. Because compileNATSource/compileNATDestination RESET
// `rule.Then` at the top of each complete `then {}` block (#3850 last-wins),
// this count reflects only the WINNING (last) block — duplicate `then`
// CONTAINERS that each carry a single action resolve to one action here, never
// a false conflict. A count of two only arises when one complete then-block
// carries contradictory actions (e.g. `off` + `pool`, or a single hierarchical
// `source-nat { interface; pool P; }` node, which #5628's setter change now
// records as two set fields rather than silently picking one by child order).
//
// The converse does NOT hold, and the gate's message must not imply it
// (#7034): a count of ONE does not mean the block carried one action. A
// contradiction whose tokens are packed onto a single node —
// `source-nat pool P off`, `source-nat off pool P`, `source-nat { pool P off; }`
// — never reaches two fields, because the packed branch of compileNATSource /
// compileNATDestination reads `t.Keys[1]` alone and drops the rest. Those
// spellings resolve to one field, count one, and commit. Tracked as #7033.
func natThenTerminalActionCount(then NATThen) int {
	n := 0
	if then.Interface {
		n++
	}
	if then.Off {
		n++
	}
	if then.PoolName != "" {
		n++
	}
	return n
}

// validateNATTerminalActionCardinalityStrict (#5628, codex-review-181 M16)
// hard-rejects a source- or destination-NAT rule whose complete `then {}` block
// does not carry EXACTLY ONE NAT-terminal translation action:
//
//   - ZERO actions (an actionless rule, or a `then {}` whose only child is not a
//     recognized source-nat/destination-nat terminal): the rule commits but the
//     snapshot builder installs no translation, and the rule is not terminal, so
//     matching traffic falls THROUGH — translated by a later, broader rule if
//     one matches, otherwise leaving untranslated. Either way an intended `off`
//     exemption silently disappears; the first case is the #3844 fail-open, the
//     second leaves the same hazard latent. See the ZERO-actions bullet below
//     for why the two are not the same outcome (#6820).
//
//   - TWO OR MORE actions (contradictory, mutually-exclusive translations such
//     as `off` + `pool` or `interface` + `pool` inside ONE block): all but one
//     authored action is silently discarded, and WITHIN THAT BLOCK the survivor
//     is chosen by a FIXED precedence rather than by the order the actions were
//     written. Scope that to the block and no further (#7035): across duplicate
//     `then` CONTAINERS configuration order DOES decide, because the reset
//     below makes the LAST container the one that supplies the fields — swap
//     `then { source-nat { off; pool P; } }` with
//     `then { source-nat { interface; pool P; } }` and the surviving action
//     changes from `interface` to `off` while the message stays the same.
//     WHERE that happens
//     differs by kind, and the two do NOT share a mechanism (#6820 round 3):
//     source NAT publishes every authored field (the #5628 else-if→if setter
//     change) and the DATAPLANE picks `off` > `interface` > `pool`; destination
//     NAT resolves `off` in the COMPILER — buildDestinationNATSnapshots
//     short-circuits on `isOff`, skips the pool lookup entirely and publishes
//     `PoolAddress: ""` — so "every action is published" is FALSE for a DNAT
//     rule and must not be written as a shared sentence. Do NOT say the compiler
//     "picks one by packed-key / child order" either: it did before #5628 and
//     does not now, and the CONTRADICTORY bullet below says so explicitly
//     (#6820 re-gate). Nor is the discarded action always harmless —
//     `interface` + `pool P` translates onto the egress interface address and
//     never uses P.
//
// This counts actions WITHIN one complete then-block only. Duplicate `then`
// CONTAINERS are #3850's intentional last-wins merge (compileNAT resets
// rule.Then per block, so the count reflects the winning block) and are NOT
// rejected here — a rule with two `then` blocks each naming one action still
// commits.
//
// It counts RESOLVED FIELDS, not authored tokens, and that is a real bound on
// the gate rather than a restatement of it (#7034). The compiler reads a
// packed `source-nat`/`destination-nat` node by a SINGLE key —
// `switch t.Keys[1]` in compileNATSource / compileNATDestination — so every
// token-packed spelling of a contradiction lowers to ONE field and is counted
// as one action: `then { source-nat off pool P; }` resolves to `{Off:true}`,
// `then { source-nat pool P off; }` and `then { source-nat { pool P off; } }`
// to `{PoolName:"P"}`, and the flat `set … then source-nat pool P off` to
// `{PoolName:"P"}` — all four COMMIT under strict (measured through
// CompileConfig at f8e720c3e; the DNAT spellings behave identically). So a
// count of one does not mean the operator wrote one action, and this gate must
// not be read as covering the block-level case in general. That gap is the
// behaviour half, #7033; the message below says so rather than claiming the
// strong form. Strict on commit / commit-check (hard reject so the malformed rule
// is operator-visible); the caller downgrades to a warning on the tolerant load
// / peer-sync path (opts.lenientNATTerminalAction, #1960 no-brick). Only a
// malformed rule reaches that path — the strict commit path rejects it — but
// what happens there is NOT symmetric between the two arities (#5717):
//
//   - CONTRADICTORY (2+ actions) CONTAINING `off`: resolves to the EXEMPTION,
//     never the inverse. The rule records EVERY field (the else-if→if setter
//     change). The two builders then reach that outcome by DIFFERENT routes:
//     source NAT forwards all three fields (nat_source.go) and destination NAT
//     short-circuits on `isOff`, skipping pool resolution and publishing a
//     pool-less `Off=true` entry (nat_destination.go). Do not describe this as
//     "the builders forward everything": that is true of SNAT only, and a
//     justification naming a mechanism the code does not use is the exact
//     defect this comment exists to remove. But do NOT describe the DNAT
//     short-circuit as DECIDING the precedence either (#6820) — it
//     CANONICALIZES. `DnatEntry::to_outcome` (nat/destination.rs) branches on
//     `off` ALONE and never consults the pool, so a hand-built or mixed-version
//     snapshot carrying BOTH `Off=true` and a usable pool still resolves to the
//     exemption; measured by
//     dnat_off_exemption_is_decided_by_off_not_by_an_empty_pool_6820
//     (nat/tests_destination.rs), whose control arm clears `off` on the same
//     rule and gets the translation. Both languages independently give `off`
//     precedence; the Go step only removes a pool that would never have been
//     read. Pinned on both sides: in Go by
//     TestTolerantContradictory{SNAT,DNAT}*_5717 (pkg/dataplane/userspace) and
//     in Rust by off_wins_over_contradictory_interface_action_5717,
//     off_wins_over_contradictory_pool_action_5717, and
//     off_wins_over_all_three_actions_5717 (nat/tests_source.rs).
//
//   - CONTRADICTORY WITHOUT `off` — source NAT `interface` + `pool`: INTERFACE
//     MODE takes precedence, producing interface translation when the egress
//     interface has a suitable same-family address and an `Unavailable`
//     (fail-closed) result otherwise — the matcher returns
//     `InterfaceNoEgressAddress` rather than forwarding untranslated
//     (nat/source.rs, the #5688 belt). Either way the authored `pool` is
//     silently discarded, because the matcher checks off → interface_mode →
//     pool_mode in that order and there is no `off` here to take precedence.
//     This is still a malformed rule the strict gate rejects; it is called out
//     because "a contradiction resolves to the exemption" is TRUE ONLY when the
//     contradiction contains `off`, and stating it unqualified is the same
//     untested-safety-claim defect. Both halves are pinned, by SEPARATE
//     fixtures: the translating half by interface_wins_over_pool_without_off_5717
//     and the fail-closed half by interface_with_pool_no_egress_fails_closed_5717
//     (both userspace-dp/src/nat/tests_source.rs). Do not cite only the first
//     for the fail-closed half — it supplies a same-family egress address, so
//     it never reaches the belt; and the generic
//     interface_source_nat_no_v{4,6}_egress_addr_fails_closed pair does not
//     close the gap either, because those rules carry no pool and so cannot
//     detect a belt that falls back to pool translation. On the Go side
//     TestTolerantContradictorySNATWithoutOffCarriesBothActions_5717
//     (pkg/dataplane/userspace) pins that the builder publishes BOTH actions
//     plus this gate's tolerant-path warning. Note that BOTH precedences are
//     enforced in Rust — the `rule.off` early return in nat/source.rs for SNAT
//     and the `off`-only branch of `DnatEntry::to_outcome` in
//     nat/destination.rs for DNAT. Mutating either of THOSE publishes the
//     exemption as a translation. The Go `isOff` short-circuit in
//     nat_destination.go is canonicalization, not the decision: reverting it
//     changes the published snapshot's shape but not the packet's fate (#6820).
//
//   - ZERO actions: NOT inert, despite installing no translation. For source
//     NAT the builder EMITS the actionless rule and the Rust matcher's `else`
//     arm (nat/source.rs) then `continue`s to the next rule; for destination
//     NAT the builder skips the rule. Either way the matched traffic FALLS
//     THROUGH — and what it falls through TO depends on what follows it (#6820
//     re-gate). If a later, broader rule matches, that rule translates it,
//     which is exactly the fail-open this gate's own zero-action rejection text
//     describes. If NOTHING later matches, the loop simply ends and the packet
//     leaves UNTRANSLATED. Only the FIRST is a fail-open: the packet is
//     translated against the operator's intent. In the second the packet's
//     disposition COINCIDES with the intended exemption — untranslated — so
//     nothing is observably wrong today, and calling it a fail-open too
//     conflates a live wrong disposition with a latent one. What is wrong in
//     the second case is the RULE, not the packet: it is non-terminal, so the
//     moment any later broader rule is added the same config silently becomes
//     the first case. That is why the gate rejects it either way. An earlier
//     revision of this comment asserted only the first outcome ("...and is
//     translated by it"), which presumes a later rule exists.
//     Making an actionless rule terminal instead would newly exempt traffic that
//     already-deployed configs translate, so it is a migration-contract
//     decision tracked on #5717, not a mechanical fix.
//     TestTolerantActionlessRuleIsNotInert_5717,
//     actionless_rule_falls_through_to_later_broader_rule_5717 and
//     actionless_rule_with_no_later_rule_passes_untranslated_5717 pin BOTH
//     dispositions so neither the "inert" framing nor the "always translated by
//     a later rule" framing can silently return.
//
// Rule-sets are walked in sorted name order for a deterministic first-reported
// offender.
func validateNATTerminalActionCardinalityStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// mechanism is the WHOLE per-kind explanation of how the surviving action is
	// chosen, not just a precedence ordering, because the two kinds do not share
	// a mechanism (#6820 round 3). Source NAT forwards every authored field and
	// the DATAPLANE picks; destination NAT resolves `off` in the COMPILER —
	// buildDestinationNATSnapshots short-circuits on `isOff`, skips pool
	// resolution entirely, and publishes `PoolAddress: ""`
	// (pkg/dataplane/userspace/nat_destination.go) — so "every one of them is
	// published" is simply false for a DNAT rule. A shared sentence would have to
	// be false for one kind, and this is operator-facing text, so it is a
	// parameter.
	check := func(kind, actions, mechanism string, rulesets []*NATRuleSet) error {
		sorted := append([]*NATRuleSet(nil), rulesets...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i] == nil || sorted[j] == nil {
				return sorted[i] != nil
			}
			return sorted[i].Name < sorted[j].Name
		})
		for _, rs := range sorted {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil {
					continue
				}
				switch n := natThenTerminalActionCount(rule.Then); {
				case n == 0:
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q: `then` carries no translation action "+
							"(expected exactly one of %s); the rule would commit but installs no "+
							"translation and does not stop rule evaluation, so matching traffic "+
							"falls through — translated by a later broader rule if one matches, "+
							"otherwise left untranslated — and an intended exemption silently "+
							"disappears",
						kind, rs.Name, rule.Name, actions)
				case n >= 2:
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q: `then` carries %d mutually-exclusive "+
							"translation actions (expected exactly one of %s); %s, so all but "+
							"one action is silently discarded and, WITHIN THIS BLOCK, the "+
							"survivor is decided by that fixed precedence rather than by the "+
							"order the actions were written. (Duplicate `then` CONTAINERS "+
							"resolve last-wins per #3850, so a rule with several containers is "+
							"counted on the LAST one — container order therefore does decide "+
							"WHICH contradiction you get here. This gate counts the actions the "+
							"rule RESOLVED to, so it catches a block that LOWERS two distinct "+
							"actions; a contradiction whose tokens are PACKED onto one node, as "+
							"in `pool <p> off`, lowers to a single action, is counted as one and "+
							"is NOT caught here — tracked as #7033.)",
						kind, rs.Name, rule.Name, n, actions, mechanism)
				}
			}
		}
		return nil
	}
	if err := check("source",
		"`source-nat interface`, `source-nat pool <p>`, or `source-nat off`",
		"every one of them is published to the dataplane, which resolves the rule "+
			"by a fixed precedence — `off` wins over `interface`, and `interface` "+
			"over `pool`",
		cfg.Security.NAT.Source); err != nil {
		return err
	}
	if cfg.Security.NAT.Destination != nil {
		if err := check("destination",
			"`destination-nat pool <p>` or `destination-nat off`",
			"the compiler resolves `off` itself, publishing a pool-less exemption "+
				"and never looking the pool up, and the dataplane applies the same "+
				"`off`-over-`pool` precedence to any entry that carries both",
			cfg.Security.NAT.Destination.RuleSets); err != nil {
			return err
		}
	}
	return nil
}

// Aggregate source-NAT pool cardinality budgets (#5877). The per-member
// grammar gate (validateSourceNATPoolAddressGrammarStrict) bounds a SINGLE pool
// address member to MaxSourceNATPoolPrefixHosts, and the port gate
// (validateSourceNATPoolStrict) bounds a single pool's range to 1..65535 — but
// NOTHING bounded the AGGREGATE across a whole config: the number of pools, the
// SUM of every pool's address cardinality, or the total port capacity.
//
// Snapshot/apply constructs a PortAllocator for each pool-mode source-NAT rule
// BEFORE reuse dedup is known (userspace-dp/src/nat/{source,allocator}.rs): every
// pool address gets a per-address occupancy bitmap sized to the port range (one
// bit per port) plus a per-address counter. So a large-but-syntactically-valid
// config forces substantial memory + CPU during a security-critical
// commit-apply — stalling commits, watchdogs, HA convergence, or the Rust
// dataplane; repeated applies magnify it. These budgets reject such a config at
// COMMIT, fail-closed, before apply builds any allocator state.
//
// The budgets are deliberately generous multiples of the per-member cap so no
// realistic SNAT / CGNAT config approaches them, while a memory-exhaustion
// config is rejected.
const (
	// MaxSourceNATPoolCount bounds the number of DISTINCT pool-mode-referenced
	// source-NAT pools in one config. Real deployments use a handful to low-tens
	// of pools; 1024 is far beyond any legitimate config but caps the count of
	// allocator instances the apply path can be asked to build.
	MaxSourceNATPoolCount = 1024

	// MaxSourceNATAggregatePoolAddresses bounds the SUM of every pool's address
	// host-count (a bare IP counts 1; a CIDR counts its full prefix range,
	// matching the Rust expand_pool_address enumeration). = 16 ×
	// MaxSourceNATPoolPrefixHosts — a /12 worth of public addresses aggregated
	// across every pool, vastly more than any real SNAT allocation, while
	// capping the per-address counter arrays and per-address allocator structs.
	MaxSourceNATAggregatePoolAddresses = 16 * MaxSourceNATPoolPrefixHosts // 1,048,576

	// MaxSourceNATAggregatePortCapacity bounds the SUM over pools of
	// (address host-count × port-range) — the total per-address occupancy-bitmap
	// SLOTS the allocator constructs (one bit per slot). 2^33 slots ⇒ the
	// occupancy bitmaps are capped at ~1 GiB. It admits, e.g., two full /16
	// pools at the default 1024-65535 PAT range (65,536 × 64,512 ≈ 4.23e9 slots
	// each) or hundreds of realistically-sized CGNAT pools, while rejecting a
	// config that would force multi-gigabyte bitmap construction at apply.
	MaxSourceNATAggregatePortCapacity uint64 = 1 << 33 // 8,589,934,592
)

// checkedAddU64 adds two uint64 values, saturating to math.MaxUint64 on overflow
// instead of wrapping (companion to checkedMulU64). The aggregate SNAT
// cardinality accumulators use it so a pathological v6 pool member (a /0 counts
// 2^128 hosts, clamped to MaxUint64) trips the budget instead of wrapping back
// into the in-bound range.
func checkedAddU64(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// sourceNATPoolMemberHostCount returns how many host addresses a single
// source-NAT pool address member expands into, matching the Rust
// expand_pool_address enumeration exactly: a bare IP is one host; a CIDR is its
// FULL prefix range (1 << (addrbits - prefixlen)). An unparseable member counts
// zero (it builds no valid allocator entry — the grammar gate rejects it when
// the pool is referenced). A prefix with >= 64 host bits is clamped to
// math.MaxUint64 so it saturates the aggregate budget rather than overflowing a
// shift.
func sourceNATPoolMemberHostCount(addr string) uint64 {
	if strings.Contains(addr, "/") {
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return 0
		}
		addrBits := 32
		if p.Addr().Is6() {
			addrBits = 128
		}
		hostBits := addrBits - p.Bits()
		if hostBits <= 0 {
			return 1
		}
		if hostBits >= 64 {
			return math.MaxUint64
		}
		return uint64(1) << uint(hostBits)
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return 0
	}
	return 1
}

// SourceNATPoolMembers returns a source-NAT pool's address membership in the
// order the dataplane receives it: the singular `address` leaf first, then the
// repeated `address` list. Nil for a pool with no members, so a caller that
// ships this straight onto the wire keeps the pre-#6812 nil-vs-empty encoding.
//
// Shared by the snapshot builder (pkg/dataplane/userspace/nat_source.go, which
// ships exactly this slice), the aggregate budget walk below, and
// SourceNATPoolUnusableReason — so "what is in this pool" has ONE answer.
func SourceNATPoolMembers(pool *NATPool) []string {
	if pool == nil || (pool.Address == "" && len(pool.Addresses) == 0) {
		return nil
	}
	members := make([]string, 0, len(pool.Addresses)+1)
	if pool.Address != "" {
		members = append(members, pool.Address)
	}
	return append(members, pool.Addresses...)
}

// SourceNATPoolPortRange resolves a source-NAT pool's EFFECTIVE port range and
// reports whether the pool is usable on that axis. An unset endpoint defaults
// to the 1024-65535 PAT range.
//
// #5457: an EXPLICITLY configured but rejected range (a non-canonical token, an
// endpoint outside 1..65535, or a reversed low>high) is never stamped into
// PortLow/PortHigh — parseSourcePoolPortRange records the raw spec in
// PortRangeInvalidSpec instead. Returning ok=false for that marker is what
// stops the tolerant load / peer-sync path from silently installing the
// defaulted 1024-65535 range the operator did not configure: the snapshot
// builder turns ok=false into an "invalid_port_range" pool-unusable marker and
// the pool installs nothing.
//
// Lived in pkg/dataplane/userspace until #6812 F1; it moved here so the
// aggregate budget walk and the builder read ONE definition of "this pool's
// port range is usable" (see SourceNATPoolUnusableReason).
func SourceNATPoolPortRange(pool *NATPool) (uint16, uint16, bool) {
	if pool == nil {
		return 0, 0, false
	}
	if pool.PortRangeInvalidSpec != "" {
		return 0, 0, false
	}
	low := pool.PortLow
	if low == 0 {
		low = 1024
	}
	high := pool.PortHigh
	if high == 0 {
		high = 65535
	}
	if low < 1 || high < 1 || low > 65535 || high > 65535 || low > high {
		return 0, 0, false
	}
	return uint16(low), uint16(high), true
}

// SourceNATPoolUnusableReason reports the fail-closed snapshot reason a
// REFERENCED source-NAT pool is unusable from its DEFINITION alone, or "" when
// the pool installs. The returned strings are the wire reasons the userspace
// snapshot carries in PoolUnusableReason, decoded on the Rust side by
// source_nat_failure_reason_from_snapshot (userspace-dp/src/nat/source.rs).
//
// Precedence is last-writer-wins — invalid_port_range over
// zone_scoped_pool_address over invalid_pool over empty_pool — the first three
// preserved verbatim from the snapshot builder's original inline checks, so a
// pool tripping more than one condition reports the reason it always did. The
// membership-grammar clause (invalid_pool, #6812 F1 round 2) is deliberately
// placed BELOW zone_scoped_pool_address: netip.ParsePrefix rejects a zone
// qualifier outright, so a `fe80::/112%eth0` member fails the grammar too, and
// only a later zone_scoped write keeps that member reporting the specific
// #5875 reason it reported before.
//
// TWO callers share this predicate so they cannot drift (#6812 F1):
//
//  1. the snapshot builder marks the pool unusable, and
//  2. sourceNATAggregateReferencedCharges EXCLUDES it from the aggregate
//     budget.
//
// (2) is the load-bearing one. An unusable pool builds NO allocator in the
// dataplane — the Rust parse loop gates its PendingPoolAllocator on
// `pool_failure.is_none()`, so resolve_pool_allocators never charges it — and
// charging it Go-side therefore refuses a HEALTHY pool the dataplane would
// admit. That over-rejection lands on the tolerant load / peer-sync path
// (#1960 no-brick), which is exactly the path an operator uses to recover.
//
// The membership clause is ALL-OR-NOTHING because the dataplane's is (#6812 F1
// round 2). The Rust parse loop ORs expand_pool_address over every member into
// one `invalid_pool_address` flag and marks the WHOLE pool
// SourceNatFailureReason::InvalidPool when ANY member fails
// (userspace-dp/src/nat/source.rs) — one malformed or over-capacity member
// poisons an otherwise honorable pool. This predicate therefore asks the SAME
// question, member by member, through sourceNATPoolAddressReason: the exact
// per-member mirror of expand_pool_address that the #5627 strict grammar gate
// already uses. It does not approximate the verdict with a derived quantity
// (the pre-round-2 budget walk summed host counts and inferred unusability
// from a zero total, which agreed with the runtime only when EVERY member
// failed).
func SourceNATPoolUnusableReason(pool *NATPool) string {
	if pool == nil {
		return "missing_pool"
	}
	reason := ""
	members := SourceNATPoolMembers(pool)
	if len(members) == 0 {
		reason = "empty_pool"
	}
	// #6812 F1 round 2: ANY member the Rust expander cannot honor — an
	// unparseable token, a malformed mask, or an over-capacity prefix
	// (`10.0.0.0/15` enumerates 131,072 hosts against a 65,536 cap) — makes
	// expand_pool_address return false, which sets `invalid_pool_address` and
	// fails the WHOLE pool as InvalidPool. "invalid_pool" is the wire reason
	// source_nat_failure_reason_from_snapshot already decodes to exactly that
	// variant, so the dataplane disposition for these pools is unchanged: only
	// WHERE the verdict is reached moves, from the Rust parse loop to the
	// shared predicate the budget walk consults.
	for _, a := range members {
		if _, ok := sourceNATPoolAddressReason(a); !ok {
			reason = "invalid_pool"
			break
		}
	}
	// #5875: an IPv6 member carrying a `%<zone>` qualifier is not
	// dataplane-representable (std::net::IpAddr has no zone model).
	for _, a := range members {
		if PoolAddressHasZoneScope(a) {
			reason = "zone_scoped_pool_address"
			break
		}
	}
	if _, _, ok := SourceNATPoolPortRange(pool); !ok {
		reason = "invalid_port_range"
	}
	return reason
}

// sourceNATAggregatePoolCharge is one DISTINCT referenced pool's charge
// against the #5877 aggregate budgets: its expanded address cardinality and
// its port capacity (addresses x port range = occupancy bitmap slots).
type sourceNATAggregatePoolCharge struct {
	name    string
	addrs   uint64
	portCap uint64
}

// sourceNATAggregateReferencedCharges walks the DISTINCT pools a pool-mode
// `then source-nat pool <name>` rule references and returns each pool's budget
// charge in deterministic first-reference order (rule-sets STABLE-sorted by
// #4161 scope tier — so config order is preserved WITHIN a tier — rules in
// config order, pools deduped by name). This is the SINGLE source of
// truth for the #5877 aggregate scoping + charge arithmetic: the strict
// validator (validateSourceNATAggregateCardinalityStrict) sums it for the
// whole-config reject, and SourceNATAggregateOverBudgetPools (#6812) first-fits
// it for the tolerant snapshot poison, so the two can never drift on what is
// counted or how.
//
// SCOPE — the charged set is exactly the set `parse_source_nat_rules`
// (userspace-dp/src/nat/source.rs) expands into a PortAllocator, which means
// TWO exclusions, each one a pool that reaches the dataplane and builds
// nothing:
//
//   - UNREFERENCED. No pool-mode rule names it, so it never reaches the
//     allocator path. (A NAT64-referenced pool uses the separate parse_pool_v4
//     path and is bounded by isNAT64PoolHostAddress, not here.)
//   - UNUSABLE (#6812 F1). SourceNATPoolUnusableReason is non-empty — empty
//     membership, a member the expander cannot honor, a `%zone` member, or a
//     rejected port range — so the snapshot ships it poisoned and the Rust
//     parse loop, which gates its PendingPoolAllocator on
//     `pool_failure.is_none()`, never charges it.
//
// Charging either would make this walk refuse a HEALTHY pool that
// resolve_pool_allocators admits — over-rejection, landing on the tolerant
// recovery path (#1960 no-brick) where a peer-sync or lenient load is how an
// operator gets back to a working state.
//
// ROUND 2 — WHY THE EXCLUSION IS A SHARED VERDICT AND NOT A LIST OF CONDITIONS.
// The dataplane's pool grammar is ALL-OR-NOTHING: one member expand_pool_address
// refuses fails the whole pool. Round 1 approximated that with a SUM — it added
// per-member host counts and skipped only when the total was zero — which
// agrees with the runtime only when EVERY member fails. A pool of
// `[198.51.100.1, not-an-ip]` summed to 1, was charged here, and built nothing
// there; 1,024 of them ahead of one healthy pool consumed the whole pool-count
// budget and poisoned the healthy pool `aggregate_over_budget` — the very F1
// defect this walk exists to prevent, in its fifth spelling. Each of the four
// earlier spellings had been closed by adding another condition to the sum.
// The exclusion above is now the SAME predicate the snapshot builder stamps on
// the wire, so the two cannot disagree by construction; there is no derived
// quantity left for a sixth spelling to slip through. A pool the walk charges
// has honorable members by that verdict, so the counted host sums are accurate
// on BOTH paths; the saturating arithmetic remains only to keep a saturating
// charge from wrapping into an accept.
func sourceNATAggregateReferencedCharges(cfg *Config) []sourceNATAggregatePoolCharge {
	if cfg == nil {
		return nil
	}
	pools := cfg.Security.NAT.SourcePools
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Source...)
	// #6812 F3: walk rule-sets in the order the DATAPLANE charges them. The
	// snapshot builder STABLE-sorts its emitted rules by #4161 scope tier
	// (SourceNATScopeTier) and resolve_pool_allocators charges that emitted
	// slice in that order — exactly so on a first apply; on a re-apply it
	// charges the REUSED keys first and then walks the remainder in slice
	// order, which cannot change which pools live (see the ORDER note on
	// SourceNATAggregateOverBudgetPools). So a stable sort by the same tier —
	// config order preserved within a tier, exactly as the builder preserves
	// it — reproduces the dataplane's first-fit sequence. Ordering by rule-set NAME
	// (through round 2) matched neither that order nor any Junos semantic: with
	// two pools that each fit alone but not together, the alphabetically
	// earlier rule-set took the budget, so an unrelated rename could poison the
	// more-specific rule-set's pool. The sibling walks in this file still sort
	// by name — they pick a deterministic first-reported OFFENDER for an error
	// message, where name order is the friendlier choice and admission plays no
	// part.
	sort.SliceStable(rulesets, func(i, j int) bool {
		return natRuleSetScopeTier(rulesets[i]) < natRuleSetScopeTier(rulesets[j])
	})
	seen := make(map[string]bool)
	var charges []sourceNATAggregatePoolCharge
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			name := rule.Then.PoolName
			if seen[name] {
				continue
			}
			seen[name] = true
			pool, ok := pools[name]
			if !ok || pool == nil {
				// Undefined reference — validateNATPoolReferencesStrict (#5626).
				continue
			}
			// #6812 F1: a pool the snapshot builder ALREADY marks unusable
			// (empty / zone-scoped member / invalid port range) never becomes a
			// PendingPoolAllocator in Rust — the parse loop gates on
			// `pool_failure.is_none()` — so resolve_pool_allocators neither
			// charges it nor lets it occupy a slot. Charging it here would
			// refuse a HEALTHY pool the dataplane admits, which is the wrong
			// direction on the tolerant recovery path.
			if SourceNATPoolUnusableReason(pool) != "" {
				continue
			}
			// INVARIANT (#6812 F1 round 2): every member of a pool that reaches
			// this line is honorable — SourceNATPoolUnusableReason above is
			// all-or-nothing over sourceNATPoolAddressReason, so a single
			// rejected member already skipped the pool. An honorable member
			// parses, so sourceNATPoolMemberHostCount returns at least 1 for
			// it, and a pool with NO members reported empty_pool. poolAddrs is
			// therefore >= 1 here by construction, which is why there is no
			// zero-total skip: the shape it used to catch (every member
			// unparseable) is no longer representable past the shared verdict.
			// TestBudgetChargeImpliesHonorableMembers_6812 binds both halves.
			var poolAddrs uint64
			for _, a := range SourceNATPoolMembers(pool) {
				poolAddrs = checkedAddU64(poolAddrs, sourceNATPoolMemberHostCount(a))
			}
			// Port range: CONSULT the shared resolver rather than recompute
			// from the raw fields (#6812 F2 round 3). SourceNATPoolPortRange is
			// what the snapshot builder ships to the dataplane
			// (pkg/dataplane/userspace/nat_source.go), so reading it here is
			// what makes the charge equal the capacity the allocator is asked
			// to build — the same "consult, do not re-derive" rule round 2
			// applied to the usability verdict, one field over.
			//
			// This is behavior-preserving on every config the compiler can
			// produce: compileNATSource defaults an unset PortLow/PortHigh to
			// 1024/65535 before the pool is stored, so the raw recompute and the
			// resolver already agreed on the live path (measured: a referenced
			// 3x /16 no-`port`-leaf config charges 4,227,858,432 slots per pool
			// either way). What it removes is the DEPENDENCE on that distant
			// defaulting: a *NATPool that reaches this walk without it — the
			// resolver's own documented input, raw 0/0 — charged zero port slots
			// and was admitted, while the builder shipped the resolved
			// 1024-65535 and the dataplane charged 64,512 per address.
			// The `ok=false` half cannot reach here (an unusable port range is
			// already an invalid_port_range skip above), so this reads the pair.
			portLow, portHigh, _ := SourceNATPoolPortRange(pool)
			var portRange uint64
			if portHigh >= portLow && portLow > 0 {
				portRange = uint64(portHigh-portLow) + 1
			}
			charges = append(charges, sourceNATAggregatePoolCharge{
				name:    name,
				addrs:   poolAddrs,
				portCap: checkedMulU64(poolAddrs, portRange),
			})
		}
	}
	return charges
}

// SourceNATAggregateOverBudgetPools (#6812) returns the set of referenced
// source-NAT pool names that do NOT fit within the #5877 aggregate budgets
// under a deterministic FIRST-FIT walk: pools are charged in the shared
// first-reference order (sourceNATAggregateReferencedCharges); a pool whose
// admission would cross any budget (count / total addresses / total port
// capacity) is refused WITHOUT consuming budget, so a later, smaller pool
// can still install. Saturating arithmetic throughout — a saturating charge
// (e.g. a ::/0 member on the tolerant path) can never fit and poisons its
// pool, never wraps into an accept.
//
// The userspace snapshot builder (pkg/dataplane/userspace/nat_source.go)
// poisons these pools (PoolUnusable + "aggregate_over_budget") so a
// TOLERATED over-budget config — lenient load / peer-sync, where the #5877
// gate only warns (#1960 no-brick) — never asks the dataplane to build the
// over-budget occupancy bitmaps (opus-review-001 R73: three full-range /16
// pools = 12,683,575,296 bitmap bits, ~1.48 GiB). The Rust apply boundary
// independently enforces the same budgets (resolve_pool_allocators in
// userspace-dp/src/nat/source.rs) as the final backstop; the first-fit
// admission rule here mirrors it — same charge, and (since #6812 F1) the same
// EXCLUSIONS, see sourceNATAggregateReferencedCharges — so Go and the dataplane
// agree on WHICH pools live.
//
// ORDER, precisely. Two earlier revisions of this comment were wrong in
// opposite directions: round 7's said "same order" flatly, and round 8's
// replaced it with "identical on a first apply, NOT identical on a re-apply" —
// also too categorical, in the narrower direction.
//
// What is actually true. This walk is a single first-fit pass in emitted
// first-reference order. resolve_pool_allocators is TWO passes: phase 1
// reserves the distinct keys that are BOTH viable in this apply AND already
// present in `previous_allocators` — reused keys are accepted unconditionally,
// so their charge is live state rather than a prediction — and only then does
// phase 2 admit NEW keys against that total (source.rs, "Reused keys are
// RESERVED before any new key is admitted", #6812 F2 round 4). Note "viable":
// a rule whose pool already failed gets no PendingPoolAllocator, so a
// previously-allocated but currently-poisoned key is NOT reserved.
//
//   - Empty `previous_allocators` GUARANTEES the sequences coincide: phase 1
//     reserves nothing and phase 2 walks the slice in order.
//   - A re-apply MAY differ, and need not. An all-reused apply coincides
//     trivially (phase 2 admits nothing new); so does any apply whose reused
//     keys already precede its new ones in emitted order. The sequences differ
//     only when a NEW key is emitted before some reused key.
//
// AND THE DIFFERENCE CANNOT CHANGE THE OUTCOME, which is the part that matters
// and is stronger than the round-8 wording ("they are not independent
// deciders") on its own. Let A be the set this walk admits. First-fit admits
// greedily and only while the running total fits, so charge(A) is within every
// budget. The poison travels on the wire and the Rust parse loop builds no
// pending for a failed pool, so the set of DISTINCT ALLOCATOR KEYS represented
// by the non-nil pendings is exactly A. The pendings themselves are per-RULE
// and a shared pool has one per referencing rule, so they are a multiset with
// repeats — the statement holds only at distinct-key granularity, and that is
// the granularity everything downstream works at: `reserved` charges a key
// once, `pool_allocators` assigns it once, and `refused_keys` refuses it
// consistently. Distinct pool NAMES map to distinct keys, because the key
// carries the pool name alongside the expanded members and the port range, and
// this builder derives all three from the pool (SourceNATPoolMembers /
// SourceNATPoolPortRange), so every rule referencing one pool ships the same
// three. Phase 1 reserves R, a subset of A. Phase 2 accepts every reused key
// unconditionally and admits a new key k when used + charge(k) fits — and R,
// the new keys already processed, and k are DISJOINT subsets of A, so that sum
// is bounded by charge(A), which fits. Rust therefore refuses nothing this walk
// admitted, in any emitted order. The live set is exactly A.
//
// The reserve-first order still earns its keep for the snapshots no Go poison
// is coming for — a tolerated, older control plane's, or handcrafted snapshot,
// where A is whatever arrived rather than something this walk computed. That is
// what makes the boundary an INDEPENDENT backstop rather than a second
// opinion.
//
// That agreement is a tested claim, not an asserted one:
// TestAggregateBudgetExcludesUnusablePools_6812
// (this package) and TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812
// (pkg/dataplane/userspace) drive the Go half, and
// production_entry_admits_a_healthy_pool_after_failed_pools_6812
// (userspace-dp/src/nat/tests_aggregate_budget.rs) drives the same scenario
// through the Rust production entry. Strict-commit configs never reach the
// builder over budget, so the poison only ever fires on the tolerant path that
// needs it.
func SourceNATAggregateOverBudgetPools(cfg *Config) map[string]bool {
	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) == 0 {
		return nil
	}
	var poolCount uint64
	var totalAddrs uint64
	var totalPortCap uint64
	var poison map[string]bool
	for _, c := range charges {
		candCount := checkedAddU64(poolCount, 1)
		candAddrs := checkedAddU64(totalAddrs, c.addrs)
		candCap := checkedAddU64(totalPortCap, c.portCap)
		if candCount > uint64(MaxSourceNATPoolCount) ||
			candAddrs > uint64(MaxSourceNATAggregatePoolAddresses) ||
			candCap > MaxSourceNATAggregatePortCapacity {
			if poison == nil {
				poison = make(map[string]bool)
			}
			poison[c.name] = true
			continue // first-fit: charge not consumed; a later pool may still fit
		}
		poolCount, totalAddrs, totalPortCap = candCount, candAddrs, candCap
	}
	return poison
}

// validateSourceNATAggregateCardinalityStrict (#5877) hard-rejects a config
// whose AGGREGATE source-NAT pool cardinality exceeds a resource budget: too
// many pools, too many total pool addresses, or too much total port capacity.
// The per-field / per-member gates bound ONE pool; this bounds the SUM across
// every pool so a large-but-syntactically-valid config cannot force the apply
// path to build multi-gigabyte allocator state (a per-address occupancy bitmap
// per pool address, sized to the port range) during a security-critical
// commit-apply. Fail-closed at COMMIT, before apply constructs any allocator.
//
// The walk (scoping + charge arithmetic) is sourceNATAggregateReferencedCharges;
// this validator sums the charges for the whole-config reject. Since #6812 F1
// that walk skips pools already destined to be unusable, so they no longer
// inflate this sum either — which is a no-op on the strict path (their own
// gates, validateSourceNATPoolStrict / validateSourceNATPoolAddressScopeStrict,
// run EARLIER in runUniformGates and reject the config first) and correct on
// the resource question regardless: a pool that builds no allocator costs no
// allocator memory.
//
// Strict on commit / commit-check (hard-reject naming the exceeded budget and by
// how much); the call site (runUniformGates) downgrades it to a warning on the
// tolerant load / peer-sync path (opts.lenientDestNATAddresses — #1960 no-brick:
// a config persisted before this gate existed still boots, and the operator is
// warned to shrink it). Since #6812 the tolerant path no longer builds the
// over-budget state it always did: the snapshot poisons the non-fitting pools
// (SourceNATAggregateOverBudgetPools) and the Rust apply boundary refuses their
// bitmaps. Shares the SNAT silent-drop doctrine flag with the sibling
// source-pool gates. Registered in the SNAT strict set
// (validateSourceNATStrictView) so #5876's peer-effective gate bounds the
// standby's identical allocator build too.
func validateSourceNATAggregateCardinalityStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	charges := sourceNATAggregateReferencedCharges(cfg)
	poolCount := len(charges)
	var totalAddrs uint64
	var totalPortCap uint64
	for _, c := range charges {
		totalAddrs = checkedAddU64(totalAddrs, c.addrs)
		totalPortCap = checkedAddU64(totalPortCap, c.portCap)
	}
	if poolCount > MaxSourceNATPoolCount {
		return fmt.Errorf(
			"source-nat references %d distinct pools, over the aggregate budget of "+
				"%d (by %d); each pool builds allocator state at apply, so an unbounded "+
				"pool count can exhaust memory and stall the commit-apply — reduce the "+
				"number of referenced `security nat source pool` stanzas (#5877)",
			poolCount, MaxSourceNATPoolCount, poolCount-MaxSourceNATPoolCount)
	}
	if totalAddrs > uint64(MaxSourceNATAggregatePoolAddresses) {
		return fmt.Errorf(
			"source-nat pools define %d total pool addresses, over the aggregate "+
				"budget of %d; every pool address gets a per-address occupancy bitmap "+
				"at apply, so an unbounded address cardinality can exhaust memory and "+
				"stall the commit-apply — shrink the pool address ranges (#5877)",
			totalAddrs, uint64(MaxSourceNATAggregatePoolAddresses))
	}
	if totalPortCap > MaxSourceNATAggregatePortCapacity {
		return fmt.Errorf(
			"source-nat pools define %d total port slots (sum of pool addresses × "+
				"port range), over the aggregate budget of %d; each slot is a bit in a "+
				"per-address occupancy bitmap the apply path builds, so an unbounded "+
				"total exhausts memory and stalls the commit-apply — shrink the pool "+
				"address ranges or narrow the port ranges (#5877)",
			totalPortCap, MaxSourceNATAggregatePortCapacity)
	}
	return nil
}

// natAllocOwner names one INDEPENDENT source-NAT / NAT64 allocator for a #5144
// external-tuple-overlap diagnostic. Each owner draws its translated addresses
// from `pool`; two DISTINCT owners whose expanded members intersect can each
// hand out the same (family, translated IP, port), and the reverse (1:N) NAT
// index cannot tell the two flows apart (reply misdelivery).
type natAllocOwner struct {
	// desc is the operator-facing identity, e.g. `source-nat pool "wan"` or
	// `nat64 rule-set "r1" (prefix 64:ff9b::/96) source-pool "wan"`.
	desc string
	// pool is the resolved source pool whose addresses this allocator draws from.
	pool *NATPool
}

// natV4Interval / natV6Interval is one expanded pool member as an inclusive
// numeric address interval within a single family, tagged with the owning
// allocator (index into the owners slice) and the original member text for the
// diagnostic. v4 endpoints are big-endian uint32 values widened to uint64 (so a
// /0 broadcast 0xFFFFFFFF+... never wraps); v6 endpoints are netip.Addr for
// 16-byte ordered comparison.
type natV4Interval struct {
	lo, hi uint64
	inst   int
	member string
}

type natV6Interval struct {
	lo, hi netip.Addr
	inst   int
	member string
}

// validateNATPoolExternalTupleOverlapStrict (#5144) rejects a config in which
// two INDEPENDENT source-NAT / NAT64 allocators can mint the same external
// tuple. The Rust dataplane keys the source-NAT PortAllocator by pool name +
// address vector (userspace-dp/src/nat/source.rs) and the NAT64 allocator by
// (prefix_bytes, pool_v4) (userspace-dp/src/nat64.rs) — so differently-named
// overlapping source pools, a source pool that also backs a NAT64 rule-set, two
// NAT64 rule-sets sharing a pool under different prefixes, and duplicate members
// WITHIN one pool each own a SEPARATE occupancy bitmap. Independent bitmaps
// share no ownership word, so two flows can be handed the same (family,
// translated IP, translated port) to the same remote endpoint; the reverse
// conntrack index (1:N) then cannot disambiguate the return packet and
// misdelivers it. The only pre-existing NAT overlap gate was NPTv6 static-prefix
// (#2241); this is its source-NAT / NAT64 analog.
//
// This is the commit-time DETECTION half of #5144 (material choice S1: reject
// independently-owned overlap). It does NOT introduce the deferred packet-path
// global cross-domain allocator (the R2 design, gated on user signoff and
// #2387/#5338/#5698). Rejecting the overlap at commit forecloses the runtime
// collision because the vulnerable config never reaches the dataplane.
//
// Allocator instances (owners) are enumerated exactly as the Rust helper keys
// its allocators, so Go and the dataplane agree on what is "one allocator":
//
//   - source-NAT: one owner per DISTINCT pool a pool-mode `then source-nat pool
//     <name>` rule references (all such rules share the pool-name-keyed
//     allocator). Unreferenced pools build no allocator and are out of scope
//     (mirrors validateSourceNATAggregateCardinalityStrict's scoping).
//   - NAT64: one owner per DISTINCT (prefix, source-pool) pair a `nat64
//     rule-set` references. Two rule-sets differing only in name share one
//     allocator (one owner); two sharing a pool under different prefixes are
//     independent (two owners).
//
// Every owner's pool members (pool.Address + pool.Addresses, ranges already
// expanded to /32s by appendPoolAddresses) are turned into family-scoped numeric
// intervals — v4 vs v6 bucketed by the colon-strict textual family
// (natAddrFamily(natCIDRIPPart(...)), the Go/Rust parity rule) so an IPv4-mapped
// IPv6 literal is never compared against a real v4 member. An O(n log n)
// sort-and-sweep over each family's intervals finds the first overlapping pair.
// An overlap between two members of the SAME owner is a within-pool
// duplicate/overlap; between two owners it is the cross-pool / cross-feature
// collision.
//
// Strict on commit / commit-check (hard-reject naming both allocators and the
// overlapping members); lenient on load / peer-sync (warn — #1960 no-brick: a
// config committed before this gate existed still boots. Unlike NPTv6/NAT64 the
// dataplane does NOT reject the snapshot — the overlap installs with a LATENT
// collision — so the warning tells the operator the risk persists until
// corrected). Uses its own opts.lenientNATPoolOverlap flag, mirroring
// validateNPTv6Strict. Placed next to the NPTv6 overlap gate (the #2241
// precedent the issue cites) in runTailGates.
func validateNATPoolExternalTupleOverlapStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	pools := cfg.Security.NAT.SourcePools
	if len(pools) == 0 {
		return nil, nil
	}

	var owners []natAllocOwner

	// Source-NAT allocator instances: one per DISTINCT pool a pool-mode rule
	// references. Walk rule-sets in sorted name order and collect referenced pool
	// names into a sorted, deduped list for a deterministic owner order.
	srcRuleSets := append([]*NATRuleSet(nil), cfg.Security.NAT.Source...)
	sort.SliceStable(srcRuleSets, func(i, j int) bool {
		if srcRuleSets[i] == nil || srcRuleSets[j] == nil {
			return srcRuleSets[i] != nil
		}
		return srcRuleSets[i].Name < srcRuleSets[j].Name
	})
	var srcPoolNames []string
	srcSeen := make(map[string]bool)
	for _, rs := range srcRuleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" || srcSeen[rule.Then.PoolName] {
				continue
			}
			srcSeen[rule.Then.PoolName] = true
			srcPoolNames = append(srcPoolNames, rule.Then.PoolName)
		}
	}
	sort.Strings(srcPoolNames)
	for _, name := range srcPoolNames {
		if pool := pools[name]; pool != nil {
			owners = append(owners, natAllocOwner{
				desc: fmt.Sprintf("source-nat pool %q", name),
				pool: pool,
			})
		}
	}

	// NAT64 allocator instances: one per DISTINCT (prefix, source-pool) pair.
	// Walk rule-sets in sorted name order and dedup on the (prefix, pool) key that
	// the Rust nat64 allocator uses.
	nat64RuleSets := append([]*NAT64RuleSet(nil), cfg.Security.NAT.NAT64...)
	sort.SliceStable(nat64RuleSets, func(i, j int) bool {
		if nat64RuleSets[i] == nil || nat64RuleSets[j] == nil {
			return nat64RuleSets[i] != nil
		}
		return nat64RuleSets[i].Name < nat64RuleSets[j].Name
	})
	nat64Seen := make(map[string]bool)
	for _, rs := range nat64RuleSets {
		if rs == nil || rs.SourcePool == "" {
			continue
		}
		pool := pools[rs.SourcePool]
		if pool == nil {
			continue
		}
		// Only a rule-set whose prefix builds a LIVE NAT64 allocator is an owner,
		// keyed on the CANONICAL (prefix, pool) identity the Rust nat64 allocator
		// uses (12 network bytes + pool_v4). An empty / malformed / non-/96 prefix
		// builds no allocator and is dropped (ok=false) so it cannot false-report
		// an overlap; two rule-sets naming one pool under equivalent /96 spellings
		// (`64:ff9b::/96` vs `64:ff9b::/096` vs `0064:ff9b:0:0:0:0:0:0/96`) dedup to
		// one owner rather than false-rejecting. See nat64PrefixOwnerKey.
		prefixKey, ok := nat64PrefixOwnerKey(rs.Prefix)
		if !ok {
			continue
		}
		key := prefixKey + "\x00" + rs.SourcePool
		if nat64Seen[key] {
			continue
		}
		nat64Seen[key] = true
		owners = append(owners, natAllocOwner{
			desc: fmt.Sprintf("nat64 rule-set %q (prefix %s) source-pool %q",
				rs.Name, rs.Prefix, rs.SourcePool),
			pool: pool,
		})
	}

	if len(owners) == 0 {
		return nil, nil
	}

	// Expand every owner's pool members into family-scoped numeric intervals.
	var v4 []natV4Interval
	var v6 []natV6Interval
	for idx := range owners {
		for _, m := range poolMemberTexts(owners[idx].pool) {
			n := parsePoolAddr(m)
			if n == nil {
				continue
			}
			switch natAddrFamily(natCIDRIPPart(m)) {
			case "v4":
				if lo, hi, ok := natV4IntervalOf(n); ok {
					v4 = append(v4, natV4Interval{lo: lo, hi: hi, inst: idx, member: m})
				}
			case "v6":
				if lo, hi, ok := natV6IntervalOf(n); ok {
					v6 = append(v6, natV6Interval{lo: lo, hi: hi, inst: idx, member: m})
				}
			}
		}
	}

	if msg := sweepNATV4Overlap(owners, v4); msg != "" {
		return emitNATOverlap(lenient, msg)
	}
	if msg := sweepNATV6Overlap(owners, v6); msg != "" {
		return emitNATOverlap(lenient, msg)
	}
	return nil, nil
}

// emitNATOverlap renders a #5144 overlap finding as a strict error or a lenient
// warning, mirroring validateNPTv6Strict's emit helper.
func emitNATOverlap(lenient bool, msg string) ([]string, error) {
	if lenient {
		return []string{msg +
			" (the config still installs on the tolerant load / peer-sync path, but " +
			"the two allocators remain independent, so a return packet for a colliding " +
			"external tuple can be misdelivered until the overlap is corrected)"}, nil
	}
	return nil, fmt.Errorf("%s", msg)
}

// nat64PrefixOwnerKey returns the canonical allocator key for a NAT64 rule-set
// prefix, and ok=false when the prefix would NOT build a live NAT64 allocator.
//
// It mirrors the Rust nat64.rs build condition — and validateNAT64PrefixStrict's
// accept set — EXACTLY: the prefix must split on '/' into exactly two parts, the
// mask must parse as a decimal 96 (so a leading-zero `/096` — which the strict
// gate and Rust's numeric parse both accept — is honored, unlike a raw
// netip.ParsePrefix which rejects it), and the address part must be IPv6 by the
// colon-strict family rule. Only such a rule-set mints external tuples at
// runtime, so only it is an allocator "owner" for the #5144 overlap gate. An
// empty / malformed / non-/96 prefix builds no allocator (nat64.rs skips it; the
// strict gate rejects a non-empty malformed prefix on commit and skips an empty
// one) — enumerating it as an owner would FALSELY report an overlap (two
// empty-prefix rule-sets sharing a pool, or an empty-prefix rule-set vs a live
// source-NAT owner), so ok=false drops it from the owner set on both paths.
//
// The key is the CANONICAL /96 network (the Rust 12-byte prefix identity) via
// netip Masked(), so equivalent spellings — a leading-zero `/096`, an expanded
// `0064:ff9b:0:0:0:0:0:0`, or host bits beyond /96 — dedup to one owner and never
// false-reject.
func nat64PrefixOwnerKey(prefix string) (string, bool) {
	parts := strings.Split(prefix, "/")
	if len(parts) != 2 {
		return "", false
	}
	if m, err := strconv.ParseUint(parts[1], 10, 8); err != nil || m != 96 {
		return "", false
	}
	if natAddrFamily(parts[0]) != "v6" {
		return "", false
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil {
		// natAddrFamily classified it v6 but netip disagrees (should not happen
		// for a genuine IPv6 literal) — fall back to a stable normalized text key
		// so it still dedups by (address text, /96) rather than crashing.
		return parts[0] + "/96", true
	}
	return netip.PrefixFrom(addr, 96).Masked().String(), true
}

// poolMemberTexts returns a source pool's translated-address members: the single
// DNAT-compat Address (empty for source pools) followed by the expanded
// Addresses list. Mirrors nat64.go / SourceNATPoolNets member enumeration.
func poolMemberTexts(pool *NATPool) []string {
	if pool == nil {
		return nil
	}
	out := make([]string, 0, len(pool.Addresses)+1)
	if pool.Address != "" {
		out = append(out, pool.Address)
	}
	return append(out, pool.Addresses...)
}

// natV4IntervalOf returns the inclusive [lo,hi] big-endian uint32 range (widened
// to uint64) an IPv4 pool member covers. A bare IP / /32 is [x,x]; a CIDR spans
// its whole prefix. ok is false when the net is not v4-representable.
func natV4IntervalOf(n *net.IPNet) (lo, hi uint64, ok bool) {
	ip4 := n.IP.To4()
	if ip4 == nil {
		return 0, 0, false
	}
	lo = uint64(binary.BigEndian.Uint32(ip4))
	ones, bits := n.Mask.Size()
	if bits != 32 {
		// Non-canonical / zero mask — treat the address as a host so it still
		// participates in exact-duplicate detection.
		return lo, lo, true
	}
	hostBits := uint(32 - ones)
	return lo, lo + (uint64(1) << hostBits) - 1, true
}

// natV6IntervalOf returns the inclusive [lo,hi] 16-byte range an IPv6 pool member
// covers, as netip.Addr values ordered by Compare. lo is the masked network
// address; hi is that address OR the inverted mask (the all-ones host suffix). ok
// is false when the net is not 16-byte-representable.
func natV6IntervalOf(n *net.IPNet) (lo, hi netip.Addr, ok bool) {
	ip16 := n.IP.To16()
	if ip16 == nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	loAddr, ok1 := netip.AddrFromSlice(ip16)
	if !ok1 {
		return netip.Addr{}, netip.Addr{}, false
	}
	mask := n.Mask
	if len(mask) != 16 {
		// A non-16-byte (e.g. v4-mapped /32) mask has no 128-bit host span; treat
		// the address as a single host.
		return loAddr, loAddr, true
	}
	hib := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hib[i] = ip16[i] | ^mask[i]
	}
	hiAddr, ok2 := netip.AddrFromSlice(hib)
	if !ok2 {
		return netip.Addr{}, netip.Addr{}, false
	}
	return loAddr, hiAddr, true
}

// sweepNATV4Overlap sorts the v4 intervals by (lo,hi) and reports the first
// overlapping pair via a running max-hi sweep (O(n log n)). Returns "" when no
// two intervals intersect.
func sweepNATV4Overlap(owners []natAllocOwner, ivs []natV4Interval) string {
	if len(ivs) < 2 {
		return ""
	}
	sort.Slice(ivs, func(i, j int) bool {
		if ivs[i].lo != ivs[j].lo {
			return ivs[i].lo < ivs[j].lo
		}
		if ivs[i].hi != ivs[j].hi {
			return ivs[i].hi < ivs[j].hi
		}
		if ivs[i].inst != ivs[j].inst {
			return ivs[i].inst < ivs[j].inst
		}
		return ivs[i].member < ivs[j].member
	})
	maxHi, maxInst, maxMember := ivs[0].hi, ivs[0].inst, ivs[0].member
	for _, iv := range ivs[1:] {
		if iv.lo <= maxHi {
			return natOverlapMessage(owners, maxInst, maxMember, iv.inst, iv.member)
		}
		if iv.hi > maxHi {
			maxHi, maxInst, maxMember = iv.hi, iv.inst, iv.member
		}
	}
	return ""
}

// sweepNATV6Overlap is the v6 analog of sweepNATV4Overlap, comparing netip.Addr
// endpoints with Compare.
func sweepNATV6Overlap(owners []natAllocOwner, ivs []natV6Interval) string {
	if len(ivs) < 2 {
		return ""
	}
	sort.Slice(ivs, func(i, j int) bool {
		if c := ivs[i].lo.Compare(ivs[j].lo); c != 0 {
			return c < 0
		}
		if c := ivs[i].hi.Compare(ivs[j].hi); c != 0 {
			return c < 0
		}
		if ivs[i].inst != ivs[j].inst {
			return ivs[i].inst < ivs[j].inst
		}
		return ivs[i].member < ivs[j].member
	})
	maxHi, maxInst, maxMember := ivs[0].hi, ivs[0].inst, ivs[0].member
	for _, iv := range ivs[1:] {
		if iv.lo.Compare(maxHi) <= 0 {
			return natOverlapMessage(owners, maxInst, maxMember, iv.inst, iv.member)
		}
		if iv.hi.Compare(maxHi) > 0 {
			maxHi, maxInst, maxMember = iv.hi, iv.inst, iv.member
		}
	}
	return ""
}

// natOverlapMessage renders the operator-facing #5144 overlap diagnostic. When
// both members belong to the same owner it is a within-pool duplicate/overlap;
// otherwise it names both independent allocators.
func natOverlapMessage(owners []natAllocOwner, instA int, memberA string, instB int, memberB string) string {
	a := owners[instA]
	if instA == instB {
		return fmt.Sprintf(
			"security nat: %s has overlapping or duplicate pool members %q and %q; "+
				"the allocator builds a separate occupancy bitmap per pool member, so "+
				"overlapping members can each hand out the same translated (address, "+
				"port) and the reverse NAT index cannot disambiguate the return flow — "+
				"remove the duplicate/overlapping member (#5144)",
			a.desc, memberA, memberB)
	}
	b := owners[instB]
	return fmt.Sprintf(
		"security nat: %s member %q overlaps %s member %q; the two are independent "+
			"NAT allocators (keyed separately), so both can mint the same translated "+
			"(family, address, port) external tuple and the reverse NAT index cannot "+
			"disambiguate the return flow (reply misdelivery) — give the pools "+
			"non-overlapping address ranges, or share a single pool so one allocator "+
			"owns the address (#5144)",
		a.desc, memberA, b.desc, memberB)
}
