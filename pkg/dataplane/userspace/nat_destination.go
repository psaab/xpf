package userspace

import (
	"log/slog"
	"net"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// dnatDestinationParts splits a DNAT `match destination-address` token into the
// base address the DNAT table keys on and, for a non-host prefix, the canonical
// masked CIDR (#3164). It is the single point that decides host-vs-prefix on the
// Go side so the snapshot and the Rust DnatTable agree:
//
//   - A bare IP ("198.51.100.42") or an explicit host mask ("198.51.100.42/32",
//     "2001:db8::1/128") is a HOST: base = the address, prefix = "" — the Rust
//     table keys it in the O(1) exact hash map (unchanged fast path).
//   - A non-host prefix ("198.51.100.0/24") is a BLOCK: base = the prefix
//     network address ("198.51.100.0"), prefix = the canonical masked CIDR
//     ("198.51.100.0/24") — the Rust table installs a longest-prefix-match
//     entry that translates every host in the block to the rule's pool.
//
// ok is false for a token that does not parse as an IP or CIDR (an unresolved
// address-book name reaches here verbatim on a typo); the caller skips it, so a
// rule whose destinations are all malformed installs no entry and matches
// nothing (fail-closed) — the commit-time gate makes the typo operator-visible.
func dnatDestinationParts(raw string) (base, prefix string, ok bool) {
	if raw == "" {
		return "", "", false
	}
	// #7481: normalize the prefix-length spelling, exactly as the commit gate
	// (config.NATMatchPrefixParses) and both Rust parsers now do. A leading `+`
	// or leading zeros are tolerated everywhere or nowhere; the failure this
	// closes is a value the gate accepts and a builder silently discards.
	//
	// #7215's differential is what caught this: widening the gate without
	// widening this function reproduced, immediately, the exact drift that test
	// was written for — "validateDestinationNATAddressesStrict carried a comment
	// promising its acceptance MUST match the builder's exactly and then drifted
	// for six years' worth of mask spellings". A comment cannot fail; that
	// differential did, in the same run.
	raw = config.NormalizeNATPrefixLen(raw)
	if strings.IndexByte(raw, '/') == -1 {
		// Bare address — always a host.
		if net.ParseIP(raw) == nil {
			return "", "", false
		}
		return raw, "", true
	}
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", "", false
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		// Canonical host mask (/32 or /128) — exact-host fast path.
		return ip.String(), "", true
	}
	// Non-host prefix: base = network address, prefix = canonical masked CIDR.
	return ipNet.IP.String(), ipNet.String(), true
}

// buildDestinationNATSnapshots is the static-only convenience wrapper retained
// for callers without a dynamic-address feed overlay (tests, legacy paths). The
// production snapshot path uses buildDestinationNATSnapshotsWithFeeds (#3303).
func buildDestinationNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []DestinationNATRuleSnapshot {
	return buildDestinationNATSnapshotsWithFeeds(cfg, natCounterIDs, nil)
}

func buildDestinationNATSnapshotsWithFeeds(cfg *config.Config, natCounterIDs map[string]uint32, feedOverlay map[string][]string) []DestinationNATRuleSnapshot {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		return nil
	}
	var out []DestinationNATRuleSnapshot
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #9874: the rule authored a `match` that constrains nothing. It
			// publishes no entry either way (an empty match leaves destAddrs
			// empty, which the emit guard below skips), so this skip changes
			// no disposition — it makes the drop LOUD instead of silent, and
			// names the rule the operator must fix. FIRST, before the #3844
			// `off` handling: an empty-match exemption has no destination
			// key either and installs nothing. The show surfaces reach the
			// same verdict through DestinationNATRuleExcludedReason.
			if rule.LenientMatchDropped {
				slog.Warn("userspace snapshot: skipping DNAT rule with an empty authored match (fail-closed, #9874)",
					"ruleset", rs.Name, "rule", rule.Name)
				continue
			}
			// #3844: `then destination-nat off` is a no-translate EXEMPTION.
			// It carries no pool, but the rule MUST still install a snapshot
			// entry so the Rust DnatTable can recognize the matched traffic as
			// exempt and SHORT-CIRCUIT later DNAT rules (the Junos "matched
			// rule wins, stop" semantic). Before #3844 the off rule compiled to
			// an empty Then, was skipped here (PoolName == ""), and the
			// "exempted" traffic fell through to be DNAT'd by a later rule
			// (fail-open). An off entry runs the SAME match expansion below
			// (destination/source addresses, protocol, ports) but with an empty
			// pool and Off=true; the pool lookup/validation is skipped.
			isOff := rule.Then.Type == config.NATDestination && rule.Then.Off
			if !isOff && rule.Then.PoolName == "" {
				continue
			}
			ruleCounterID := natCounterID(natCounterIDs, dataplane.NATCounterTypeDest, rs.Name, rule.Name)
			var pool *config.NATPool
			var poolAddr string
			// #6820: this skip CANONICALIZES an exemption entry to an empty pool;
			// it does NOT decide off-over-pool precedence, and gate comments that
			// said it did have been corrected. `DnatEntry::to_outcome`
			// (userspace-dp/src/nat/destination.rs) branches on `off` alone and
			// never reads the pool, and `DnatTable::from_snapshots` independently
			// refuses to parse an off entry's pool address. A snapshot carrying
			// both Off=true and a usable pool — which this builder never emits,
			// but a mixed-version xpfd/helper pair can, since the snapshot IS the
			// xpfd->helper wire form — still resolves to the exemption; see
			// dnat_off_exemption_is_decided_by_off_not_by_an_empty_pool_6820.
			if !isOff {
				// #3450 fail-closed (lenient / peer-sync backstop; the commit
				// gate validateDNATPoolStrict rejects these). A missing /
				// address-less pool, a non-host pool address, or a
				// configured-but-invalid port must publish NO entry, so the
				// rule matches NOTHING rather than wrapping the port on a
				// uint16 cast, collapsing to preserve-destination-port, or
				// coercing a non-host CIDR to its network base.
				//
				// #6534: the verdict comes from
				// config.DestinationNATRuleExcludedReason so this builder and
				// natshow.RenderDestRuleDetail cannot disagree about which
				// rules are armed. The per-clause rationale lives with the
				// predicate.
				if reason := config.DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rule); reason != "" {
					slog.Warn("userspace snapshot: skipping DNAT rule (fail-closed, #3450)",
						"ruleset", rs.Name, "rule", rule.Name,
						"pool", rule.Then.PoolName, "reason", reason)
					continue
				}
				pool = cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]
				// The predicate above already proved this resolves; the second
				// return is the host form the wire carries.
				poolAddr, _ = config.DNATPoolHostIP(pool.Address)
			}
			// #2395: a DNAT rule may publish multiple destination addresses
			// (`match destination-address [ A B C ]`). The DNAT table is keyed
			// by exact destination IP, so each configured destination needs its
			// OWN snapshot entry sharing the rule's pool/counter id. Iterating
			// only the singular `DestinationAddress` (the first list element)
			// collapsed the rule to its first destination and silently dropped
			// translation for B and C. Mirror the source-address idiom: prefer
			// the bracket-list form, fall back to the singular match value.
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			// #3229: `match destination-address-name <book-entry>` selects the
			// translated destination by an address-book reference instead of a
			// literal prefix. It was parsed into DestinationAddressName but never
			// resolved into the destination list the DNAT table is keyed on, so a
			// name-scoped DNAT rule installed NO table entry (silently dropped).
			// Resolve the name to its concrete prefixes via the same address-book
			// expander the source path uses (appendNATDestinationAddressName).
			// Each resolved host installs its own table entry below; a non-host
			// prefix is stripped to its network address like a literal CIDR
			// destination. On an unknown name the raw token is appended: it
			// cannot parse as an IP and is skipped in the emit loop, so the rule
			// matches NOTHING (fail-closed). The commit-time strict gate
			// (validateNATSourceAddressNameReferencesStrict) makes the typo
			// operator-visible.
			// #3431: resolve EVERY name of a bracket list / repeated leaf.
			for _, name := range rule.Match.DestinationAddressNameList() {
				destAddrs = appendNATDestinationAddressName(cfg, feedOverlay, destAddrs, name)
			}
			if len(destAddrs) == 0 {
				continue
			}

			// #2394: carry the DNAT `match source-address` constraint into the
			// snapshot. Junos DNAT source-address restricts which sources the
			// destination translation fires for; dropping it published the
			// internal service to every source in the from-zone (fail-open).
			// Mirror the SNAT builder: prefer the bracket-list form, fall back
			// to the singular match value. An empty result = match any source.
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			// #2416: `match source-address-name <book-entry>` scopes the DNAT
			// the same way a literal `match source-address` does, but as an
			// address-book reference. It was parsed into SourceAddressName yet
			// never resolved into the source list the #2394 enforcement reads,
			// so a name-scoped DNAT published an EMPTY source list = match any
			// source = fail-open (a destination translation the operator scoped
			// to a named source set fired for everyone). Resolve the name to its
			// concrete prefixes via the same address-book expander the policy
			// path uses and append them. On an unknown name we append the raw
			// token: it cannot parse on the Rust side (IpAddr::parse fails) so it
			// contributes no prefix, but it keeps the source list NON-EMPTY so
			// source_constrained stays true and the rule matches NOTHING
			// (fail-closed) instead of collapsing back to match-any. A commit-
			// time strict gate (validateNATSourceAddressNameReferencesStrict)
			// makes the typo operator-visible; this is the dataplane backstop.
			// #3431: resolve EVERY name of a bracket list / repeated leaf.
			for _, name := range rule.Match.SourceAddressNameList() {
				sourceAddrs = appendNATSourceAddressName(cfg, feedOverlay, sourceAddrs, name)
			}

			// Resolve application match to protocol+ports if specified.
			//
			// #3437: an application also pins a `source-port` (H10) and, for an
			// ICMP/ICMPv6 application, an ICMP type[,code] (H11). The pre-#3437
			// DNAT builder reduced an app to protocol + destination-port only and
			// dropped both — a fail-open widening (any source port / every ICMP
			// type was translated to the VIP). Carry them per term:
			//   - srcPorts: the application's `source-port` spec coalesced to wire
			//     ranges, with the same fail-CLOSED never-match sentinel the SNAT
			//     path uses (#3429/#3491) when it was configured but coalesces to
			//     nothing. nil = source-port unconstrained.
			//   - icmpType / icmpCode: the application's ICMP type[,code]
			//     constraint, carried verbatim (already valid u8s). nil = no ICMP
			//     type/code constraint (match every type/code of the protocol).
			type appTerm struct {
				proto string
				// #5250 (A6-b2 F3): the destination-port axis is carried
				// ALREADY COALESCED. It used to be a []int of every individual
				// port, so an application with `destination-port 1-65535`
				// materialized ~65k ints per term (and again per application-set
				// member) only for the loop below to collapse them back into one
				// range. dstPortsPresent preserves the one thing the slice was
				// also read for: whether the source list was non-empty BEFORE
				// coalescing, which the #3726/#3857 fail-closed test needs and a
				// coalesced list cannot recover (a spec of "0" is present but
				// coalesces away).
				dstRanges       []NatPortRangeWire
				dstPortsPresent bool
				srcPorts        []NatPortRangeWire
				icmpType        *uint8
				icmpCode        *uint8
				// dstPortConfigured records that the application specified a
				// non-empty destination-port spec, even if it coalesced to no
				// representable port (all out of 1..65535, or a reversed
				// "200-100" range rejected by appPortsFromSpec, #3726). The
				// port-filtering loop below reads this so a configured-but-
				// unrepresentable app destination-port fails CLOSED (never
				// match) instead of widening to the wildcard match-any-port
				// term — the DNAT analog of the source-NAT #3429/#3491 guard.
				dstPortConfigured bool
			}
			var appTerms []appTerm

			appTermFor := func(a *config.Application) appTerm {
				srcPorts := appPortRangesFromSpec(a.SourcePort)
				if a.SourcePort != "" && len(srcPorts) == 0 {
					// #3437: a configured source-port that coalesces to nothing
					// (every value out of 1..65535) fails CLOSED — match no source
					// port rather than widening to any.
					srcPorts = []NatPortRangeWire{natNeverMatchPortRange}
				}
				return appTerm{
					proto:             a.Protocol,
					dstRanges:         appPortRangesFromSpec(a.DestinationPort),
					dstPortsPresent:   a.DestinationPort != "",
					srcPorts:          srcPorts,
					icmpType:          a.ICMPType,
					icmpCode:          a.ICMPCode,
					dstPortConfigured: a.DestinationPort != "",
				}
			}

			// #3431: expand EVERY application of a bracket list / repeated
			// `match application [ a b ]` into the union of its terms (match
			// ANY). Pre-#3431 only the first application was read and the rest
			// silently dropped, narrowing the rule.
			// #5102: mirror buildSourceNATAppTerms — a sole "any"/empty
			// application is UNCONSTRAINED (match any application), not a
			// configured-but-unresolvable app. SNAT collapses "any"/"" to no
			// constraint; DNAT must too, otherwise `match application any`
			// resolves to zero terms and the appConfigured branch below emits
			// the #3434 never-match sentinel that silently disables a valid,
			// strict-commit-accepted rule. A REAL reference (non-"any",
			// non-empty) still counts as configured, so a typo / dangling ref /
			// defined-but-empty application-set still fails CLOSED (#3434) via
			// that branch. A real app alongside "any" is kept — the resolve
			// loop below skips the unresolvable "any" and adds the real terms.
			// #5102: mirror buildSourceNATAppTerms — a sole "any"/empty
			// application is UNCONSTRAINED (match any application), not a
			// configured-but-unresolvable app. SNAT collapses "any"/"" to no
			// constraint; DNAT must too, otherwise `match application any`
			// resolves to zero terms and the appConfigured branch below emits
			// the #3434 never-match sentinel that silently disables a valid,
			// strict-commit-accepted rule. A REAL reference (non-"any",
			// non-empty) still counts as configured, so a typo / dangling ref /
			// defined-but-empty application-set still fails CLOSED (#3434) via
			// that branch. A real app alongside "any" is kept — the resolve
			// loop below skips the unresolvable "any" and adds the real terms.
			appConfigured := false
			for _, appName := range rule.Match.ApplicationList() {
				if appName != "" && appName != "any" {
					appConfigured = true
					break
				}
			}
			if appConfigured {
				userApps := cfg.Applications.Applications
				for _, appName := range rule.Match.ApplicationList() {
					app, found := config.ResolveApplication(appName, userApps)
					if found {
						appTerms = append(appTerms, appTermFor(app))
					} else if _, isSet := config.ResolveApplicationSet(appName, cfg.Applications.ApplicationSets); isSet {
						// #5629: resolve the SET through the #4102
						// predefined-set-aware config.ResolveApplicationSet, NOT a
						// bare cfg.Applications.ApplicationSets membership test
						// (USER sets only). A strict predefined bundle
						// (junos-ms-rpc, junos-sun-rpc, ...) referenced by a
						// destination-NAT rule otherwise resolved to zero terms and
						// fell through to the #3434 never-match sentinel — the DNAT
						// rule silently disabled. ExpandApplicationSet falls back to
						// the predefined table, so a user set stays bit-identical.
						expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err == nil {
							for _, termName := range expanded {
								tApp, ok := config.ResolveApplication(termName, userApps)
								if !ok {
									continue
								}
								appTerms = append(appTerms, appTermFor(tApp))
							}
						}
					}
				}
			}

			// If no application terms resolved, the behavior depends on WHETHER
			// an application was configured:
			//
			//   - #3434: an application WAS configured (rule.Match.Application !=
			//     "") but resolved to ZERO terms — a typo / dangling reference or
			//     a defined-but-EMPTY application-set. Falling through to the
			//     explicit-match fallback would emit proto="" + dstPort=0 = a
			//     wildcard match-ALL term and publish the pool VIP for EVERY
			//     flow to the destination (the H07/H08 fail-open, the DNAT analog
			//     of the source-NAT buildSourceNATAppTerms natProtoNever guard).
			//     Emit a never-match term instead, reusing the #3437 source-port
			//     never-match sentinel (an impossible Low>High range): the entry
			//     installs but can never satisfy l4_extra_matches, so the rule
			//     matches NOTHING. The commit-time strict gate
			//     (validateNATMatchApplicationsStrict, #3434) rejects the
			//     typo/empty-set so this is only the lenient load / peer-sync
			//     backstop.
			//
			//   - No application configured: use the explicit match grammar
			//     (protocol + destination-port). DNAT `match` grammar has no
			//     source-port or ICMP type/code, so those axes stay unconstrained
			//     on the explicit-match fallback term. The term carries the
			//     rule's destination-port list directly; #3857 additionally
			//     resolves the rule-level destination-port below (ruleDstPorts /
			//     ruleDstPortConfigured) so the port-filtering loop can tell a
			//     configured-but-unresolved destination-port from a genuine
			//     wildcard and fail closed — for BOTH this path and the
			//     application-present path.
			if len(appTerms) == 0 {
				if appConfigured {
					appTerms = []appTerm{{srcPorts: []NatPortRangeWire{natNeverMatchPortRange}}}
				} else {
					// #3431: one explicit-match term per protocol of a bracket
					// list / repeated `match protocol [ tcp udp ]` (match ANY).
					// Pre-#3431 only the first protocol was published. With no
					// protocol configured, ProtocolList() is empty and a single
					// proto="" wildcard term is emitted (unchanged behavior).
					protos := rule.Match.ProtocolList()
					if len(protos) == 0 {
						protos = []string{""}
					}
					for _, proto := range protos {
						appTerms = append(appTerms, appTerm{
							proto:           proto,
							dstRanges:       coalescePortRanges(rule.Match.DestinationPorts),
							dstPortsPresent: len(rule.Match.DestinationPorts) > 0,
						})
					}
				}
			}

			// #3857: an explicit rule-level `match destination-port` is
			// authoritative for the DNAT destination-port axis and applies to
			// EVERY resolved application term. Before #3857 the rule-level port
			// was consulted ONLY on the no-application explicit-match path
			// (explicitFallback); with an application ALSO present the builder
			// (a) dropped a VALID rule destination-port (the application's own
			// port, or a match-any wildcard, won), (b) collapsed a multi-value
			// list to the singular first port, and (c) — for a port-less
			// application — WIDENED an invalid/unrepresentable token to the
			// wildcard [0,0] port, a fail-open that bypassed the #3446 dport
			// guard on the lenient / HA peer-sync decode path. Resolve the
			// rule's port list once here (the plural, falling back to the scalar
			// a mixed-version peer may carry alone) and, when configured, use it
			// in place of the application's own destination-port on every term.
			// The application still constrains protocol / source-port / ICMP
			// type-code; only the destination-port axis is taken from the
			// explicit rule match. A configured-but-unrepresentable value fails
			// CLOSED below (the rule is omitted), exactly like the no-application
			// path and the source-NAT builder — it never widens to [0,0].
			ruleDstPorts := rule.Match.DestinationPorts
			if len(ruleDstPorts) == 0 && rule.Match.DestinationPort != 0 {
				ruleDstPorts = []int{rule.Match.DestinationPort}
			}
			ruleDstPortConfigured := len(ruleDstPorts) > 0 || len(rule.Match.InvalidDestinationPorts) > 0

			for _, term := range appTerms {
				// #3446: a `match destination-port` that was configured but
				// resolves to NO valid 1..65535 port must match NOTHING (fail
				// closed) — never widen to the wildcard port (0 = any). Out-of-
				// range numerics are dropped here (the bare uint16 cast used to
				// wrap 70000→4464); non-numeric tokens (`http`) were dropped at
				// parse and surface via Match.InvalidDestinationPorts. The strict
				// commit gate (validateNATMatchDestinationPortStrict) rejects all
				// of these at commit; this hardens the lenient / peer-sync path.
				//
				// #3449: coalesce the term's valid 1..65535 ports into inclusive
				// [Low,High] ranges so a wide `destination-port low to high` (or
				// an application's wide destination-port) carries ONE compact
				// entry instead of (high-low+1) per-port snapshots — a
				// control-plane memory/apply-time amplification hazard. A single
				// port (Low==High) keeps the exact-port O(1) fast-path entry; a
				// multi-port range becomes a wildcard-port (DestinationPort=0)
				// entry whose MatchDestinationPorts the Rust l4_extra_matches
				// AND-checks against the flow's destination port (mirroring the
				// #3437 MatchSourcePorts handling). coalescePortRanges drops
				// out-of-range values; an all-invalid configured port therefore
				// coalesces to nothing and is failed CLOSED below.
				// #3857: the explicit rule-level `match destination-port`
				// overrides the application's own destination-port on this term.
				// term.ports (the application's destination-port) is used only
				// when the rule did NOT configure `match destination-port`. On
				// the no-application explicit-match path term.ports already IS
				// rule.Match.DestinationPorts, so the override is a no-op there.
				termRanges := term.dstRanges
				termPortsPresent := term.dstPortsPresent
				termDstPortConfigured := term.dstPortConfigured
				if ruleDstPortConfigured {
					termRanges = coalescePortRanges(ruleDstPorts)
					termPortsPresent = len(ruleDstPorts) > 0
					termDstPortConfigured = true
				}
				portRanges := termRanges
				// Did this term CONFIGURE a destination-port at all? A configured
				// port that survived to no valid value must not become wildcard.
				// #3726: term.dstPortConfigured is true when the application named
				// a destination-port that coalesced to nothing (all out of
				// 1..65535, or a reversed "200-100" range rejected by
				// appPortsFromSpec). #3857: termDstPortConfigured is also true
				// when the rule pinned an explicit `match destination-port` (a
				// numeric out-of-range, or non-numeric token on
				// InvalidDestinationPorts). Without this the empty ports slip
				// through to the wildcard match-any-port default — a fail-open
				// that widens the DNAT rule to every port.
				portConfigured := termPortsPresent || termDstPortConfigured
				if len(portRanges) == 0 {
					switch {
					case portConfigured:
						// Configured but no valid port → fail closed: emit no
						// snapshot for this term so the rule matches nothing.
						// #3857: this now also catches an invalid/unrepresentable
						// rule-level `match destination-port` present ALONGSIDE an
						// application, which previously widened to the [0,0]
						// wildcard via the removed singular-port switch case.
						continue
					default:
						// Genuine wildcard (no port match): a [0,0] range maps to
						// DestinationPort=0 with no range constraint below.
						portRanges = []NatPortRangeWire{{Low: 0, High: 0}}
					}
				}

				for _, pr := range portRanges {
					// A single-port range (Low==High, including the [0,0]
					// wildcard) keeps the exact wire key; a multi-port range
					// uses the wildcard key (DestinationPort=0) plus a
					// MatchDestinationPorts range constraint so it is NOT
					// expanded per port.
					var dstPort uint16
					var matchDstPorts []NatPortRangeWire
					if pr.Low == pr.High {
						dstPort = pr.Low
					} else {
						dstPort = 0
						matchDstPorts = []NatPortRangeWire{pr}
					}
					poolPort := dstPort
					// #3844: an off (exemption) rule has no pool — `pool` is
					// nil, so the pool-port override is skipped. The Rust side
					// short-circuits on the Off flag before reading any pool
					// value, so poolPort/poolAddr are unused for off entries.
					if !isOff && pool.Port != 0 {
						// #3450: pool.Port is gated to 1..65535 above (an
						// invalid configured port skips the whole rule), so this
						// uint16 cast can no longer wrap. Port == 0 (no `port`
						// leaf) preserves the destination port, unchanged.
						poolPort = uint16(pool.Port)
					}

					// Determine the protocol(s) to key this snapshot under. A
					// port-based rule (an exact port OR a range constraint) that
					// did NOT pin a protocol matches BOTH TCP and UDP, exactly as
					// Junos does for a bare `match destination-port` (#6462): emit
					// one snapshot per protocol below so UDP to the VIP:port is
					// translated too. Before #6462 the builder defaulted such a
					// rule to TCP only — a UDP (proto 17) packet hit none of the
					// TCP-keyed entries and was silently NOT translated (a silent
					// UDP-service outage — DNS/SIP/VPN — plus an observability lie:
					// `show security nat destination` still listed the rule). When
					// a protocol IS pinned it is honored verbatim; a protocol-less
					// rule with NO port constraint stays a single match-any
					// (empty-protocol) entry. TCP and UDP are emitted explicitly
					// rather than under PROTO_ANY: ports exist only for TCP/UDP so
					// PROTO_ANY would wrongly translate ICMP/other, and the Rust
					// lookup probes (proto,dst_ip,dst_port) but never
					// (PROTO_ANY,dst_ip,dst_port), so a single PROTO_ANY+port row
					// could not be found by a UDP packet anyway.
					protos := []string{term.proto}
					if term.proto == "" && (dstPort != 0 || len(matchDstPorts) > 0) {
						protos = []string{"tcp", "udp"} // bare dest-port matches both (Junos)
					}

					// #3450: poolAddr is the validated single-host IP (CIDR
					// suffix stripped, non-host prefix / non-IP token already
					// rejected above). Computed once before the rule loop.

					// #2395: emit one snapshot per configured destination so a
					// bracket-list DNAT installs a table entry for EVERY
					// published destination, not just the first.
					//
					// #3164: a destination may now be a non-host prefix
					// (`match destination-address 198.51.100.0/24`).
					// dnatDestinationParts classifies each token: a host (bare IP,
					// /32, /128) carries an empty DestinationPrefix and keys the
					// Rust exact hash map (unchanged fast path); a non-host prefix
					// carries the canonical masked CIDR in DestinationPrefix (the
					// network base in DestinationAddress) and installs a
					// longest-prefix-match entry that translates every host in the
					// block to the rule's pool. A token that does not parse as an
					// IP or CIDR is skipped — if a rule has destinations but ALL
					// are malformed, no entry is emitted, so the rule matches
					// NOTHING (fail-closed) rather than broadening to match-any.
					for _, rawDst := range destAddrs {
						base, prefix, ok := dnatDestinationParts(rawDst)
						if !ok {
							continue
						}
						// #6462: one snapshot per protocol (see `protos` above).
						// For a bare `match destination-port` with no configured
						// protocol this installs BOTH a TCP- and a UDP-keyed row
						// for (base, dstPort) so a UDP packet to the VIP:port is
						// translated, mirroring Junos. Both rows share the rule's
						// single CounterID exactly like an explicit
						// `match protocol [ tcp udp ]` (#3431): a packet is either
						// TCP or UDP, so it hits exactly one row and the shared
						// counter increments once — no double-count.
						for _, proto := range protos {
							out = append(out, DestinationNATRuleSnapshot{
								Name:                rule.Name,
								FromZone:            rs.FromZone,
								FromInterface:       rs.FromInterface,
								FromRoutingInstance: rs.FromRoutingInstance,
								SourceAddresses:     sourceAddrs,
								DestinationAddress:  base,
								DestinationPrefix:   prefix,
								DestinationPort:     dstPort,
								// #3449: a multi-port range rides this field as
								// one [Low,High] constraint instead of (High-Low+1)
								// per-port entries; empty for a single/exact port.
								MatchDestinationPorts: matchDstPorts,
								Protocol:              proto,
								PoolAddress:           poolAddr,
								PoolPort:              poolPort,
								// #3437: carry the application's source-port and
								// ICMP type/code constraints so the DNAT match is no
								// wider than the referenced application.
								MatchSourcePorts: term.srcPorts,
								MatchICMPType:    term.icmpType,
								MatchICMPCode:    term.icmpCode,
								// #3844: a `then destination-nat off` exemption. When
								// set, the Rust DnatTable treats a match as
								// no-translate and short-circuits later DNAT rules;
								// the pool fields are unused. PoolAddress is empty
								// for an off entry.
								Off:       isOff,
								CounterID: ruleCounterID,
							})
						}
					}
				}
			}
		}
	}
	return out
}
