package userspace

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// buildSourceNATSnapshots is the static-only convenience wrapper retained for
// callers that carry no dynamic-address feed overlay (tests, legacy paths). The
// production snapshot path uses buildSourceNATSnapshotsWithFeeds so feed-backed
// `match {source,destination}-address-name` references resolve their live feed
// prefixes (#3303).
func buildSourceNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []SourceNATRuleSnapshot {
	return buildSourceNATSnapshotsWithFeeds(cfg, natCounterIDs, nil)
}

func buildSourceNATSnapshotsWithFeeds(cfg *config.Config, natCounterIDs map[string]uint32, feedOverlay map[string][]string) []SourceNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		return nil
	}
	// #6812: poison the pools that do not fit the #5877 aggregate cardinality
	// budget (opus-review-001 R73). A STRICT commit never reaches this builder
	// with an over-budget config (the gate hard-rejects it), so this only ever
	// fires for a TOLERATED config — lenient load / peer-sync, where the gate
	// downgrades to a warning (#1960 no-brick). Before this poison the builder
	// shipped the full pool set and the Rust apply boundary eagerly built
	// every pool's per-address occupancy bitmap (three full-range /16 pools =
	// 12,683,575,296 bitmap bits, ~1.48 GiB). The marked pools install nothing
	// (fail-closed, matching the missing/empty/invalid markers below) and the
	// Rust boundary independently re-derives admission over what survives —
	// the first-fit rule is shared (SourceNATAggregateOverBudgetPools /
	// resolve_pool_allocators), so Go and the dataplane agree on which pools
	// live. Precisely: a poisoned pool builds no PendingPoolAllocator, so the
	// set Rust considers is exactly the set Go admitted, whose total charge
	// already fits every budget — Rust therefore refuses none of it, whatever
	// order the slice arrives in and whether or not its keys are reused (the
	// argument is written out on SourceNATAggregateOverBudgetPools). Rust
	// refusing a pool of its OWN is reserved for the snapshots no Go poison is
	// coming for: a tolerated, older control plane's, or handcrafted one. The over-budget compile warning still tells the operator to shrink
	// the config; this marker makes the degraded state per-pool visible.
	overBudgetPools := config.SourceNATAggregateOverBudgetPools(cfg)
	out := make([]SourceNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #9874: the rule authored a `match` that constrains nothing. The
			// snapshot still ships it — with the LenientMatchDropped marker
			// the Rust table fails CLOSED (drop + count) — so say so loudly:
			// without the marker this rule would install as an unconstrained
			// catch-all translator.
			if rule.LenientMatchDropped {
				slog.Warn("userspace snapshot: source NAT rule authored an empty match; shipping fail-closed",
					"ruleset", rs.Name, "rule", rule.Name)
			}
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			// #2416: resolve `match source-address-name` for SNAT too — same
			// builder gap as DNAT (the source list only carried literal
			// prefixes). See appendNATSourceAddressName.
			// #3431: resolve EVERY name of a bracket list / repeated leaf.
			for _, name := range rule.Match.SourceAddressNameList() {
				sourceAddrs = appendNATSourceAddressName(cfg, feedOverlay, sourceAddrs, name)
			}
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			// #3229: resolve `match destination-address-name` the same way the
			// source path resolves source-address-name — without this a
			// name-scoped destination constraint published an EMPTY list =
			// match-any destination (fail-open).
			// #3431: resolve EVERY name of a bracket list / repeated leaf.
			for _, name := range rule.Match.DestinationAddressNameList() {
				destAddrs = appendNATDestinationAddressName(cfg, feedOverlay, destAddrs, name)
			}
			var poolAddresses []string
			var portLow, portHigh uint16
			var poolNoTranslation bool
			var persistentNAT bool
			var persistentNATPermitAnyRemoteHost bool
			var persistentNATPermit string
			var persistentNATInactivityTimeout int
			var poolUnusable bool
			var poolUnusableReason string
			// #4559: deterministic CGNAT (mode 1, IPv4 subscriber) block-alloc
			// params. Zero when the pool is not deterministic OR the subscriber
			// host is IPv6 (mode 2, not yet enforced) — the dataplane then
			// round-robins and the commit-time advisory surfaces the gap.
			var detMode uint8
			var detBlockSize, detBlocksPerIP uint16
			var detHostBase, detHostCount uint32
			if rule.Then.PoolName != "" {
				pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
				if !ok || pool == nil {
					slog.Warn("userspace snapshot: marking source NAT rule with missing pool unusable",
						"rule", rule.Name, "pool", rule.Then.PoolName)
					poolUnusable = true
					poolUnusableReason = "missing_pool"
				} else {
					poolAddresses = config.SourceNATPoolMembers(pool)
					// #3906: `port no-translation` preserves the source port.
					// The dataplane takes the address-only path and ignores the
					// port range in this mode, so a defaulted/valid range is
					// fine even when no-translation is set.
					poolNoTranslation = pool.PortNoTranslation
					portLow, portHigh, _ = config.SourceNATPoolPortRange(pool)
					// #6812 F1: ONE predicate decides a pool is unusable from its
					// DEFINITION — empty membership, a member the Rust expander
					// cannot honor (unparseable, malformed mask, or an
					// over-capacity prefix; round 2), a `%zone` member that is not
					// dataplane-representable (#5875), or a port range the parser
					// rejected (#5457). config.SourceNATPoolUnusableReason is the
					// SSOT that the aggregate budget walk
					// (sourceNATAggregateReferencedCharges) also reads to EXCLUDE
					// such a pool from the budget, so the set this builder poisons
					// and the set the budget charges cannot drift apart. Before
					// they shared it, the 1,024 pools this loop marked unusable
					// still consumed the whole pool-count budget and the next
					// healthy pool was poisoned "aggregate_over_budget" — a pool
					// the dataplane would have installed.
					//
					// Round 2 widened the predicate rather than adding a second
					// skip beside it, because the runtime's pool grammar is
					// ALL-OR-NOTHING: `expand_pool_address` failing on ONE member
					// fails the whole pool as InvalidPool. A pool mixing a valid
					// member with a bad one was therefore marked usable here,
					// charged the budget, and installed nothing there. The
					// "invalid_pool" reason it now carries decodes to exactly the
					// SourceNatFailureReason::InvalidPool the Rust parse loop
					// reached on its own, so the dataplane disposition of such a
					// pool is unchanged — but it is now visible in this warning
					// and excluded from the budget.
					if reason := config.SourceNATPoolUnusableReason(pool); reason != "" {
						slog.Warn("userspace snapshot: marking source NAT rule with unusable pool",
							"rule", rule.Name, "pool", rule.Then.PoolName, "reason", reason,
							"port_low", pool.PortLow, "port_high", pool.PortHigh)
						poolUnusable = true
						poolUnusableReason = reason
					}
					// #6812: a pool that does not fit the #5877 aggregate
					// cardinality budget on the TOLERANT path is marked
					// unusable so the dataplane never builds its occupancy
					// bitmap. Checked AFTER the more specific per-pool
					// markers so those keep their precise reason.
					if !poolUnusable && overBudgetPools[rule.Then.PoolName] {
						slog.Warn("userspace snapshot: marking source NAT rule with over-budget aggregate pool unusable",
							"rule", rule.Name, "pool", rule.Then.PoolName)
						poolUnusable = true
						poolUnusableReason = "aggregate_over_budget"
					}
					if pool.PersistentNAT != nil {
						persistentNAT = true
						// #2823: carry the full three-way permit enum. Default
						// an unset mode to target-host-port (the pre-#2823
						// false-flag (dst_ip, dst_port) keying) so existing
						// configs stay byte-identical. The
						// PermitAnyRemoteHost bool is kept on the wire for
						// back-compat with an older helper that predates the
						// enum (#1961 wire-skew discipline).
						permit := pool.PersistentNAT.Permit
						if permit == "" {
							permit = config.PersistentNATPermitTargetHostPort
						}
						persistentNATPermit = string(permit)
						persistentNATPermitAnyRemoteHost = permit == config.PersistentNATPermitAnyRemoteHost
						persistentNATInactivityTimeout = pool.PersistentNAT.InactivityTimeout
						if persistentNATInactivityTimeout <= 0 {
							persistentNATInactivityTimeout = 300
						}
					}
					// #6041: `persistent-nat` + `port no-translation` on the same
					// pool is now SUPPORTED. The userspace dataplane implements an
					// address-only persistent lease
					// (reserve_address_only_persistent, userspace-dp/src/nat/
					// allocator.rs) that pins a public pool ADDRESS across the
					// configured permit scope without consuming a translated pool
					// port. The #5819 fail-closed marker
					// ("persistent_nat_no_translation") that stood in until leases
					// existed was therefore removed — the pool stays usable and the
					// dataplane honours the persistent binding. The permit /
					// inactivity-timeout fields carried above (persistentNATPermit /
					// persistentNATInactivityTimeout) drive the lease.
					// #4559: deterministic CGNAT block-allocation params. Only
					// meaningful for a usable pool with a valid port range; a
					// zero mode leaves the dataplane on the round-robin path.
					if !poolUnusable {
						detMode, detBlockSize, detBlocksPerIP, detHostBase, detHostCount =
							deterministicSourceNATFields(pool, portLow, portHigh)
					}
				}
			}
			// #3429: carry the source-NAT L4 match constraints to the
			// dataplane. `match destination-port` becomes a set of inclusive
			// port ranges; `match application` is pre-expanded to (protocol,
			// port-range) terms (an application-set yields one term per resolved
			// member). The Rust matcher enforces these before translating AND
			// before applying a `then source-nat off` exemption, so a
			// port/app-scoped rule no longer silently widens to every port.
			matchDestPorts := sourceNATDestPortRanges(rule.Match.DestinationPorts, rule.Match.InvalidDestinationPorts)
			matchApps := buildSourceNATAppTerms(cfg, rule.Match.ApplicationList())

			out = append(out, SourceNATRuleSnapshot{
				Name:                             rule.Name,
				FromZone:                         rs.FromZone,
				ToZone:                           rs.ToZone,
				FromInterface:                    rs.FromInterface,
				ToInterface:                      rs.ToInterface,
				FromRoutingInstance:              rs.FromRoutingInstance,
				ToRoutingInstance:                rs.ToRoutingInstance,
				SourceAddresses:                  sourceAddrs,
				DestinationAddresses:             destAddrs,
				InterfaceMode:                    rule.Then.Interface,
				Off:                              rule.Then.Off,
				PoolName:                         rule.Then.PoolName,
				PoolAddresses:                    poolAddresses,
				PortLow:                          portLow,
				PortHigh:                         portHigh,
				PoolNoTranslation:                poolNoTranslation,
				AddressPersistent:                cfg.Security.NAT.AddressPersistent,
				PersistentNAT:                    persistentNAT,
				PersistentNATPermitAnyRemoteHost: persistentNATPermitAnyRemoteHost,
				PersistentNATPermit:              persistentNATPermit,
				PersistentNATInactivityTimeout:   persistentNATInactivityTimeout,
				PoolUnusable:                     poolUnusable,
				PoolUnusableReason:               poolUnusableReason,
				MatchDestinationPorts:            matchDestPorts,
				MatchApplications:                matchApps,
				DeterministicMode:                detMode,
				DeterministicBlockSize:           detBlockSize,
				DeterministicBlocksPerIP:         detBlocksPerIP,
				DeterministicHostBase:            detHostBase,
				DeterministicHostCount:           detHostCount,
				CounterID:                        natCounterID(natCounterIDs, dataplane.NATCounterTypeSource, rs.Name, rule.Name),
				// #9874: the fail-closed poison for an empty authored match.
				LenientMatchDropped: rule.LenientMatchDropped,
			})
		}
	}
	// #4161: Junos source-NAT rule-set precedence is MOST-SPECIFIC-SCOPE-WINS,
	// not config-order first-match. Among overlapping rule-sets whose scopes
	// all match a flow, Junos selects by the specificity of the match context
	// — interface > zone > routing-instance (interface most specific) — and
	// only then applies within-set rule order. The Rust matcher
	// (userspace-dp/src/nat/source.rs match_source_nat_result_for_tuple) is
	// first-match on slice order, so we make "first match" == "most-specific
	// match" by STABLE-sorting the emitted snapshot by context tier here. A
	// stable sort keeps config order WITHIN a tier (Junos within-rule-set order
	// plus equal-specificity rule-set-definition order) and keeps each
	// rule-set's rules contiguous, so rule-sets never interleave. The tier is a
	// pure function of the six scope fields already stamped above — no new wire
	// plumbing (they were carried since #3096). This is why the Rust first-match
	// loop is deliberately left unchanged: it reads a pre-tiered Vec.
	//
	// Scope note: DNAT (destination.rs match_entries) and static
	// (static_nat.rs pick_scoped) tier only zone-SCOPED vs zone-WILDCARD — a
	// narrower axis that does NOT rank interface above zone. Extending this full
	// interface>zone>routing-instance hierarchy to them is a separate,
	// out-of-scope follow-up.
	sort.SliceStable(out, func(i, j int) bool {
		return sourceNATScopeTier(out[i]) < sourceNATScopeTier(out[j])
	})
	return out
}

// Source-NAT context-specificity tiers (#4161). LOWER = more specific = higher
// precedence, matching Junos rule-set selection (interface most specific).
//
// #6812 F3: the tier definition moved to pkg/config (SourceNATScopeTier) so the
// emission order here and the aggregate budget walk's first-fit order
// (config.sourceNATAggregateReferencedCharges) read ONE definition. These
// aliases keep the local spelling for this file and its #4161 tests.
const (
	snatTierInterface       = config.SourceNATTierInterface
	snatTierZone            = config.SourceNATTierZone
	snatTierRoutingInstance = config.SourceNATTierRoutingInstance
	snatTierUnscoped        = config.SourceNATTierUnscoped
)

// sourceNATScopeTier returns the Junos context-specificity tier of a
// source-NAT rule-set snapshot (#4161) — the MIN of its from- and to-context
// tiers. The rule (including why an EMPTY context, not a zone literally named
// "any", is the wildcard) lives on config.SourceNATScopeTier.
func sourceNATScopeTier(s SourceNATRuleSnapshot) int {
	return config.SourceNATScopeTier(
		s.FromInterface, s.FromZone, s.FromRoutingInstance,
		s.ToInterface, s.ToZone, s.ToRoutingInstance,
	)
}

// natProtoAny is the source-NAT match-term protocol wildcard, mirroring the
// Rust SOURCE_NAT_PROTO_ANY (256): outside the 0-255 protocol range so it never
// aliases protocol 0 (HOPOPT). It denotes a GENUINELY unconstrained term and
// must never be used as a fallback for an unresolvable protocol (that is a
// fail-open widen — Codex finding on PR #3471; see natAppProtoNumber). The
// builder does not currently emit it: an application always constrains protocol,
// and an unconstrained `match application` (empty / "any") produces NO term at
// all rather than an any-protocol term. Kept defined to document the wire
// wildcard the Rust matcher honors and to keep the two sides legible. #3429.
const natProtoAny uint16 = 256

var _ = natProtoAny // reserved wire wildcard; see doc above (not emitted today)

// natProtoNever is a reserved protocol sentinel that can never equal a real
// 0-255 protocol and is not the wildcard, so a term carrying it matches no flow
// (#3429). Emitted for a `match application` that was configured but resolved to
// ZERO terms (a typo / dangling reference / empty application-set) so the rule
// fails CLOSED — it matches nothing — rather than silently widening to every
// protocol/port. The commit-time strict gate (#2187) rejects the typo so this
// is only the lenient load / peer-sync backstop.
const natProtoNever uint16 = 0xFFFF

// sourceNATDestPortRanges coalesces a configured source-NAT `match
// destination-port` list to wire ranges, failing CLOSED when the constraint was
// specified but nothing is representable (#3429, #3546). The two inputs mirror
// the parser's two signals (parseDNATPortList): `ports` is every numeric token
// (out-of-range values included, dropped by coalescePortRanges) and `invalid`
// is the raw non-numeric tokens (`http`, garbage) the parser preserved on
// NATMatch.InvalidDestinationPorts. A constraint is CONSIDERED CONFIGURED when
// either list is non-empty. An all-empty input (no constraint configured) stays
// empty — a legitimate match-any-port wildcard. A configured constraint that
// coalesces to nothing — every numeric out of 1..65535, OR an all-nonnumeric
// list whose only tokens are invalid (#3546) — returns the never-match sentinel
// so the rule matches NOTHING instead of widening to every port. A mix of one
// valid port and invalid tokens (`[ http 8080 ]`) keeps the valid port (8080),
// matching the lenient DNAT builder. The strict commit gate
// (validateNATMatchDestinationPortStrict) rejects both the out-of-range and the
// nonnumeric case at commit; this guard hardens the #1960 tolerant-load /
// peer-sync path, where the bad rule would otherwise reach the dataplane.
//
// Before #3546 this builder consulted only `ports` and ignored `invalid`, so an
// all-nonnumeric source-NAT dest-port (e.g. `http`) parsed to an EMPTY `ports`
// list, coalesced to nothing, and — with no configured-numeric to trip the
// existing fail-closed branch — returned empty = unconstrained match-any-port
// (the AGY/Codex fail-open residual split out of #3446). The DNAT builder
// already failed closed on this case via InvalidDestinationPorts.
//
// NOTE: source NAT has no `match source-port` grammar (the SNAT parser only
// reads source/destination address(-name), destination-port, and application),
// so there is no source-port coalesce path to guard symmetrically.
func sourceNATDestPortRanges(ports []int, invalid []string) []NatPortRangeWire {
	ranges := coalescePortRanges(ports)
	if (len(ports) > 0 || len(invalid) > 0) && len(ranges) == 0 {
		return []NatPortRangeWire{natNeverMatchPortRange}
	}
	return ranges
}

// natAppProtoNumber resolves an application's protocol token to its IANA number
// for the source-NAT match wire (#3429). A resolvable token — including a
// numeric "0" (HOPOPT) — maps to its IANA value via the appid SSOT
// (appid.ProtocolNumber, the same resolver the policy path uses). An EMPTY or
// unresolvable protocol returns natProtoNever (0xFFFF), a never-match sentinel:
// a Junos application ALWAYS constrains protocol, so a term whose protocol
// cannot be resolved must match NOTHING. Returning natProtoAny (256, the
// wildcard) here would widen the app-scoped rule to EVERY protocol — a fail-open
// of the same class #3429 closes (Codex finding on PR #3471). natProtoAny is
// reserved for a genuinely unconstrained term, which the app path never produces
// (the "any" / empty app name short-circuits to no terms before this is called).
func natAppProtoNumber(proto string) uint16 {
	if n, ok := appid.ProtocolNumber(proto); ok {
		return uint16(n)
	}
	return natProtoNever
}

// buildSourceNATAppTerms resolves a source-NAT `match application [ <name>... ]`
// into (protocol, destination-port range, source-port range) terms for the
// dataplane match (#3429, #3491). A single user/predefined application yields
// one term; an application-set yields one term per resolved member; #3431 a
// multi-value list yields the UNION of every member's terms (match ANY). The
// empty list (or a sole "any") is unconstrained and yields no terms. A term's
// Ports are the application's destination-port spec coalesced to ranges and
// SrcPorts its source-port spec; an application with no destination (resp.
// source) port leaves that axis empty (unconstrained on it). When EVERY
// configured reference resolves to nothing, a single never-match term is
// emitted so the rule fails closed (see natProtoNever); an unresolvable member
// in a list that has at least one good member just contributes nothing (the
// strict commit gate rejects the typo — this is the lenient/peer-sync path).
func buildSourceNATAppTerms(cfg *config.Config, appNames []string) []NatAppTermWire {
	if cfg == nil {
		return nil
	}
	// Collapse a list that carries only the unconstrained "any" / empty
	// tokens to "no constraint" (nil terms). A real app alongside "any" is
	// kept verbatim — "any" then resolves to nothing per the loop below.
	configured := false
	for _, n := range appNames {
		if n != "" && n != "any" {
			configured = true
			break
		}
	}
	if !configured {
		return nil
	}
	userApps := cfg.Applications.Applications
	var terms []NatAppTermWire
	addApp := func(a *config.Application) {
		if a == nil {
			return
		}
		ports := appPortRangesFromSpec(a.DestinationPort)
		if a.DestinationPort != "" && len(ports) == 0 {
			// #3429: the application carried a destination-port spec but none of
			// it is representable (out of 1..65535) — fail CLOSED so the term
			// matches nothing rather than silently demoting to a protocol-only
			// (any-port) match. An app with NO destination-port keeps Ports empty
			// (a legitimate protocol-only match).
			ports = []NatPortRangeWire{natNeverMatchPortRange}
		}
		// #3491: the application's source-port constraint, dropped before this
		// fix. Same fail-CLOSED guard as the destination-port axis: an app that
		// configured a source-port but coalesces to nothing (all out of
		// 1..65535) gets the never-match sentinel rather than widening to any
		// source port. An app with NO source-port keeps SrcPorts empty (a
		// legitimate source-port-unconstrained match — the common case).
		srcPorts := appPortRangesFromSpec(a.SourcePort)
		if a.SourcePort != "" && len(srcPorts) == 0 {
			srcPorts = []NatPortRangeWire{natNeverMatchPortRange}
		}
		terms = append(terms, NatAppTermWire{
			Protocol: natAppProtoNumber(a.Protocol),
			Ports:    ports,
			SrcPorts: srcPorts,
		})
	}
	for _, appName := range appNames {
		if appName == "" || appName == "any" {
			continue
		}
		if app, found := config.ResolveApplication(appName, userApps); found {
			addApp(app)
		} else if _, isSet := config.ResolveApplicationSet(appName, cfg.Applications.ApplicationSets); isSet {
			// #5629: resolve the SET through config.ResolveApplicationSet (the
			// #4102 predefined-set-aware lookup), NOT a bare
			// cfg.Applications.ApplicationSets membership test which only sees
			// USER-defined sets. A strict predefined bundle (junos-ms-rpc,
			// junos-sun-rpc, ...) referenced by a source-NAT rule otherwise
			// matched neither branch, resolved to zero terms, and failed CLOSED
			// to natProtoNever (never-match) — the rule silently never
			// translated. ExpandApplicationSet already falls back to the
			// predefined set table, so a user-defined set stays bit-identical.
			if expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications); err == nil {
				for _, termName := range expanded {
					if a, ok := config.ResolveApplication(termName, userApps); ok {
						addApp(a)
					}
				}
			}
		}
	}
	if len(terms) == 0 {
		// Every configured app reference resolved to nothing -> fail closed.
		terms = []NatAppTermWire{{Protocol: natProtoNever}}
	}
	return terms
}

// deterministicSourceNATFields computes the IPv4 (mode 1) deterministic CGNAT
// block-allocation parameters for a source pool (#4559). It returns the wire
// fields the dataplane's allocate_deterministic_v4 needs:
//   - mode: 1 for an IPv4 host CIDR, 0 otherwise (round-robin fallback)
//   - blockSize: per-subscriber port block size (Junos `block-size`)
//   - blocksPerIP: (portHigh-portLow+1)/blockSize, computed against the SAME
//     defaulted port range the snapshot carries so block boundaries align with
//     the Rust allocator
//   - hostBase: subscriber-CIDR network address as a host-order uint32
//   - hostCount: subscriber count in the host CIDR (1 << (32-prefix_len))
//
// Only an IPv4 host CIDR yields mode 1 HERE. An IPv6 host (Junos mode 2 /
// NAPT64) is a v6→v4 translation the plain source-NAT path never performs, so
// this function returns mode 0 for it; mode 2 is enforced on the NAT64 forward
// path instead (buildNAT64Snapshots.deterministicNAT64V6Fields →
// nat64.rs allocate_deterministic_v6, #4559). A degenerate block-size / port
// range also returns mode 0 (the commit validator already rejects these for a
// committed config; this is defence in depth for the lenient/reload path).
func deterministicSourceNATFields(pool *config.NATPool, portLow, portHigh uint16) (mode uint8, blockSize, blocksPerIP uint16, hostBase, hostCount uint32) {
	if pool == nil || pool.Deterministic == nil {
		return 0, 0, 0, 0, 0
	}
	det := pool.Deterministic
	if det.BlockSize <= 0 || det.HostAddress == "" {
		return 0, 0, 0, 0, 0
	}
	_, hostNet, err := net.ParseCIDR(det.HostAddress)
	if err != nil {
		return 0, 0, 0, 0, 0
	}
	ones, bits := hostNet.Mask.Size()
	if bits != 32 {
		// IPv6 subscriber (mode 2, NAT64) — deferred, not yet enforced.
		return 0, 0, 0, 0, 0
	}
	base := hostNet.IP.To4()
	if base == nil {
		return 0, 0, 0, 0, 0
	}
	if portHigh < portLow {
		return 0, 0, 0, 0, 0
	}
	portRange := int(portHigh) - int(portLow) + 1
	if det.BlockSize > portRange {
		return 0, 0, 0, 0, 0
	}
	bpi := portRange / det.BlockSize
	if bpi <= 0 || bpi > 0xFFFF {
		return 0, 0, 0, 0, 0
	}
	hostBits := uint(bits - ones)
	if hostBits >= 32 {
		// A /0 subscriber range (>= 2^32 subscribers) is not a realistic CGNAT
		// deployment and the uint32 shift would overflow — fall back.
		return 0, 0, 0, 0, 0
	}
	hc := uint32(1) << hostBits
	return 1, uint16(det.BlockSize), uint16(bpi), binary.BigEndian.Uint32(base), hc
}

// sourceNATPoolPortRange moved to config.SourceNATPoolPortRange in #6812 F1 —
// the aggregate budget walk (pkg/config) has to read the SAME "is this pool's
// port range usable" verdict this builder does, or it charges budget for pools
// that install nothing. See config.SourceNATPoolUnusableReason.
