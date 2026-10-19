package dataplane

import (
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// resolveSNATMatchAddr resolves a SNAT match CIDR to an address ID.
// If the CIDR already exists as an address-book entry, reuses that ID.
// Otherwise, creates an implicit address-book entry with a synthetic name.
// Returns 0 (any) if the CIDR is empty.
func resolveSNATMatchAddr(dp DataPlane, cidr string, result *CompileResult) (uint32, error) {
	if cidr == "" {
		return 0, nil
	}

	// Normalize CIDR
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}

	// Create implicit address-book entry (LPM trie handles deduplication)
	synthName := "_snat_match_" + cidr
	if id, ok := result.AddrIDs[synthName]; ok {
		return id, nil
	}

	addrID := result.nextAddrID
	result.nextAddrID++
	result.AddrIDs[synthName] = addrID

	if err := dp.SetAddressBookEntry(cidr, addrID); err != nil {
		return 0, fmt.Errorf("set implicit address %s: %w", cidr, err)
	}
	if err := dp.SetAddressMembership(addrID, addrID); err != nil {
		return 0, fmt.Errorf("set self-membership for implicit %s: %w", cidr, err)
	}

	slog.Debug("implicit SNAT match address created", "cidr", cidr, "id", addrID)
	return addrID, nil
}

// NAT counter-key type prefixes (#2218). The per-rule NAT translation hit
// counter map is keyed by "natType/rulesetName/ruleName". The type prefix is
// required because the same (rule-set, rule) name pair can be reused across
// source-, destination-, and static-NAT (Junos allows independent name spaces
// per NAT type). Without the prefix those distinct rules collide on a single
// counter ID and their hit counts merge. Write site (assignNATCounterID) and
// every read site MUST use NATCounterKey with the matching type.
const (
	NATCounterTypeSource = "snat"
	NATCounterTypeDest   = "dnat"
	NATCounterTypeStatic = "static"
)

// NATCounterKey builds the per-rule NAT translation hit counter map key for a
// NAT rule. natType is one of the NATCounterType* constants. This is the single
// key formatter shared by the compiler write site and every operator read site
// (CLI / gRPC / REST / natshow) so the type-namespaced key stays consistent.
func NATCounterKey(natType, ruleSet, rule string) string {
	return natType + "/" + ruleSet + "/" + rule
}

// natCounterIDForKey derives the stable per-rule translation hit counter ID
// for a type-namespaced NAT rule key. The ID is a function of the rule's
// IDENTITY (the NATCounterKey string), not its compile-time position, so the
// same rule keeps the same ID across a config reorder or the removal/re-add of
// an unrelated rule (#2255). It is a 32-bit FNV-1a hash of the key, remapped
// off the reserved 0 sentinel ("no counter"). The wide 32-bit space makes two
// distinct keys colliding negligible (~256²/2³² ≈ 8e-6 at the 256-rule cap);
// assignNATCounterID resolves the rare in-compile collision deterministically.
func natCounterIDForKey(ruleKey string) uint32 {
	h := fnv.New32a()
	// fnv.Write never errors.
	_, _ = h.Write([]byte(ruleKey))
	id := h.Sum32()
	if id == 0 {
		// 0 is the "no counter" sentinel — remap a (vanishingly rare) zero
		// hash to a fixed non-zero id so the rule still gets a counter.
		id = 1
	}
	return id
}

// assignNATCounterID assigns (or reuses) the per-rule translation hit
// counter ID for a NAT rule keyed by NATCounterKey(natType, ruleSet, rule).
// Counter IDs are non-zero (0 means "no counter") and DERIVED from the rule
// key by natCounterIDForKey, so they are STABLE across compiles: a rule's ID
// is a function of its identity, never of its position in the config. This
// keeps the Rust helper's cumulative numeric-keyed counter store correctly
// attributed across a config reorder/removal by construction (#2255) — a
// reused config slot can no longer inherit a different rule's prior count.
// The assignment is shared across all expanded address/port/protocol pairs of
// the same rule so every hit on that rule attributes to a single counter.
//
// This is the single source of truth for NAT rule counter IDs across SNAT,
// DNAT, and static NAT. The compiler-assigned IDs are surfaced to the Rust
// userspace dataplane via the config snapshot (so the hot path can attribute
// a translation hit to the matched rule) and read back by the operator
// surfaces through Manager.ReadNATRuleCounter (#2218). The natType prefix keeps
// same-named rules across SNAT/DNAT/static from colliding on one counter ID.
//
// Collisions: two distinct keys can in principle hash to the same id. This
// streaming pass gives each key a provisional unique id (re-hash with a "#N"
// suffix until free) so the vestigial per-rule stamp and the exhaustion count
// stay correct, but the winner of a contested BASE id here depends on which key
// was compiled first — a compile-order dependence that a harmless config
// reorder would expose (#5099). finalizeNATCounterIDs re-derives the
// AUTHORITATIVE result.NATCounterIDs map in a stable sorted order after all NAT
// phases run, so the id a rule ends up with is a pure function of the rule key
// set, independent of traversal order. When the number of distinct counters
// reaches MaxNATRuleCounters the rule falls back to counter 0 (no per-rule
// attribution) and a warning is logged, preserving the historical exhaustion
// contract.
func assignNATCounterID(result *CompileResult, natType, ruleSet, rule string) uint32 {
	ruleKey := NATCounterKey(natType, ruleSet, rule)
	if existing, ok := result.NATCounterIDs[ruleKey]; ok {
		return existing
	}
	if len(result.NATCounterIDs) >= MaxNATRuleCounters {
		slog.Warn("NAT rule counter IDs exhausted, reusing counter 0",
			"nat-type", natType, "rule-set", ruleSet, "rule", rule,
			"count", len(result.NATCounterIDs), "max", MaxNATRuleCounters)
		result.NATCounterIDs[ruleKey] = 0
		return 0
	}
	// Derive the stable id; resolve the rare distinct-key collision against the
	// ids already assigned in this compile by deterministic re-hash.
	counterID := natCounterIDForKey(ruleKey)
	for attempt := 1; natCounterIDInUse(result, ruleKey, counterID); attempt++ {
		counterID = natCounterIDForKey(fmt.Sprintf("%s#%d", ruleKey, attempt))
		if counterID == 0 {
			counterID = 1
		}
	}
	result.NATCounterIDs[ruleKey] = counterID
	return counterID
}

// natCounterIDInUse reports whether counterID is already assigned to a rule key
// OTHER than ruleKey in this compile. Used by assignNATCounterID to detect a
// distinct-key hash collision before claiming the id.
func natCounterIDInUse(result *CompileResult, ruleKey string, counterID uint32) bool {
	for k, id := range result.NATCounterIDs {
		if id == counterID && k != ruleKey {
			return true
		}
	}
	return false
}

// finalizeNATCounterIDs makes the per-rule NAT counter ID assignment
// independent of compile/traversal order (#5099). It MUST run once after every
// NAT phase that calls assignNATCounterID (SNAT, DNAT, static NAT) so it sees
// the full key set.
//
// assignNATCounterID resolves a distinct-key base-hash collision by bumping
// whichever colliding key it happens to visit SECOND to a "#N" re-hash. That
// makes the loser a function of visit order: for two keys that share a base id,
// the first-compiled key claims the base id and the second is bumped, so a
// harmless config reorder swaps their ids — contradicting the stable-identity
// contract (id = f(rule identity), never f(identity, already-visited)). Because
// the Rust helper keeps cumulative counters keyed by numeric id across
// reconcile, the swapped pair would read each other's history.
//
// This pass re-derives the id for every key that received a real counter by
// walking the keys in a STABLE lexicographic order and applying the SAME
// per-key "#N" re-hash probe assignNATCounterID uses. Sorting removes the
// visit-order dependence: among keys sharing a base id the lexicographically
// smallest keeps the base id and the rest probe deterministically, so the same
// SET of keys always yields the same assignment regardless of the order the
// rules compiled in. Exhausted keys (id 0, no per-rule attribution) are left
// untouched — exhaustion selection is a separate, config-order concern.
func finalizeNATCounterIDs(result *CompileResult) {
	if len(result.NATCounterIDs) == 0 {
		return
	}
	// Collect the keys that received a real counter; sort for a traversal-order
	// independent assignment.
	keys := make([]string, 0, len(result.NATCounterIDs))
	for k, id := range result.NATCounterIDs {
		if id != 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	used := make(map[uint32]struct{}, len(keys))
	for _, k := range keys {
		id := natCounterIDForKey(k)
		for attempt := 1; ; attempt++ {
			if _, taken := used[id]; !taken {
				break
			}
			id = natCounterIDForKey(fmt.Sprintf("%s#%d", k, attempt))
			if id == 0 {
				id = 1
			}
		}
		used[id] = struct{}{}
		result.NATCounterIDs[k] = id
	}
}

// nextSourceNATPoolID advances the source-NAT pool numbering, refusing to WRAP.
//
// #8597 K75. The numbering is a uint8 incremented per named pool and per
// anonymous interface-mode pool, with no bound anywhere — so it wrapped
// silently. Measured before the guard, with 260 named pools each referenced by
// one SNAT rule:
//
//	260 pools -> 256 distinct IDs, 4 colliding IDs, NextPoolID=4
//	pool ID 0 is shared by [pool256 pool000]
//
// and a wrapped NextPoolID then hands compileNAT64's auto-assign branch an id
// another pool already holds.
//
// It saturates rather than rejecting, and warns. Rejecting would fail a commit
// that works today: nothing indexes a live structure by this id since #8606
// (see the note on compileNAT), so 256 pools forward correctly right now and a
// new commit-time refusal would be a regression dressed as a fix. Saturating
// keeps the aliasing bounded to the last id and makes it AUDIBLE, which is the
// same exhaustion contract assignNATCounterID uses for the sibling identifier
// space — that one has a guard and this one did not.
//
// The cap is the uint8 range, NOT MAX_NAT_POOLS (32). The 32 is the legacy
// eBPF map's ABI, and those maps are no longer written on the only production
// compile path; capping the allocator there would reject working configs.
func nextSourceNATPoolID(cur uint8, poolName string) uint8 {
	if cur == maxSourceNATPoolID {
		slog.Warn("source NAT pool IDs exhausted; further pools reuse the last id",
			"pool", poolName, "max", maxSourceNATPoolID)
		return cur
	}
	return cur + 1
}

// maxSourceNATPoolID is the largest assignable source-NAT pool id — the uint8
// range the numbering is declared in, not a policy limit.
const maxSourceNATPoolID uint8 = 255

// compileNAT resolves the source- and destination-NAT configuration into the
// identifiers and runtime state that OUTLIVE the compile, and rejects the
// configurations that cannot be enforced.
//
// What escapes this function, i.e. what it exists for after #6420:
//
//   - result.PoolIDs / result.NextPoolID — the source-NAT pool numbering that
//     compileNAT64's auto-assign branch continues from.
//
//     THIS USED TO SAY the operator surfaces read the numbering back through
//     ApplyResult (`show security nat source pool`, the REST/gRPC pool views,
//     the Prometheus pool metrics). They do not, and have not since #8606
//     moved every one of them to the helper's live pool status keyed by pool
//     NAME. Measured for #8597 K75: outside pkg/dataplane the only mentions of
//     PoolIDs are the two maps.Clone calls in apply.go that copy it into
//     ApplyResult, and nothing reads it there. Corrected rather than deleted,
//     because the numbering IS still assigned and still feeds compileNAT64.
//
//   - result.NATCounterIDs — the per-rule translation hit counter IDs stamped
//     onto the userspace config snapshot (buildSnapshotWithSchedulerStateAnd-
//     NATCounters) and read back by every operator NAT surface.
//
//   - result.AddrIDs / result.nextAddrID — the implicit "_snat_match_<cidr>"
//     address-book entries resolveSNATMatchAddr synthesizes.
//
//   - the persistent-NAT table (dp.GetPersistentNAT), which the conntrack GC
//     and `show security nat source persistent-nat-table` read. This is the
//     one dataplane call in this file that is NOT a shim no-op.
//
//   - the errors: an unknown zone, an unknown pool, and a DNAT match/pool
//     address that is a prefix rather than a host still fail the compile, and
//     the #4960 validate-before-mutate pre-pass surfaces them ahead of the
//     first host mutation.
//
// What it no longer does is BUILD eBPF NAT map records. The legacy
// snat_rules / snat_rules_v6 / dnat_table / dnat_table_v6 / nat_pool_configs /
// nat_pool_ips_v4 / nat_pool_ips_v6 / snat_egress_ips writes were retired with
// the eBPF dataplane (#1373/#1476). The only production compile path is
// Manager.CompileUserspaceShim, whose userspaceShimCompileDataplane implements
// every NAT setter and every stale-NAT deleter as `return nil` (loader.go), and
// the AF_XDP helper receives NAT policy through the config snapshot instead.
// The record construction was therefore pure work whose product was discarded.

// natPersistentStaging accumulates persistent-NAT registrations across
// compileNAT and compileNAT64 so the live table is swapped only after both
// succeed (#14679). Discarded pre-pass compiles have pnat==nil.
type natPersistentStaging struct {
	pnat        *PersistentNATTable
	poolConfigs map[string]PersistentNATPoolInfo
	natIPToPool map[netip.Addr]string
	registered  map[string]bool
}

func newNATPersistentStaging(dp DataPlane) *natPersistentStaging {
	s := &natPersistentStaging{
		poolConfigs: make(map[string]PersistentNATPoolInfo),
		natIPToPool: make(map[netip.Addr]string),
		registered:  make(map[string]bool),
	}
	if dp != nil {
		s.pnat = dp.GetPersistentNAT()
	}
	return s
}

func (s *natPersistentStaging) commit() {
	if s == nil || s.pnat == nil {
		return
	}
	s.pnat.ReplacePoolConfigs(s.poolConfigs, s.natIPToPool)
}

// registerPool stages one pool's persistent registration using exact
// allocator semantics for the caller: expanded addresses for SNAT pools,
// NAT64 host addresses for NAT64-only pools. Returns true when a config was
// staged. Duplicate pool names keep the first staged config, mirroring
// compileNAT's compiledPools de-duplication.
func (s *natPersistentStaging) registerPool(pool *config.NATPool, effPNAT *config.PersistentNATConfig, addrs []netip.Addr, dp DataPlane) {
	if s == nil || s.pnat == nil || pool == nil || effPNAT == nil {
		return
	}
	if s.registered[pool.Name] {
		return
	}
	s.registered[pool.Name] = true
	timeout := config.SecondsToDuration(effPNAT.InactivityTimeout, 0)
	if timeout == 0 {
		timeout = 300 * time.Second
	}
	s.poolConfigs[pool.Name] = PersistentNATPoolInfo{Timeout: timeout, Permit: effPNAT.Permit}
	for _, addr := range addrs {
		s.natIPToPool[addr] = pool.Name
	}
	compileInfo(dp, "persistent NAT pool registered",
		"pool", pool.Name,
		"timeout", timeout,
		"permit", string(effPNAT.Permit))
}

func compileNAT(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	return compileNATWithStaging(dp, cfg, result, nil)
}

func compileNATWithStaging(dp DataPlane, cfg *config.Config, result *CompileResult, staging *natPersistentStaging) error {
	ownStaging := staging == nil
	if ownStaging {
		staging = newNATPersistentStaging(dp)
	}
	natCfg := &cfg.Security.NAT

	// Source NAT: allocate pool IDs and compile pools + rules
	poolID := uint8(0)

	// Remember which named pools were already parsed so a pool referenced by
	// several SNAT rules is registered — and logged — exactly once.
	compiledPools := make(map[string]bool)

	for _, rs := range natCfg.Source {
		// #12525: validate provenance per side. A non-empty scope or the
		// compiler stamp for that absent clause is required independently;
		// one side's stamp must never authorize an empty scope on the other.
		if !rs.HasNATFromScopeStamp() {
			return fmt.Errorf("source NAT from-zone %q not found", rs.FromZone)
		}
		if !rs.HasNATToScopeStamp() {
			return fmt.Errorf("source NAT to-zone %q not found", rs.ToZone)
		}
		if rs.FromZone != "" {
			if _, ok := result.ZoneIDs[rs.FromZone]; !ok {
				return fmt.Errorf("source NAT from-zone %q not found", rs.FromZone)
			}
		}
		if rs.ToZone != "" {
			if _, ok := result.ZoneIDs[rs.ToZone]; !ok {
				return fmt.Errorf("source NAT to-zone %q not found", rs.ToZone)
			}
		}
		for _, rule := range rs.Rules {
			if !rule.Then.Interface && rule.Then.PoolName == "" && !rule.Then.Off {
				compileWarn(dp, "SNAT rule has no action",
					"rule", rule.Name, "rule-set", rs.Name)
				continue
			}
			// Assign the translation-hit counter independently of interface
			// egress-IP resolution. Non-zone to-scopes have no ToZone entry,
			// but their userspace snapshots still need this rule identity.
			counterID := assignNATCounterID(result, NATCounterTypeSource, rs.Name, rule.Name)

			// source-nat off: exemption rule (no pool allocation)
			if rule.Then.Off {
				// Resolve source addresses (supports bracket lists)
				srcAddrs := rule.Match.SourceAddresses
				if len(srcAddrs) == 0 {
					srcAddrs = []string{rule.Match.SourceAddress}
				}

				// Resolve destination addresses (supports bracket lists)
				dstAddrs := rule.Match.DestinationAddresses
				if len(dstAddrs) == 0 {
					dstAddrs = []string{rule.Match.DestinationAddress}
				}

				for _, srcAddr := range srcAddrs {
					srcAddrID, err := resolveSNATMatchAddr(dp, srcAddr, result)
					if err != nil {
						return fmt.Errorf("snat rule %s/%s source match %q: %w",
							rs.Name, rule.Name, srcAddr, err)
					}
					for _, dstAddr := range dstAddrs {
						dstAddrID, err := resolveSNATMatchAddr(dp, dstAddr, result)
						if err != nil {
							return fmt.Errorf("snat rule %s/%s dest match %q: %w",
								rs.Name, rule.Name, dstAddr, err)
						}

						compileInfo(dp, "source NAT off rule compiled",
							"rule-set", rs.Name, "rule", rule.Name,
							"from", rs.FromZone, "to", rs.ToZone,
							"counter_id", counterID,
							"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
							"src_addr", srcAddr, "dst_addr", dstAddr)
					}
				}
				continue
			}

			var curPoolID uint8

			if rule.Then.Interface {
				// Interface mode: resolve the egress zone's per-interface
				// addresses. They no longer reach snat_egress_ips, but whether
				// ANY of them resolves still decides whether this rule consumes
				// a pool ID, so the resolution stays load-bearing.
				toZoneCfg, ok := cfg.Security.Zones[rs.ToZone]
				// #6918: a map entry present with a NIL *ZoneConfig makes ok
				// true, so testing ok alone falls through to the deref below and
				// panics the compile. The sibling sweep in compiler_iface.go
				// already treats a nil zone slot as reachable — its comment
				// names the tolerant/programmatic and HA-peer-sync paths, which
				// do not go through the parser that always allocates a zone.
				// Treat nil exactly like a zone with no interfaces: skip the
				// rule, warning only when the operator named a to-zone.
				if !ok || toZoneCfg == nil || len(toZoneCfg.Interfaces) == 0 {
					if rs.ToZone != "" {
						compileWarn(dp, "to-zone has no interfaces",
							"zone", rs.ToZone, "rule-set", rs.Name)
					}
					continue
				}

				var v4IPs []net.IP
				var v6IPs []net.IP

				for _, ifaceRef := range toZoneCfg.Interfaces {
					physName, cfgName, unitNum, vlanID := resolveInterfaceRef(ifaceRef, cfg)

					physIface, err := result.cachedInterfaceByName(physName)
					if err != nil {
						slog.Debug("interface not found for SNAT egress",
							"interface", physName, "err", err)
						continue
					}

					var unitV4 net.IP
					var unitV6 net.IP

					ifCfg, ifOK := cfg.Interfaces.Interfaces[cfgName]
					if ifOK && ifCfg.RedundancyGroup > 0 {
						// RETH: read addresses from config (VIPs may not be on this node)
						if unit, uOK := ifCfg.Units[unitNum]; uOK {
							for _, addr := range unit.Addresses {
								ip, _, perr := net.ParseCIDR(addr)
								if perr != nil {
									continue
								}
								if ip4 := ip.To4(); ip4 != nil && unitV4 == nil {
									unitV4 = ip4
								} else if ip.IsGlobalUnicast() && unitV6 == nil {
									unitV6 = ip
								}
							}
						}
					} else {
						// Non-RETH: query live interface
						subName := physName
						if vlanID > 0 {
							subName = fmt.Sprintf("%s.%d", physName, vlanID)
						}
						if ip, ierr := getInterfaceIPFn(subName, result); ierr == nil {
							unitV4 = ip
						}
						if ip, ierr := getInterfaceIPv6Fn(subName, result); ierr == nil {
							unitV6 = ip
						}
					}

					if unitV4 == nil && unitV6 == nil {
						continue
					}

					if unitV4 != nil {
						v4IPs = append(v4IPs, unitV4)
					}
					if unitV6 != nil {
						v6IPs = append(v6IPs, unitV6)
					}
					compileInfo(dp, "SNAT egress IP resolved",
						"interface", ifaceRef, "ifindex", physIface.Index,
						"vlan", vlanID, "v4", unitV4, "v6", unitV6)
				}

				if len(v4IPs) == 0 && len(v6IPs) == 0 {
					compileWarn(dp, "no IP addresses for interface SNAT",
						"zone", rs.ToZone)
					continue
				}

				// Interface pools are anonymous: they consume a pool ID but are
				// never named in result.PoolIDs.
				curPoolID = poolID
				poolID++
			} else {
				// Pool mode: look up named pool
				pool, ok := natCfg.SourcePools[rule.Then.PoolName]
				if !ok {
					// #15002 (A08-03): the tolerant load / peer-sync path
					// downgrades the missing-pool gate (#5626) to a
					// warning, and the userspace builder ships this rule
					// with pool_unusable=missing_pool — fail-closed, the
					// rule translates nothing. Warn-and-skip the rule on
					// the validation pass so one dangling reference does
					// not abort the whole apply before any host mutation;
					// the real pass keeps the hard rejection.
					if isValidationPass(dp) {
						compileWarn(dp, "source NAT pool not found, skipping rule",
							"pool", rule.Then.PoolName, "rule", rule.Name, "rule-set", rs.Name)
						continue
					}
					return fmt.Errorf("source NAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Check if pool was already compiled — skip the reparse.
				if compiledPools[pool.Name] {
					curPoolID = result.PoolIDs[pool.Name]
				} else {
					// First encounter: assign ID, parse addresses.
					if existingID, exists := result.PoolIDs[pool.Name]; exists {
						curPoolID = existingID
					} else {
						curPoolID = poolID
						result.PoolIDs[pool.Name] = curPoolID
						poolID = nextSourceNATPoolID(poolID, pool.Name)
					}

					// Register persistent NAT pool config and IPs.
					// #14110: registration must cover exactly the set the
					// userspace SNAT allocator can allocate from —
					// config.SourceNATPoolMembers (singular Address plus
					// Addresses) with every CIDR member expanded over its
					// full masked prefix, not only pool.Addresses and not
					// only a CIDR's base IP. Otherwise preservePersistent-
					// NATV4/V6 LookupPool misses a translated IP and the
					// binding is silently not preserved on session deletion.
					// An unusable pool (any member the expander cannot
					// honor, or over the aggregate budget) installs no
					// allocator in the dataplane, so it registers nothing —
					// fail-closed rather than a narrowed subset.
					// #14626: rule-effective persistence (rule tail over pool).
					if effPNAT, hasPNAT := rule.EffectivePersistentNAT(cfg); hasPNAT && effPNAT != nil {
						if staging.pnat != nil {
							expanded, usable := config.SourceNATPoolExpandedAddresses(pool)
							if usable && config.SourceNATAggregateOverBudgetPools(cfg)[pool.Name] {
								usable = false
							}
							if !usable {
								compileWarn(dp, "persistent NAT pool not registered: pool installs no dataplane allocator",
									"pool", pool.Name)
								staging.registered[pool.Name] = true
							} else {
								staging.registerPool(pool, effPNAT, expanded, dp)
							}
						}
					}

					compiledPools[pool.Name] = true
				}
			}

			// Resolve SNAT match addresses (supports bracket lists). Each
			// distinct CIDR gets an implicit address-book ID in result.AddrIDs.
			srcAddrs := rule.Match.SourceAddresses
			if len(srcAddrs) == 0 {
				srcAddrs = []string{rule.Match.SourceAddress}
			}
			dstAddrs := rule.Match.DestinationAddresses
			if len(dstAddrs) == 0 {
				dstAddrs = []string{rule.Match.DestinationAddress}
			}

			for _, srcAddr := range srcAddrs {
				srcAddrID, err := resolveSNATMatchAddr(dp, srcAddr, result)
				if err != nil {
					return fmt.Errorf("snat rule %s/%s source match %q: %w",
						rs.Name, rule.Name, srcAddr, err)
				}
				for _, dstAddr := range dstAddrs {
					dstAddrID, err := resolveSNATMatchAddr(dp, dstAddr, result)
					if err != nil {
						return fmt.Errorf("snat rule %s/%s dest match %q: %w",
							rs.Name, rule.Name, dstAddr, err)
					}

					compileInfo(dp, "source NAT rule compiled",
						"rule-set", rs.Name, "rule", rule.Name,
						"from", rs.FromZone, "to", rs.ToZone,
						"pool_id", curPoolID,
						"counter_id", counterID,
						"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
						"src_addr", srcAddr, "dst_addr", dstAddr)
				}
			}
		}
	}

	// Destination NAT
	if natCfg.Destination != nil {
		for _, rs := range natCfg.Destination.RuleSets {
			if !rs.HasNATFromScopeStamp() {
				return fmt.Errorf("destination NAT from-zone %q not found", rs.FromZone)
			}
			if rs.FromZone != "" {
				if _, ok := result.ZoneIDs[rs.FromZone]; !ok {
					return fmt.Errorf("destination NAT from-zone %q not found", rs.FromZone)
				}
			}
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" && !rule.Then.Off {
					continue
				}

				// Exemptions have no pool but are installed by the userspace
				// snapshot builder; allocate their translation-hit counter too
				// so the snapshot lookup does not stamp counter 0 (#13548).
				assignNATCounterID(result, NATCounterTypeDest, rs.Name, rule.Name)
				if rule.Then.Off {
					continue
				}

				pool, ok := natCfg.Destination.Pools[rule.Then.PoolName]
				if !ok {
					// #15002 (A08-03): the tolerant path downgrades the
					// missing-pool gate (#5626) to a warning, and the
					// userspace builder drops this rule
					// (DestinationNATRuleExcludedReason) — fail-closed.
					// Warn-and-skip on the validation pass; the real pass
					// keeps the hard rejection.
					if isValidationPass(dp) {
						compileWarn(dp, "DNAT pool not found, skipping rule",
							"pool", rule.Then.PoolName, "rule", rule.Name, "rule-set", rs.Name)
						continue
					}
					return fmt.Errorf("DNAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Validate source-address-name if present (config compatibility)
				if rule.Match.SourceAddressName != "" {
					if _, ok := result.AddrIDs[rule.Match.SourceAddressName]; !ok {
						compileWarn(dp, "DNAT source-address-name not found in address-book",
							"rule", rule.Name, "name", rule.Match.SourceAddressName)
					}
				}

				// #3229: validate destination-address-name (config compat)
				if rule.Match.DestinationAddressName != "" {
					if _, ok := result.AddrIDs[rule.Match.DestinationAddressName]; !ok {
						compileWarn(dp, "DNAT destination-address-name not found in address-book",
							"rule", rule.Name, "name", rule.Match.DestinationAddressName)
					}
				}

				// Parse match destination address
				if rule.Match.DestinationAddress == "" {
					compileWarn(dp, "DNAT rule has no match destination-address",
						"rule", rule.Name)
					continue
				}

				matchIP, _, err := net.ParseCIDR(rule.Match.DestinationAddress)
				if err != nil {
					// Try as plain IP
					matchIP = net.ParseIP(rule.Match.DestinationAddress)
					if matchIP == nil {
						compileWarn(dp, "invalid DNAT match address",
							"addr", rule.Match.DestinationAddress)
						continue
					}
				}

				// Parse pool address
				poolIP, poolNet, err := net.ParseCIDR(pool.Address)
				if err != nil {
					poolIP = net.ParseIP(pool.Address)
					if poolIP == nil {
						compileWarn(dp, "invalid DNAT pool address",
							"addr", pool.Address)
						continue
					}
				} else {
					// DNAT requires exact host address — reject non-host CIDRs.
					ones, bits := poolNet.Mask.Size()
					if (bits == 32 && ones != 32) || (bits == 128 && ones != 128) {
						// #15002 (A08-03): the tolerant path downgrades
						// the non-host DNAT pool gate (#3450) to a
						// warning, and the userspace builder drops
						// this rule (DestinationNATRuleExcludedReason)
						// — fail-closed. Warn-and-skip on the
						// validation pass; the real pass keeps the
						// hard rejection.
						if isValidationPass(dp) {
							compileWarn(dp, "DNAT pool address is a network prefix, skipping rule",
								"pool", pool.Name, "addr", pool.Address, "rule", rule.Name, "rule-set", rs.Name)
							continue
						}
						return fmt.Errorf("DNAT pool %q address %q is a network prefix, not a host address (use /%d for DNAT)",
							pool.Name, pool.Address, bits)
					}
				}

				// Resolve the application match so an unresolvable application
				// or application-set still warns. The protocol/port expansion
				// this used to drive existed only to key dnat_table entries;
				// the userspace snapshot carries the rule's own match instead.
				if rule.Match.Application != "" {
					userApps := cfg.Applications.Applications
					if _, found := config.ResolveApplication(rule.Match.Application, userApps); !found {
						if _, isSet := cfg.Applications.ApplicationSets[rule.Match.Application]; isSet {
							// Expand application-set to individual terms
							expanded, eerr := config.ExpandApplicationSet(rule.Match.Application, &cfg.Applications)
							if eerr != nil {
								compileWarn(dp, "DNAT expand application-set failed",
									"rule", rule.Name, "application", rule.Match.Application, "err", eerr)
							} else {
								for _, termName := range expanded {
									if _, ok := config.ResolveApplication(termName, userApps); !ok {
										compileWarn(dp, "DNAT application-set term not found",
											"rule", rule.Name, "term", termName)
									}
								}
							}
						} else {
							compileWarn(dp, "DNAT application not found, ignoring",
								"rule", rule.Name, "application", rule.Match.Application)
						}
					}
				}

				compileInfo(dp, "destination NAT rule compiled",
					"rule-set", rs.Name, "rule", rule.Name,
					"match_ip", matchIP,
					"pool", pool.Name, "pool_ip", poolIP)
			}
		}
	}

	// Record highest pool ID so compileNAT64 can auto-assign additional pools.
	result.NextPoolID = poolID

	if ownStaging {
		staging.commit()
	}
	return nil
}

// compileStaticNAT validates the static-NAT rule-sets and assigns their
// per-rule translation hit counter IDs.
//
// The bidirectional static_nat_v4 / static_nat_v6 map entries this used to
// write went with the eBPF dataplane (#1373/#1476/#6420): SetStaticNATEntryV4
// and SetStaticNATEntryV6 are `return nil` on the only production compile path
// (userspaceShimCompileDataplane, loader.go), and the AF_XDP helper installs
// static NAT from the config snapshot. What still escapes is
// result.NATCounterIDs — the ID `show security nat static rule` reads hits
// back through — and the mixed-address-family rejection, which the #4960
// pre-pass surfaces before the first host mutation.
func compileStaticNAT(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	count := 0
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.IsNPTv6 {
				continue // handled by compileNPTv6
			}
			if rule.Match == "" || rule.Then == "" {
				compileWarn(dp, "static NAT rule missing match or then",
					"rule-set", rs.Name, "rule", rule.Name)
				continue
			}

			// Parse external (match) address
			matchCIDR := rule.Match
			if !strings.Contains(matchCIDR, "/") {
				if strings.Contains(matchCIDR, ":") {
					matchCIDR += "/128"
				} else {
					matchCIDR += "/32"
				}
			}
			extIP, _, err := net.ParseCIDR(matchCIDR)
			if err != nil {
				compileWarn(dp, "invalid static NAT match address",
					"addr", rule.Match, "err", err)
				continue
			}

			// Parse internal (then) address
			thenCIDR := rule.Then
			if !strings.Contains(thenCIDR, "/") {
				if strings.Contains(thenCIDR, ":") {
					thenCIDR += "/128"
				} else {
					thenCIDR += "/32"
				}
			}
			intIP, _, err := net.ParseCIDR(thenCIDR)
			if err != nil {
				compileWarn(dp, "invalid static NAT then address",
					"addr", rule.Then, "err", err)
				continue
			}

			// Validate address family consistency — mixed IPv4/IPv6 is not supported.
			extIsV4 := extIP.To4() != nil
			intIsV4 := intIP.To4() != nil
			if extIsV4 != intIsV4 {
				// #15002 (A08-03): the tolerant path downgrades the
				// mixed-family gate (#13922) to a warning. Unlike the
				// block-pair case the Rust table drops per-rule, a
				// host mixed pair is installed keyed by family on each
				// side and simply never matches — fail-closed. Warn-
				// and-skip on the validation pass (no counter ID, so
				// `show` does not claim hits for an inert rule); the
				// real pass keeps the hard rejection.
				if isValidationPass(dp) {
					compileWarn(dp, "static NAT rule has mixed address families, skipping rule",
						"rule", rule.Name, "rule-set", rs.Name, "match", rule.Match, "then", rule.Then)
					continue
				}
				return fmt.Errorf("static NAT rule %q has mixed address families (match=%s, then=%s)",
					rule.Name, rule.Match, rule.Then)
			}

			// Assign the per-rule translation hit counter ID (#2218) so the
			// userspace dataplane can attribute static-NAT translations to
			// this rule and `show security nat static rule` reports non-zero.
			_ = assignNATCounterID(result, NATCounterTypeStatic, rs.Name, rule.Name)

			count++
			compileInfo(dp, "static NAT rule compiled",
				"rule-set", rs.Name, "rule", rule.Name,
				"external", rule.Match, "internal", rule.Then)
		}
	}

	if count > 0 {
		compileInfo(dp, "static NAT compilation complete", "entries", count)
	}

	return nil
}

// compileNPTv6 VALIDATES the NPTv6 rules in cfg. Since #7268 it writes nothing:
// the eBPF `nptv6_rules` map surface it used to fill is retired, and the AF_XDP
// helper builds its own NPTv6 state from the config snapshot
// (buildNptv6Snapshots copies Match/Then out independently) and computes its own
// RFC 6296 adjustment (userspace-dp/src/nptv6.rs `compute_adjustment`).
//
// What remains is load-bearing and is the reason this is still a compile PHASE
// rather than a deleted function: it is the #4960 validate-before-mutate
// pre-pass deciding whether an apply can succeed, carrying the #6894 r9 / #7077
// reject-vs-warn split. A rule the helper would REFUSE is a hard error here, so
// the failure lands before compileZones mutates the host; a rule the helper
// would DROP or would INSTALL keeps warn-and-skip, because erroring on those
// would fail an apply that succeeds today.
//
// dp is still taken so the phase keeps the shared row signature, and it is still
// READ — isValidationPass(dp) gates the log records so the pre-pass stays quiet.
func compileNPTv6(dp DataPlane, cfg *config.Config) error {
	count := 0

	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if !rule.IsNPTv6 || rule.Match == "" || rule.Then == "" {
				continue
			}

			// #6894 r9 F1 (#4960): choose the DISPOSITION of a per-rule prefix
			// fault by whether the rule will actually reach the enforcement
			// plane.
			//
			// A rule the userspace snapshot builder EMITS is handed to
			// `Nptv6State::try_from_snapshots`, which rejects the WHOLE snapshot
			// on any unparseable / length-mismatched / host-bits-set prefix
			// (userspace-dp/src/nptv6.rs, #2240/#4519). That rejection lands in
			// publishPreparedSnapshotFailClosedLocked -- AFTER compileZones has created
			// VLANs and reconciled addresses -- so warning and skipping here left
			// the #4960 validate-before-mutate pre-pass ACCEPTING a config the
			// real backend then rejects post-mutation, which is the precise shape
			// the pre-pass exists to prevent. Returning the error instead moves
			// an ALREADY-CERTAIN apply failure ahead of the mutation point; it
			// does not create a new one. It also cannot brick a boot or a peer
			// sync: Store.Load / Store.SyncApply compile through
			// pkg/config.compileTreeLenient and never reach this function, so the
			// config still loads with the warning validateNPTv6Strict emits, and
			// only the dataplane apply -- which already fails today -- fails.
			//
			// A rule the builder DROPS (#5818 unsupported match scope) never
			// reaches the helper: today's apply SUCCEEDS with the rule simply not
			// installed. It keeps the warn-and-skip disposition, because erroring
			// on it would fail an apply that works today.
			// #9877: a rule the builder drops for unknown match leaves never
			// reaches the helper either — same warn-and-skip disposition.
			installed := !config.NPTv6ScopeUnsupported(rs, rule) && config.StaticNATRuleExcludedReason(rule) == ""
			// #7077 (#6894 r10): the SAME argument applies a second time, and
			// missing it turned this fix into a regression. "The helper rejects
			// this" was inferred from Go's own parse failing, but the two
			// grammars are not identical: Rust's `parse_prefix` parses the mask
			// with `u8::from_str`, which takes a leading `+`, while Go's
			// net.ParseCIDR mask parser does not. So `nptv6-prefix fd00:9::/+48`
			// is a Go parse ERROR and a helper ACCEPT -- today's apply succeeds
			// and installs the translation. Hard-erroring on it failed an apply
			// that works, reached on the tolerant-load / HA-peer-sync path #1960
			// exists to keep booting.
			//
			// Note this cannot be discriminated by strict-vs-lenient instead:
			// validateNPTv6Strict rejects EVERY malformed class at commit, so a
			// malformed rule only ever arrives here from the lenient path, and
			// "warn when lenient" would be a full revert. See
			// compiler_nptv6_helper_grammar.go for the measurement.
			//
			// So a rule the helper would INSTALL keeps warn-and-skip for the
			// same reason a DROPPED rule does: erroring fails an apply that
			// succeeds today. Skipping costs nothing observable -- this function
			// writes the retired eBPF map surface, while buildNptv6Snapshots
			// copies Match/Then out of the config independently, so the rule
			// still reaches the helper and is still installed.
			helperInstalls := nptv6HelperWouldInstallFn(rule.Match, rule.Then)
			reject := func(reason string, attrs ...any) error {
				if !installed || helperInstalls {
					compileWarn(dp, "nptv6: "+reason, attrs...)
					return nil
				}
				return fmt.Errorf("rule-set %q rule %q: %s (match %q, nptv6-prefix %q); "+
					"the userspace helper rejects the whole NPTv6 snapshot on this rule "+
					"(#2240/#4519), so the apply cannot succeed -- correct or remove the "+
					"rule",
					rs.Name, rule.Name, reason, rule.Match, rule.Then)
			}

			// Parse external prefix (match destination-address)
			extIP, extNet, err := net.ParseCIDR(rule.Match)
			if err != nil {
				if rerr := reject("invalid match prefix", "addr", rule.Match, "err", err); rerr != nil {
					return rerr
				}
				continue
			}
			extOnes, _ := extNet.Mask.Size()

			// Parse internal prefix (nptv6-prefix)
			intIP, intNet, err := net.ParseCIDR(rule.Then)
			if err != nil {
				if rerr := reject("invalid nptv6-prefix", "addr", rule.Then, "err", err); rerr != nil {
					return rerr
				}
				continue
			}
			intOnes, _ := intNet.Mask.Size()

			// Validate: both must be same length, /48 or /64 IPv6
			if extOnes != intOnes {
				if rerr := reject("prefix lengths must match",
					"external", rule.Match, "internal", rule.Then); rerr != nil {
					return rerr
				}
				continue
			}
			if extOnes != 48 && extOnes != 64 {
				if rerr := reject("only /48 and /64 prefix lengths supported",
					"external", rule.Match, "internal", rule.Then); rerr != nil {
					return rerr
				}
				continue
			}
			ext16 := extIP.To16()
			int16 := intIP.To16()
			if ext16 == nil || int16 == nil {
				if rerr := reject("prefixes must be IPv6",
					"external", rule.Match, "internal", rule.Then); rerr != nil {
					return rerr
				}
				continue
			}
			// #4519 parity: the helper's parse_prefix fails CLOSED when any bit
			// is set beyond the prefix length rather than masking, because
			// masking-and-accepting would silently WIDEN the translation past
			// what the operator authored. The prefix-byte truncation below does
			// exactly that masking, so without this check the compiler accepts a
			// prefix the helper rejects -- the same pre-pass/backend divergence
			// as an unparseable prefix, one string away. /48 and /64 are both
			// word-aligned, so "host bits clear" is equivalent to the address
			// equalling its own network address.
			if !extIP.Equal(extNet.IP) || !intIP.Equal(intNet.IP) {
				if rerr := reject("host bits set beyond the prefix length",
					"external", rule.Match, "internal", rule.Then); rerr != nil {
					return rerr
				}
				continue
			}

			// #7268: the eBPF nptv6_rules writes that used to close this
			// branch are gone. What remains — every parse and disposition
			// decision above — is NOT dead: it is the #4960
			// validate-before-mutate pre-pass deciding whether an apply can
			// succeed, and the #6894 r9 / #7077 reject-vs-warn split that
			// decides which faults are hard errors. The helper builds its own
			// NPTv6 state from the config (buildNptv6Snapshots copies
			// Match/Then out independently) and computes its own adjustment
			// (userspace-dp/src/nptv6.rs compute_adjustment), so the rule still
			// reaches the enforcement plane; only this compiler's write of the
			// retired map surface is removed.

			count++
			compileInfo(dp, "nptv6 rule compiled",
				"rule-set", rs.Name, "rule", rule.Name,
				"external", rule.Match, "internal", rule.Then,
				"prefix_len", extOnes)
		}
	}

	// #7078: the CROSS-RULE overlap class, the residual named in
	// compiler_validate_4960.go's header. Everything above is per-rule; the
	// helper additionally refuses the WHOLE snapshot when two rules' prefixes
	// overlap within a conflicting zone scope (#2241, zone-partitioned per
	// #5176). Without this the #4960 pre-pass ACCEPTS such a config, compileZones
	// mutates the host, and the helper then rejects at
	// publishPreparedSnapshotFailClosedLocked with no rollback — the exact shape the
	// pre-pass exists to prevent, still live for this input.
	//
	// This is checked AFTER the per-rule loop because it is a property of the
	// SET, not of a rule, which is also why it could not live in
	// nptv6HelperWouldInstall (#7077's per-rule seam says so explicitly).
	//
	// The three #4960 over-rejection properties are preserved, and the predicate
	// carries them rather than this call site:
	//
	//   - config.NPTv6OverlapConflict skips rules the snapshot builder DROPS
	//     (NPTv6ScopeUnsupported), so a dropped rule cannot trigger a hard error
	//     for a rejection the helper never makes.
	//   - It skips rules whose prefixes do not parse or whose lengths disagree,
	//     because the helper refuses those on an earlier arm — reporting them as
	//     overlaps would name the wrong reason for a correct rejection.
	//   - It partitions by zone exactly as `zones_conflict` does, so the #5176
	//     split-horizon configurations the helper installs are NOT rejected.
	//     Reusing validateNPTv6Strict's older overlap check would have failed
	//     precisely those working configs: its `seenPrefix` carries no zone.
	if conflict := config.NPTv6OverlapConflict(cfg); conflict != "" {
		return fmt.Errorf("%s; the userspace helper rejects the whole NPTv6 snapshot "+
			"on an overlapping prefix pair (#2241), so the apply cannot succeed -- "+
			"correct or remove one of the rules", conflict)
	}

	if count > 0 {
		compileInfo(dp, "nptv6 compilation complete", "rules", count)
	}

	return nil
}

// compileNAT64 validates the NAT64 rule-sets and resolves each one's source
// pool, auto-assigning a pool ID to a pool that no SNAT rule referenced.
//
// The nat64_configs / nat64_count / nat64_prefix_map and nat_pool_* writes
// went with the eBPF dataplane (#1373/#1476/#6420) — SetNAT64Config,
// SetNAT64Count, SetNATPoolIPV4/V6 and SetNATPoolConfig are `return nil` on the
// only production compile path (userspaceShimCompileDataplane, loader.go), and
// the AF_XDP helper builds its NAT64 state from the config snapshot. What still
// escapes is result.PoolIDs / result.NextPoolID (the pool numbering the
// operator surfaces read back) plus the prefix and source-pool rejections the
// #4960 pre-pass surfaces before the first host mutation.
func compileNAT64(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	return compileNAT64WithStaging(dp, cfg, result, nil)
}

func compileNAT64WithStaging(dp DataPlane, cfg *config.Config, result *CompileResult, staging *natPersistentStaging) error {
	ruleSets := cfg.Security.NAT.NAT64
	ownStaging := staging == nil
	if ownStaging {
		staging = newNATPersistentStaging(dp)
	}
	// When called standalone, stage any SNAT persistent pools already in
	// PoolIDs so committing does not wipe them. Production passes shared staging.
	if ownStaging && staging.pnat != nil {
		stageExistingSNATPersistentPools14679(dp, cfg, result, staging)
	}
	if len(ruleSets) == 0 {
		if ownStaging {
			staging.commit()
		}
		return nil
	}

	count := uint32(0)
	for _, rs := range ruleSets {
		if count >= 4 { // MAX_NAT64_PREFIXES
			compileWarn(dp, "max NAT64 prefixes exceeded, skipping", "rule-set", rs.Name)
			break
		}

		// #15002 (A08-03): on the validation pass, every fault below that
		// the tolerant config path downgrades to a warning (the NAT64
		// prefix gate #3886/#8667, a dangling or unusable source pool)
		// warns-and-skips this rule-set instead of aborting the whole
		// apply: the userspace builder emits the rule-set (prefix through
		// the #8667 normaliser) and the Rust loader skips an
		// unparseable/non-/96 prefix or installs no allocator for a
		// missing/unusable pool, scoped to this rule-set (#3888). The
		// real pass keeps each hard rejection below verbatim.
		if isValidationPass(dp) {
			norm := config.NormaliseNAT64PrefixForSnapshot(rs.Prefix)
			normIP, normNet, nerr := net.ParseCIDR(norm)
			if nerr != nil {
				compileWarn(dp, "NAT64 rule-set has invalid prefix, skipping rule-set",
					"rule-set", rs.Name, "prefix", rs.Prefix, "err", nerr)
				continue
			}
			if ones, _ := normNet.Mask.Size(); ones != 96 || normIP.To16() == nil {
				compileWarn(dp, "NAT64 rule-set prefix is not an IPv6 /96, skipping rule-set",
					"rule-set", rs.Name, "prefix", rs.Prefix)
				continue
			}
			if _, pooled := result.PoolIDs[rs.SourcePool]; !pooled {
				pool, poolExists := cfg.Security.NAT.SourcePools[rs.SourcePool]
				if !poolExists || pool == nil {
					compileWarn(dp, "NAT64 rule-set source pool not found, skipping rule-set",
						"rule-set", rs.Name, "pool", rs.SourcePool)
					continue
				}
				if _, usable := config.NAT64PoolHostAddresses(pool); !usable {
					compileWarn(dp, "NAT64 rule-set source pool has no valid addresses, skipping rule-set",
						"rule-set", rs.Name, "pool", pool.Name)
					continue
				}
			}
		}

		// Parse the /96 prefix (e.g. "64:ff9b::/96")
		ip, ipNet, err := net.ParseCIDR(rs.Prefix)
		if err != nil {
			return fmt.Errorf("NAT64 rule-set %q: invalid prefix %q: %w", rs.Name, rs.Prefix, err)
		}
		ones, _ := ipNet.Mask.Size()
		if ones != 96 {
			return fmt.Errorf("NAT64 rule-set %q: prefix must be /96, got /%d", rs.Name, ones)
		}
		if ip.To16() == nil {
			return fmt.Errorf("NAT64 rule-set %q: prefix is not IPv6", rs.Name)
		}

		// Look up the source pool ID. If the pool was defined in source NAT
		// but not referenced by any SNAT rule (e.g. interface-mode rules), we
		// auto-assign it a pool ID here.
		poolID, ok := result.PoolIDs[rs.SourcePool]
		if !ok {
			pool, poolExists := cfg.Security.NAT.SourcePools[rs.SourcePool]
			if !poolExists || pool == nil {
				// #15000: warn-and-skip instead of erroring. The strict
				// commit gate (validateNAT64PrefixStrict) rejects an empty
				// or undefined source-pool; a leniently loaded / peer-synced
				// config must not abort the whole compile (and with it
				// every later apply) over one unresolvable rule-set.
				// buildNAT64Snapshots emits it with an empty pool, which
				// the Rust helper fail-closes per-packet (#2291).
				compileWarn(dp, "NAT64 source pool not found, skipping rule-set",
					"rule-set", rs.Name, "source-pool", rs.SourcePool)
				continue
			}
			// #14679: NAT64 installs only IPv4 host addresses (Rust
			// parse_pool_v4, all-or-nothing). Members are singular Address
			// plus Addresses; any non-host/IPv6/unparseable member poisons
			// the whole pool, so it has no valid NAT64 addresses.
			hosts, usable := config.NAT64PoolHostAddresses(pool)
			if !usable {
				return fmt.Errorf("NAT64 rule-set %q: source pool %q has no valid addresses",
					rs.Name, pool.Name)
			}
			// Assign next pool ID (after those used by SNAT).
			newID := result.NextPoolID
			result.NextPoolID = nextSourceNATPoolID(result.NextPoolID, pool.Name)
			result.PoolIDs[pool.Name] = newID
			poolID = newID

			if pool.PersistentNAT != nil && staging.pnat != nil && !staging.registered[pool.Name] {
				staging.registerPool(pool, pool.PersistentNAT, hosts, dp)
			}
			compileInfo(dp, "auto-assigned NAT64 source pool",
				"pool", pool.Name, "pool_id", newID, "v4_ips", len(hosts), "v6_ips", 0)
		}

		compileInfo(dp, "compiled NAT64 prefix",
			"rule-set", rs.Name, "prefix", rs.Prefix,
			"pool", rs.SourcePool, "pool_id", poolID)
		count++
	}

	compileInfo(dp, "NAT64 compilation complete", "prefixes", count)
	if ownStaging {
		staging.commit()
	}
	return nil
}

// stageExistingSNATPersistentPools14679 stages SNAT pools already numbered in
// result.PoolIDs for a standalone compileNAT64 commit. It mirrors compileNAT's
// SNAT registration gate (expanded addresses + aggregate budget, rule-effective
// persistence with pool fallback).
func stageExistingSNATPersistentPools14679(dp DataPlane, cfg *config.Config, result *CompileResult, staging *natPersistentStaging) {
	if cfg == nil || staging == nil || staging.pnat == nil {
		return
	}
	overBudget := config.SourceNATAggregateOverBudgetPools(cfg)
	// Pool-level fallback for pools with no SNAT rule (defensive; compileNAT
	// normally registers rule-referenced pools).
	seenRulePool := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			if _, numbered := result.PoolIDs[rule.Then.PoolName]; !numbered {
				continue
			}
			pool := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
			if pool == nil || staging.registered[pool.Name] {
				continue
			}
			seenRulePool[pool.Name] = true
			effPNAT, hasPNAT := rule.EffectivePersistentNAT(cfg)
			if !hasPNAT || effPNAT == nil {
				staging.registered[pool.Name] = true
				continue
			}
			expanded, usable := config.SourceNATPoolExpandedAddresses(pool)
			if usable && overBudget[pool.Name] {
				usable = false
			}
			if !usable {
				staging.registered[pool.Name] = true
				continue
			}
			staging.registerPool(pool, effPNAT, expanded, dp)
		}
	}
	for name := range result.PoolIDs {
		if seenRulePool[name] || staging.registered[name] {
			continue
		}
		pool := cfg.Security.NAT.SourcePools[name]
		if pool == nil || pool.PersistentNAT == nil {
			continue
		}
		expanded, usable := config.SourceNATPoolExpandedAddresses(pool)
		if usable && overBudget[pool.Name] {
			usable = false
		}
		if !usable {
			staging.registered[pool.Name] = true
			continue
		}
		staging.registerPool(pool, pool.PersistentNAT, expanded, dp)
	}
}
