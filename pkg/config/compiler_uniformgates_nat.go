package config

import "fmt"

// runUniformGatesNAT runs the nat sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesNAT(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2396(c) destination-NAT destination-address gate. Strict on commit /
	// commit-check (hard-reject a DNAT rule whose `match destination-address`
	// resolves to NO parseable host IP — every configured destination is
	// empty/malformed); lenient on load / peer-sync (downgrade to a warning so
	// an already-persisted or peer-synced config still boots — #1960 no-brick;
	// the snapshot builder skips each bad destination and the Rust DNAT table
	// drops the rule on its own, so a leniently-loaded bad config is inert).
	// Without this gate such a rule committed cleanly and then silently
	// translated nothing — the operator had no feedback that the only
	// destination address was a typo. Runs AFTER the policy gates so a
	// structural/policy error still wins the first-error slot.
	if err := validateDestinationNATAddressesStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("destination-nat address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #7145 NAT match-address literal gate. The four (NAT kind x match leaf)
	// slots that had NO parse gate at all — `match source-address` on source /
	// destination / static NAT, and `match destination-address` on source NAT —
	// accepted a malformed CIDR (`999.1.1.1/24`) that the sibling slot in the
	// SAME rule rejected. The values reach the wire verbatim; each Rust consumer
	// drops the unparseable entry but keeps the rule CONSTRAINED, so the rule
	// silently narrows and an all-malformed list matches NOTHING. Strict on
	// commit / commit-check (hard reject); lenient on load / peer-sync
	// (downgrade to a warning so an already-persisted or peer-synced config
	// still boots — #1960 no-brick; the value is KEPT so the dataplane's
	// fail-closed drop still applies rather than collapsing to match-any).
	// Runs immediately after the sibling destination-address gate so the two
	// read as one family, and so a rule tripping BOTH reports the older,
	// narrower message first (no change to an existing config's first error).
	if err := validateNATMatchAddressLiteralsStrict(cfg); err != nil {
		if opts.lenientNATMatchAddressLiterals {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("nat match address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2396(a)/(3) destination-NAT match-protocol gate. The DNAT `match
	// protocol <token>` reaches the wire VERBATIM (nodeVal -> rule.Match.Protocol
	// -> snapshot, with no validation), and the Rust DNAT table drops a token
	// ip_proto::proto_number cannot resolve (the dataplane backstop). So an
	// unresolvable `match protocol` (a typo, or a junos-* alias the DNAT path
	// does not pre-resolve) committed cleanly and then silently translated
	// nothing — the #2396 silent-drop class. Strict on commit / commit-check
	// (hard-reject); lenient on load / peer-sync (downgrade to a warning so a
	// config persisted before this gate existed still boots — #1960 no-brick;
	// the dataplane drops the inert rule on its own). Shares the
	// lenientDestNATAddresses flag (same #2396 DNAT silent-drop doctrine). Runs
	// after the address gate so a malformed-destination error wins first.
	if err := validateDestinationNATProtocolStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("destination-nat protocol (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3446 source/destination-NAT match destination-port gate. The DNAT/SNAT
	// `match destination-port` parser used a bare strconv.Atoi with no bound
	// check and the builders cast straight to uint16, so a 0/out-of-range
	// (70000→4464, -1→65535) or non-numeric (`http`) port wrapped to the wrong
	// port or collapsed the whole match to the wildcard port (translating every
	// port). Static NAT already validates its typed destination-port leaf
	// (#2491); this closes the same gap for the source/destination NAT match
	// grammar. Strict on commit / commit-check (hard-reject); lenient on load /
	// peer-sync (downgrade to a warning so a config persisted before this gate
	// existed still boots — #1960 no-brick; the snapshot builders independently
	// fail CLOSED). Shares the lenientDestNATAddresses flag (same NAT
	// silent-drop / wrong-translate doctrine). Runs after the protocol gate.
	if err := validateNATMatchDestinationPortStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("nat match destination-port (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3450 destination-NAT pool port/address gate. The DNAT pool `port` parser
	// used a bare strconv.Atoi with no bound check and the snapshot builder cast
	// straight to uint16, so `port 70000` wrapped to 4464 / `-1` to 65535 (wrong
	// backend port) and `port 0`/`port httpp` collapsed to 0 = preserve-dest-port
	// (silent no-op of the rewrite). The pool `address` was stored verbatim: a
	// non-host CIDR (10.0.0.0/24) was coerced to the network base and an
	// address-book name (web-server) was dropped by the Rust parser, leaving the
	// VIP untranslated. Strict on commit / commit-check (hard-reject); lenient on
	// load / peer-sync (downgrade to a warning so a config persisted before this
	// gate existed still boots — #1960 no-brick; the snapshot builder
	// independently fails CLOSED, skipping the rule rather than wrapping the port
	// or coercing the address). Shares the lenientDestNATAddresses flag (same NAT
	// silent-drop / wrong-translate doctrine). Runs after the destination-port
	// gate.
	if err := validateDNATPoolStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("destination-nat pool (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3906 source-NAT pool port-range gate. The pool `port range <low> to
	// <high>` was parsed with the wrong keyword shape and silently ignored (the
	// pool defaulted to 1024-65535 PAT), so an operator narrowing the range got
	// the full default range and a reversed/out-of-range range committed green
	// then dropped the rule at runtime. Reject a reversed (low > high) or
	// out-of-range (not 1-65535) explicitly-configured range. Strict on commit /
	// commit-check (hard-reject); lenient on load / peer-sync (downgrade to a
	// warning so a config persisted before this gate existed still boots — #1960
	// no-brick; the snapshot builder independently fails CLOSED via
	// sourceNATPoolPortRange). Shares the lenientDestNATAddresses flag (same NAT
	// silent-drop / wrong-translate doctrine). Runs after the DNAT pool gate.
	if err := validateSourceNATPoolStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("source-nat pool (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5626 source/destination-NAT pool-REFERENCE definedness gate. A NAT rule
	// whose `then ... pool <name>` names a pool NOT defined under `security nat
	// source/destination pool` committed cleanly (warn-only) and then failed the
	// translation closed at runtime in an order-dependent way: the SNAT snapshot
	// builder marks the rule unusable (missing_pool) and the DNAT builder drops
	// it (pool lookup misses), so matching traffic is silently left untranslated
	// and falls through to a later rule or the no-NAT default. Strict on commit /
	// commit-check (hard-reject so the dangling reference is operator-visible);
	// lenient on load / peer-sync (downgrade to a warning so a config persisted
	// before this gate existed still boots — #1960 no-brick; the snapshot
	// builders independently fail CLOSED, installing nothing). Shares the
	// lenientDestNATAddresses flag (same NAT silent-drop doctrine). This gate
	// subsumes the warn-only pool-reference loop that previously lived in
	// ValidateConfig (it would otherwise emit a duplicate warning alongside the
	// downgraded gate warning on the lenient path). Runs after the pool-value
	// gates so a bad pool DEFINITION still wins the first-error slot.
	if err := validateNATPoolReferencesStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("nat pool reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5875 source-NAT pool ZONE-SCOPED ADDRESS gate. A source-NAT pool address
	// may carry an IPv6 zone/scope qualifier (`fe80::1%eth0`): the Junos lexer
	// admits `%` and Go's netip.ParseAddr honors a zone, so the scoped literal
	// slipped through and the snapshot builder copied the raw string onto the
	// wire. But the Rust allocator parses each pool member as std::net::IpAddr
	// (no scope model), so the scoped form fails to parse, the pool is marked
	// InvalidPool, and the rule silently stops translating after apply — a
	// commit-vs-apply divergence. Reject the scoped form: a global SNAT pool
	// address never needs an interface scope, and stripping `%zone` silently
	// would change the modeled address. Strict on commit / commit-check
	// (hard-reject so the un-representable pool is operator-visible); lenient on
	// load / peer-sync (downgrade to a warning so a config persisted before this
	// gate existed still boots — #1960 no-brick; the snapshot builder
	// independently marks the pool unusable with reason "zone_scoped_pool_address").
	// Shares the lenientDestNATAddresses flag (same NAT silent-drop /
	// wrong-translate doctrine). Runs BEFORE the grammar gate so a `%zone`-scoped
	// member (including a scoped-CIDR the grammar gate would otherwise reject with
	// a generic invalid-CIDR message) gets the precise, actionable scope
	// diagnostic. Registered in the SNAT strict set, so #5876's peer-effective
	// SNAT gate covers it too.
	if err := validateSourceNATPoolAddressScopeStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("source-nat pool zone-scoped address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5627 source-NAT pool ADDRESS-grammar gate. The strict path validated a
	// source pool's `port range` but left its ADDRESS members unchecked, so a
	// pool referenced by a pool-mode `then source-nat pool <name>` rule that
	// carried a malformed member (`not-an-ip`, `203.0.113.1/garbage`), an
	// over-capacity prefix (host count > MaxSourceNATPoolPrefixHosts — a `/15`,
	// `10.0.0.0/8`, or a v6 prefix shorter than `/112`), or no addresses at all
	// committed green — then the live Rust allocator (`expand_pool_address`,
	// userspace-dp/src/nat/source.rs) marked the pool InvalidPool/EmptyPool and
	// DROPPED the rule at runtime, a persistent NAT outage visible only after
	// apply. Reject the same shapes the dataplane rejects so Go and live stay
	// grammar-equivalent. Strict on commit / commit-check (hard-reject);
	// lenient on load / peer-sync (downgrade to a warning so a config persisted
	// before this gate existed still boots — #1960 no-brick; the snapshot
	// builder independently marks the pool unusable). Shares the
	// lenientDestNATAddresses flag (same NAT silent-drop / wrong-translate
	// doctrine as validateNATPoolReferencesStrict). Runs AFTER the pool-reference
	// gate so an UNDEFINED pool wins the first-error slot.
	if err := validateSourceNATPoolAddressGrammarStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("source-nat pool address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6041: `persistent-nat` + `port no-translation` on one source-NAT pool is
	// now SUPPORTED. The userspace dataplane implements an address-only
	// persistent lease (reserve_address_only_persistent in
	// userspace-dp/src/nat/allocator.rs) that pins a public pool ADDRESS across
	// the configured permit scope without consuming a translated pool port, so
	// the combination no longer silently degrades to per-flow address-only NAT.
	// The #5819 fail-closed reject (validateSourceNATPersistentNoTranslationStrict
	// + the "persistent_nat_no_translation" snapshot marker) was therefore
	// removed — the combo commits cleanly and installs a usable pool.

	// #5877 source-NAT AGGREGATE pool-cardinality gate. The per-field and
	// per-member source-pool gates above bound ONE pool (a member's host count to
	// MaxSourceNATPoolPrefixHosts, a pool's port range to 1..65535), but nothing
	// bounded the AGGREGATE across a whole config: pool COUNT, the SUM of every
	// pool's address cardinality, or total port capacity. Snapshot/apply builds a
	// PortAllocator for each pool-mode rule BEFORE reuse dedup is known
	// (userspace-dp/src/nat/{source,allocator}.rs) — every pool address gets a
	// per-address occupancy bitmap sized to the port range — so a
	// large-but-syntactically-valid config forces substantial memory + CPU during
	// a security-critical commit-apply (stalling commits, watchdogs, HA
	// convergence, or the Rust dataplane), and repeated applies magnify it. Reject
	// an over-budget config at commit, fail-closed, before apply constructs any
	// allocator state. Strict on commit / commit-check (hard-reject naming the
	// exceeded budget and by how much); lenient on load / peer-sync (downgrade to
	// a warning so a config persisted before this gate existed still boots — #1960
	// no-brick; apply builds the state it always did and the operator is warned to
	// shrink it). Shares the lenientDestNATAddresses flag (same NAT silent-drop /
	// resource-safety doctrine as the sibling source-pool gates). Runs AFTER the
	// per-pool value/grammar gates so a single structurally broken pool still wins
	// the first-error slot.
	if err := validateSourceNATAggregateCardinalityStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("source-nat aggregate pool cardinality (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
