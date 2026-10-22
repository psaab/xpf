// #16145 W2.1 NAT sub-run gate registry.
//
// This file is the per-sub-run registry for the NAT uniform gates. It is
// the first sub-run converted behind the #16166 PR-0 completeness census
// (TestLenientCompileOptsCompleteness16166), NAT first per the issue.
// Essays/comments travel verbatim: every essay that headed a gate in
// runUniformGatesNAT now heads that gate's registry entry, unchanged.
// Gate order is censused: the slice order below IS the execution order,
// and TestNATGateRegistryOrderCensus16145 pins it against the censused
// sequence so a reorder cannot silently change which diagnostic an
// operator sees first (strict first-error, invariant #6) or the tolerant
// warning-accumulation order (invariant #7).
//
// Structured Diagnostic is additive; prose stays: cfg.Warnings remains
// []string with byte-identical text. For every warning a registry gate
// appends on the tolerant path, warnNATDiagnostic16145 also records a
// Diagnostic with the same prose plus its gate identity, so a future
// show/reason surface can group or filter without re-parsing strings;
// warnings appended outside the registry (the trailing warning-only
// potential-shadow appender) get no Diagnostic. Nothing reads
// cfg.Diagnostics yet.
//
// Explicitly NOT a generic Check(*Config) registry: the rejected cross-P5
// form cannot represent scrub/prune/order or the offender-enumerating
// gates. Each entry therefore carries its own run func with the exact
// signature its gate needs, and the runner reproduces the hand-written
// control flow exactly: on the strict path the first failing gate
// returns its error; on the tolerant path every gate runs and warnings
// accumulate in slice order. One NAT step has no strict error at all in
// the original code and stays outside the slice, called by
// runUniformGatesNAT in its censused position:
// appendDNATOffShadowPotentialWarnings (trailing, warning-only).

package config

import "fmt"

// Diagnostic is the structured, additive record of one gate finding on
// the tolerant path (#16145). Prose is the exact string also appended to
// cfg.Warnings — the prose surface is retained unchanged; this struct
// exists so consumers can attribute a warning to its gate without
// string-matching. Gate is the registry entry name (see natGate.Name).
type Diagnostic struct {
	Gate  string
	Prose string
}

// natGate is one entry in the NAT sub-run registry. run executes the
// gate exactly as the hand-written stanza did: it returns a non-nil
// error iff the strict path must abort with that error (the first such
// error wins). On the tolerant path run appends its warning prose to
// cfg.Warnings (and its Diagnostic records to cfg.Diagnostics) and
// returns nil. lenient reports whether this compile is on the tolerant
// path for this gate — most NAT gates share opts.lenientDestNATAddresses
// (same NAT silent-drop / wrong-translate doctrine), but the field is
// per-entry so a gate with its own flag keeps it.
type natGate struct {
	name    string
	lenient func(opts compileOpts) bool
	run     func(cfg *Config, lenient bool) error
}

// natGates is the censused NAT sub-run registry, in execution order.
// The order is observable and pinned by
// TestNATGateRegistryOrderCensus16145: do not reorder, insert, or
// remove an entry without updating that census deliberately — a silent
// reorder changes the strict first-error and the tolerant warning order.
//
// runUniformGatesNAT iterates this slice. Every essay below is verbatim
// from the hand-written gate it replaces.
var natGates = []natGate{
	{
		name:    "destNATAddresses",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "destNATAddresses",
						fmt.Sprintf("destination-nat address (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "natMatchAddressLiterals",
		lenient: func(opts compileOpts) bool { return opts.lenientNATMatchAddressLiterals },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "natMatchAddressLiterals",
						fmt.Sprintf("nat match address (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "destNATProtocol",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "destNATProtocol",
						fmt.Sprintf("destination-nat protocol (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "natMatchDestinationPort",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "natMatchDestinationPort",
						fmt.Sprintf("nat match destination-port (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "natUnknownMatchLeaves",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #9877 unknown-match-leaf gate. A `match` leaf the compiler does not read
			// (a typo beside a valid leaf) was silently dropped and the rule compiled
			// as the surviving dimensions only, with no operator-facing warning on the
			// tolerant path. The match switches record such leaves on the typed rule;
			// this gate rejects (strict, first error) or warns naming them (lenient,
			// EVERY marked rule — a single warning would leave a second skipped rule
			// or a widened exemption silent), and the snapshot builders independently
			// fail CLOSED.
			//
			// Runs BEFORE the #8430 gate: a typo-ONLY match is both unknown-leaf and
			// unconstrained, and the unknown-leaf diagnosis names the cause while the
			// #8430 text would call it an empty match the operator never authored.
			// Shares the lenientDestNATAddresses flag (same NAT silent-drop /
			// wrong-translate doctrine).
			if err := validateNATUnknownMatchLeavesStrict(cfg); err != nil {
				if lenient {
					for _, v := range enumerateNATUnknownMatchLeaves(cfg) {
						warnNATDiagnostic16145(cfg, "natUnknownMatchLeaves",
							fmt.Sprintf("nat rule match leaves (downgraded to warning on tolerant path): %v", v))
					}
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "natRuleMatchConstrained",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #8430 unconstrained-match gate. An empty NAT match set is read by the
			// dataplane as UNCONSTRAINED (`if !constrained { return true }`), so a rule
			// that constrains nothing translates EVERY packet reaching it rather than
			// none — a fail-OPEN. Two routes reach that empty set: an unknown or
			// misspelled leaf, now closed by the closedWorld flip on the three `match`
			// subtrees in setSchema, and a VALUELESS supported leaf or an empty
			// `match { }`, which no allowlist can see because the leaf IS recognised.
			//
			// Written against the COMPILED match rather than the AST on purpose: that
			// is what binds the harm, and it catches every route into the empty set
			// including ones nobody has enumerated. An explicit catch-all
			// (`source-address 0.0.0.0/0`) is constrained and passes.
			//
			// Strict on commit / commit-check; lenient on load / peer-sync so a config
			// persisted before this gate existed still boots (#1960 no-brick).
			if err := validateNATRuleMatchConstrainedStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "natRuleMatchConstrained",
						fmt.Sprintf("nat rule match (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "dnatPool",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #3450/#10289 destination-NAT pool port/address gate. The DNAT pool
			// `port` parser used a bare strconv.Atoi with no bound check and the snapshot
			// builder cast straight to uint16, so `port 70000` wrapped to 4464 / `-1`
			// to 65535 (wrong backend port) and `port 0`/`port httpp` collapsed to 0 =
			// preserve-dest-port (silent no-op of the rewrite). The pool `address`
			// previously collapsed any extra token to the final one; non-host CIDRs
			// (10.0.0.0/24) were also coerced to the network base and address-book names
			// (web-server) were dropped by the Rust parser, leaving the VIP untranslated.
			// Strict on commit / commit-check (hard-reject); lenient on load / peer-sync
			// (downgrade to a warning so a config persisted before this gate existed
			// still boots — #1960 no-brick; the snapshot builder independently fails
			// CLOSED, skipping the rule rather than wrapping the port, collapsing an
			// address range, or coercing the address). Shares the lenientDestNATAddresses
			// flag (same NAT silent-drop / wrong-translate doctrine). Runs after the
			// destination-port gate.
			if err := validateDNATPoolStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "dnatPool",
						fmt.Sprintf("destination-nat pool (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "destinationNATPoolUnknownLeaves",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #13538: destination pools use the same closed-world behavior as source
			// pools. Strict commits reject unsupported leaves; tolerant loads warn so
			// persisted configs still boot.
			if err := validateDestinationNATPoolUnknownLeavesStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "destinationNATPoolUnknownLeaves",
						fmt.Sprintf("destination-nat pool unsupported leaf (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "sourceNATPoolUnknownLeaves",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #10291 source-NAT pool closed-world gate. The source-pool compiler
			// supports only its modeled leaves; every other child used to be ignored,
			// so a valid-but-unimplemented Junos knob or a typo committed cleanly and
			// had no effect at runtime. Strict on commit / commit-check (hard-reject);
			// lenient on load / peer-sync (downgrade to a warning so a persisted config
			// still boots). The compiler preserves the authored keyword in
			// NATPool.UnknownLeaves for this gate. Shares lenientDestNATAddresses with
			// the sibling source-pool gates.
			if err := validateSourceNATPoolUnknownLeavesStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATPoolUnknownLeaves",
						fmt.Sprintf("source-nat pool unsupported leaf (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "sourceNATDeterministic",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #13538: deterministic validation used to run while compiling pools,
			// before CompileConfigLenient could downgrade the error. Keep strict
			// behavior, but warn and retain the pool on tolerant loads.
			if err := validateSourceNATDeterministicStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATDeterministic",
						fmt.Sprintf("source-nat deterministic pool (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "sourceNATPool",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATPool",
						fmt.Sprintf("source-nat pool (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "natPoolAddressRange",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #8814 NAT pool address-RANGE size gate. `address <low> to <high>` expands
			// to one address per IP and is capped at 256; the cap used to be raised as a
			// compile error inside expandAddressRange, which put it on the LENIENT path
			// as well -- the security compiler chain carries no compileOpts, so nothing
			// could downgrade it, and a persisted config with an oversized range FAILED
			// TO LOAD. That defeats what CompileConfigLenient is for ("so an upgraded
			// node boots through"), and it was true of the BRACED spelling on master
			// independently of #8800; #8800 only removed the accident that hid it for
			// the packed spelling.
			//
			// The compiler now records the range and this gate decides its severity:
			// strict on commit / commit-check (hard-reject, so an operator still cannot
			// author one), lenient on load / peer-sync (warn; the pool loads without
			// that range and keeps its other addresses). Shares lenientDestNATAddresses
			// with the pool gates above -- same NAT silent-drop doctrine, same
			// population.
			if err := validateNATPoolAddressRangeStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "natPoolAddressRange",
						fmt.Sprintf("nat pool address range (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "natPoolReferences",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "natPoolReferences",
						fmt.Sprintf("nat pool reference (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "sourceNATRulePersistentNAT",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #14626: rule-level `then source-nat pool P persistent-nat ...` must not
			// commit clean while doing nothing. The tail is compiled per-rule; a
			// malformed tail, a tail on interface/off, or a tail disagreeing with the
			// pool / a sibling rule on the same pool rejects here. Tolerant load warns
			// and EffectivePersistentNAT falls back to the pool's own config.
			if err := validateSourceNATRulePersistentNATStrict14626(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATRulePersistentNAT",
						fmt.Sprintf("source-nat rule persistent-nat (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "sourceNATPoolAddressScope",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATPoolAddressScope",
						fmt.Sprintf("source-nat pool zone-scoped address (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "sourceNATPoolAddressGrammar",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATPoolAddressGrammar",
						fmt.Sprintf("source-nat pool address (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},

	// #6041: `persistent-nat` + `port no-translation` on one source-NAT pool is
	// now SUPPORTED. The userspace dataplane implements an address-only
	// persistent lease (reserve_address_only_persistent in
	// userspace-dp/src/nat/allocator.rs) that pins a public pool ADDRESS across
	// the configured permit scope without consuming a translated pool port, so
	// the combination no longer silently degrades to per-flow address-only NAT.
	// The #5819 fail-closed reject (validateSourceNATPersistentNoTranslationStrict
	// + the "persistent_nat_no_translation" snapshot marker) was therefore
	// removed — the combo commits cleanly and installs a usable pool. This note
	// stays verbatim in its original position between the address-grammar and
	// aggregate-cardinality gates; it is a removal record, not a gate, so it
	// has no registry entry.
	{
		name:    "sourceNATAggregateCardinality",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
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
				if lenient {
					warnNATDiagnostic16145(cfg, "sourceNATAggregateCardinality",
						fmt.Sprintf("source-nat aggregate pool cardinality (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
	{
		name:    "dnatOffShadow",
		lenient: func(opts compileOpts) bool { return opts.lenientDestNATAddresses },
		run: func(cfg *Config, lenient bool) error {
			// #9879 rejects a proven DNAT `off` shadow on strict commit and warns on
			// tolerant load. #11352 keeps the documented application, address-book,
			// and cross-rule-set cases visible as conservative warnings instead of
			// claiming an unproven overlap is certain.
			if err := validateDNATOffShadowStrict(cfg); err != nil {
				if lenient {
					warnNATDiagnostic16145(cfg, "dnatOffShadow",
						fmt.Sprintf("destination-nat off shadowed (downgraded to warning on tolerant path): %v", err))
				} else {
					return err
				}
			}
			return nil
		},
	},
}

// warnNATDiagnostic16145 appends one tolerant-path NAT warning: the
// prose string to cfg.Warnings (byte-identical to the pre-registry
// hand-written appends) and, additively, its structured Diagnostic
// record to cfg.Diagnostics. Strict callers never reach this helper —
// they return the error instead — so Diagnostics only ever records
// downgraded findings, in gate order.
func warnNATDiagnostic16145(cfg *Config, gate, prose string) {
	cfg.Warnings = append(cfg.Warnings, prose)
	cfg.Diagnostics = append(cfg.Diagnostics, Diagnostic{Gate: gate, Prose: prose})
}

// runNATGates16145 executes the NAT registry in censused order. The
// first strict error wins and aborts the sub-run (invariant #6); on the
// tolerant path every gate runs and warnings accumulate in slice order
// (invariant #7). It is split from runUniformGatesNAT so the order
// census test can drive the registry directly.
func runNATGates16145(cfg *Config, opts compileOpts) error {
	for _, g := range natGates {
		if err := g.run(cfg, g.lenient(opts)); err != nil {
			return err
		}
	}
	return nil
}
