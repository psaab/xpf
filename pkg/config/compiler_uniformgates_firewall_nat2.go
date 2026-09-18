package config

import "fmt"

// runUniformGatesFirewallNAT2 runs the firewall nat2 sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesFirewallNAT2(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// A term naming a policer that is not defined under `firewall policer` /
	// `firewall three-color-policer` compiled cleanly and the rate-limit
	// silently never applied (fail-open — the term's traffic passed
	// unpoliced). Strict on commit / commit-check (hard reject so the typo is
	// operator-visible); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960). Runs on the
	// fully-compiled *Config so the policer maps are populated regardless of
	// authoring order. Mirrors validateRoutingExportReferencesStrict.
	if err := validateFirewallPolicerReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall policer reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3076 / #4953: firewall-filter `from tcp-flags` enforceability gate.
	// An expression the conjunctive dataplane matcher cannot represent
	// (disjunction, negated group, unknown flag, dangling negation, or a
	// required/forbidden contradiction) compiled cleanly before #3076 and the
	// constraint was silently dropped on the wire (fail-open — the term
	// matched every TCP segment). Strict on commit / commit-check (hard reject
	// so the operator error is visible); lenient on load / peer-sync (warn so a
	// config an older binary persisted, or a peer authored, before the reject
	// existed still boots — #1960 no-brick). On the leniently-loaded boot the
	// term keeps its raw TCPFlags and the userspace snapshot builder marks it
	// TCPFlagsUnparseable, failing the term CLOSED (#3367) rather than widening
	// it. This reject previously lived inline in compileFirewall, which the P4
	// dispatch calls with no compileOpts — so it could not be mode-gated and an
	// upgraded / peer-synced node blacked out or alarm-looped HA sync.
	if err := validateFirewallTCPFlagsStrict(cfg); err != nil {
		if opts.lenientFirewallTCPFlags {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter tcp-flags (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2506: firewall-filter `from source-prefix-list <name>` /
	// `destination-prefix-list <name>` cross-reference. A term naming a
	// prefix-list not defined under `policy-options prefix-list` compiled
	// cleanly and the userspace snapshot builder contributed no prefixes for
	// it, silently losing the address scope (fail-open or fail-closed depending
	// on the action). Strict on commit / commit-check (hard reject so the typo
	// is operator-visible); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960; the resolver then
	// contributes no prefixes for the unresolved reference). Mirrors the policer
	// gate above.
	if err := validateFirewallPrefixListReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall prefix-list reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #7273: the prefix-list reference gate above proves only the list NAME
	// resolves. Reject malformed entries in the referenced list before the
	// resolver can silently narrow the term to its parseable subset.
	if err := validateFirewallPrefixListEntriesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall prefix-list entry (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #5456: firewall-filter term rule-expansion advisory. A term whose
	// source×destination×dest-port×src-port cross-product (prefix-list prefixes
	// folded into src/dst) exceeds MaxFilterTermExpansion is COMMITTED, not
	// rejected: the live userspace dataplane enforces it natively (prefix-set
	// membership + name-keyed per-term counters) and never materializes the
	// cross-product, so rejecting would false-reject a legitimate config. The
	// silent uint32 truncation this issue fixes is already closed by
	// FilterTermExpansionCount's checked-uint64 clamp; this advisory only flags
	// that per-rule `show firewall filter` counts on the RETIRED-eBPF counter
	// path (unused on this build) would be clamped/inexact for such a term. Runs
	// on the fully-compiled *Config so the prefix-list maps are populated
	// regardless of authoring order. Emitted on BOTH the strict commit and the
	// tolerant load / peer-sync paths (it never blocks either — #1960 no-brick).
	warnFilterTermExpansionOverBound(cfg)

	// #2416: NAT `match source-address-name <book-entry>` cross-reference. A
	// source / destination NAT rule naming an address-book entry not defined
	// under `security address-book` compiled cleanly; the snapshot builder
	// resolves the name to no prefixes and (per the fail-closed backstop) the
	// rule matches NOTHING. That is safe but silent — the operator's intended
	// source scoping is gone with no signal. Strict on commit / commit-check
	// (hard reject so the typo is operator-visible); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — #1960;
	// the dataplane then fails closed for the unresolved reference). Mirrors the
	// firewall prefix-list gate above.
	if err := validateNATSourceAddressNameReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("NAT address-name reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4290: reject a static-NAT rule that would install with an EMPTY
	// translation target — an unresolvable `then static-nat prefix-name` or a
	// misspelled / unhandled target keyword the free-form static-nat leaf
	// accepted. Both silently installed a 1:1 NAT with no translation. Strict on
	// commit / commit-check (hard reject so the broken target is operator-
	// visible); lenient on load / peer-sync (warn — #1960; the dataplane then
	// fails closed on the empty prefix). Reuses lenientFirewallRefs, the same
	// opt the NAT address-name gate above uses.
	if err := validateStaticNATThenTargetStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT translation target (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5859: reject a static-NAT rule whose target is the NAT64 keyword `then
	// static-nat inet`. The compiler accepts the keyword but the userspace
	// snapshot emits the literal string "inet" into the same-family static_nat
	// address slot; the Rust parse of "inet" fails and the rule is SILENTLY
	// SKIPPED — a strict-valid config claims NAT64 but installs nothing. No
	// dataplane lowering of `static-nat inet` exists (the supported IPv6->IPv4
	// path is the native `security nat nat64` rule-set). Strict on commit /
	// commit-check (hard reject so the inert rule is operator-visible, naming
	// the native alternative); lenient on load / peer-sync (warn — #1960; the
	// snapshot builder then DROPS the rule so the sentinel never reaches Rust).
	// Reuses lenientFirewallRefs, the same opt the target gates above use.
	if err := validateStaticNATInetTargetStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT inet (NAT64) target (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6659: a static-NAT `match destination-address` list. The leaf is
	// declared `multi: true`, but the compiler read it with nodeVal and kept
	// only the first prefix — so the remaining prefixes were neither translated
	// NOR validated (a malformed prefix in any slot but the first committed
	// clean). The compiler now accumulates every value; this gate rejects the
	// multi-valued case because a static-NAT rule lowers to exactly ONE
	// dataplane row. Strict on commit / commit-check (hard reject so the
	// previously-silent collapse is operator-visible); lenient on load /
	// peer-sync (warn — #1960 no-brick; Match still carries the SELECTED prefix,
	// so the tolerant path behaves exactly as it did pre-#6659). Reuses
	// lenientFirewallRefs like the sibling static-NAT gates above.
	//
	// #6673: "selected", not "first". compileNATStatic assigns
	// `rule.Match = nodeVal(m)` once per `destination-address` sibling, so the
	// LAST authored statement wins; only WITHIN one bracket/block list is the
	// selected value that statement's first. And "AT MOST one" is honoured, not
	// "exactly one": the selected slot can be an authored blank
	// (`destination-address [ "" a b ];`), which lowers ExternalIP as "" and
	// makes the dataplane drop the rule entirely.
	if err := validateStaticNATMatchAddressesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT `match destination-address` LIST FORM IS NOT SUPPORTED — "+
					"AT MOST ONE prefix is honoured — the one the wrapped error names "+
					"(the LAST authored `match destination-address` statement, or within "+
					"a bracketed list that statement's first value; none at all when that "+
					"value is empty) — and the rest carry no translation; "+
					"author one rule per external prefix. A static-NAT rule is a 1:1 "+
					"mapping — one `match destination-address` against one `then static-nat "+
					"prefix` — so N external prefixes against one internal prefix has no "+
					"defined target, which is why this is the permanent contract and not a "+
					"pending feature (#6674). Downgraded to a warning on the tolerant load / "+
					"peer-sync path so an already-persisted config still boots: %v", err))
		} else {
			return err
		}
	}

	// #7216: the SELECTED `match destination-address` is empty — the rule
	// exists but has no external prefix, so it lowers ExternalIP as "" and the
	// Rust parse_nat_prefix drops the WHOLE mapping. The operator authored a
	// rule that does not exist at runtime, with no commit error and no warning.
	//
	// Runs AFTER the cardinality gate above ON PURPOSE. When two or more
	// prefixes are listed and the selection is the blank, that gate's #6673 arm
	// already rejects with a message that can name the prefixes being passed
	// over; firing here first would replace a richer diagnosis with a poorer
	// one. What reaches this gate is the shape #6673 could not see: a blank
	// selection with at most one non-empty prefix beside it.
	//
	// This does NOT disturb #6673's empty-SLOT semantics. That rule is about
	// COUNTING — an empty slot in MatchAddresses is the marker that nodeVal
	// selected a blank, so the cardinality gate counts only non-empty values.
	// This gate reads the SELECTION, never the slot count.
	//
	// Strict on commit / commit-check (hard reject); lenient on load /
	// peer-sync (warn — #1960 no-brick: the value committed clean on every
	// build before this gate, so boxes carrying one exist by construction, and
	// the dataplane already drops the rule there so a leniently-loaded config
	// is no worse off). Reuses lenientFirewallRefs like the sibling static-NAT
	// gates above.
	if err := validateStaticNATSelectedMatchAddressStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT rule with NO external prefix — the rule is "+
					"DROPPED ENTIRELY by the dataplane and translates nothing "+
					"(downgraded to a warning on the tolerant load / peer-sync path so an "+
					"already-persisted config still boots): %v", err))
		} else {
			return err
		}
	}

	// #6659 follow-up: a `security nat proxy-arp ... address` value the
	// dataplane cannot parse. #6659 widened this arm from nodeVal (first value
	// only) to the full list, so a malformed tail address now MATERIALISES into
	// ProxyARPEntry.Addresses instead of being dropped at compile — and
	// proxyarp.go's installer parses each address with netip.ParsePrefix and
	// SKIPS the failures, leaving a silently-inert entry that answers no
	// ARP/ND. Widening a read requires widening its validator in the same
	// change, so the gate lands here rather than being deferred. It is not
	// tail-only: proxy-ARP addresses carried NO commit-time validator at all
	// before this, so a malformed FIRST address committed clean too. Strict on
	// commit / commit-check (hard reject); lenient on load / peer-sync (warn —
	// #1960 no-brick; the installer already skips the bad entry, so a
	// leniently-loaded config is no worse than before the gate). Reuses
	// lenientFirewallRefs like the sibling NAT gates above.
	if err := validateProxyARPAddressesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("proxy-ARP address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5628 (codex-review-181 M16): a source / destination NAT rule's complete
	// `then` block must carry EXACTLY ONE NAT-terminal translation action. A
	// rule with ZERO actions installs no translation and is NOT terminal (an
	// intended `off` exemption silently disappears and the traffic falls
	// through — translated by a later broader rule if one matches, otherwise
	// untranslated); a rule
	// with TWO+ mutually-exclusive actions inside one block let the compiler
	// silently pick one by packed-key/child order (an exemption COULD then
	// publish as a translation — the inverse of the authored action). Both
	// clauses are past tense on purpose: since #5628 the compiler records every
	// field and the dataplane resolves them by a fixed precedence, so the
	// present-tense form of this sentence is false — see the corrected
	// rejection text on validateNATTerminalActionCardinalityStrict (#6820).
	// Strict on commit /
	// commit-check (hard reject so the malformed rule is operator-visible);
	// lenient on load / peer-sync (warn — #1960 no-brick). What happens on that
	// tolerant path differs per shape: a contradiction CONTAINING `off`
	// resolves to the EXEMPTION via `off` precedence; a contradiction WITHOUT
	// `off` (source-NAT `interface` + `pool`) gives INTERFACE MODE precedence,
	// producing interface translation when a suitable same-family egress
	// address exists and a fail-closed `Unavailable` otherwise, silently
	// discarding the pool either way; an actionless rule FALLS THROUGH — to a
	// later broader rule if one matches, otherwise off the end of the rule list
	// untranslated. All three are spelled out and test-cited
	// on validateNATTerminalActionCardinalityStrict (#5717). Do not restate
	// them as "inert", and do not compress them to "a contradiction resolves to
	// the exemption" — that is true only for the `off`-bearing case. Preserves #3850
	// duplicate-`then`-CONTAINER last-wins (the count reflects the winning block
	// only).
	if err := validateNATTerminalActionCardinalityStrict(cfg); err != nil {
		if opts.lenientNATTerminalAction {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("NAT terminal-action cardinality (downgraded to warning on tolerant path): %v", err))
			// #7640: record EVERY offender, not just the one the warning names.
			// The warning goes to the commit response and an apply-time log
			// line; a tolerant LOAD (boot, peer-sync, rollback) has neither a
			// commit response nor anything that survives the log, so without
			// this the surviving rules are invisible for the life of the node.
			// Set only here, so a non-empty slice means precisely "admitted
			// leniently" — the strict branch below returns instead.
			cfg.LenientNATTerminalActionRules = natTerminalActionCardinalityOffenders(cfg)
		} else {
			return err
		}
	}
	// #10294: term-level children outside `from`/`then`, and unknown
	// source-NAT action children, previously compiled away without a
	// diagnostic. Strict commit rejects; tolerant load/peer-sync warns.
	if err := validateFirewallUnknownChildrenStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall unknown child (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2217 Finding C: firewall-filter `then routing-instance <name>` (FBF)
	// cross-reference. A term naming a routing-instance not defined under
	// `routing-instances` compiled cleanly and the dataplane steered matched
	// packets toward a routing table that does not exist — a silent blackhole
	// / fall-through to the default table. Strict on commit / commit-check;
	// lenient on load / peer-sync (warn — #1960). Mirrors the policer gate
	// above.
	if err := validateFirewallRoutingInstanceReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall routing-instance reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3296: interface/unit (and lo0) `family inet|inet6 filter input|output
	// <name>` cross-reference. A filter hook naming a filter not defined under
	// `firewall family inet|inet6 filter` compiled cleanly with only a
	// warning, and the userspace filter compiler left the per-interface
	// fast-path map empty for the missing key, so the hot path returned the
	// default Accept — the security hook was silently disarmed and the
	// interface forwarded unfiltered (a fail-OPEN on a typo'd firewall hook).
	// Strict on commit / commit-check (hard reject so the typo is operator-
	// visible); lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960; the helper's snapshot-integrity
	// backstop then refuses to publish a snapshot whose interface references an
	// undefined filter, preserving prior good state rather than degrading the
	// hook to Accept). Supersedes the warn-only interface filter-reference loop
	// in ValidateConfig. Mirrors validateFirewallPrefixListReferencesStrict.
	if err := validateFirewallFilterReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3432: an OUTPUT-attached firewall filter carrying a `then
	// routing-instance <x>` (FBF) term compiled cleanly but was a silent
	// no-op: the userspace route-override path only consults the INPUT
	// filter's affects_route_lookup flag (the Rust filter compiler sets it
	// only on the input attach branch), so an output attach never steers the
	// traffic. Reject the unsupported direction at commit so the dead steering
	// action is operator-visible. Strict on commit / commit-check; lenient on
	// load / peer-sync (warn — #1960; the runtime already treats the output
	// steering term as inert). Mirrors the filter-reference gate above.
	if err := validateFilterRoutingInstanceDirectionStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter routing-instance direction (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
