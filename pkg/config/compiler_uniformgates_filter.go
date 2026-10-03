package config

import "fmt"

// runUniformGatesFilter runs the filter sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesFilter(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2175 firewall-filter `from protocol <token>` fail-open gate. Strict on
	// commit / commit-check (hard-reject a term whose protocol token is not
	// resolvable by the centralized appid.ProtocolNumber SSOT — neither a
	// known protocol name, a junos-* alias, nor a 0..255 number). Before this
	// gate such a token was caught only by the dataplane compiler
	// (compileFirewallFilters → validateFilterProtocols), whose error the
	// daemon SWALLOWS (not in requiredProtocolGateSentinels, so
	// compileErrorMustAbortApply == false): commit returned SUCCESS, the
	// config was promoted, and the term silently programmed NO protocol match
	// (the pre-#2175 "match protocol 0" surprise). The dataplane gate remains
	// as defense-in-depth; this gate makes the refusal operator-visible at
	// commit, consistent with validateApplicationSpecsStrict / the other
	// fail-open gates. Lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config carrying a bad token still boots — #1960
	// no-brick; the dataplane drops the constraint independently so the term
	// is inert, never silently "protocol 0"). Runs on the fully-compiled
	// *Config (firewall filters compiled) so the typed term list is populated.
	if err := validateFilterProtocolsStrict(cfg); err != nil {
		if opts.lenientFilterProtocols {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter protocol (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3723 firewall-filter cross-field satisfiability gate. Strict on commit /
	// commit-check (hard-reject a term whose `from` block combines a port with a
	// non-port protocol, tcp-flags with a non-TCP protocol, or icmp-type/code with
	// a non-ICMP protocol — or an icmp-code with no icmp-type). Such a term
	// compiles cleanly but the dataplane matcher (userspace-dp engine/matching.rs)
	// can NEVER satisfy the cross-field pair, so a `then discard`/`reject` term
	// silently never matches and the traffic is admitted by the implicit accept
	// (fail-OPEN) — the stateless-filter mirror of the application cross-field gate
	// #3373/#3348. Runs AFTER validateFilterProtocolsStrict so a truly unknown
	// protocol token is reported by that gate first. Lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — #1960
	// no-brick; the Rust UnsatisfiableFilterCrossField backstop then fails the
	// whole snapshot closed independently). Runs on the fully-compiled *Config so
	// the typed term list (Protocols + ports + tcp-flags + icmp populated by
	// compileFilterFrom, covering both `protocol` and `next-header`) is available.
	if err := validateFilterCrossFieldStrict(cfg); err != nil {
		if opts.lenientFilterCrossField {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter cross-field (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2399 (032-16) firewall-filter `then` action fail-open gate. Strict on
	// commit / commit-check (hard-reject a term whose `then` block carries a
	// token that is neither a recognized terminating action nor a recognized
	// modifier). `compileFilterThen` records unknown tokens in `UnknownActions`;
	// `compileFirewall` finalizes the complete term to `discard` only after all
	// `then` blocks have contributed. This uniform gate rejects on strict commit
	// and warns on tolerant load / peer-sync, keeping startup unbricked (#1960)
	// while ensuring the term fails closed rather than falling through to
	// implicit accept. It runs on the fully-compiled *Config so the typed term
	// list (with `UnknownActions` populated by `compileFilterThen`) is available.
	if err := validateFilterActionsStrict(cfg); err != nil {
		if opts.lenientFilterActions {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter action (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3205 (agy-070 #07/#08) firewall-filter symbolic-match-value gate. Strict
	// on commit / commit-check (hard-reject a term whose icmp-type/icmp-code
	// name or named port could not be resolved to a number by compileFilterFrom).
	// Before this gate such a value was silently dropped: an unresolved icmp-type
	// left the type set empty and matched ALL ICMP (a policy bypass for an
	// `accept` term), and an unresolved named port made a `*-port-except` term
	// match ALL ports (fail open — it permitted the excluded port). Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config still
	// boots — #1960 no-brick; the dataplane fails CLOSED on the kept-verbatim
	// token independently). Runs on the fully-compiled *Config so the typed term
	// list (with UnknownICMPTypes/UnknownICMPCodes/UnknownPorts populated by
	// compileFilterFrom) is available.
	if err := validateFilterMatchValuesStrict(cfg); err != nil {
		if opts.lenientFilterMatchValues {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter match value (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3203 (agy-070 #02/#03/#04) firewall-filter flexible-match-range gate.
	// Strict on commit / commit-check (hard-reject a term whose byte-offset/
	// bit-length/match-value/match-mask could not be parsed or fell outside the
	// representable range). Before this gate such a token was silently ignored
	// by compileFilterFrom, leaving the field at its zero default — a malformed
	// or >32-bit match-value became 0x0 and the rule matched the WRONG (zero)
	// pattern with a clean commit. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick).
	// Runs on the fully-compiled *Config so the typed term list (with
	// UnknownFlexMatch populated by compileFilterFrom) is available.
	if err := validateFilterFlexMatchStrict(cfg); err != nil {
		if opts.lenientFlexMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter flexible-match-range (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3297 firewall-filter positive-vs-except port mutual-exclusion gate.
	// Strict on commit / commit-check (hard-reject a term carrying BOTH a
	// positive port match and the negated *-port-except list in the same
	// direction — Junos rejects this as ambiguous). Before this gate xpf
	// accepted the term and the Rust matcher silently applied positive-wins,
	// dropping the except side. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// dataplane's positive-wins fallback keeps that direction fail-safe). Runs
	// on the fully-compiled *Config so the typed term list (with
	// SourcePorts/DestinationPorts and SourcePortsExcept/DestPortsExcept
	// populated by compileFilterFrom) is available.
	if err := validateFilterPortExceptStrict(cfg); err != nil {
		if opts.lenientFilterPortExcept {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter port-except (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3359 firewall-filter positive-vs-except ADDRESS mutual-exclusion gate.
	// Strict on commit / commit-check (hard-reject a term that mixes a positive
	// address match — literal source/destination-address or a non-except
	// prefix-list — with an `except` prefix-list in the same direction; Junos
	// rejects this as ambiguous). Before this gate xpf accepted the term and the
	// userspace lowering FOLDED the except prefixes into the positive set,
	// dropping the except modifier — a silent fail-OPEN for a discard/reject
	// term. Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; the dataplane's
	// positive-wins fallback keeps that direction fail-safe). Sibling of the
	// #3297 port-except gate above.
	if err := validateFilterAddressExceptStrict(cfg); err != nil {
		if opts.lenientFilterAddressExcept {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter address-except (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3307 firewall-filter unenforced-`from`-leaf gate. Strict on commit /
	// commit-check (hard-reject a term whose `from` block carries a match leaf
	// the dataplane does NOT enforce — ttl / source-mac-address / ip-options /
	// fragment-offset / hop-limit / ...). The schema gate is opt-in, so such a
	// leaf passed commit and was silently DROPPED by compileFilterFrom (no
	// default arm), leaving the term matching MORE broadly than authored — an
	// accept over-permits (fail open), a discard/reject over-drops. Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config still
	// boots — #1960 no-brick; the dataplane never represented the leaf, so the
	// term matches without it independently). Runs on the fully-compiled *Config
	// so the typed term list (with UnknownFrom populated by compileFilterFrom) is
	// available.
	// #3433 firewall-filter literal-address gate. Strict on commit / commit-check
	// (hard-reject a term whose literal source/destination-address is malformed or
	// of the wrong family for the filter). The address leaves were untyped at
	// commit, so a bad literal reached the kernel lo0 nft mirror verbatim and
	// either failed the atomic `nft -f -` load (breaking a legitimate commit) or,
	// on the lenient path, left the kernel mirror ABSENT while userspace stayed
	// armed — a host-protection divergence. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// lowering's family-filter and the userspace matcher both fail closed for the
	// bad token independently). Runs on the fully-compiled *Config so the typed
	// term address slices are available. Sibling of the #3307 from-match gate.
	if err := validateFilterAddressLiteralsStrict(cfg); err != nil {
		if opts.lenientFilterAddressLiterals {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter address literal (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	if err := validateFilterFromMatchStrict(cfg); err != nil {
		if opts.lenientFilterFromMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter from-match (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3308 firewall-filter routing-instance-vs-discard/reject mutual-exclusion
	// gate. Strict on commit / commit-check (hard-reject a term that co-locates
	// `then routing-instance <x>` with a terminating `then discard`/`then
	// reject`). Such a term is contradictory: it asks the dataplane to BOTH steer
	// the packet into <x> AND drop/reject it. Both forwarding paths now resolve
	// the contradiction to the DENY — the userspace PBR runtime
	// (ingress_route_table_override) returns RouteOverride::Drop (#4392) and the
	// kernel `ip rule` mirror (buildPBRFromFilter, pkg/routing) skips the steering
	// rule (#4534). This gate stays strict at commit so the operator never
	// authors the contradiction, but is lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; both
	// runtimes drop the term independently). Runs on the fully-compiled *Config so
	// the typed term list (RoutingInstance + Action populated by compileFilterThen)
	// is available.
	if err := validateFilterRoutingInstanceConflictStrict(cfg); err != nil {
		if opts.lenientFilterRoutingInstanceConflict {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter routing-instance conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #11321: a kernel PBR rule for FBF attached to a non-forwarding
	// routing-instance member is structurally unreachable: the l3mdev lookup
	// (pref 1000) and its miss terminator (pref 2000) precede the 29000-29999
	// PBR band, while the Rust helper would honor the override. Strict commit
	// rejects the divergence. Tolerant load / peer-sync keeps #1960 boot safety
	// but removes the override from the compiled filter, so both planes use the
	// native VRF table and the packet's firewall term remains terminal.
	if opts.lenientMemberFBFKernelBand {
		if warnings := suppressMemberFBFKernelBand11321(cfg); len(warnings) != 0 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("FBF override on routing-instance member skipped on tolerant path (#11321): %s", warnings[0]))
		}
	} else if err := validateMemberFBFKernelBandStrict(cfg); err != nil {
		return err
	}

	// #4375 (avo-review-007 H3) firewall-filter conflicting-terminal-actions gate.
	// Strict on commit / commit-check (hard-reject a term that specifies more than
	// one DISTINCT terminating action — accept/reject/discard are mutually
	// exclusive in Junos). Before this gate compileFilterThen wrote each keyword
	// onto the single-valued term.Action (last-write-wins), so a term with `then
	// accept` AND `then reject` silently compiled to whichever came last — the
	// operator's intent was ambiguous. Lenient on load / peer-sync it warns
	// instead of rejecting so persisted config still boots (#1960 no-brick),
	// but conflict poison keeps discard as a conservative internal action.
	// Snapshot builders see TerminalActions and set FromUnrepresentable, so
	// userspace and lo0 refuse the whole candidate and retain previous-good
	// state instead of installing either an accidental accept or a fresh drop.
	// Runs on the fully-compiled *Config so the typed term list
	// (TerminalActions populated by compileFilterThen) is available.
	if err := validateFilterTerminalConflictStrict(cfg); err != nil {
		if opts.lenientFilterTerminalConflict {
			failClosedFilterTerminalConflicts(cfg)
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter terminal-action conflict (downgraded to warning on tolerant path; conflicting terms are marked unrepresentable and not installed): %v", err))
		} else {
			return err
		}
	}

	// #9882 policer `then` unknown-action gate. A policer whose `then` carries
	// a token that is none of the recognized actions kept the "discard"
	// default while the token vanished silently — a typo that committed clean
	// on every path including strict and over-dropped with zero diagnostic.
	// Reads the DEFERRED channel (UnknownActions) populated by compileFirewall,
	// the policer path's analog of the #2399 filter-term gate (which likewise
	// runs before its terminal-conflict sibling). Runs BEFORE the #8445
	// terminal-vs-marking gate below: an unknown token means the intent cannot
	// be fully characterized, so it is reported first.
	if err := validateFirewallPolicerUnknownActionsStrict(cfg); err != nil {
		if opts.lenientPolicerUnknownActions {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall policer unknown then-action (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #8445 policer `then` terminal-vs-marking gate. A policer whose `then`
	// carries both `discard` and a marking action keeps only the last, and with
	// `discard` written first the compiled policer meters and drops NOTHING —
	// an authored rate limit that commits clean and is entirely unenforced.
	// Reads the AUTHORED action set (ThenActions) rather than the last-wins
	// survivor, which is the only place the conflict is visible.
	if err := validateFirewallPolicerThenConflictStrict(cfg); err != nil {
		if opts.lenientPolicerThenConflict {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall policer then-action conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3309 firewall-filter DSCP / traffic-class range gate. Strict on commit /
	// commit-check (hard-reject a `from dscp`/`from traffic-class` match or a
	// `then dscp`/`then traffic-class` rewrite token that is neither a known
	// code-point name nor an integer 0..63). Before this gate such a token was
	// appended raw and SILENTLY DROPPED by the snapshot builder
	// (pkg/dataplane/userspace/filters.go) — a dropped match value left the term
	// matching ALL DSCPs (a policy widening) and a dropped rewrite no-opped.
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the snapshot builder drops the bad
	// token independently). Runs on the fully-compiled *Config so the typed term
	// list (DSCPs + DSCPRewrite populated by compileFilterFrom/compileFilterThen)
	// is available.
	if err := validateFilterDSCPStrict(cfg); err != nil {
		if opts.lenientFilterDSCP {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter dscp (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
