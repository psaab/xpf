package config

import "fmt"

// runUniformGatesSamplingAppSet runs the sampling appset sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesSamplingAppSet(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2461: per-flow-server NetFlow v9 / IPFIX template cross-reference. A
	// flow-server `version9 { template <name> }` / `version-ipfix { template
	// <name> }` (or the flat `version9-template` / `version-ipfix-template`)
	// naming a template not defined under `services flow-monitoring`
	// compiled cleanly; the live exporter ignored the reference and used the
	// first map-iteration template, so the collector silently received a
	// template (timeouts / export-extensions) it never requested and the
	// choice flipped across restarts. Strict on commit / commit-check (hard
	// reject so the typo is operator-visible); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots —
	// #1960; the resolver drops a group with an undefined template, exporting
	// nothing for that collector rather than the wrong template). Mirrors
	// validateLogProfileStreamReferencesStrict.
	if err := validateFlowServerTemplateReferencesStrict(cfg); err != nil {
		if opts.lenientFlowServerTemplateRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("flow-server template reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2462: multi-sampling-instance conflict. Two `forwarding-options
	// sampling instance` blocks that each export the same (export-version,
	// address-family) pair are genuinely ambiguous — there is no per-interface
	// sampling-instance selector, so the runtime cannot attribute a flow of
	// that family to one instance — and were previously silently flattened
	// into one global policy (first-nonzero map-order rate, merged collectors;
	// flows crossing from one instance's policy to another's collectors).
	// Strict on commit / commit-check (hard reject so the operator sees it);
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960; the resolver emits both instances'
	// independent ExportConfigs, duplicating eligible flows rather than
	// bricking). Mirrors validateFlowServerTemplateReferencesStrict.
	if err := validateSamplingInstanceConflictsStrict(cfg); err != nil {
		if opts.lenientSamplingInstanceConflicts {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("sampling instance conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5244: sampling instance input-rate lower bound (compiler-side defense-
	// in-depth). A negative `forwarding-options sampling instance <name> input
	// rate` is a fail-open — the exporter's `SamplingRate > 1` gate is false
	// for a negative value (every eligible flow exports, the ratio is ignored)
	// and the retired eBPF cast wrapped it into a huge divisor. At strict
	// operator commit this is already hard-rejected by the #1979 SchemaValidate
	// typed-leaf gate (ValidateInteger(0, maxWireU32)), which runs before the
	// compiler; `compileSampling` itself, however, stored the value unchecked,
	// unlike the sibling `compilePortMirroring`, which carries its own inline
	// guard. This gate closes that asymmetry so a negative rate reaching the
	// compiler without the typed-leaf gate (tolerant load / peer-sync, direct
	// CompileConfig callers, future refactors) is still caught. Strict on
	// commit / commit-check; lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960; the userspace
	// snapshot builder clamps rate <= 0 -> 1, so the running dataplane is
	// safe). `0` stays valid (sample every packet). Mirrors
	// validateSamplingInstanceConflictsStrict.
	// #6769: flow-export template `seconds` knobs are stored by the compiler
	// with a bare strconv.Atoi and no range check, and the consumer converts
	// with `time.Duration(n) * time.Second`, which OVERFLOWS int64 for a large
	// enough value and can wrap to a sub-second interval — a template-export
	// flood at every collector. Strict on commit / commit-check; lenient on
	// load / peer-sync (warn — #1960; `flowexport.secondsToDuration` falls back
	// to the default independently, so the running exporter is safe either way
	// and this gate is about the operator being TOLD rather than silently
	// getting the default).
	if err := validateFlowExportSecondsStrict(cfg); err != nil {
		if opts.lenientFlowExportSeconds {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("flow-export template seconds (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	if err := validateSamplingInputRateStrict(cfg); err != nil {
		if opts.lenientSamplingInputRate {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("sampling instance input rate (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2217 Finding B: application-set member cross-reference. An
	// `applications application-set <set>` member referencing neither a defined
	// application (user / junos-* predefined) nor a defined nested
	// application-set compiled cleanly; a policy matching the set silently
	// failed to match the intended traffic (the unresolved member never
	// matches — an effective no-op term, fail-open). Strict on commit /
	// commit-check; lenient on load / peer-sync (warn — #1960; the dataplane
	// drops the unresolved member independently, so it is already inert).
	// Reuses ExpandApplicationSet, the same resolver the compiler already uses,
	// so no new definedness table is introduced. Mirrors
	// validateApplicationSpecsStrict.
	if err := validateApplicationSetMembersStrict(cfg); err != nil {
		if opts.lenientApplicationSetMembers {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application-set member (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3144 security-policy match-application definedness gate. A policy
	// `match application <name>` token resolving to no predefined junos-*
	// application, no user-defined application, and no application-set was
	// previously only WARNED at commit — yet the userspace capability gate
	// (resolveUserspaceApplicationNames) resolves the SAME name set and returns
	// false for an unknown name, so the dataplane REFUSES to arm security
	// policies. The operator gets a green commit and a silently DISARMED policy
	// engine on the firewall's allow/deny path (a commit/apply split,
	// fail-open). Strict on commit / commit-check (hard reject naming the
	// policy scope, the policy, and the undefined app); lenient on load /
	// peer-sync (warn — #1960; the dataplane independently refuses the policy,
	// so a leniently-loaded bad config is no worse off, now flagged). Resolves
	// via ResolveApplication / ResolveApplicationSet — the EXACT name set the
	// runtime gate uses — so commit and runtime cannot diverge. Covers
	// zone-pair + global policies and the multi-value application list. Runs
	// AFTER the application-set member gate (#2217) so a dangling member of a
	// DEFINED set still wins the first-error slot; this gate catches a wholly
	// undefined top-level reference that #2217's ExpandApplicationSet never
	// sees.
	if err := validatePolicyMatchApplicationsStrict(cfg); err != nil {
		if opts.lenientPolicyMatchApplications {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match application (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3434 (Codex audit 095 H07/H08): source/destination-NAT match-application
	// definedness gate, the NAT analog of validatePolicyMatchApplicationsStrict
	// (#3144/#3146). A NAT `match application <name>` resolving to no
	// predefined/user application and no non-empty application-set previously
	// committed cleanly — yet the DNAT snapshot builder then fell through to a
	// wildcard match-all term and published the pool VIP for every flow to the
	// destination (fail-open). Strict on commit / commit-check (hard reject
	// naming the NAT kind, rule-set, rule, and the undefined app); lenient on
	// load / peer-sync (warn — #1960; the dataplane now fails such a rule closed
	// via a never-match term, so a leniently-loaded bad config is no worse off,
	// now flagged). Resolves via ResolveApplication / ResolveApplicationSet —
	// the EXACT name set the SNAT/DNAT snapshot builders use — so commit and
	// runtime cannot diverge. Covers source and destination NAT rule-sets
	// (static NAT carries no application match).
	if err := validateNATMatchApplicationsStrict(cfg); err != nil {
		if opts.lenientNATMatchApplications {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("NAT match application (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3149 (folds #3147): policy match address-set member / empty-set
	// fail-open gate. A security-policy source/destination address naming a
	// DEFINED address-book entry whose members dangle, or a defined-but-empty
	// address-set / prefix-less address, was only WARNED at commit
	// (compiler_validate_warn.go) — yet the runtime address resolver returns
	// false for the same name and the userspace gate then REFUSES to arm
	// security policies, silently disarming the allow/deny path (commit/apply
	// split, fail-open; address-book sibling of #3144/#3146). Strict on commit /
	// commit-check (hard reject); lenient on load / peer-sync (warn — #1960; the
	// dataplane independently refuses such a policy, so a leniently-loaded bad
	// config is no worse off, now flagged). Runs AFTER the #2008 token gate
	// (which catches a wholly-undefined token) so a defined-name resolution
	// failure is this gate's first-error.
	if err := validatePolicyMatchAddressSetMembersStrict(cfg); err != nil {
		if opts.lenientPolicyMatchAddressSetMembers {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match address-set members (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #9490: an address-set member that names nothing, checked for every set
	// and not only sets a policy references. It runs AFTER the policy-side
	// gate, so a dangling member of a set a policy uses keeps that gate's
	// message, which names the policy (#3149); this one catches the rest. Strict on commit / commit-check;
	// warn on load / peer-sync (#1960).
	if err := validateAddressSetMembersDefinedStrict(cfg); err != nil {
		if opts.lenientAddressSetMembersDefined {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("address-set members (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
