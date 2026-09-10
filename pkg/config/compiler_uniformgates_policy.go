package config

import "fmt"

// runUniformGatesPolicy runs the policy sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesPolicy(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2008 policy match-address fail-open gate. Strict on commit /
	// commit-check (hard-reject a typo'd source/destination address
	// that would be silently dropped and — under `*-address-excluded`
	// inversion — fail open to match-all); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots).
	// Runs AFTER the strict accumulator + device-map so a structural
	// CoS/policer/device-map error still wins the first-error slot.
	if err := validatePolicyMatchAddressesStrict(cfg); err != nil {
		if opts.lenientPolicyMatchAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2401 security-policy zone-pair reference fail-open gate. Strict on
	// commit / commit-check (hard-reject a `from-zone`/`to-zone` policy
	// stanza naming an undefined security zone — such a rule was only warned,
	// then compiled and KEPT, but the dataplane never indexes it into the
	// zone-pair lookup so the pair falls through to the default action,
	// failing OPEN under a permit default); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config with a stale zone
	// reference still boots — #1960 no-brick). A leniently-loaded bad reference
	// is NOT inert. This comment used to say "the dataplane drops the unindexed
	// rule on its own"; that is historical. Since #3402 the helper's integrity
	// preflight refuses the WHOLE policy snapshot on an unresolvable zone
	// (previous-good retained, fresh-boot default-deny). One token was covered by
	// neither reading: a zone-pair stanza naming the reserved `junos-global`
	// sentinel was classified by the helper as a device-wide GLOBAL rule and
	// enforced for every zone pair (#9570). The snapshot builder now poisons such
	// a rule, so it fails closed the same way.
	// Exempts the `any` / `junos-host` / empty special tokens. Validates
	// zone-pair from/to zones AND (as of #3148) a global policy's optional
	// `match from-zone`/`match to-zone` context. Runs AFTER the policy match-address gate so a
	// structural CoS/policer/device-map error and a bad match-address still
	// win the first-error slot before a zone-reference error.
	// #9246: a bracketed zone list on from-zone/to-zone. Runs BEFORE the
	// undefined-zone gate, because the from-zone form otherwise surfaces there
	// as an undefined zone literally named "to-zone" -- loud, but blaming the
	// wrong thing, and telling the operator to define a zone rather than to fix
	// the bracket. Same lenient downgrade as its neighbour (#1960): an
	// already-persisted or peer-synced config an older binary accepted must
	// still boot, and on that path the operator is told rather than locked out.
	if len(cfg.Security.MalformedZonePairs) > 0 {
		err := fmt.Errorf("security policies %s", cfg.Security.MalformedZonePairs[0])
		if opts.lenientPolicyZoneRefs {
			for _, m := range cfg.Security.MalformedZonePairs {
				cfg.Warnings = append(cfg.Warnings,
					fmt.Sprintf("security policies %s (downgraded to warning on tolerant path)", m))
			}
		} else {
			return err
		}
	}

	if err := validatePolicyZoneReferencesStrict(cfg); err != nil {
		if opts.lenientPolicyZoneRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy zone reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3090: the from-zone/to-zone `any` wildcard is now properly indexed and
	// enforced by the userspace dataplane (PolicyState's from-any / to-any /
	// both-any tiers, evaluated in Junos most-specific-first precedence before
	// global/default — userspace-dp/src/policy.rs). The #3018 interim commit
	// reject (validatePolicyWildcardZoneStrict) is therefore lifted: a
	// from-zone/to-zone `any` policy commits AND is enforced. The undefined-zone
	// gate (validatePolicyZoneReferencesStrict) still exempts `any` via
	// policyZoneSpecialTokens, so the wildcard is accepted without being mistaken
	// for an undefined zone, and a `security zone` named `any` is still rejected
	// by validateReservedZoneNamesStrict.

	// #3043 security-policy terminal-action fail-open gate. Strict on commit /
	// commit-check (hard-reject a policy that does not name exactly one of
	// permit/deny/reject — a log-only/count-only or typo'd policy compiled to
	// the PolicyPermit zero value and silently PERMITTED all matching traffic,
	// and multiple terminal actions resolved last-wins by parse order);
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; compilePolicy defaults an actionless
	// policy to DENY, so a leniently-loaded bad config fails closed rather than
	// open). Runs AFTER the policy zone-reference gate so a structural error, a
	// bad match-address, and a bad zone reference still win the first-error slot.
	if err := validatePolicyTerminalActionStrict(cfg); err != nil {
		if opts.lenientPolicyTerminalAction {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy terminal action (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3060 security-policy `then log` accepted-but-inert gate. Strict on commit
	// / commit-check (hard-reject a policy whose `then log` names neither
	// session-init nor session-close — a bare `then log` compiles to a non-nil
	// PolicyLog with both flags false, so the policy REPORTS logging enabled
	// over REST/gRPC/CLI yet emits NO session records; Junos requires at least
	// one of session-init/session-close). Lenient on load / peer-sync (warn so
	// an already-persisted or peer-synced config still boots — #1960 no-brick; a
	// leniently-loaded bare-log policy simply logs nothing, the pre-existing
	// behavior). Covers both per-zone-pair and global policies. Runs after the
	// terminal-action gate so a missing/conflicting terminal action still wins
	// the first-error slot.
	if err := validatePolicyLogActionStrict(cfg); err != nil {
		if opts.lenientPolicyLogAction {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy log action (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3473 duplicate-policy-name gate. Strict on commit / commit-check
	// (hard-reject two security policies that share a name within the same
	// from/to-zone zone-pair, or within the global rulebase — Junos requires
	// unique policy names within a context). xpf accepted duplicates silently;
	// the name-keyed userspace hit counter then coalesces the duplicates onto one
	// counter, so hit-count observability breaks (the two rules cannot be told
	// apart) and removing one duplicate transfers its accumulated hits to the
	// survivor. Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; first-match enforcement is
	// still correct, only the shared-counter observability bug remains). The
	// validator reads the already-aggregated typed Policies/GlobalPolicies slices,
	// so a duplicate split across two `security {}` blocks is still caught
	// (compileSecurity runs for every `security` root). Runs after the policy
	// log-action gate so an earlier policy-structural error still wins the
	// first-error slot.
	if err := validateDuplicatePolicyNamesStrict(cfg); err != nil {
		if opts.lenientDuplicatePolicyNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("duplicate policy name (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
