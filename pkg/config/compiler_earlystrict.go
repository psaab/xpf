package config

import (
	"errors"
	"fmt"
)

// runEarlyStrictAndFolds runs the P6a "early-strict + folds" phase of config
// compilation — the entangled block extracted from compileExpanded as step 6
// (the final step) of the #4406 god-orchestrator decomposition (ps-review-011
// / codex-173 #4).
//
// Unlike the pure-mutation P5 (resolveDerivedConfig) and the uniform fail-open
// P6b (runUniformGates), this phase INTERLEAVES validation with two mutations
// whose output is consumed non-locally in P6b. The plan (#4406) flags it RISKY,
// so its internal ORDER and the errors.Join accumulator semantics are load-
// bearing and a VERBATIM lift of the master block:
//
//  1. validateDataplaneTypeStrict — fail-fast (no lenient downgrade). #1526:
//     placed FIRST so a retired dataplane-type wins the first-error slot over
//     any unrelated structural error; the migration message is the documented
//     path. Pinned by TestDataplaneTypeDPDKRejectedAtCommitFiresFirst.
//  2. validateAddressBookEntryNamesStrict on the PRISTINE global book (#3061 /
//     #4340) — MUST run before the zone-local fold injects the `/`-bearing
//     synthetic names. Strict on commit; downgraded to a warning on the
//     tolerant lenientAddressBookNames path (#1960 no-brick).
//     2b. validateAddressBookNameCollisionStrict on the PRISTINE books (#5676) —
//     rejects a same-name `address` + `address-set` in one book (global or
//     zone-local). Same pristine-book ordering constraint as (2): runs before
//     the fold so a global vs a different-zone name are not misreported as a
//     collision. Strict on commit; downgraded on lenientAddressBookNameCollision.
//  3. resolveZoneLocalAddressBooks (MUT cfg.Security) — folds zone-local books
//     into the global book under zone-qualified internal names. Output consumed
//     non-locally by the P6b policy match-address validators.
//  4. resolveStaticNATThenPrefixNames (MUT cfg.Security) — resolves
//     `then static-nat prefix-name` targets now that the global book is folded.
//     Output consumed non-locally by validateStaticNATThenTargetStrict (P6b,
//     invariant #5) — the mutation persists across the helper boundary because
//     cfg is threaded by pointer and this phase runs BEFORE runUniformGates.
//  5. The #1538 independent strict-validator accumulator: five families each
//     append to strictErrs (fully CONTAINED here — NOT threaded into P6b), then
//     errors.Join surfaces one error per family in a single `commit check`
//     response.
//
// Behavior-preserving invariants (do NOT reorder relative to master): runs
// AFTER the P5 resolveDerivedConfig derivations and BEFORE the P6b uniform
// gates, so the strict first-error slot (invariant #6) and the tolerant-path
// warning accumulation ORDER (invariant #7) are unchanged. It mutates the
// shared *Config in place (the folds + the lenient warning append) and returns
// the FIRST fail-fast error or the joined accumulator error. Covered by the
// reusable golden-output gate in compile_golden_4406_test.go.
func runEarlyStrictAndFolds(cfg *Config, opts compileOpts) error {
	// #1526 — reject retired dataplane backends at commit time.
	// Placed BEFORE the other strict validators so that an operator
	// editing a candidate that has BOTH a retired dataplane-type and
	// an unrelated structural error (CoS, policers, scheduler-map)
	// sees the migration message first. The retirement is the
	// documented migration path; the other errors only become
	// actionable after migration. This precheck stays fail-fast
	// (the no-leak contract is pinned by
	// TestDataplaneTypeDPDKRejectedAtCommitFiresFirst in
	// parser_ast_test.go).
	//
	// Store.Load and Store.SyncApply tolerate retired-backend
	// configs via rewriteRetiredDataplaneType which strips the
	// retired leaf from the AST before compile (#1373 ebpf +
	// #1525 dpdk handle both this way). See
	// pkg/configstore/dataplane_retire.go.
	if err := validateDataplaneTypeStrict(cfg); err != nil {
		return err
	}

	// #3061 (narrowed in #4340) — enforce the two naming invariants that keep
	// the synthetic zone-local/<zone>/<name> internal names minted by
	// resolveZoneLocalAddressBooks collision-proof, BEFORE folding zone-local
	// books: an operator address-book entry name may not begin with the reserved
	// `zone-local/` prefix, and a security-zone name may not contain `/`. A `/`
	// elsewhere in an entry name (net_10.0.0.0/8) is permitted — the
	// prefix-in-name convention real vSRX configs use (#4340). This MUST run on
	// the pristine global book — i.e. before the fold injects the `/`-bearing
	// synthetic names — so it is placed here rather than in the post-fold
	// accumulator. Strict on commit / commit-check (hard-reject); tolerant load /
	// peer-sync downgrade to a warning (#1960 no-brick; the fold's no-clobber
	// guard keeps it from silently overwriting an operator entry).
	if err := validateAddressBookEntryNamesStrict(cfg); err != nil {
		if opts.lenientAddressBookNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("address-book/zone name (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #9523 — reject an address-book address / address-set (global or
	// zone-local) or a dynamic-address address-name named after a policy
	// match-all keyword. On the pristine books, for the same reason as the gate
	// above: a zone-local object must be reported under its authored name.
	// Strict on commit / commit-check; tolerant load / peer-sync keep the object
	// with a warning (#1960 no-brick), and the keyword keeps matching every
	// address because IsPolicyAddressWildcardKeyword is asked before any name
	// lookup.
	if err := validateReservedAddressNamesStrict(cfg); err != nil {
		if opts.lenientReservedAddressNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reserved address name (downgraded to warning on tolerant path; the keyword still matches every address): %v", err))
		} else {
			return err
		}
	}
	// #5676 — reject a same-name `address` + `address-set` collision within one
	// address book (global or zone-local). The two kinds share one operator-
	// visible namespace but land in separate maps, so a plain address silently
	// shadowed a same-named address-set at name→prefix resolution (address-first
	// everywhere), changing which traffic a permit/deny rule covers with no
	// diagnostic. MUST run here, on the PRISTINE books BEFORE the zone-local fold
	// mints synthetic zone-local/<zone>/<name> names — so a global `address foo`
	// and a different zone's zone-local `address-set foo` (distinct namespaces
	// post-fold) are not misreported as a collision, and a real zone-local
	// collision is named against the clean zone. Strict on commit / commit-check
	// (hard reject; Junos forbids the collision outright); tolerant load /
	// peer-sync downgrade to a warning (#1960 no-brick — the runtime keeps the
	// deterministic address-first winner it already used). Mirrors
	// validateAddressBookEntryNamesStrict.
	if err := validateAddressBookNameCollisionStrict(cfg); err != nil {
		if opts.lenientAddressBookNameCollision {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("address-book name collision (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #3061 — fold zone-local address books into the global book under
	// zone-qualified internal names and rewrite policy match tokens. Runs after
	// the name gate (above) and before the policy match-address resolution
	// validators (validatePolicyMatchAddressesStrict /
	// validatePolicyMatchAddressSetMembersStrict), which depend on the rewritten
	// tokens and synthetic global entries.
	resolveZoneLocalAddressBooks(&cfg.Security)

	// #4290 — resolve `then static-nat prefix-name <name>` translation targets
	// into their literal prefix now that the global address book is fully
	// folded (compileNAT can run before compileAddressBook within a `security {}`
	// root, so this cannot happen inline in the then switch). An unresolvable
	// reference leaves Then=="" and is rejected below by
	// validateStaticNATThenTargetStrict (warn on the tolerant path).
	resolveStaticNATThenPrefixNames(&cfg.Security)

	// #1538 — accumulate independent strict-validator families so
	// `commit check` surfaces one error per family in a single
	// response. This saves operator round-trips on first-touch
	// upgrades from legacy candidates that carry several dormant
	// structural findings at once. Validators in this group MUST
	// remain independent: each reads its own typed sub-struct of
	// *Config and does not depend on another's success. Each
	// validator still fail-fasts INTERNALLY (one error per family
	// in a single response), which is sufficient for the upgrade
	// UX win; full intra-validator accumulation is deliberately
	// out of scope. If a future validator depends on another's
	// success it must be added as a separate post-accumulator
	// step with its own guard rather than slotted in alongside
	// the independent set.
	var strictErrs []error
	if err := validateClassOfServiceStrict(cfg.ClassOfService); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateThreeColorPolicersStrict(cfg.Firewall.ThreeColorPolicers); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validatePolicySchedulerReferencesStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateRPMProbePinsStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateIPMonitoringStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	// #7121: a routing-policy `from protocol` token is rendered verbatim as
	// ` match source-protocol` and ONE FRR-rejected line degrades the whole
	// managed reload, so an unknown token cannot be left to the render side.
	if err := validateRoutingPolicyProtocolsStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	// #1830 (e): the #1733 equal-flow worker-cap validator
	// (validateEqualFlowWorkerCapStrict / MaxEqualFlowWorkers) is retired.
	// The v8 lease rotation now sizes its per-worker scratch from the true
	// worker count (heap scratch in rotate_epoch_v8.rs), so
	// equal-flow-enforcement no longer fail-opens above 32 workers and the
	// commit-time rejection has nothing left to guard.
	if err := errors.Join(strictErrs...); err != nil {
		return err
	}
	return nil
}
