package config

import "fmt"

// validateDuplicatePolicySchedulerName14449 hard-rejects a security
// policy that carries two DIFFERENT `scheduler-name` values (#14449).
//
// Before this gate compilePolicy read only the FIRST `scheduler-name`
// sibling (FindChild), so `scheduler-name wide; scheduler-name narrow;`
// silently installed `wide` (00:00-23:59) although the operator's
// last-authored value selected `narrow` (09:00-17:00): the policy then
// enforced outside its intended time window — a fail-open enforcement
// loss, since the runtime evaluator gates the policy on the installed
// scheduler (pkg/dataplane/userspace/policies_lower.go). The reverse
// ordering was fail-closed, but the defect is that the strict path
// committed EITHER ordering silently; no gate counted `scheduler-name`
// occurrences, and the reference-existence gate
// (validatePolicySchedulerReferencesStrict) checked only the compiled
// (first) name, which resolves vacuously because scheduler definitions
// themselves merge (#5825) so both names exist.
//
// The compiler now collects every `scheduler-name` value in author
// order on Policy.schedulerNames and installs the LAST one, so this
// typed gate — mirroring validatePolicyTerminalActionStrict (#3043) —
// rejects any policy whose collected values are not all identical.
// Identical repeats stay legal, like identical terminal actions
// (#3850). Scheduler DEFINITIONS are untouched: both schedulers keep
// existing and merging (#5825); only the duplicate binding is rejected.
//
// Strict on commit / commit-check (CompileConfig — hard-reject naming
// the policy, both scheduler names); downgraded to a cfg.Warnings entry
// on tolerant load / peer-sync paths (flag lenientDuplicatePolicySchedulerName14449)
// so an already-persisted or peer-synced config still BOOTS (#1960
// no-brick). On that tolerant path the compiled name is the last-wins
// value, and when the policy would PERMIT under a scheduler other than
// the first-authored one the selected window may be wider than the
// first value intended, so the caller in runUniformGatesPolicy also
// marks such a permit policy LenientContentDropped: the userspace
// snapshot builder poisons it with the __unsupported__ sentinel and the
// Rust integrity preflight refuses the whole snapshot (previous-good
// retained; fresh-boot default-deny) rather than enforcing a window the
// operator may not have intended. Deny/reject policies keep the
// last-wins name unpoisoned: refusing a deny would itself fail open.
// Iteration order (cfg.Security.Policies, then GlobalPolicies) is
// deterministic, so the first-reported error is stable.
func validateDuplicatePolicySchedulerName14449(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil || len(pol.schedulerNames) < 2 {
			return nil
		}
		first := pol.schedulerNames[0]
		for _, name := range pol.schedulerNames[1:] {
			if name != first {
				return fmt.Errorf(
					"security policies %s policy %q: conflicting duplicate `scheduler-name` values %q and %q; a policy must name exactly one scheduler (the enforced time window would otherwise depend on parse order) (#14449)",
					scope, pol.Name, first, name)
			}
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// hasConflictingDuplicateSchedulerName14449 reports whether a policy
// carries two differing `scheduler-name` values (the strict gate's
// conflict predicate, without allocating an error). Used on the
// tolerant path to decide which permit policies to poison.
func hasConflictingDuplicateSchedulerName14449(pol *Policy) bool {
	if pol == nil || len(pol.schedulerNames) < 2 {
		return false
	}
	first := pol.schedulerNames[0]
	for _, name := range pol.schedulerNames[1:] {
		if name != first {
			return true
		}
	}
	return false
}

// poisonConflictingSchedulerPermits14449 marks, on the tolerant path, a
// PERMIT policy whose conflicting duplicate `scheduler-name` values make
// the last-wins window potentially wider than the first-authored value
// intended. The snapshot refusal is action-agnostic fail-closed (see
// Policy.LenientContentDropped); deny/reject policies are deliberately
// left unpoisoned because refusing a deny would fail open.
func poisonConflictingSchedulerPermits14449(cfg *Config) {
	if cfg == nil {
		return
	}
	mark := func(pol *Policy) {
		if pol == nil || pol.Action != PolicyPermit {
			return
		}
		if hasConflictingDuplicateSchedulerName14449(pol) {
			pol.LenientContentDropped = true
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			mark(pol)
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		mark(pol)
	}
}
