package userspace

import "github.com/psaab/xpf/pkg/config"

// Scheduler-activation predicates shared by the snapshot builder and the
// read-only show surfaces.
// Split from policies.go (#4421) with no logic change.

func policyRuleInactive(schedulerName string, activeState map[string]bool) bool {
	if schedulerName == "" {
		return false
	}
	if activeState == nil {
		return true
	}
	active, ok := activeState[schedulerName]
	return !ok || !active
}

// policyRuleInactiveForAction applies the scheduler's fail-closed latch to
// the policy action: deny/reject rules remain eligible while freshness is
// latched unknown, but ordinary inactive and unavailable states stay inactive.
func policyRuleInactiveForAction(
	schedulerName string,
	action config.PolicyAction,
	activeState map[string]bool,
	failClosed bool,
) bool {
	if failClosed && schedulerName != "" {
		if active, ok := activeState[schedulerName]; ok && !active &&
			(action == config.PolicyDeny || action == config.PolicyReject) {
			return false
		}
	}
	return policyRuleInactive(schedulerName, activeState)
}

// PolicyInactive reports whether a policy bound to schedulerName is
// currently runtime-inactive given the daemon-maintained per-scheduler
// active-state map (see Manager.PolicySchedulerActiveState). It is the
// SSOT predicate shared between the snapshot builder (policyRuleInactive)
// and the read-only show surfaces (#3062 CLI/gRPC policy detail), so the
// display planes report exactly what the dataplane enforces rather than
// recomputing wall-clock schedule windows. An empty schedulerName is
// always active; a nil map (scheduler state not yet published) treats a
// scheduled policy as inactive, matching the builder's fail-closed
// behaviour — the dataplane drops such a rule until state arrives.
func PolicyInactive(schedulerName string, activeState map[string]bool) bool {
	return policyRuleInactive(schedulerName, activeState)
}

// PolicyInactiveFn returns a per-policy scheduler-inactivity predicate bound to
// a fixed live active-state snapshot, suitable for use as
// policymatch.Query.PolicyInactiveFn (#3104). It wraps the SSOT PolicyInactive
// predicate so the operator-side policy simulator skips exactly the rules the
// dataplane drops (and the #3062 display reports inactive). The snapshot is
// captured by value at call time; pass the result of
// Manager.PolicySchedulerActiveState.
//
// The returned predicate is fail-closed for the unavailable-state case (#3414):
// a nil activeState (scheduler state not yet published / accessor not wired)
// marks every scheduler-bound policy inactive, matching the snapshot builder
// (policyRuleInactive: nil map => dropped). Live diagnostic surfaces
// (REST/gRPC/CLI match-policies) therefore bind this predicate ALWAYS — even
// when they cannot obtain live state — so the simulator never certifies a
// scheduled policy as active while the dataplane is skipping it. Only a purely
// offline, dataplane-less config simulator (no runtime to agree with) should
// leave Query.PolicyInactiveFn nil to stay scheduler-unaware.
func PolicyInactiveFn(activeState map[string]bool) func(schedulerName string) bool {
	return func(schedulerName string) bool {
		return policyRuleInactive(schedulerName, activeState)
	}
}
