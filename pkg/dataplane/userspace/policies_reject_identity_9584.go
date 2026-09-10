package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9584: the RULE-IDENTITY arm of the fail-closed policy-content mirror.
//
// THE DEFECT. The userspace helper's integrity preflight refuses the WHOLE
// policy snapshot when two rules resolve to one stable identity
// (SnapshotIntegrityError::DuplicateRuleId, #3713) or share a non-zero
// positional policy_id (DuplicatePolicyId). PolicyContentRejectionReasons had
// no arm for either, so `show security match-policies` returned a first-match
// verdict for a snapshot the helper refuses, and the #3261 surfaces it feeds
// (LastSnapshotRejectReasons, the one-shot warning, the rejection gauge) stayed
// empty. On a running node the refusal keeps the previous config enforced; on a
// first apply it leaves transit dropped. Neither was visible from the Go side.
//
// WHY IT IS REACHABLE, since strict commit rejects a duplicate policy name
// (#3473). CompileConfigLenient only warns, and the #8752 fold merges repeated
// `policy <name>` children under ONE from-zone / global node. A duplicate
// written in separate stanzas — two `security {}` roots, two
// `from-zone a to-zone b` stanzas for one pair, two `policies` blocks, two
// `global` blocks — is never merged, so the builder emits two rules with the
// identical rule_id.
//
// MIRRORED AGAINST THE BUILT RULES, in the helper's order: for each rule, the
// identity check first, then the policy_id check (policy.rs
// parse_policy_state_with_counters). The helper stops at the first failure; the
// mirror reports each distinct duplicate once so the operator sees every
// offending name, and its first reason names what the helper's error names.

// stableRuleIdentity9584 mirrors userspace-dp policy.rs stable_policy_rule_id:
// the explicit wire rule_id when present, else "<from>-><to>/<name>".
func stableRuleIdentity9584(rule *PolicyRuleSnapshot) string {
	if rule.RuleID != "" {
		return rule.RuleID
	}
	return rule.FromZone + "->" + rule.ToZone + "/" + rule.Name
}

// collectPolicyIdentityRejections reproduces the helper's duplicate-identity
// preflight over the built rules.
//
// A policy_id of 0 is excluded exactly as the helper excludes it: it is both the
// valid first id and the omitempty value an older producer leaves on EVERY rule,
// so rejecting a repeated 0 would fail closed a legitimate older-peer snapshot.
// DefaultPolicySentinelID is excluded because no configured rule carries it.
func collectPolicyIdentityRejections(policies []PolicyRuleSnapshot) []string {
	seenIdentity := make(map[string]bool, len(policies))
	seenPolicyID := make(map[uint32]bool, len(policies))
	reportedIdentity := map[string]bool{}
	reportedPolicyID := map[uint32]bool{}
	var reasons []string
	for i := range policies {
		rule := &policies[i]
		identity := stableRuleIdentity9584(rule)
		if seenIdentity[identity] {
			if !reportedIdentity[identity] {
				reportedIdentity[identity] = true
				reasons = append(reasons, duplicateRuleIdentityReason9584(rule, identity))
			}
			continue
		}
		seenIdentity[identity] = true
		pid := rule.PolicyID
		if pid == 0 || pid == dataplane.DefaultPolicySentinelID {
			continue
		}
		if seenPolicyID[pid] {
			if !reportedPolicyID[pid] {
				reportedPolicyID[pid] = true
				reasons = append(reasons, duplicatePolicyIDReason9584(rule, pid))
			}
			continue
		}
		seenPolicyID[pid] = true
	}
	return reasons
}

func duplicateRuleIdentityReason9584(rule *PolicyRuleSnapshot, identity string) string {
	return fmt.Sprintf(
		"policy %s has the same rule identity %q as an earlier policy (a duplicate policy name in one "+
			"context, left unmerged on the tolerant load path): the userspace helper REJECTS THE WHOLE POLICY "+
			"SNAPSHOT (SnapshotIntegrityError::DuplicateRuleId), so none of this config's policies is enforced — "+
			"the previous good snapshot is retained, or a freshly booted helper serves default-deny; rename one "+
			"of the policies",
		policyRejectionScope(rule), identity)
}

func duplicatePolicyIDReason9584(rule *PolicyRuleSnapshot, policyID uint32) string {
	return fmt.Sprintf(
		"policy %s carries policy_id %d, already assigned to an earlier rule: the userspace helper REJECTS "+
			"THE WHOLE POLICY SNAPSHOT (SnapshotIntegrityError::DuplicatePolicyId), so none of this config's "+
			"policies is enforced — the previous good snapshot is retained, or a freshly booted helper serves "+
			"default-deny",
		policyRejectionScope(rule), policyID)
}
