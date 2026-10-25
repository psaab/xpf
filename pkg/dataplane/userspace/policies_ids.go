package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// Runtime policy-ID namespace and stable rule identities.
// Split from policies.go (#4421) with no logic change.

// RuntimePolicyIDs returns the span-accumulated runtime/RT_FLOW policy ID for
// every configured policy, keyed by [policySetID, sliceIndex] where policySetID
// is the zone-pair set index (global policies occupy set len(Policies)) and
// sliceIndex is the raw position within that set's policy slice — exactly the
// (policySetID, i) loop variables the read-only show surfaces already track.
//
// The IDs are computed by walkPolicyRuleSlots, the same SSOT that assigns
// PolicyRuleSnapshot.PolicyID on the dataplane write side, so a display surface
// keying off this lookup prints the identical numeric ID the RT_FLOW/event path
// logs (#3063). Before this, the CLI policy-detail Index used the raw ordinal
// policySetID*MaxRulesPerPolicy + i, which does NOT advance by application-set
// expansion, so the displayed Index drifted from the logged policy ID after a
// multi-application policy and an operator cross-referencing a policy-deny log
// landed on the wrong row.
//
// Returned IDs are display identity only; they are NOT the counter handle. The
// per-policy counter store is name-keyed and ReadPolicyCounters takes the
// PolicyCounterID handle that round-trips through policyRuleIDForCounter —
// callers MUST keep passing that handle to ReadPolicyCounters. On a config
// that would overflow the total/set bounds the walk stops early and the
// partial map omits the offending entries; a caller falls back to the
// PolicyCounterID handle for any missing key (such a config cannot be
// applied anyway, so the dataplane never enforces it).
func RuntimePolicyIDs(cfg *config.Config) map[[2]uint32]uint32 {
	out := make(map[[2]uint32]uint32)
	_ = walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		out[[2]uint32{slot.PolicySetID, slot.SliceIndex}] = slot.policyID()
		return nil
	})
	return out
}

// PolicyIDsByStableKey maps every configured policy's STABLE string identity
// (StablePolicyRuleID: "<from>-><to>/<name>", global policies keyed with
// from==to=="junos-global") to the numeric runtime policy ID the dataplane
// stamps on each admitted session's policy_id (#3056). It is the same
// span-accumulated base ID walkPolicyRuleSlots writes to
// PolicyRuleSnapshot.PolicyID, so the value round-trips to what a live session
// carries.
//
// Unlike RuntimePolicyIDs — keyed by the POSITIONAL [policySetID, sliceIndex] —
// the key here is invariant to a sibling policy's deletion: removing policy B
// does not shift policy A's key, only (possibly) its numeric ID. A caller can
// therefore diff two configs by key and recover, from the OLD config, the
// numeric IDs of policies present before but absent after — the exact IDs the
// deleted policies' still-live sessions carry. The commit-time deletion-clear
// (#4234) uses this to invalidate those sessions.
//
// The numeric IDs are unique per policy within a single config (the userspace
// preflight rejects a duplicate policy_id, policy.rs DuplicatePolicyId), so the
// returned values collide only across the DIFFERENT configs a caller diffs —
// which is exactly the intended semantics (a deleted policy's OLD ID identifies
// its OLD sessions, independent of any NEW policy that inherits that slot).
//
// A config that would overflow the total/set bounds stops the walk early (as in
// RuntimePolicyIDs); such a config is rejected at apply and never enforced, so a
// partial map is harmless.
func PolicyIDsByStableKey(cfg *config.Config) map[string]uint32 {
	out := make(map[string]uint32)
	_ = walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		out[stablePolicyRuleID(slot.FromZone, slot.ToZone, slot.Policy.Name)] = slot.policyID()
		return nil
	})
	return out
}

// PoliciesByStableKey maps the same stable policy key PolicyIDsByStableKey uses
// (StablePolicyRuleID: "<from>-><to>/<name>", globals keyed junos-global) to the
// compiled *config.Policy behind it. It exists so a caller can diff two configs
// by key and, for a policy present in BOTH, compare its match/action to detect a
// MODIFICATION — the commit-time modified-policy re-evaluation (#4234
// policy-rematch) uses this alongside PolicyIDsByStableKey (which supplies the
// OLD numeric ID that a modified policy's still-live sessions carry). A policy
// expanded into multiple rule slots (application-set expansion) maps its key to
// the same *config.Policy on every slot, so last-write-wins stores the one
// policy object — exactly what a match/action comparison needs.
func PoliciesByStableKey(cfg *config.Config) map[string]*config.Policy {
	out := make(map[string]*config.Policy)
	_ = walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		out[stablePolicyRuleID(slot.FromZone, slot.ToZone, slot.Policy.Name)] = slot.Policy
		return nil
	})
	return out
}

func stablePolicyRuleID(fromZone, toZone, ruleName string) string {
	return StablePolicyRuleID(fromZone, toZone, ruleName)
}

// StablePolicyRuleID returns the stable string rule identity
// ("<from>-><to>/<name>") carried as PolicyRuleSnapshot.RuleID and joined to
// runtime events. It is exported so the read-only inventory surfaces (REST
// GetPolicies, gRPC GetPolicies) can emit the identical rule_id the snapshot /
// event path uses, without re-deriving the format and risking drift (#3336).
// Global policies pass fromZone == toZone == "junos-global", matching the
// snapshot builder.
func StablePolicyRuleID(fromZone, toZone, ruleName string) string {
	return fmt.Sprintf("%s->%s/%s", fromZone, toZone, ruleName)
}

// RuntimePolicyIndex returns the contiguous runtime/RT_FLOW policy ID for
// the policy at (policySetID, sliceIndex) from a RuntimePolicyIDs map, falling
// back to the PolicyCounterID handle when the map has no entry (a config the
// dataplane would reject for exceeding the total/set bounds). This is the
// DISPLAY identity an inventory surface should report as policy_id so it
// matches the numeric ID the RT_FLOW/event path logs; it is NOT the counter
// handle passed to ReadPolicyCounters (callers keep passing PolicyCounterID).
// Exported for the REST/gRPC inventory surfaces (#3336), the gRPC text detail
// renderer, and the local CLI detail renderer (which now delegates here) so
// the Index column cannot drift across surfaces (#3667).
func RuntimePolicyIndex(ids map[[2]uint32]uint32, policySetID, sliceIndex uint32) uint32 {
	if id, ok := ids[[2]uint32{policySetID, sliceIndex}]; ok {
		return id
	}
	return PolicyCounterID(policySetID, sliceIndex)
}

func userspacePolicyRuleExpansionCount(cfg *config.Config, apps []string) uint32 {
	if len(apps) == 0 {
		return 1
	}
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return 1
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return 1
		}
		for _, name := range resolved {
			seen[name] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return 1
	}
	return uint32(len(seen))
}
