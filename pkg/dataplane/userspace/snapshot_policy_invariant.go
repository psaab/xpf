package userspace

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// HARDENING (#15742 follow-up): the empty-policy snapshot class fails loudly
// at every layer. 670274c712 dropped `Policies: policies` from the full
// builder literal while Summary.PolicyCount still reported the compiled
// rule count, so the helper installed an empty policy set and
// default-denied all transit with no error anywhere. Three independent
// gates now catch the class:
//
//   - validateSnapshotPolicyInvariant (builder): the published policy
//     set must equal the effective POST-QUARANTINE set derived from the
//     compiled config (a fully-quarantined config legitimately expects
//     zero; non-quarantined rules vanishing still fails).
//   - the requestApplySnapshotPreparedLocked send-site gate (see
//     apply_snapshot_identity_9520.go): len(Policies) must agree with
//     BOTH the snapshot's self-declared Summary.PolicyCount AND the
//     manager's stamped expectation from the last full Compile — so
//     zeroing both transmitted fields (0 == 0) still refuses.
//   - the Rust helper (userspace-dp snapshot apply): a count mismatch,
//     or an empty policy install over a non-empty installed set,
//     increments snapshot_policy_mismatch_total and the whole apply is
//     refused, keeping prior policies.
//
// errSnapshotPolicyMismatch marks a snapshot send refused because its
// published policy set disagrees with its own Summary.PolicyCount. Like
// errRGProviderNotWired it provably never reached the helper, so it must
// never adopt retry-debt authority (isKnownUnsentFailure); callers surface
// it and the next consistent publish converges.
var errSnapshotPolicyMismatch = errors.New("userspace: snapshot policy count mismatch; refusing snapshot publish (#15742)")

// #16153 (W2.4 P2-narrowed): typed policy actions with the invariant
// check as the deliverable. Go gives no exhaustiveness, so instead of
// pretending a string-to-enum conversion is checked, the send-site gate
// validates every action token against the typed vocabulary below.
// The permit/deny/reject (security policy) and accept/discard/reject
// (firewall filter) vocabularies are deliberately NOT unified: they are
// distinct Junos surfaces with distinct Rust readers, and the reject
// token is shared spelling, not a shared meaning. The Rust enum is the
// enforcement backstop (parse_action in userspace-dp/src/policy.rs
// rejects unknown tokens fail-closed); it does not gate this Go check.

// policyAction is the typed form of a security-policy wire action
// (PolicyRuleSnapshot.Action and ConfigSnapshot.DefaultPolicy). The
// string values are the wire tokens; typedPolicyAction validates
// without changing them, so the wire stays byte-identical.
type policyAction string

const (
	policyActionPermit policyAction = "permit"
	policyActionDeny   policyAction = "deny"
	policyActionReject policyAction = "reject"
)

// valid reports whether the token is one of the known policy actions.
// The empty token is NOT valid for a rule action (every configured rule
// carries a concrete action; Rust rejects empty fail-closed, #3365).
// For DefaultPolicy the empty token is the legitimate omitempty wire
// state that decodes to deny in Rust — validateSnapshotForSend applies
// that exception explicitly rather than weakening this predicate.
func (a policyAction) valid() bool {
	switch a {
	case policyActionPermit, policyActionDeny, policyActionReject:
		return true
	}
	return false
}

// typedPolicyAction converts a wire token to its typed form, reporting
// false for any token outside the vocabulary (empty, malformed, or a
// future variant such as "reject-*"). Callers that admit a snapshot
// must fail closed on !ok rather than collapsing the token to deny:
// collapsing an unrecognized REJECT variant to deny loses the
// RST/ICMP-unreachable reply (fail-open in effect), which is exactly
// the Rust #3365 rationale mirrored at the Go send gate.
func typedPolicyAction(token string) (policyAction, bool) {
	a := policyAction(token)
	return a, a.valid()
}

// errSnapshotPolicyAction marks a snapshot send refused because a
// policy action token is outside the typed vocabulary. Like
// errSnapshotPolicyMismatch it provably never reached the helper (the
// gate runs before the control request), so isKnownUnsentFailure in
// process_control.go matches it and it never adopts retry-debt
// authority.
var errSnapshotPolicyAction = errors.New("userspace: snapshot policy action invalid; refusing snapshot publish (#16153)")

// firstPolicyZonePair renders the first published rule's zone pair for
// refusal logs, or the first compiled config zone pair when the snapshot
// carries no rules (the dropped-field case, where the zone pair is the
// only pointer to which rules vanished).
func firstPolicyZonePair(snap *ConfigSnapshot, cfg *config.Config) string {
	if snap != nil && len(snap.Policies) > 0 {
		return snap.Policies[0].FromZone + "->" + snap.Policies[0].ToZone
	}
	if cfg != nil {
		for _, zp := range cfg.Security.Policies {
			if zp != nil && len(zp.Policies) > 0 {
				return zp.FromZone + "->" + zp.ToZone
			}
		}
		if len(cfg.Security.GlobalPolicies) > 0 {
			return "global"
		}
	}
	return ""
}

// expectedPolicyCount returns the effective POST-QUARANTINE rule count
// a full build of cfg must publish: lower the compiled rules, scrub the
// ones zone quarantine removes (the exact scrub quarantineCollidingZones
// applies — policySnapshotAfterZoneQuarantine), and count the
// survivors. This is the correct ground truth for the builder gate: a
// config whose every rule is legitimately quarantined expects ZERO
// published policies (TestBuildSnapshotDropsDanglingGlobalMatchZone),
// while the 670274c712 dropped-field shape — non-quarantined rules
// vanishing between lowering and the literal — still disagrees.
func expectedPolicyCount(cfg *config.Config) (int, error) {
	if cfg == nil {
		return 0, nil
	}
	policies, err := buildPolicySnapshotsWithAddressBookAndFailClosed(cfg, nil, nil, nil, false)
	if err != nil {
		return 0, err
	}
	surviving, _ := policySnapshotAfterZoneQuarantine(cfg, policies)
	return len(surviving), nil
}

// validateSnapshotPolicyInvariant is the builder-layer gate. It runs on
// the post-quarantine snapshot and checks it against the post-quarantine
// ground truth (expectedPolicyCount), NOT the raw authored rule count:
// quarantine legitimately scrubs rules and resyncs Summary.PolicyCount,
// so a fully-scrubbed build is 0 == 0 == 0 and passes. A violation means
// the builder itself drifted between lowering and publication — the
// exact #15742 mechanism — so the build fails closed and the prior
// snapshot stays enforced.
func validateSnapshotPolicyInvariant(snap *ConfigSnapshot, cfg *config.Config) error {
	if snap == nil {
		return nil
	}
	expected, err := expectedPolicyCount(cfg)
	if err != nil {
		return fmt.Errorf("%w: cannot derive expected policy count: %v", errSnapshotPolicyMismatch, err)
	}
	if snap.Summary.PolicyCount != len(snap.Policies) || len(snap.Policies) != expected {
		slog.Error("userspace: refusing to publish snapshot: published policies disagree with the post-quarantine policy set",
			"expected_policy_count", expected,
			"policy_count", snap.Summary.PolicyCount,
			"policies_len", len(snap.Policies),
			"first_zone_pair", firstPolicyZonePair(snap, cfg),
			"generation", snap.Generation)
		return fmt.Errorf("%w: expected %d policies after quarantine but snapshot carries %d (summary policy_count=%d, first zone pair %s)",
			errSnapshotPolicyMismatch, expected, len(snap.Policies), snap.Summary.PolicyCount, firstPolicyZonePair(snap, cfg))
	}
	return nil
}

// commitExpectedPolicyCountFromLandedSnapshot records the policy count
// of a full build the HELPER HAS ACCEPTED, regardless of what the outer
// Compile call later returns (round-4): applyCompiledSnapshot advances
// m.lastSnapshot/publishedSnapshot at acceptance and can then fail its
// post-publish tail with PublishedSnapshotTailError — the snapshot IS
// enforced, so the stamp must follow it, or every later partial wedges
// against the stale count. Caller holds m.mu or documents otherwise.
func (m *Manager) commitExpectedPolicyCountFromLandedSnapshot(snap *ConfigSnapshot) {
	if snap == nil {
		return
	}
	m.expectedPolicyCount = len(snap.Policies)
}

// reconcileExpectedPolicyCountFromStatusLocked makes the stamp follow
// HELPER-PROVEN state in the status loop (round-4): when the helper
// reports an applied generation >= the retained generation, the policy
// count it reports for that landing IS the accepted count — including
// applies whose Compile returned a tail error and unknown-outcome
// retries that landed without Compile observing success. Caller holds
// m.mu (syncSnapshotLocked's context).
func (m *Manager) reconcileExpectedPolicyCountFromStatusLocked() {
	if m.lastSnapshot == nil || m.publishedSnapshot == 0 {
		return
	}
	if m.lastStatus.LastSnapshotGeneration >= m.lastSnapshot.Generation {
		m.expectedPolicyCount = int(m.lastStatus.LastSnapshotPolicyCount)
	}
}

// validateSnapshotForSend is the send-site gate, with the manager's
// stamped expectation as ground truth. Manager.Compile stamps
// expectedPolicyCount (post-quarantine) on every successful full build;
// partial publishers clone the retained snapshot and must preserve that
// expectation. A send whose len(Policies) disagrees with EITHER the
// snapshot's self-declared Summary.PolicyCount OR the stamped count is
// refused known-unsent — so zeroing BOTH transmitted fields (0 == 0)
// still refuses whenever the last full Compile expected policies.
// Before any stamp (expected < 0: no full Compile yet), only the
// self-consistency arm applies; the Rust helper's installed-set gate is
// the backstop there.
func (m *Manager) validateSnapshotForSend(snap *ConfigSnapshot) error {
	if snap == nil {
		return nil
	}
	// #16153 (P2): typed-action invariant. Every rule action must be a
	// known permit/deny/reject token, and a non-empty DefaultPolicy must
	// be one too (empty = the legitimate omitempty unspecified state
	// Rust decodes to deny). An unknown/empty rule action or a garbage
	// default is refused known-unsent BEFORE the count arms: the Go
	// lowerer (policyActionString) can only emit the three tokens, so a
	// violation here means a hand-built, corrupt, or version-drifted
	// snapshot — failing closed here keeps the prior enforced snapshot
	// live instead of shipping a token whose Rust reading the operator
	// never configured. This check does not collapse unknown tokens to
	// deny (see typedPolicyAction) and does not touch the firewall-
	// filter accept/discard vocabulary, which has its own reader.
	if _, ok := typedPolicyAction(snap.DefaultPolicy); snap.DefaultPolicy != "" && !ok {
		slog.Error("userspace: refusing snapshot send: default policy action is not a known token",
			"default_policy", snap.DefaultPolicy,
			"generation", snap.Generation)
		return fmt.Errorf("%w: default_policy %q is not a known policy action (generation %d)",
			errSnapshotPolicyAction, snap.DefaultPolicy, snap.Generation)
	}
	for i := range snap.Policies {
		if _, ok := typedPolicyAction(snap.Policies[i].Action); !ok {
			slog.Error("userspace: refusing snapshot send: policy rule action is not a known token",
				"rule", snap.Policies[i].Name,
				"action", snap.Policies[i].Action,
				"generation", snap.Generation)
			return fmt.Errorf("%w: policy rule %q action %q is not a known policy action (generation %d)",
				errSnapshotPolicyAction, snap.Policies[i].Name, snap.Policies[i].Action, snap.Generation)
		}
	}
	// #16056 (A6-06): the interface/zone twin of the policy arm below.
	// A dropped Interfaces/Zones section with the summary retained is
	// refused known-unsent here (and again by the helper), so a partial
	// publisher that zeroed a section never unbinds the dataplane.
	if snap.Summary.InterfaceCount != len(snap.Interfaces) || snap.Summary.ZoneCount != len(snap.Zones) {
		slog.Error("userspace: refusing snapshot send: summary section count does not match published sections",
			"interface_count", snap.Summary.InterfaceCount,
			"interfaces_len", len(snap.Interfaces),
			"zone_count", snap.Summary.ZoneCount,
			"zones_len", len(snap.Zones),
			"generation", snap.Generation)
		return fmt.Errorf("%w: summary interface_count=%d but snapshot carries %d interfaces, zone_count=%d but snapshot carries %d zones",
			errSnapshotPolicyMismatch, snap.Summary.InterfaceCount, len(snap.Interfaces), snap.Summary.ZoneCount, len(snap.Zones))
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		slog.Error("userspace: refusing snapshot send: summary policy count does not match published policies",
			"policy_count", snap.Summary.PolicyCount,
			"policies_len", len(snap.Policies),
			"first_zone_pair", firstPolicyZonePair(snap, snap.Config),
			"generation", snap.Generation)
		return fmt.Errorf("%w: summary policy_count=%d but snapshot carries %d policies (first zone pair %s)",
			errSnapshotPolicyMismatch, snap.Summary.PolicyCount, len(snap.Policies), firstPolicyZonePair(snap, snap.Config))
	}
	// FULL builds bypass the stamp arm entirely (Codex3): a full build
	// is ground truth — the builder invariant already validated its
	// count against the post-quarantine expectation — and ANY ordinary
	// policy-count change (N->M, 0->M, clear-all) arrives as one.
	// Gating it on the prior stamp deadlocked every policy edit. The
	// stamp is re-committed only after the full apply succeeds, so a
	// refused full build leaves partials sized for the retained set.
	// Partial publishers (clones: overlay/link-refresh/scheduler/
	// capture/deferred) carry fullBuild=false once they rebuild or
	// clone content, and the stamp arm below enforces the last ACCEPTED
	// full count on them — including the both-zeroed shape.
	if snap.fullBuild {
		return nil
	}
	if m.expectedPolicyCount >= 0 && len(snap.Policies) != m.expectedPolicyCount {
		slog.Error("userspace: refusing snapshot send: published policies disagree with the last full Compile expectation",
			"expected_policy_count", m.expectedPolicyCount,
			"policy_count", snap.Summary.PolicyCount,
			"policies_len", len(snap.Policies),
			"first_zone_pair", firstPolicyZonePair(snap, snap.Config),
			"generation", snap.Generation)
		return fmt.Errorf("%w: last full Compile expects %d policies but snapshot carries %d (summary policy_count=%d, first zone pair %s)",
			errSnapshotPolicyMismatch, m.expectedPolicyCount, len(snap.Policies), snap.Summary.PolicyCount, firstPolicyZonePair(snap, snap.Config))
	}
	return nil
}
