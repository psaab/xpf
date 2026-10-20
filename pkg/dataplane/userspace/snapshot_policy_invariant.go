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
