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
//   - validateSnapshotPolicyInvariant (builder): a full build whose
//     compiled config carries >=1 security policy rule must publish a
//     non-empty Policies slice whose length equals Summary.PolicyCount.
//   - the requestApplySnapshotPreparedLocked send-site gate (see
//     apply_snapshot_identity_9520.go): any snapshot whose
//     Summary.PolicyCount != len(Policies) never reaches the helper.
//   - the Rust helper (userspace-dp snapshot apply): policy_count>0 with
//     empty policies increments snapshot_policy_mismatch_total and the
//     whole apply is refused, keeping prior policies.
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

// compiledPolicyRuleCount counts the RAW security policy rules the
// compiled config carries: every zone-pair rule plus every global rule,
// before lowering/quarantine. It is the builder-side ground truth for
// "this config has policies" — lowering may legitimately drop rules only
// via zone quarantine, which resyncs Summary.PolicyCount afterwards.
func compiledPolicyRuleCount(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	n := len(cfg.Security.GlobalPolicies)
	for _, zp := range cfg.Security.Policies {
		if zp != nil {
			n += len(zp.Policies)
		}
	}
	return n
}

// validateSnapshotPolicyInvariant is the builder-layer gate. It runs on
// the post-quarantine snapshot, so Summary.PolicyCount already equals
// len(Policies) for every legitimate build (the literal sets both from
// the same slice; quarantine resyncs after scrubbing). A violation here
// means the builder itself drifted — the exact #15742 mechanism — so the
// build fails closed and the prior snapshot stays enforced.
func validateSnapshotPolicyInvariant(snap *ConfigSnapshot, cfg *config.Config) error {
	if snap == nil {
		return nil
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		slog.Error("userspace: refusing to publish snapshot: summary policy count does not match published policies",
			"policy_count", snap.Summary.PolicyCount,
			"policies_len", len(snap.Policies),
			"first_zone_pair", firstPolicyZonePair(snap, cfg),
			"generation", snap.Generation)
		return fmt.Errorf("%w: summary policy_count=%d but snapshot carries %d policies (first zone pair %s)",
			errSnapshotPolicyMismatch, snap.Summary.PolicyCount, len(snap.Policies), firstPolicyZonePair(snap, cfg))
	}
	if compiled := compiledPolicyRuleCount(cfg); compiled > 0 && len(snap.Policies) == 0 {
		slog.Error("userspace: refusing to publish snapshot: compiled config carries security policy rules but snapshot policies are empty",
			"compiled_policy_rules", compiled,
			"policy_count", snap.Summary.PolicyCount,
			"policies_len", len(snap.Policies),
			"first_zone_pair", firstPolicyZonePair(snap, cfg),
			"generation", snap.Generation)
		return fmt.Errorf("%w: compiled config carries %d security policy rules (first zone pair %s) but snapshot policies are empty",
			errSnapshotPolicyMismatch, compiled, firstPolicyZonePair(snap, cfg))
	}
	return nil
}

// validateSnapshotForSend is the send-site gate: it refuses any snapshot
// whose Summary.PolicyCount disagrees with the policies it actually
// carries, whatever builder path produced it (full Compile, partial
// republish clones, hand-built publishers). It needs no Config: the wire
// carries both numbers, and their disagreement is self-evidently a
// dropped-field defect.
func validateSnapshotForSend(snap *ConfigSnapshot) error {
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
	return nil
}
