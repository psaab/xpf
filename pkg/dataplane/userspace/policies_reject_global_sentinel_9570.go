package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// #9570: a ZONE-PAIR policy stanza that names the reserved `junos-global`
// sentinel as a zone.
//
// THE DEFECT. Strict commit rejects such a stanza (#2401). The tolerant path
// (Store.Load, Store.SyncApply, upgrade) keeps it with a warning and this builder
// copied both zone strings onto the wire verbatim. The helper then classified the
// rule by string: `from_zone == "junos-global" || to_zone == "junos-global"` put
// it in the GLOBAL tier with an all-zones scope, so one leniently-loaded
// `from-zone junos-global to-zone trust ... then permit` permitted every zone
// pair. `show security match-policies` said the opposite: the #9410 mirror
// treated the half spelling as an undefined zone and reported the snapshot
// refused, so the plane that enforced was the more permissive one.
//
// WHY THE FIX IS HERE. The helper's predicate is now `&&`, which sends the half
// spellings to the zone-pair arm and refuses them. That cannot reach the
// both-sided spelling: `from-zone junos-global to-zone junos-global` is
// wire-identical to a real `security policies global` rule, because
// walkPolicyRuleSlots emits the same two strings for one. Only this builder
// knows which list a rule came from. So a zone-pair rule that names the sentinel
// on EITHER side is poisoned with the #5575 `__unsupported__` application
// sentinel, which every helper already refuses with a whole-snapshot integrity
// error (previous-good retained, fresh-boot default-deny). Poisoning the half
// spellings too, rather than relying on the helper's `&&`, keeps the refusal
// independent of which helper binary reads the snapshot. An ordinary undefined
// zone already fails closed the same way (#3402), so this token now joins that
// class instead of escaping it.
//
// THE ACCEPTING CASES are the ones a careless fix would break, and they are
// covered alongside the rejecting ones: a real global policy (Global slot, never
// asked), and a zone-pair rule whose zones merely contain the substring or use
// the other reserved tokens (`any`, `junos-host`).

// poisonZonePairGlobalSentinel poisons snap when it is a zone-pair rule whose
// from-zone or to-zone is the `junos-global` sentinel. The caller must pass only
// zone-pair rules: a global rule carries the sentinel on both sides by
// construction.
func poisonZonePairGlobalSentinel(snap *PolicyRuleSnapshot) {
	side := config.ZonePairGlobalSentinelSide(snap.FromZone, snap.ToZone)
	if side == "" {
		return
	}
	snap.zonePairGlobalSentinelSide = side
	snap.ApplicationTerms = []PolicyApplicationSnapshot{{
		Name:     unsupportedApplicationSentinel,
		Protocol: unsupportedApplicationSentinel,
	}}
}

// globalSentinelZoneRejectionReason9570 is the content-rejection reason for a
// poisoned zone-pair rule. It names the side and says what to do, because the
// generic undefined-zone reason would tell the operator to define a zone that
// #3055 forbids defining.
func globalSentinelZoneRejectionReason9570(rule *PolicyRuleSnapshot) string {
	return fmt.Sprintf(
		"policy %s names %q as its %s: that is the reserved global-policy context, not a "+
			"security zone, so the userspace helper REJECTS THE WHOLE POLICY SNAPSHOT rather "+
			"than enforce the rule as a device-wide global policy, and none of this config's "+
			"policies is enforced — the previous good snapshot is retained, or a freshly "+
			"booted helper serves default-deny; move the rule under `security policies global` "+
			"or name a defined zone",
		policyRejectionScope(rule), config.JunosGlobalZoneName, rule.zonePairGlobalSentinelSide)
}
