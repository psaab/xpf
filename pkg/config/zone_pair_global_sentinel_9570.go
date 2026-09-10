package config

// JunosGlobalZoneName is the reserved structural zone name a `security policies
// global` rule carries on BOTH sides of its userspace snapshot
// (pkg/dataplane/userspace/policies.go walkPolicyRuleSlots). It is not a
// security zone: #3055 rejects a zone DEFINITION of this name and #2401 rejects
// a zone-pair REFERENCE to it at commit.
const JunosGlobalZoneName = "junos-global"

// ZonePairGlobalSentinelSide reports which structural side(s) of a ZONE-PAIR
// security-policy stanza (`from-zone <a> to-zone <b> { policy ... }`) name the
// reserved global-policy sentinel: "from-zone", "to-zone",
// "from-zone and to-zone", or "" when neither does (#9570).
//
// WHY THIS IS ITS OWN PREDICATE rather than one more undefined zone. Strict
// commit rejects the reference, but the tolerant load / peer-sync path only
// warns (lenientPolicyZoneRefs, #1960 no-brick) and hands the stanza to the
// userspace snapshot builder with both zone strings verbatim. For an ordinary
// undefined zone that is fail-closed, because the helper refuses the whole
// snapshot on an unresolvable zone (#3402). For THIS token it was fail-open: the
// helper classified any rule naming `junos-global` as a device-wide GLOBAL rule
// with an all-zones scope and enforced it for every zone pair, while the Go
// content-rejection mirror reported the snapshot refused. The both-sided spelling
// is also wire-identical to a real global rule, so no helper-side predicate can
// tell the two apart; only the builder, which knows which list a rule came from,
// can.
//
// It is the single source of truth for the two consumers that must not drift:
//   - validatePolicyZoneReferencesStrict, which names the reserved context in
//     the commit error instead of telling the operator to define a zone that
//     #3055 forbids defining;
//   - the userspace snapshot builder, which poisons such a rule with the #5575
//     `__unsupported__` sentinel so the helper refuses the whole snapshot, and
//     the #9410 mirror, which reports that refusal.
//
// Ask it only about a ZONE-PAIR stanza. A global policy's structural sides are
// the sentinel by construction.
func ZonePairGlobalSentinelSide(fromZone, toZone string) string {
	from := fromZone == JunosGlobalZoneName
	to := toZone == JunosGlobalZoneName
	switch {
	case from && to:
		return "from-zone and to-zone"
	case from:
		return "from-zone"
	case to:
		return "to-zone"
	}
	return ""
}
