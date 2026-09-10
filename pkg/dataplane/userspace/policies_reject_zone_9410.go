package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// #9410: the ZONE-RESOLUTION arm of the fail-closed policy-content mirror.
//
// THE DEFECT. `PolicyContentRejectionReasons` is the Go-side SSOT for "the
// userspace helper would fail this config's policy snapshot CLOSED and enforce
// NONE of it", and `pkg/policymatch` gates its permit/deny verdict on it. It
// reproduced the snapshot builder's per-rule content sentinels and the
// app-catalog build — and had NO arm for an unresolvable ZONE REFERENCE, which
// the helper rejects as a WHOLE-SNAPSHOT integrity error:
//
//	policy.rs build_global_zone_scope      empty element / unresolved -> Err
//	policy.rs (the three rule-indexing arms) -> Err(UnresolvableZoneReference)
//	server/handlers/snapshot.rs            -> response.ok = false, snapshot REFUSED
//
// A refused snapshot means the helper retains the PREVIOUS good state, or, on a
// fresh boot, serves default-deny. So `show security match-policies` returned a
// concrete permit/deny verdict for a configuration the dataplane enforces no
// part of — measured as `0 reasons, Matched=true, Display="deny"` on a scoped
// global naming a typo'd zone, and `Display="permit"` on a healthy rule sitting
// beside a dangling zone-pair.
//
// WHY IT IS REACHABLE, since a typo cannot commit. `CompileConfigLenient`
// downgrades `validatePolicyZoneReferencesStrict` to a warning, and that path is
// production code, not hypothetical: `Store.Load` (booting a persisted active
// config), `Store.SyncApply` (an HA standby receiving from an un-upgraded
// primary) and `cmd/xpfd/upgrade.go` all use it. That is precisely the class the
// #3402 backstop exists for.
//
// MIRRORED AGAINST THE SNAPSHOT, NOT THE CONFIG, and that is deliberate. The
// obvious implementation reuses `validatePolicyZoneReferencesStrict`'s
// predicate over `cfg.Security.Zones`, but the helper resolves against the ZONE
// SNAPSHOT, whose map (`zone_name_to_id_from_snapshot`) DROPS a zone with id 0
// or an id in the reserved sentinel range. A config-side predicate cannot see
// that, so it would answer "resolvable" for a zone the helper cannot resolve —
// the simulator agreeing with the compiler while disagreeing with the
// dataplane, which is the shape of the defect rather than its fix.

// policyZoneResolver mirrors userspace-dp `zone_name_to_id_from_snapshot` +
// `resolve_policy_zone_id`: the map is built from the ZoneSnapshots the helper
// will receive, with the same three exclusions, and `junos-host` resolves to
// its reserved id without appearing in the map.
type policyZoneResolver struct {
	byName map[string]uint16
}

func newPolicyZoneResolver(zones []ZoneSnapshot) policyZoneResolver {
	byName := make(map[string]uint16, len(zones))
	for _, z := range zones {
		// Exactly `zone_name_to_id_from_snapshot`'s skips, in its order: a
		// zero id and an empty name are unaddressable, and an id at or above
		// the reserved floor collides with the junos-global / junos-host
		// sentinels. Reproduced rather than assumed equivalent to "the zone is
		// defined in cfg" — see this file's header for why that difference is
		// the whole reason the mirror reads the snapshot.
		if z.ID == 0 || z.Name == "" {
			continue
		}
		if z.ID >= config.ZoneIDReservedMin {
			continue
		}
		byName[z.Name] = z.ID
	}
	return policyZoneResolver{byName: byName}
}

// resolves reports whether the helper's `resolve_policy_zone_id` would return
// Some for this name.
func (r policyZoneResolver) resolves(name string) bool {
	if name == junosHostZoneName9410 {
		// The reserved self-traffic zone is mapped by NAME, never through the
		// snapshot map. A configured zone can never be named junos-host (the
		// strict definition gate rejects it), so this cannot shadow a real one.
		return true
	}
	_, ok := r.byName[name]
	return ok
}

const junosHostZoneName9410 = "junos-host"

// collectPolicyZoneRejections reproduces every zone-resolution path on which
// the helper refuses the WHOLE snapshot.
//
// A reason is emitted PER RULE and names the offending zone, so the operator is
// pointed at the token rather than told the snapshot is bad. The reasons join
// the same slice the content sentinels use, so `pkg/policymatch`'s existing
// single gate inherits the arm with no change at the call site.
//
// ORDER MATTERS AND IS COPIED, not invented: on a zone-pair rule with BOTH
// sides unresolvable the helper reports the FROM zone (policy.rs's `(None, _)`
// arm precedes `(_, None)`, itself matching the Go strict gate's order), so a
// reason string an operator compares against a helper log names the same zone.
func collectPolicyZoneRejections(policies []PolicyRuleSnapshot, zones []ZoneSnapshot) []string {
	r := newPolicyZoneResolver(zones)
	var reasons []string
	for i := range policies {
		rule := &policies[i]
		if isGlobalPolicyRule9410(rule) {
			// GLOBAL: both scope SETS go through build_global_zone_scope.
			// An empty set or one containing "any" is GlobalZoneScope::Any and
			// resolves nothing (the wildcard); otherwise every element must be
			// non-empty AND resolvable.
			if bad, zone := unresolvableScopeElement(r, effectiveGlobalScope9410(rule.MatchFromZones, rule.MatchFromZone)); bad {
				reasons = append(reasons, zoneRejectionReason9410(rule, "match from-zone", zone))
				continue
			}
			if bad, zone := unresolvableScopeElement(r, effectiveGlobalScope9410(rule.MatchToZones, rule.MatchToZone)); bad {
				reasons = append(reasons, zoneRejectionReason9410(rule, "match to-zone", zone))
			}
			continue
		}
		// ZONE-PAIR: the literal `any` on either side is the Junos wildcard and
		// is routed to a dedicated index without resolution (policy.rs's
		// (true,true) / (true,false) / (false,true) arms). Only a CONCRETE side
		// is resolved.
		fromAny := rule.FromZone == "any"
		toAny := rule.ToZone == "any"
		if !fromAny && !r.resolves(rule.FromZone) {
			reasons = append(reasons, zoneRejectionReason9410(rule, "from-zone", rule.FromZone))
			continue
		}
		if !toAny && !r.resolves(rule.ToZone) {
			reasons = append(reasons, zoneRejectionReason9410(rule, "to-zone", rule.ToZone))
		}
	}
	return reasons
}

// isGlobalPolicyRule9410 is the same predicate policyRejectionScope uses to
// pick the global rendering, kept as one expression so the two cannot drift:
// a global rule keeps the junos-global sentinel on BOTH structural sides and
// carries its real scope out-of-band in the Match* fields.
func isGlobalPolicyRule9410(rule *PolicyRuleSnapshot) bool {
	return rule.FromZone == "junos-global" && rule.ToZone == "junos-global"
}

// effectiveGlobalScope9410 mirrors the helper's additive-wire-field
// resolution: prefer the PLURAL set, fall back to the singular field for a
// snapshot an older Go binary produced, and yield nil for an unscoped rule.
func effectiveGlobalScope9410(plural []string, singular string) []string {
	if len(plural) > 0 {
		return plural
	}
	if singular != "" {
		return []string{singular}
	}
	return nil
}

// unresolvableScopeElement answers build_global_zone_scope's question: is this
// scope set one the helper would refuse?
//
// The wildcard test is `config.IsWildcardZoneSet` — the tree's existing SSOT
// for "this set names every zone" — rather than a re-spelled `len == 0 ||
// contains any`, so the simulator and the compiler cannot disagree about which
// sets are wildcards. It is the set-level mirror of build_global_zone_scope's
// own first line.
//
// THE EMPTY-ELEMENT CASE IS EXPLICIT, matching #6464: an empty string INSIDE a
// non-wildcard set is not the wildcard, and the helper fails it closed exactly
// like an unresolvable name. Relying on "the map never holds an empty name"
// would make this correct by an invariant that belongs to another function.
func unresolvableScopeElement(r policyZoneResolver, scope []string) (bool, string) {
	if config.IsWildcardZoneSet(scope) {
		return false, ""
	}
	for _, name := range scope {
		if name == "" {
			return true, name
		}
		if !r.resolves(name) {
			return true, name
		}
	}
	return false, ""
}

func zoneRejectionReason9410(rule *PolicyRuleSnapshot, side, zone string) string {
	return fmt.Sprintf(
		"policy %s references undefined %s %q: the userspace helper REJECTS THE WHOLE POLICY SNAPSHOT "+
			"on an unresolvable zone (SnapshotIntegrityError::UnresolvableZoneReference), so none of this "+
			"config's policies is enforced — the previous good snapshot is retained, or a freshly booted "+
			"helper serves default-deny",
		policyRejectionScope(rule), side, zone)
}
