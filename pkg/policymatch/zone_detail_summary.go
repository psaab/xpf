package policymatch

import (
	"fmt"
	"slices"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ZoneScopeLabel renders a SINGLE reported zone token (e.g. a
// policymatch.Result's From/To scope column, #3148/#3685) for a display
// surface: an empty token is the historical "all-zones" wildcard and prints as
// "any" (the idiomatic Junos token). An explicit "any" (#3680) is already "any"
// and passes through unchanged.
//
// #4626 M03: the scoped-global match SCOPE is a zone SET, rendered by
// config.ZoneScopeSetLabel; ZoneScopeLabel remains the SSOT for a single
// resolved reported zone (the concrete flow zone a match traversed).
func ZoneScopeLabel(zone string) string {
	if zone == "" {
		return "any"
	}
	return zone
}

// zoneDetailModifiers renders the trailing "[...]" annotation appended to a
// zone-detail policy summary line. It threads the per-rule metadata the
// REST/gRPC inventory already carries but the pre-#3684 name+action summary
// dropped:
//
//   - id <N>                      runtime/RT_FLOW policy id (#3684 M11) — the
//     identity the session/event/RT_FLOW telemetry logs, so the summary can be
//     joined to "this packet hit policy_id=N".
//   - scheduler <name>            scheduler binding (#3624); when the runtime
//     reports the scheduler currently inactive the rule is skipped by the
//     dataplane, so it renders "scheduler <name> (inactive)" (#3684 H03) — a
//     scheduled-off rule can no longer read as an active participant.
//   - log <modes>                 session-log triggers via the config
//     SessionLogModes SSOT (#3667), joined at-create/at-close (#3684 M12).
//   - count                       `then count` hit-count accounting (#3684 M12).
//   - source-address (except) /   Junos source/destination-address-excluded
//     destination-address (except) inverted matches, using the ExceptSuffix SSOT
//     shared with the match-policies renderer (#3684 M12).
//
// The id token is always present; the remaining tokens appear only when set.
func zoneDetailModifiers(id uint32, schedulerName string, inactive bool, log *config.PolicyLog, count, srcExcluded, dstExcluded bool) string {
	tokens := []string{fmt.Sprintf("id %d", id)}
	if schedulerName != "" {
		if inactive {
			tokens = append(tokens, fmt.Sprintf("scheduler %s (inactive)", schedulerName))
		} else {
			tokens = append(tokens, fmt.Sprintf("scheduler %s", schedulerName))
		}
	}
	if modes := log.SessionLogModes(); len(modes) > 0 {
		tokens = append(tokens, "log "+strings.Join(modes, ","))
	}
	if count {
		tokens = append(tokens, "count")
	}
	if srcExcluded {
		tokens = append(tokens, "source-address"+ExceptSuffix(true))
	}
	if dstExcluded {
		tokens = append(tokens, "destination-address"+ExceptSuffix(true))
	}
	return "[" + strings.Join(tokens, ", ") + "]"
}

// ZoneDetailPolicySummary renders the "Policy summary" block of
// `show security zones detail` for one zone. It is the single source of truth
// consumed by the local CLI (pkg/cli), gRPC-text (pkg/grpcapi), and any other
// detail surface, so the three former hand-rolled renderers can no longer drift
// (#3684 L10). Each returned element is one complete, already-indented output
// line WITHOUT a trailing newline; the caller prints each line verbatim, so the
// CLI and gRPC-text output stay byte-identical.
//
// The lines span the three tiers the runtime evaluates in order — zone-pair,
// applicable global (#3148/#3680 scope), then the effective default-policy
// catch-all (#3658) — and thread the inventory metadata the pre-#3684 summary
// omitted: the runtime/RT_FLOW policy id (M11), scheduler binding + runtime
// inactive state (H03/#3624), the log/count/address-exclusion modifiers (M12),
// and the default-policy log posture + reserved sentinel id (M13).
//
// The runtime policy ids are span-accumulated exactly as the snapshot builder
// assigns them (dpuserspace.RuntimePolicyIDs / RuntimePolicyIndex), so the
// displayed id equals the numeric policy id the RT_FLOW/event path logs even
// after a multi-application policy shifts the id namespace.
//
// Quarantine layering (#12896): this function annotates each row's LIVE
// applicability itself. A zone-pair row whose set the apply-time scrub
// (dataplane/userspace scrubPoliciesForQuarantinedZones) would drop — either
// endpoint quarantined, the peer-of-healthy-zone case — and a global row whose
// configured scope that scrub prunes carry
// config.ZoneQuarantinePoliciesQualifier, so a scrubbed rule is never read as
// governing the zone. Wildcard sides and unscoped globals are selected only
// for an INSTALLED viewed zone: a quarantined zone is omitted by the builder,
// so nothing can govern it and only rows that literally name it stay (each
// itself scrub-marked). The CLI and gRPC zones-detail renderers additionally
// prefix the block-level qualifier when the REQUESTED zone is quarantined
// (#10530); that line speaks about the zone while these marks speak about
// individual rules, so neither makes the other redundant.
func ZoneDetailPolicySummary(cfg *config.Config, zone string, schedActive map[string]bool, haveSched bool) []string {
	if cfg == nil {
		return nil
	}
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	lines := []string{"  Policy summary (evaluation order: zone-pair, global, default-policy):"}
	// #12896: two quarantine verdict sets, each aligned with the runtime
	// consumer it mirrors. `excluded` is what the snapshot builder omits
	// (collision losers + reserved names) — it decides whether the VIEWED
	// zone is installed, because a wildcard side or an unscoped global can
	// only affect an installed zone. `scrubbed` is the exact set the policy
	// scrub (scrubPoliciesForQuarantinedZones) drops rules for — it decides
	// whether a row is live, so the display verdict can never disagree with
	// what apply would publish.
	excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
	_, viewedExcluded := excluded[zone]
	scrubbed := config.QuarantinedZoneNames(config.ZoneQuarantineNamesForConfig(cfg))

	// Tier 1: zone-pair policies. Track policySetID across ALL zone-pair sets
	// (matching or not, nil or not) exactly like the runtime walker so the
	// displayed id lands in the correct span-accumulated namespace.
	//
	// #4885: two divergences from the runtime evaluator are fixed here.
	//
	//  1. A wildcard zone-pair side ("any") governs THIS zone too, but the
	//     pre-fix `FromZone == zone || ToZone == zone` filter dropped it: a
	//     `from any to untrust` set governs a trust->untrust flow (any matches
	//     trust as ingress), and a `from any to any` set governs every zone —
	//     yet neither literally names `zone`, so both were omitted. Match a
	//     side when it equals `zone` OR is the "any" wildcard — except that
	//     the wildcard leg is live-zone-gated (#12896): "every zone" means
	//     every INSTALLED zone, and a quarantined viewed zone is omitted by
	//     the builder, so a wildcard cannot govern it. A literal reference
	//     still selects the set so the row stays visible for diagnosis,
	//     scrub-marked below.
	//  2. The runtime evaluates zone-pair sets in TIER order regardless of
	//     config placement — exact (both sides concrete), then single-wildcard
	//     (exactly one side "any"), then both-any (see policymatch.go transit
	//     Tiers 1-3). Emit the summary in that same order (config order kept
	//     within each tier) so an operator reads the effective precedence, not
	//     raw stanza placement.
	//
	// policySetID still advances in config order so each rule's displayed id
	// stays in the correct span-accumulated namespace no matter which tier
	// bucket its line lands in.
	var exactLines, singleWildLines, bothAnyLines []string
	zonePairPolicies := 0
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, rather than dereferencing zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		fromAny := zpp.FromZone == "any"
		toAny := zpp.ToZone == "any"
		fromAffects := zpp.FromZone == zone || (fromAny && !viewedExcluded)
		toAffects := zpp.ToZone == zone || (toAny && !viewedExcluded)
		// #12896: the apply-time scrub drops this whole set when either
		// endpoint is a collision loser ("any" is a policy sentinel, never a
		// quarantined name), so every rule in it renders with the qualifier
		// instead of reading as an active participant.
		_, fromScrubbed := scrubbed[zpp.FromZone]
		_, toScrubbed := scrubbed[zpp.ToZone]
		setScrubbed := fromScrubbed || toScrubbed
		if fromAffects || toAffects {
			for i, pol := range zpp.Policies {
				// #3476: skip a nil rule like the runtime walker does.
				if pol == nil {
					continue
				}
				id := dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i))
				inactive := haveSched && dpuserspace.PolicyInactive(pol.SchedulerName, schedActive)
				mods := zoneDetailModifiers(id, pol.SchedulerName, inactive, pol.Log,
					pol.Count, pol.Match.SourceAddressExcluded, pol.Match.DestinationAddressExcluded)
				line := fmt.Sprintf("    [zone-pair] %s -> %s: %s (%s) %s",
					zpp.FromZone, zpp.ToZone, pol.Name, ActionString(pol.Action), mods)
				if setScrubbed {
					line += " " + config.ZoneQuarantinePoliciesQualifier
				}
				switch {
				case fromAny && toAny:
					bothAnyLines = append(bothAnyLines, line)
				case fromAny || toAny:
					singleWildLines = append(singleWildLines, line)
				default:
					exactLines = append(exactLines, line)
				}
				zonePairPolicies++
			}
		}
		policySetID++
	}
	lines = append(lines, exactLines...)
	lines = append(lines, singleWildLines...)
	lines = append(lines, bothAnyLines...)

	// Tier 2: applicable GLOBAL policies. The global tier's policySetID is the
	// count of zone-pair sets (policySetID after the loop), mirroring the
	// snapshot builder + REST/gRPC inventory.
	globalPolicies := 0
	for i, gp := range cfg.Security.GlobalPolicies {
		// #3476-style defensiveness: skip a nil global rule.
		if gp == nil {
			continue
		}
		if !globalAppliesToZoneAfterQuarantine(gp.Match, zone, viewedExcluded) {
			continue
		}
		// #12896: render the scope the apply-time scrub would leave. A
		// configured side keeps only its surviving members (a side emptied by
		// the prune drops the whole rule, so the AUTHORED scope stays on the
		// dead row for diagnosis) and any pruned member earns the qualifier.
		fromLabel, fromEmptied, fromTouched := scrubbedScopeLabel(gp.Match.FromZones, scrubbed)
		toLabel, toEmptied, toTouched := scrubbedScopeLabel(gp.Match.ToZones, scrubbed)
		id := dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i))
		inactive := haveSched && dpuserspace.PolicyInactive(gp.SchedulerName, schedActive)
		mods := zoneDetailModifiers(id, gp.SchedulerName, inactive, gp.Log,
			gp.Count, gp.Match.SourceAddressExcluded, gp.Match.DestinationAddressExcluded)
		line := fmt.Sprintf("    [global] %s -> %s: %s (%s) %s",
			fromLabel, toLabel, gp.Name, ActionString(gp.Action), mods)
		if fromEmptied || toEmptied || fromTouched || toTouched {
			line += " " + config.ZoneQuarantinePoliciesQualifier
		}
		lines = append(lines, line)
		globalPolicies++
	}
	if zonePairPolicies == 0 && globalPolicies == 0 {
		lines = append(lines, "    (no zone-pair or global policies affecting this zone)")
	}

	// Tier 3: the effective default-policy catch-all — always surfaced so the
	// unmatched-transit disposition is never hidden (#3658 M05). M13: thread the
	// reserved DefaultPolicySentinelID (the id the default-verdict RT_FLOW logs)
	// and the default-policy log posture (DefaultPolicyLogSessionInit/Close),
	// which requests RT_FLOW session logging for flows that hit the implicit
	// default verdict.
	// #7422 row 13: the EFFECTIVE flags. Under a default-DENY/REJECT no
	// session is installed, so the session-init/close records never fire and
	// rendering the modifier claims logging that does not happen.
	defLogInit, defLogClose := config.EffectiveDefaultPolicyLogFlags(cfg)
	defLog := &config.PolicyLog{
		SessionInit:  defLogInit,
		SessionClose: defLogClose,
	}
	defMods := zoneDetailModifiers(dataplane.DefaultPolicySentinelID, "", false, defLog, false, false, false)
	lines = append(lines, fmt.Sprintf("    [default] %s: %s %s",
		dataplane.DefaultPolicyName, ActionString(cfg.Security.DefaultPolicy), defMods))
	return lines
}

// globalAppliesToZoneAfterQuarantine is the #12896 live-zone-aware tier-2
// selection predicate. For an INSTALLED viewed zone it is exactly
// config.GlobalPolicyAppliesToZone (wildcard-or-membership on either side).
// For a quarantined viewed zone only a scope that LITERALLY names the zone
// keeps the row visible — an unscoped/explicit-any global "applies to every
// zone" only in the sense that every zone is installed, and the builder omits
// this one, so listing it there represented a live rule as governing a zone
// that cannot carry traffic. The literal spellings stay for diagnosis, each
// scrub-marked by scrubbedScopeLabel.
func globalAppliesToZoneAfterQuarantine(m config.PolicyMatch, zone string, viewedExcluded bool) bool {
	if !viewedExcluded {
		return config.GlobalPolicyAppliesToZone(m, zone)
	}
	return slices.Contains(m.FromZones, zone) || slices.Contains(m.ToZones, zone)
}

// scrubbedScopeLabel renders one scoped-global match side the way the
// apply-time policy scrub (scrubPoliciesForQuarantinedZones) would leave it:
// quarantined members are pruned from a configured set, and a set the prune
// EMPTIES means the whole rule is dropped, so the authored label stays on the
// dead row (what the operator wrote) rather than a surviving-scope label.
// emptied reports the dropped-rule case, touched any pruned member; an
// omitted or wildcard set is untouched by construction ("any" is a policy
// sentinel, never a quarantined zone name).
func scrubbedScopeLabel(zs []string, scrubbed map[string]struct{}) (label string, emptied, touched bool) {
	if len(zs) == 0 {
		return config.ZoneScopeSetLabel(zs), false, false
	}
	kept := make([]string, 0, len(zs))
	for _, z := range zs {
		if _, dead := scrubbed[z]; dead {
			touched = true
			continue
		}
		kept = append(kept, z)
	}
	if len(kept) == 0 {
		return config.ZoneScopeSetLabel(zs), true, true
	}
	if touched {
		return config.ZoneScopeSetLabel(kept), false, true
	}
	return config.ZoneScopeSetLabel(zs), false, false
}
