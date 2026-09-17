package policymatch

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// AnalyzePolicyShadowing runs a conservative shadow / redundancy pass over the
// configured zone-pair policies (fable-167 C-1c, #4314), mirroring Junos
// `request security policies check`. Within each ordered zone-pair list, an
// earlier policy shadows a later one when it matches a SUPERSET of the later
// policy's traffic — because policies are terminal (permit/deny/reject) and
// evaluated first-match, the later policy is then unreachable.
//
// The superset test is a NAME-SET containment on the match fields
// (source-address, destination-address, application), with "any" treated as
// the universal set. It deliberately does NOT resolve address-book names to
// prefixes — that would need the address-book expansion and risks false
// positives — so it is conservative: it reports only high-confidence
// wildcard-or-containment shadows, never a partial-overlap guess. Policies
// that invert a match sense (source/destination-address-excluded) or that are
// schedule-gated (scheduler-name — not always active) are never treated as
// shadowers, since their coverage is not a plain superset.
//
// A finding distinguishes a pure REDUNDANT rule (same action as its shadower —
// harmless but dead) from a SHADOWED rule whose distinct action never applies
// (the operationally dangerous case).
//
// IT LIVES HERE, NOT IN pkg/cli, BECAUSE TWO SURFACES RUN IT (#8597 K47). The
// remote `cli` binary is the surface most operators actually use, and it
// rejected `request security policies check` outright — the verb existed only
// on the local console. pkg/grpcapi cannot import pkg/cli (pkg/cli imports
// pkg/grpcapi), so a server-side implementation had to be either a second copy
// of this analysis or a move. This package is where the operator-side policy
// analysis already lives for exactly this reason: #3042 collapsed three
// hand-written shadow matchers into one after all three diverged from the
// runtime evaluator.
func AnalyzePolicyShadowing(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var findings []string
	// Deterministic order: sort zone pairs by from/to zone. Stable sorting is
	// important here: the runtime preserves the authored order among distinct
	// same-pair stanzas, while this pass only reorders independent scopes for
	// deterministic diagnostics.
	pairs := append([]*config.ZonePairPolicies(nil), cfg.Security.Policies...)
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i] == nil || pairs[j] == nil {
			return pairs[j] == nil
		}
		if pairs[i].FromZone != pairs[j].FromZone {
			return pairs[i].FromZone < pairs[j].FromZone
		}
		return pairs[i].ToZone < pairs[j].ToZone
	})
	for i := 0; i < len(pairs); {
		zpp := pairs[i]
		if zpp == nil {
			i++
			continue
		}

		// #9994: the compiler keeps each same-pair stanza as a distinct
		// ZonePairPolicies entry, but the runtime appends every rule index for
		// that (from-zone,to-zone) key and walks the resulting stream in order.
		// Concatenate the stanzas before analyzing so a rule in a later stanza
		// cannot evade a shadower in an earlier one. Do not mutate any stanza's
		// Policies slice: the analyzer's sorted diagnostic view is independent
		// of the active config. Keep the common single-stanza case allocation-
		// free; copy only when a second stanza actually joins the group.
		policies := zpp.Policies
		grouped := false
		j := i + 1
		for j < len(pairs) && pairs[j] != nil &&
			pairs[j].FromZone == zpp.FromZone && pairs[j].ToZone == zpp.ToZone {
			if !grouped {
				policies = append([]*config.Policy(nil), zpp.Policies...)
				grouped = true
			}
			policies = append(policies, pairs[j].Policies...)
			j++
		}
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		findings = analyzePolicyListShadowing(policies, scope, nil, findings)
		i = j
	}
	// codex-182 A10-b00-C01: global policies (`security policies global`) are
	// an ordered, terminal, first-match list too — an earlier global shadows a
	// later one on the same conservative name-set superset. The extra
	// globalScopeCovers gate additionally requires the earlier global's
	// from-zone/to-zone match context (#3148/#4626) to COVER the later's (an
	// empty zone set = all zones), so two globals narrowed to disjoint zone
	// contexts are never falsely reported as shadowing. Cross-tier shadowing
	// between a zone-pair policy and a global is deliberately NOT analyzed: the
	// global tier is reached only when no zone-pair policy matched, so a
	// zone-pair superset is not an unreachability proof for a global.
	findings = analyzePolicyListShadowing(cfg.Security.GlobalPolicies, "global", globalScopeCovers, findings)
	return findings
}

// analyzePolicyListShadowing runs the conservative shadow / redundancy pass
// over ONE ordered, terminal, first-match policy list (a single zone-pair list
// or the global list) and appends findings tagged with scope. extraSuperset,
// when non-nil, is an ADDITIONAL superset predicate that must also hold for a
// shadow to be reported (used by the global list to require zone-context
// containment on top of the address/application superset); it is nil for
// zone-pair lists, whose zone context is fixed by the surrounding stanza.
func analyzePolicyListShadowing(policies []*config.Policy, scope string, extraSuperset func(earlier, later *config.Policy) bool, findings []string) []string {
	for j := 1; j < len(policies); j++ {
		later := policies[j]
		if later == nil {
			continue
		}
		for i := 0; i < j; i++ {
			earlier := policies[i]
			if earlier == nil {
				continue
			}
			if !policyMatchIsSuperset(earlier, later) {
				continue
			}
			if extraSuperset != nil && !extraSuperset(earlier, later) {
				continue
			}
			if earlier.Action == later.Action &&
				policyMatchIsSuperset(later, earlier) &&
				(extraSuperset == nil || extraSuperset(later, earlier)) {
				findings = append(findings, fmt.Sprintf(
					"  [%s] policy %q is REDUNDANT: identical match and action to earlier policy %q",
					scope, later.Name, earlier.Name))
			} else if earlier.Action == later.Action {
				findings = append(findings, fmt.Sprintf(
					"  [%s] policy %q is REDUNDANT: earlier policy %q already matches a superset with the same action (%s)",
					scope, later.Name, earlier.Name, policyActionName(earlier.Action)))
			} else {
				findings = append(findings, fmt.Sprintf(
					"  [%s] policy %q is SHADOWED and UNREACHABLE: earlier policy %q matches a superset with a different action (%s vs %s)",
					scope, later.Name, earlier.Name,
					policyActionName(earlier.Action), policyActionName(later.Action)))
			}
			break // report the first shadower only
		}
	}
	return findings
}

// globalScopeCovers reports whether global policy a's from-zone/to-zone match
// context (#3148/#4626) covers b's — a's zone set must be a superset of b's on
// BOTH sides, where an all-zones set means the universal set. Two global
// policies narrowed to disjoint (or merely non-nesting) zone contexts never
// shadow each other even when their address/application match sets nest, so this
// gate keeps the global shadow pass free of that false positive.
//
// #5720 (codex): host-inbound globals (`match to-zone junos-host`,
// config.IsHostToZoneScope) and transit globals are enforced on SEPARATE paths.
// The dataplane host gate (matchJunosHost / evaluate_junos_host_policy_l3_aware,
// policymatch.go ~:1247) is consulted for host-bound traffic and NEVER falls
// through to the transit global tier, and a transit global is only reached once
// no host policy matched. A global on one path therefore can never render a
// global on the other unreachable, however their address/application sets or
// zone scopes nest — so a transit-scoped global must never be reported as
// shadowing a host-scoped (`to-zone junos-host`) global, and vice versa. Without
// this exclusion an unscoped/`to-zone any` transit permit would falsely "cover"
// a later reachable `to-zone junos-host` deny (an empty/`any` a covers the
// junos-host token under zoneSetCovers).
func globalScopeCovers(a, b *config.Policy) bool {
	if config.IsHostToZoneScope(a.Match.ToZones) != config.IsHostToZoneScope(b.Match.ToZones) {
		return false
	}
	return zoneSetCovers(a.Match.FromZones, b.Match.FromZones) &&
		zoneSetCovers(a.Match.ToZones, b.Match.ToZones)
}

// zoneSetCovers reports whether zone set a covers zone set b. An all-zones a is
// the universal set and covers everything; a non-universal a covers b only when
// every zone in b is present in a. An all-zones b against a non-universal a is
// NOT covered — b ("all zones") is the broader context.
//
// "All zones" is defined by the runtime SSOT config.IsWildcardZoneSet
// (pkg/config/types_security.go): the empty set OR a set containing the reserved
// token "any". Before #5720 this used len()==0 only, so an explicit `["any"]`
// scope was treated as a concrete one-element set and diverged from the runtime
// (build_global_zone_scope in userspace-dp/src/policy.rs maps both "" and "any"
// to GlobalZoneScope::Any) — an explicit-`any` global then failed to cover a
// narrower later global that it does in fact make redundant.
func zoneSetCovers(a, b []string) bool {
	if config.IsWildcardZoneSet(a) {
		return true
	}
	if config.IsWildcardZoneSet(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, z := range a {
		set[z] = struct{}{}
	}
	for _, z := range b {
		if _, ok := set[z]; !ok {
			return false
		}
	}
	return true
}

// policyMatchIsSuperset reports whether policy a matches a superset of the
// traffic policy b matches, using conservative name-set containment. It is
// disqualified (returns false, the safe no-shadow answer) whenever EITHER
// policy inverts a match sense, or a is schedule-gated.
//
// An excluded (`source-address-excluded` / `destination-address-excluded`)
// sense makes the match set the COMPLEMENT of the named set, so a plain
// name-set containment no longer proves coverage. It must disqualify on BOTH
// sides, not just a: if b (the later, candidate-shadowed policy) is excluded,
// the two match sets can be disjoint even when the named sets are identical —
// e.g. earlier `permit source-address [A]` vs later `deny source-address [A]
// source-address-excluded` matches src∈{A} vs src∉{A}, which is FULLY
// reachable, not shadowed. Ignoring b's excluded flags produced that false
// positive (fable-167 C-1c review MINOR); a lint that cries wolf on an
// advisory erodes trust, so the no-false-positive contract wins over
// completeness here.
func policyMatchIsSuperset(a, b *config.Policy) bool {
	if a == nil || b == nil {
		return false
	}
	// An inverted match sense on EITHER policy breaks plain name-set
	// containment; a schedule-gated shadower is not always active.
	if a.Match.SourceAddressExcluded || a.Match.DestinationAddressExcluded {
		return false
	}
	if b.Match.SourceAddressExcluded || b.Match.DestinationAddressExcluded {
		return false
	}
	if a.SchedulerName != "" {
		return false
	}
	return nameSetSuperset(a.Match.SourceAddresses, b.Match.SourceAddresses) &&
		nameSetSuperset(a.Match.DestinationAddresses, b.Match.DestinationAddresses) &&
		nameSetSuperset(a.Match.Applications, b.Match.Applications)
}

// nameSetSuperset reports whether super is a superset of sub as Junos match
// name sets: "any" in super is the universal set; otherwise every element of
// sub must appear in super. An "any" in sub that super lacks is NOT covered.
// An empty sub is treated as unconstrained (== "any") for safety, so it is
// covered only when super is also "any".
func nameSetSuperset(super, sub []string) bool {
	if shadowNamesContainAny(super) {
		return true
	}
	if len(sub) == 0 || shadowNamesContainAny(sub) {
		// sub is universal but super is not.
		return false
	}
	set := make(map[string]struct{}, len(super))
	for _, s := range super {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// shadowNamesContainAny reports whether a match-field name set includes the
// universal "any" token. Named for the shadow analysis specifically: this
// package already has a containsAny over IP prefixes, and the two answer
// different questions over different types.
func shadowNamesContainAny(names []string) bool {
	for _, n := range names {
		if n == "any" {
			return true
		}
	}
	return false
}

func policyActionName(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

// RenderPolicyCheck is the OPERATOR-FACING rendering of the shadow analysis,
// single-sourced for the same reason the analysis is (#8597 K47).
//
// Sharing only AnalyzePolicyShadowing would leave each surface to write its own
// header line, its own empty-result sentence and its own nil-config wording —
// three strings that must agree for `request security policies check` to mean
// the same thing on the console and over gRPC, with nothing to notice when one
// of them changed. The local CLI prints this; the gRPC ShowText topic returns
// it. TestPolicyCheckRendersIdenticallyOnBothSurfaces_8597 pins the agreement.
//
// A nil config is the "no active configuration" answer rather than an error:
// asking a box with nothing committed to lint its policies has an answer, and
// it is not a failure.
func RenderPolicyCheck(cfg *config.Config) string {
	if cfg == nil {
		return "no active configuration\n"
	}
	findings := AnalyzePolicyShadowing(cfg)
	if len(findings) == 0 {
		return "Policy check complete: no shadowed or redundant policies detected.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Policy check complete: %d issue(s) detected.\n\n", len(findings))
	for _, f := range findings {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return b.String()
}
