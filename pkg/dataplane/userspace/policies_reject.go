package userspace

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// Policy content-rejection detection and human-readable reasons.
// Split from policies.go (#4421) with no logic change.

// offendingAddressTokens returns the configured address tokens the userspace
// matcher cannot represent (#3376). Used to name the exact poisoned object in a
// fail-closed content-rejection reason rather than the bare "an address". The
// returned tokens are the operator-configured strings (an undefined book name,
// or a book that resolves to no representable prefix), in config order.
func offendingAddressTokens(addrRepresentable func(tok string) bool, addrs []string) []string {
	var bad []string
	for _, tok := range addrs {
		if !addrRepresentable(tok) {
			bad = append(bad, tok)
		}
	}
	return bad
}

// offendingApplicationTokens returns the configured application tokens the
// userspace matcher cannot represent (#3376), identified by re-running the
// snapshot application expansion on each token individually. A token whose
// single-element expansion fails (protocol-less app, unrepresentable
// protocol/port, undefined name, or an application-set with such a member) is
// reported by its configured name, so the reason names the exact poisoned
// application rather than the bare "an application".
func offendingApplicationTokens(cfg *config.Config, apps []string) []string {
	var bad []string
	for _, app := range apps {
		if _, ok := expandUserspacePolicyApplications(cfg, []string{app}); !ok {
			bad = append(bad, app)
		}
	}
	return bad
}

// collectPolicyContentRejections scans the BUILT policy rules for the #3261
// fail-closed sentinels and returns a human-readable reason per offending rule.
// This is the ACCURATE, feed-aware signal that the published snapshot will be
// rejected by the helper integrity preflight (the application __unsupported__
// term or the __unsupported_address__ literal) — unlike the cfg-only capability
// gate, it sees the feed overlay already folded into the rules, so a healthy
// dynamic-address feed policy does NOT false-positive. A non-empty result means
// the helper keeps the previous-good state (or fresh-boot default-deny) and
// stays armed; an empty result means every rule is representable.
func collectPolicyContentRejections(policies []PolicyRuleSnapshot) []string {
	var reasons []string
	for i := range policies {
		rule := &policies[i]
		appBad := false
		for _, term := range rule.ApplicationTerms {
			if term.Protocol == unsupportedApplicationSentinel || term.Name == unsupportedApplicationSentinel {
				appBad = true
				break
			}
		}
		srcBad := addressListHasSentinel(rule.SourceLiterals) || addressListHasSentinel(rule.SourceAddresses)
		dstBad := addressListHasSentinel(rule.DestinationLiterals) || addressListHasSentinel(rule.DestinationAddresses)
		if !appBad && !srcBad && !dstBad {
			continue
		}
		// #3376: name the stable rule identity (scope-qualified, so duplicate
		// policy names across distinct zone pairs / global scope are
		// distinguishable) AND the offending side + configured object(s), so the
		// operator can jump straight to the poisoned token on the fail-closed
		// keep-armed path instead of hand-auditing every source/destination/app.
		var causes []string
		if srcBad {
			causes = append(causes, rejectionCause("source-address", rule.rejectedSourceAddresses))
		}
		if dstBad {
			causes = append(causes, rejectionCause("destination-address", rule.rejectedDestAddresses))
		}
		if appBad {
			causes = append(causes, rejectionCause("application", rule.rejectedApplications))
		}
		reasons = append(reasons, fmt.Sprintf("policy %s names content the userspace matcher cannot represent: %s",
			policyRejectionScope(rule), strings.Join(causes, "; ")))
	}
	return reasons
}

// PolicyContentRejectionReasons is the config-level SSOT for "the userspace
// helper would fail this config's policy snapshot CLOSED and enforce NONE of
// it". It is the single mirror of the runtime fail-closed policy-content set,
// shared with the `request security match-policies` simulator (pkg/policymatch)
// so the simulator reports the dataplane's fail-closed retention instead of a
// fabricated permit/deny/default verdict (#4394) — the same SSOT-reuse pattern
// as RuntimePolicyIDs and ClassifyHostInbound (#4352).
//
// It reproduces buildSnapshot's two policy-content fail-close paths exactly:
//
//   - PER-RULE SENTINELS (collectPolicyContentRejections over the BUILT rules):
//     the policy snapshot builder poisons a rule with the __unsupported__
//     application term or the __unsupported_address__ literal when it names
//
//   - a protocol-less application (proto == "" ->
//     expandUserspacePolicyApplications ok=false, #3323),
//
//   - an unrepresentable protocol or port (appid.ProtocolNumber /
//     userspacePortSpecRepresentable rejects it, #2124/#4345),
//
//   - an undefined application reference (resolveUserspaceApplicationNames
//     ok=false),
//
//   - an unresolvable address (an undefined address-book / prefix-list name,
//     or a defined book/set whose value is a non-literal dns-name / wildcard
//     / range or resolves to no concrete prefix — addrRepresentable false,
//     #3261).
//     The Rust integrity preflight rejects any such rule
//     (UnrepresentableApplicationProtocol / UnrepresentableAddress), so the
//     helper retains its previous-good snapshot or fresh-boots default-deny.
//     This scan is feed-aware — a healthy dynamic-address feed policy resolves
//     through feedOverlay and does NOT false-positive.
//
//   - APP-CATALOG BUILD (buildAppCatalogSnapshot): pkg/appid BuildCatalog walks
//     EVERY configured application-set and errors on the first it cannot expand,
//     which fails the whole snapshot closed REGARDLESS of a leading `any` token
//     in the referencing policy (the per-rule scan short-circuits on `any`, so a
//     `match application [ any bad-set ]` policy is missed there but still fails
//     closed here). It is consulted only when the per-rule scan is empty, so a
//     bad set already named with a scoped per-rule reason is not double-reported.
//
// A non-empty result means the dataplane enforces NONE of this config; an empty
// result means every policy rule is representable. feedOverlay is the live
// dynamic-address feed-prefix overlay (nil = no live feeds); callers MUST pass
// the same overlay the production builder uses so the simulator agrees with the
// helper on feed-backed address-names.
func PolicyContentRejectionReasons(cfg *config.Config, feedOverlay map[string][]string) []string {
	if cfg == nil {
		return nil
	}
	policies, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, feedOverlay)
	if err != nil {
		// A policy-snapshot build error (e.g. the #2514 address-book content-ID
		// collision, or a MaxRulesPerPolicy overflow) is itself a fail-closed
		// condition: buildSnapshot returns the error, the apply path rejects the
		// config, and the helper retains the prior dataplane state. Report it so
		// the simulator does not fabricate a verdict the dataplane never enforces.
		return []string{fmt.Sprintf("policy snapshot cannot be built (fail-closed): %v", err)}
	}
	reasons := collectPolicyContentRejections(policies)
	// #9410: the ZONE-RESOLUTION arm. The helper rejects the WHOLE snapshot on an
	// unresolvable policy zone reference (SnapshotIntegrityError::Unresolvable-
	// ZoneReference), not just the offending rule, so without this arm the
	// simulator certified a concrete permit/deny for a config the dataplane
	// enforces no part of. Appended to the same slice so every existing caller --
	// pkg/policymatch's single gate included -- inherits the arm unchanged.
	//
	// It reads the ZONE SNAPSHOT rather than cfg.Security.Zones on purpose; see
	// policies_reject_zone_9410.go for why a config-side predicate answers the
	// wrong question.
	reasons = append(reasons, collectPolicyZoneRejections(policies, buildZoneSnapshots(cfg))...)
	if len(reasons) == 0 {
		if _, cerr := buildAppCatalogSnapshot(cfg); cerr != nil {
			reasons = append(reasons, fmt.Sprintf(
				"application catalog cannot be built (fail-closed): %v", cerr))
		}
	}
	return reasons
}

// policyRejectionScope returns the stable, scope-qualified rule identity used in
// a content-rejection reason (#3376). A zone-pair rule renders as
// "from-zone->to-zone/name"; a global rule (FromZone == ToZone ==
// "junos-global") renders as "global/name", appending its optional
// from-zone/to-zone match context ("global(a->b)/name") when present. The bare
// name alone is ambiguous because duplicate policy names across distinct zone
// pairs / global scope are valid and common.
func policyRejectionScope(rule *PolicyRuleSnapshot) string {
	if rule.FromZone == "junos-global" && rule.ToZone == "junos-global" {
		// #4626 M03: render the FULL scoped-global zone SET (from the plural
		// wire fields, singular fallback). ZoneScopeSetLabel maps an empty side
		// to "any", preserving the pre-#4626 "" -> "any" fallback.
		from := rule.effectiveMatchFromZones()
		to := rule.effectiveMatchToZones()
		if len(from) > 0 || len(to) > 0 {
			return fmt.Sprintf("global(%s->%s)/%s",
				config.ZoneScopeSetLabel(from), config.ZoneScopeSetLabel(to), rule.Name)
		}
		return fmt.Sprintf("global/%s", rule.Name)
	}
	return fmt.Sprintf("%s->%s/%s", rule.FromZone, rule.ToZone, rule.Name)
}

// rejectionCause renders one side's content-rejection cause for #3376, naming
// the exact offending tokens when known (e.g. `source-address "missing-book"`).
// It falls back to the bare side label when the offending tokens were not
// captured (e.g. the snapshot was decoded from the wire, which does not carry
// the build-time-only detail).
func rejectionCause(side string, tokens []string) string {
	if len(tokens) == 0 {
		return side
	}
	quoted := make([]string, len(tokens))
	for i, t := range tokens {
		quoted[i] = fmt.Sprintf("%q", t)
	}
	return fmt.Sprintf("%s %s", side, strings.Join(quoted, ", "))
}

func addressListHasSentinel(addrs []string) bool {
	for _, a := range addrs {
		if a == unsupportedAddressSentinel {
			return true
		}
	}
	return false
}
