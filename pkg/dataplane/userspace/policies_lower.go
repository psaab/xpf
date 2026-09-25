package userspace

import (
	"github.com/psaab/xpf/pkg/config"
)

// Policy snapshot lowering: Junos policy config -> PolicyRuleSnapshot.
// Split from policies.go (#4421) with no logic change.

func buildPolicySnapshots(cfg *config.Config) ([]PolicyRuleSnapshot, error) {
	return buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
}

func buildPolicySnapshotsWithSchedulerState(cfg *config.Config, activeState map[string]bool) ([]PolicyRuleSnapshot, error) {
	return buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, activeState, nil)
}

// buildPolicySnapshotsWithSchedulerStateAndFeeds builds the policy snapshots,
// classifying address tokens against the address-book ID map that INCLUDES the
// dynamic-address feed-prefix overlay (#2049). A policy token that names a
// feed-backed address-name resolves through nameToID to a SourceBookIDs /
// DestinationBookIDs reference (instead of falling through to a no-match
// literal), so the helper enforces the feed prefixes.
func buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg *config.Config, activeState map[string]bool, feedOverlay map[string][]string) ([]PolicyRuleSnapshot, error) {
	if cfg == nil || (len(cfg.Security.Policies) == 0 && len(cfg.Security.GlobalPolicies) == 0) {
		return nil, nil
	}
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return nil, err
	}
	return buildPolicySnapshotsWithAddressBook(cfg, activeState, feedOverlay, nameToID)
}

func buildPolicySnapshotsWithAddressBook(cfg *config.Config, activeState map[string]bool, feedOverlay map[string][]string, nameToID map[string]uint32) ([]PolicyRuleSnapshot, error) {
	if cfg == nil || (len(cfg.Security.Policies) == 0 && len(cfg.Security.GlobalPolicies) == 0) {
		return nil, nil
	}
	// addrRepresentable reports whether the userspace matcher can represent a
	// single policy address token. A token is representable iff it is match-any,
	// a valid literal CIDR/IP, a feed-bound name (in the overlay — an empty feed
	// is MatchNone BY DESIGN per #2049, NOT unrepresentable), or a known book/
	// address-set that is STRUCTURALLY representable (nameRepresentable: every
	// resolved member parses to a concrete prefix or is itself feed-bound).
	//
	// #3261: the structural check (not "row has >=1 prefix") is what closes the
	// two fail-opens Codex caught. (A) An address-book entry whose value is a
	// Junos dns-name / wildcard-address / range-address compiles to Value==""
	// (compiler_validate_warn.go) and expandBookNameToCIDRs USED to widen "" to
	// 0.0.0.0/0 — so a `deny <dns-name-book>` installed an overbroad deny-all
	// and a `permit` widened to permit-any. (B) A book MIXING a literal and a
	// dns-name member had row content from the literal, so a "row non-empty"
	// check called it representable while the dns-name member was silently
	// dropped (deny narrowing / under-match). nameRepresentable rejects BOTH
	// (any unrepresentable member taints the name) so the address sentinel is
	// emitted and the Rust preflight rejects the whole snapshot (previous-good
	// retained / fresh-boot default-deny). A set that CONTAINS a feed-bound
	// member stays representable (the member resolves via the overlay) and
	// #3294 (A′) now merges that member's live feed prefixes INTO the set's row,
	// so a `deny <set-with-a-feed>` enforces the feed portion instead of
	// under-denying it.
	representabilityCache := make(map[string]bool)
	resolveRepresentability := func(tok string) bool {
		switch tok {
		case "":
			return true
		}
		if config.IsPolicyAddressWildcardKeyword(tok) || isUserspaceLiteralAddress(tok) {
			return true
		}
		if _, feedBound := feedOverlay[tok]; feedBound {
			return true
		}
		if cfg.Security.DynamicAddress.AddressBindings[tok] != nil {
			return false
		}
		if _, known := nameToID[tok]; known {
			return nameRepresentable(cfg.Security.AddressBook, feedOverlay, cfg.Security.DynamicAddress.AddressBindings, tok, make(map[string]bool))
		}
		return false
	}
	addrRepresentable := func(tok string) bool {
		if cached, ok := representabilityCache[tok]; ok {
			return cached
		}
		result := resolveRepresentability(tok)
		representabilityCache[tok] = result
		return result
	}
	out := make([]PolicyRuleSnapshot, 0)
	// walkPolicyRuleSlots is the single source of truth for the runtime
	// policy-ID namespace (#3143/#3145). Using it on the snapshot WRITE side
	// guarantees the IDs assigned here decode back to the same policy on the
	// counter READ side (policyRuleIDForCounter), and enforces the
	// MaxRulesPerPolicy cap so an app-set expansion cannot spill into the next
	// policy set's namespace.
	if err := walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		policyID := slot.policyID()
		snap := buildOneRuleSnapshot(cfg, nameToID, addrRepresentable, slot.Policy, slot.FromZone, slot.ToZone, policyID, activeState)
		// #9570: a ZONE-PAIR stanza naming the reserved `junos-global` sentinel
		// must fail closed rather than be enforced as a device-wide global rule.
		// Only the builder can decide this, because only it knows which list the
		// rule came from.
		if !slot.Global {
			poisonZonePairGlobalSentinel(&snap)
		}
		out = append(out, snap)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func buildOneRuleSnapshot(
	cfg *config.Config,
	nameToID map[string]uint32,
	addrRepresentable func(tok string) bool,
	pol *config.Policy,
	fromZone, toZone string,
	policyID uint32,
	activeState map[string]bool,
) PolicyRuleSnapshot {
	// #1606 v3 fields reference address-book content once on the snapshot and
	// carry only IDs on each rule. Legacy expanded lists remain for non-v3
	// sides; v3 readers use the book IDs/literals and the exact protocol gate
	// prevents older readers from observing snapshots that omit book payloads.
	srcBookIDs, srcLiterals := classifyPolicyAddresses(cfg, nameToID, pol.Match.SourceAddresses)
	dstBookIDs, dstLiterals := classifyPolicyAddresses(cfg, nameToID, pol.Match.DestinationAddresses)
	srcUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.SourceAddresses)
	dstUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.DestinationAddresses)
	var sourceAddresses, destinationAddresses []string
	if srcUnrepresentable {
		sourceAddresses = []string{unsupportedAddressSentinel}
	} else if len(srcBookIDs) == 0 && len(srcLiterals) == 0 {
		sourceAddresses, _ = expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
	}
	if dstUnrepresentable {
		destinationAddresses = []string{unsupportedAddressSentinel}
	} else if len(dstBookIDs) == 0 && len(dstLiterals) == 0 {
		destinationAddresses, _ = expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
	}
	// #3376: capture the exact offending tokens BEFORE the side collapses to
	// the sentinel so collectPolicyContentRejections can name them per side.
	var rejectedSrc, rejectedDst, rejectedApps []string
	if srcUnrepresentable {
		rejectedSrc = offendingAddressTokens(addrRepresentable, pol.Match.SourceAddresses)
	}
	if dstUnrepresentable {
		rejectedDst = offendingAddressTokens(addrRepresentable, pol.Match.DestinationAddresses)
	}
	applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
	if !ok {
		rejectedApps = offendingApplicationTokens(cfg, pol.Match.Applications)
		// #2124: the rule cites application terms the userspace matcher cannot
		// honor (unrepresentable protocol or port). Emit a reserved unparseable
		// sentinel term instead of nil. nil would decode on the Rust side as
		// GENUINE match-any (no application constraint), so even though the
		// capability gate sets ForwardingSupported=false the published snapshot
		// could fail OPEN in the window before the helper is disarmed (and on a
		// same-plan refresh). The sentinel makes Rust drop the only term, see
		// an all-dropped non-empty term list, and reject the WHOLE snapshot via
		// SnapshotIntegrityError (keeping the previous good state) — an
		// action-agnostic fail-closed for both permit and deny rules.
		applicationTerms = []PolicyApplicationSnapshot{{
			Name:     unsupportedApplicationSentinel,
			Protocol: unsupportedApplicationSentinel,
		}}
	}
	// #5575 / #11013 / #11014: a policy the tolerant load / peer-sync compile
	// path accepted only by DOWNGRADING a reject for dropped enforcement
	// content had its constraint silently discarded, leaving an empty match
	// dimension, an unconditional direct permit, or an incomplete policy
	// subtree. Poison the rule with the __unsupported__ application sentinel
	// so the Rust integrity preflight rejects the WHOLE snapshot
	// (previous-good retained; fresh-boot default-deny) — an action-agnostic
	// fail-CLOSED instead of publishing the incomplete policy.
	// A strict commit rejects these policies outright, so this only fires on
	// tolerant load / peer-sync ingress.
	if pol.LenientContentDropped {
		if len(rejectedApps) == 0 {
			rejectedApps = []string{lenientDroppedConstraintToken}
		}
		applicationTerms = []PolicyApplicationSnapshot{{
			Name:     unsupportedApplicationSentinel,
			Protocol: unsupportedApplicationSentinel,
		}}
	}
	// #1606 v3 fields classify each address token as a named book reference or
	// a free-form literal.
	// #3261: force the unrepresentable-address sentinel onto BOTH the v3
	// (book-ids + literals) and the legacy (sourceAddresses, set above) address
	// shapes, clearing the book IDs, so the Rust preflight raises
	// UnrepresentableAddress no matter which shape it reads. Covers an undefined
	// book name (classified as a literal Rust would drop) AND a static
	// non-literal book (classified as a book ID whose table entry is empty).
	if srcUnrepresentable {
		srcBookIDs, srcLiterals = nil, []string{unsupportedAddressSentinel}
	}
	if dstUnrepresentable {
		dstBookIDs, dstLiterals = nil, []string{unsupportedAddressSentinel}
	}
	schedulerName := pol.SchedulerName
	// #2508: carry the per-policy `then log session-init`/`session-close`
	// selection into the snapshot so the dataplane can gate the per-policy
	// RT_FLOW SYSLOG records. The global NetFlow/IPFIX close exporter
	// (#2460) is independent of these flags.
	var logSessionInit, logSessionClose bool
	if pol.Log != nil {
		logSessionInit = pol.Log.SessionInit
		logSessionClose = pol.Log.SessionClose
	}
	return PolicyRuleSnapshot{
		RuleID:               stablePolicyRuleID(fromZone, toZone, pol.Name),
		PolicyID:             policyID,
		Name:                 pol.Name,
		FromZone:             fromZone,
		ToZone:               toZone,
		SchedulerName:        schedulerName,
		Inactive:             policyRuleInactive(schedulerName, activeState),
		SourceAddresses:      sourceAddresses,
		DestinationAddresses: destinationAddresses,
		SourceBookIDs:        srcBookIDs,
		DestinationBookIDs:   dstBookIDs,
		SourceLiterals:       srcLiterals,
		DestinationLiterals:  dstLiterals,
		Applications:         append([]string(nil), pol.Match.Applications...),
		ApplicationTerms:     applicationTerms,
		Action:               policyActionString(pol.Action),
		// #2008 H2: carry the match-inversion flags to the dataplane.
		SourceAddressExcluded:      pol.Match.SourceAddressExcluded,
		DestinationAddressExcluded: pol.Match.DestinationAddressExcluded,
		// #2508: per-policy RT_FLOW SYSLOG log selection.
		LogSessionInit:  logSessionInit,
		LogSessionClose: logSessionClose,
		// #3148/#4626: a global policy keeps fromZone/toZone == "junos-global"
		// (preserving global-tier classification + ordering) and carries its
		// optional zone SCOPE out-of-band in these fields. The singular fields
		// carry the first zone for backward compatibility with an old helper
		// during a rolling upgrade; the plural fields carry the full set. For a
		// zone-pair policy pol.Match.FromZones/ToZones are empty, so this is
		// inert.
		MatchFromZone:  config.ScopeSingular(pol.Match.FromZones),
		MatchToZone:    config.ScopeSingular(pol.Match.ToZones),
		MatchFromZones: pol.Match.FromZones,
		MatchToZones:   pol.Match.ToZones,
		// #3376: build-time-only offending-token detail (not serialized).
		rejectedSourceAddresses: rejectedSrc,
		rejectedDestAddresses:   rejectedDst,
		rejectedApplications:    rejectedApps,
	}
}

// effectiveMatchFromZones returns the FULL scoped-global from-zone SET carried
// by a snapshot (#4626 M03), preferring the plural MatchFromZones field and
// falling back to the singular MatchFromZone for an old-Go snapshot that omits
// the plural (additive-wire safety). Empty for an unscoped / zone-pair rule.
func (s *PolicyRuleSnapshot) effectiveMatchFromZones() []string {
	if len(s.MatchFromZones) > 0 {
		return s.MatchFromZones
	}
	if s.MatchFromZone != "" {
		return []string{s.MatchFromZone}
	}
	return nil
}

// effectiveMatchToZones is the to-side of effectiveMatchFromZones (#4626 M03).
func (s *PolicyRuleSnapshot) effectiveMatchToZones() []string {
	if len(s.MatchToZones) > 0 {
		return s.MatchToZones
	}
	if s.MatchToZone != "" {
		return []string{s.MatchToZone}
	}
	return nil
}

func policyActionString(action config.PolicyAction) string {
	switch action {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyReject:
		return "reject"
	default:
		return "deny"
	}
}
