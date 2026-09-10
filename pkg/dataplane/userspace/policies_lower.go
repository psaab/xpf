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
	addrRepresentable := func(tok string) bool {
		switch tok {
		// `any4`/`any6` are the internal short forms; `any-ipv4`/`any-ipv6` are
		// the Junos config keywords. A committed config never carries the Junos
		// keywords raw — compilePolicy rewrites them to 0.0.0.0/0 // ::/0
		// (compiler_security_policy.go normalizePolicyAddrToken) — but a lenient /
		// HA-synced / hand-built snapshot can, and the Rust matcher accepts the
		// WHOLE set as a family wildcard (policy.rs parse_v3_literal_set:
		// `"any4" | "any-ipv4" => any_v4`). Accept the same set so the
		// representability gate never emits a false __unsupported_address__
		// sentinel (a spurious whole-snapshot fail-close) for a token the matcher
		// actually honors — which would also make the #4394 match-policies
		// simulator falsely report ContentRejected for a raw `any-ipv4` policy.
		case "", "any", "any4", "any6", "any-ipv4", "any-ipv6":
			return true
		}
		if isUserspaceLiteralAddress(tok) {
			return true
		}
		if _, feedBound := feedOverlay[tok]; feedBound {
			return true
		}
		// #5645 residual (codex-182): a DECLARED dynamic-address binding that is
		// ABSENT from the resolved overlay is UNRESOLVED — at least one of its feed
		// constituents has no installed snapshot yet (SnapshotForBindings publishes
		// a binding only when ALL feeds are ready). It must fail CLOSED even when a
		// STATIC address-book entry of the SAME name exists: otherwise a
		// `deny <name>` would enforce only the partial static subset and the unready
		// feed's prefixes would be silently unmatched (a deny fail-OPEN). Returning
		// false here (before the static nameToID branch) taints the side so
		// buildOneRuleSnapshot emits the __unsupported_address__ sentinel and the
		// Rust preflight rejects the whole snapshot (previous-good retained /
		// fresh-boot default-deny) — the static-alias analogue of the all-unready
		// omission the daemon's feed overlay already fails closed. Indexing a nil
		// AddressBindings map is safe (zero value nil).
		if b := cfg.Security.DynamicAddress.AddressBindings[tok]; b != nil {
			return false
		}
		if _, known := nameToID[tok]; known {
			// #5753: thread the declared dynamic-address bindings into the walk so
			// a binding buried inside a nested address-set with an UNREADY feed
			// fails closed even when a static alias of the same name exists — the
			// nested-set analogue of the top-level guard above.
			return nameRepresentable(cfg.Security.AddressBook, feedOverlay, cfg.Security.DynamicAddress.AddressBindings, tok, make(map[string]bool))
		}
		return false
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
	// Legacy back-compat field: full expansion. Same as today's
	// behaviour for old-Rust readers.
	sourceAddresses, okSrc := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
	if !okSrc {
		sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
	}
	destinationAddresses, okDst := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
	if !okDst {
		destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
	}
	// #3261: a side that names an address the matcher cannot represent (an
	// undefined book name, or a static book that resolves to no prefix — but
	// NOT a feed-bound name, whose empty content is MatchNone by design) must
	// reject the WHOLE snapshot rather than silently collapse to MatchNone. The
	// raw address strings otherwise fall through to the Rust matcher, which
	// drops an unparseable literal / empties a non-literal book; a
	// `deny <unrepresentable-address>` rule would then match nothing and fall
	// through to a later permit / default-permit (deny fail-OPEN). The sentinel
	// is the address analog of the application sentinel below.
	srcUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.SourceAddresses)
	dstUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.DestinationAddresses)
	// #3376: capture the exact offending tokens BEFORE the side collapses to
	// the sentinel so collectPolicyContentRejections can name them per side.
	var rejectedSrc, rejectedDst, rejectedApps []string
	if srcUnrepresentable {
		rejectedSrc = offendingAddressTokens(addrRepresentable, pol.Match.SourceAddresses)
		sourceAddresses = []string{unsupportedAddressSentinel}
	}
	if dstUnrepresentable {
		rejectedDst = offendingAddressTokens(addrRepresentable, pol.Match.DestinationAddresses)
		destinationAddresses = []string{unsupportedAddressSentinel}
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
	// #5575: a policy the tolerant load / peer-sync compile path accepted only
	// by DOWNGRADING a hard reject to a warning (a missing required match
	// dimension #3044, an unsupported `match` leaf #3113, or an unsupported
	// `then permit` modifier #3114) had that constraint SILENTLY DROPPED by the
	// compiler, leaving the dimension EMPTY / the permit UNCONDITIONAL. The
	// matcher reads an empty dimension as match-ANY, so the leniently-loaded
	// policy would otherwise arm a permit BROADER than the operator configured
	// (a fail-open). Poison the rule with the SAME __unsupported__ application
	// sentinel the #2124/#3261 unrepresentable-content path uses so the Rust
	// integrity preflight rejects the WHOLE snapshot (previous-good retained;
	// fresh-boot default-deny) — an action-agnostic fail-CLOSED that turns the
	// widened permit (and a symmetric over-broad deny) into never-match instead
	// of match-any. A strict commit rejects such a policy outright, so this only
	// ever fires on the tolerant load / peer-sync path (LenientContentDropped is
	// never set for a clean strict-committed policy).
	if pol.LenientContentDropped {
		if len(rejectedApps) == 0 {
			rejectedApps = []string{lenientDroppedConstraintToken}
		}
		applicationTerms = []PolicyApplicationSnapshot{{
			Name:     unsupportedApplicationSentinel,
			Protocol: unsupportedApplicationSentinel,
		}}
	}
	// #1606 v3 fields: classify each address token as "named book
	// reference" vs "free-form literal".
	srcBookIDs, srcLiterals := classifyPolicyAddresses(cfg, nameToID, pol.Match.SourceAddresses)
	dstBookIDs, dstLiterals := classifyPolicyAddresses(cfg, nameToID, pol.Match.DestinationAddresses)
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
