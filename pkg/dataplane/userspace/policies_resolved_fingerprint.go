package userspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// PolicyResolvedFingerprints returns, per stable policy key, a fingerprint of
// the RESOLVED form of that policy -- what the dataplane would actually be sent.
//
// WHY IT EXISTS (#8993). `policy-rematch` re-evaluates live sessions of a
// policy whose own match/action TEXT changed. Junos' `policy-rematch extensive`
// also re-evaluates sessions of an UNCHANGED policy when a referenced object's
// DEFINITION changes: tighten the address-set `trusted-hosts` to drop a host and
// that host's established sessions must be re-evaluated even though every
// policy's text is byte-identical. A name-level comparison cannot see it --
// the policy says `source-address trusted-hosts` before and after.
//
// WHY THE RULE SNAPSHOT IS SUFFICIENT ON ITS OWN, which is not obvious and was
// MEASURED rather than assumed. An earlier draft also hashed the address-book
// table separately, but the policy rule already commits to its resolved content:
//
//   - V3 sides carry content-addressed book IDs plus literals. Legacy-only
//     sides carry their expanded addresses.
//   - Book IDs are CONTENT hashes (addressBookContentHash64 over canonical
//     bucket bytes), so changing a referenced address-set definition changes
//     the ID carried by every referencing policy.
//
// Application definitions need no special handling either: buildOneRuleSnapshot
// lowers them into ApplicationTerms, so an application whose definition changed
// already alters the snapshot.
//
// So this hashes exactly what ships, and adds nothing of its own -- which is
// also what keeps it from drifting away from the dataplane's view.
//
// Scheduler state is nil on both sides so it cannot manufacture a difference;
// scheduler transitions are handled by policySchedulerBecameInactive. Feed
// overlays are supplied by the daemon from its live feed manager: passing nil
// here would make every declared binding unresolved, collapse an entire policy
// side to the unsupported-address sentinel, and hide static sibling changes.

// canonicalResolvedRule returns the fingerprint-normalized copy of a resolved
// rule (#15666). The fingerprint answers one question: did the RESOLVED
// verdict-relevant content of this policy change? Runtime and bookkeeping
// fields that never decide a verdict must therefore not move the hash:
//
//   - PolicyID is a positional runtime slot: inserting, deleting, or
//     reordering earlier policies changes it without changing behavior.
//   - LogSessionInit / LogSessionClose gate only the per-policy SYSLOG
//     records; toggling `then log` re-labels logging, it does not change
//     whether a session is permitted.
//   - SchedulerName / Inactive: PolicyResolvedFingerprints is built with
//     activeState=nil, so any named scheduler stamps Inactive=true. Scheduler
//     transitions are a separate gate (policySchedulerBecameInactive owns
//     the active->inactive verdict change, evaluated against live scheduler
//     state), so a name or liveness flip must not double-fire here.
//   - RuleID carries identity only; the fingerprint map key already pins it.
//
// Match collections are SETS for verdict purposes — what the dataplane
// matches is union membership — so each is canonicalized to sorted,
// duplicate-free form. That includes ApplicationTerms: term order decides
// only which overlapping term stamps the per-application inactivity
// timeout (first-term-wins on the session), never the permit/deny/reject
// verdict or the set of flows matched, so it is not resolved match content
// for rematch purposes. MatchFromZone / MatchToZone are derived from the
// plural sets (config.ScopeSingular) so normalizing the sets and
// re-deriving the singulars keeps the two consistent.
//
// Everything else — action, match inversion flags, book IDs, literals,
// expanded addresses, application terms' content, zone scope membership —
// stays hashed, so a genuine referenced-object change (an address-set
// tightening, an application redefinition) still moves the fingerprint.
func canonicalResolvedRule(r PolicyRuleSnapshot) PolicyRuleSnapshot {
	r.PolicyID = 0
	r.RuleID = ""
	r.LogSessionInit = false
	r.LogSessionClose = false
	r.SchedulerName = ""
	r.Inactive = false
	r.SourceAddresses = canonicalStringSet(r.SourceAddresses)
	r.DestinationAddresses = canonicalStringSet(r.DestinationAddresses)
	r.SourceBookIDs = canonicalBookIDSet(r.SourceBookIDs)
	r.DestinationBookIDs = canonicalBookIDSet(r.DestinationBookIDs)
	r.SourceLiterals = canonicalStringSet(r.SourceLiterals)
	r.DestinationLiterals = canonicalStringSet(r.DestinationLiterals)
	r.Applications = canonicalStringSet(r.Applications)
	r.ApplicationTerms = canonicalApplicationTerms(r.ApplicationTerms)
	r.MatchFromZones = canonicalStringSet(r.MatchFromZones)
	r.MatchToZones = canonicalStringSet(r.MatchToZones)
	r.MatchFromZone = config.ScopeSingular(r.MatchFromZones)
	r.MatchToZone = config.ScopeSingular(r.MatchToZones)
	return r
}

// canonicalStringSet returns a sorted, duplicate-free copy of in. Nil and
// empty both canonicalize to nil so an absent dimension and an empty one
// hash identically (they match identically in the dataplane).
func canonicalStringSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sorted := slices.Clone(in)
	sort.Strings(sorted)
	out := sorted[:1]
	for _, s := range sorted[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// canonicalBookIDSet returns a sorted, duplicate-free copy of in.
func canonicalBookIDSet(in []uint32) []uint32 {
	if len(in) == 0 {
		return nil
	}
	sorted := slices.Clone(in)
	slices.Sort(sorted)
	out := sorted[:1]
	for _, id := range sorted[1:] {
		if id != out[len(out)-1] {
			out = append(out, id)
		}
	}
	return out
}

// canonicalApplicationTerms returns the terms sorted by their JSON encoding
// with duplicates removed. marshalApplicationTermKey cannot fail for this
// plain-data struct; a failure is mapped to the empty key so the sort stays
// total and deterministic rather than panicking on the commit path.
func canonicalApplicationTerms(in []PolicyApplicationSnapshot) []PolicyApplicationSnapshot {
	if len(in) == 0 {
		return nil
	}
	sorted := slices.Clone(in)
	slices.SortFunc(sorted, func(a, b PolicyApplicationSnapshot) int {
		return strings.Compare(marshalApplicationTermKey(a), marshalApplicationTermKey(b))
	})
	out := sorted[:1]
	for _, term := range sorted[1:] {
		if marshalApplicationTermKey(term) != marshalApplicationTermKey(out[len(out)-1]) {
			out = append(out, term)
		}
	}
	return out
}

func marshalApplicationTermKey(term PolicyApplicationSnapshot) string {
	blob, err := json.Marshal(term)
	if err != nil {
		return ""
	}
	return string(blob)
}

// fingerprintResolvedRules hashes canonicalized rules per stable policy key:
// every expanded slot of a policy contributes its canonical blob, sorted, so
// the fingerprint is independent of slot order.
func fingerprintResolvedRules(rules []PolicyRuleSnapshot) (map[string]string, bool) {
	perKey := make(map[string][]string, len(rules))
	for _, r := range rules {
		blob, err := json.Marshal(canonicalResolvedRule(r))
		if err != nil {
			return nil, false
		}
		key := stablePolicyRuleID(r.FromZone, r.ToZone, r.Name)
		perKey[key] = append(perKey[key], string(blob))
	}
	out := make(map[string]string, len(perKey))
	for key, parts := range perKey {
		sort.Strings(parts)
		sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
		out[key] = hex.EncodeToString(sum[:])
	}
	return out, true
}

func PolicyResolvedFingerprints(cfg *config.Config, feedOverlay map[string][]string) map[string]string {
	if cfg == nil {
		return nil
	}
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return nil
	}
	rules, err := buildPolicySnapshotsWithAddressBook(cfg, nil, feedOverlay, nameToID)
	if err != nil {
		// A config whose snapshot does not build is one the commit path
		// rejects anyway. Returning nil makes the caller fall back to the
		// name-level comparison rather than reporting a universal change.
		return nil
	}
	// #14330: hash exactly what ships. The publish path runs
	// quarantineCollidingZones, which drops a scoped-global rule whose
	// match side is fully quarantined and prunes only the quarantined
	// members of a partially quarantined side. Without this scrub a
	// commit whose only enforcement change is a zone becoming quarantined
	// (StableZoneID collision / poisoned child) hashes identically to
	// the pre-quarantine config, so policy-rematch never re-evaluates
	// live sessions of the dropped/narrowed rule.
	rules, _ = policySnapshotAfterZoneQuarantine(cfg, rules)
	out, ok := fingerprintResolvedRules(rules)
	if !ok {
		return nil
	}
	return out
}

// PolicyResolvedIdentityStrippedFingerprints returns fingerprints of the
// resolved rule content with stable-name and runtime-id identity fields
// removed. It is used only to validate an explicit rename ancestry relation;
// ordinary delete/add pairs must not infer continuity from matching content.
func PolicyResolvedIdentityStrippedFingerprints(cfg *config.Config, feedOverlay map[string][]string) map[string]string {
	if cfg == nil {
		return nil
	}
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return nil
	}
	rules, err := buildPolicySnapshotsWithAddressBook(cfg, nil, feedOverlay, nameToID)
	if err != nil {
		return nil
	}
	// #14330: same quarantine scrub as PolicyResolvedFingerprints — a
	// solely-quarantined rule is absent from the published snapshot and
	// must be absent here too, or rename-ancestry validation could infer
	// continuity for a rule the helper no longer enforces.
	rules, _ = policySnapshotAfterZoneQuarantine(cfg, rules)
	// Identity-stripping runs on top of the same canonicalization as
	// PolicyResolvedFingerprints (#15666): non-verdict fields and match-set
	// order must not break rename continuity either. The key is still taken
	// from the rule BEFORE stripping, so an unrelated add/delete never mints
	// a shared "" key.
	perKey := make(map[string][]string, len(rules))
	for _, rule := range rules {
		key := stablePolicyRuleID(rule.FromZone, rule.ToZone, rule.Name)
		rule = canonicalResolvedRule(rule)
		rule.Name = ""
		rule.FromZone = ""
		rule.ToZone = ""
		// #12857: scoped-global policies carry their zone scope in the
		// Match* fields, not FromZone/ToZone. Strip those too, or a pure
		// zone rename changes the fingerprint and rename continuity is
		// refused for content-identical rules.
		rule.MatchFromZone = ""
		rule.MatchToZone = ""
		rule.MatchFromZones = nil
		rule.MatchToZones = nil
		blob, err := json.Marshal(rule)
		if err != nil {
			return nil
		}
		perKey[key] = append(perKey[key], string(blob))
	}
	out := make(map[string]string, len(perKey))
	for key, parts := range perKey {
		sort.Strings(parts)
		sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
		out[key] = hex.EncodeToString(sum[:])
	}
	return out
}
