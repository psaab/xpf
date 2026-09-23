package userspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// MEASURED rather than assumed. An earlier draft of this function also hashed
// the address-book table, on the reasoning that a rule carries book IDs and "an
// ID is stable while its contents change". That reasoning is FALSE here, and a
// mutation test caught it: removing the book-table contribution changed no
// result. Two independent properties make the rule snapshot complete:
//
//   - SourceAddresses/DestinationAddresses in the snapshot are the RESOLVED
//     prefixes, not the names. Tightening a set changes them directly.
//   - Book IDs are CONTENT hashes (addressBookContentHash64 over the bucket's
//     canonical bytes), so a redefinition moves the ID too.
//
// Application definitions need no special handling either: buildOneRuleSnapshot
// lowers them into ApplicationTerms, so an application whose definition changed
// already alters the snapshot.
//
// So this hashes exactly what ships, and adds nothing of its own -- which is
// also what keeps it from drifting away from the dataplane's view.
//
// Scheduler state and feed overlay are nil for both configs so they are computed
// identically on each side and cannot manufacture a difference; scheduler
// transitions are handled by policySchedulerBecameInactive, and a feed refresh
// is not a commit-time event.
func PolicyResolvedFingerprints(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		// A config whose snapshot does not build is one the commit path
		// rejects anyway. Returning nil makes the caller fall back to the
		// name-level comparison rather than reporting a universal change.
		return nil
	}
	// A policy expanded into several rule slots (application-set expansion)
	// contributes every slot, sorted, so the fingerprint is order-independent.
	perKey := make(map[string][]string, len(rules))
	for _, r := range rules {
		blob, err := json.Marshal(r)
		if err != nil {
			return nil
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
	return out
}

// PolicyResolvedIdentityStrippedFingerprints returns fingerprints of the
// resolved rule content with stable-name and runtime-id identity fields
// removed. It is used only to validate an explicit rename ancestry relation;
// ordinary delete/add pairs must not infer continuity from matching content.
func PolicyResolvedIdentityStrippedFingerprints(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		return nil
	}
	perKey := make(map[string][]string, len(rules))
	for _, rule := range rules {
		key := stablePolicyRuleID(rule.FromZone, rule.ToZone, rule.Name)
		rule.RuleID = ""
		rule.PolicyID = 0
		rule.Name = ""
		rule.FromZone = ""
		rule.ToZone = ""
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
