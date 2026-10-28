package config

import (
	"fmt"
	"sort"
)

// #6455 Finding 1 — group-authored duplicate names.
//
// The pre-expansion duplicate-name gates
// (validateDuplicateNamedBlockAST #5180, validateDuplicateNATRuleNamesAST
// #5649, validateDuplicateNATRuleSetNamesAST #6454) scan only TOP-LEVEL
// stanzas. That is deliberate and still correct for them: apply-groups
// DEEP-MERGES a group-provided named block that has an inline top-level peer,
// so a pre-expansion scan that walked group bodies would count one merged
// object twice.
//
// But a duplicate authored ENTIRELY inside an applied group, with no inline
// peer, is appended wholesale by ast_groups.go and never coalesced. Measured on
// `52f51200e`, this compiled CLEAN and produced a rule-set holding TWO rules
// both named "R":
//
//	groups { G { security { nat { source { rule-set RS {
//	    rule R { then { source-nat { interface; } } }
//	    rule R { then { source-nat { off;       } } }
//	} } } } } }
//	apply-groups G;
//
// while the byte-identical duplicate authored inline is hard-rejected. Same
// config, same compiled shape, opposite verdict, decided by where the operator
// happened to write it.
//
// WHY A PER-GROUP-BODY SCAN IS THE WRONG FIX, since it is the obvious one and
// it was tried and withdrawn in PR #6491. Fragments of ONE named object
// authored across repeated group roots COALESCE under mergeNodes during
// ExpandGroups: two `interfaces` roots each contributing a `ge-0/0/0` unit
// become one interface with two units; an `ids-option P { icmp }` plus an
// `ids-option P { tcp }` become one profile. A pre-expansion sibling-scan
// cannot model that same-pass coalescing, so it rejects configs that compile to
// a single object — unacceptable for a commit gate.
//
// THE FIX runs the SAME three scanners on the EXPANDED tree, where the
// coalescing has already happened. A fragment pair is one node by then and
// reports nothing; a genuinely duplicated pair is still two sibling nodes and
// reports. The scanners are pure functions of a tree, so this reuses them
// verbatim rather than reimplementing the name-keying — which also means the
// two views cannot disagree about what "duplicate" means.
//
// BOTH-NODE UNION. The expansion is done once per cluster node (node0 AND
// node1), mirroring the #5878 / #5879 / #6178 / #6662 union gates and reusing
// their exact clone-and-expand shape (see
// collectNodeExpandedInterfaceUnitSpellings). A `groups node1` body that only
// the PEER's `${node}` expansion selects would otherwise commit green on the
// active node and reach the standby through the tolerant sync path, where it
// only warns. Both views are computed on BOTH physical nodes from the shared
// candidate, so the verdict is a pure function of the candidate and is
// identical on either node.
//
// NOT INCLUDED, deliberately: expandInterfaceRanges is NOT applied to the
// clone (the unit-alias helper does apply it). A range that expands to two
// identical interface names is a different defect on a different axis, nothing
// detects it today, and widening this gate to cover it would be exactly the
// speculative scope that produced the withdrawn false-reject. Leaving it out is
// a non-regression.

// dupNameScannersExpanded is the scanner set re-run on the expanded tree.
//
// It is a slice rather than three inline calls so a fourth pre-expansion
// duplicate-name gate cannot be added to the family without a decision about
// this view. #16607 adds validateSourceNATDuplicateContextAST as the fourth
// scanner (the duplicate-context axis, not a name axis).
var dupNameScannersExpanded = []func(*ConfigTree, bool) ([]string, error){
	validateDuplicateNamedBlockAST,
	validateDuplicateNATRuleNamesAST,
	validateDuplicateNATRuleSetNamesAST,
	validateSourceNATDuplicateContextAST,
}

// expandCandidateForNode returns a group-expanded CLONE of tree under
// the given cluster node's `${node}` binding, or nil when that node's
// expansion fails (gateNodeView, #17222).
//
// A per-node expansion error is non-fatal here and contributes the
// empty view: the real path's own ExpandGroups (compiler.go) owns
// reporting a broken apply-groups reference, and this gate must not
// turn a diagnostic it does not own into a second, differently-worded
// rejection. No generic fallback view: the pre-expansion scanners
// already cover the raw top-level tree.
func expandCandidateForNode(tree *ConfigTree, nodeID int) *ConfigTree {
	return gateNodeView(tree, nodeID, false)
}

// validateDuplicateNamesExpandedAST is the post-expansion half of the
// duplicate-name gate family (#6455 Finding 1).
//
// preWarnings is the lenient-path warning set the three PRE-expansion gates
// already produced for this same candidate. Findings that match one of them are
// dropped, so an inline top-level duplicate — which is present in the expanded
// tree too — is reported exactly once. Deduplication is by the rendered message
// because both views render through the SAME scanner functions, so an identical
// finding produces a byte-identical string by construction; there is no second
// wording to keep in sync.
//
// On the strict path preWarnings is empty and the dedup is a no-op: the
// pre-expansion gates return their error immediately, so reaching this gate at
// all means they found nothing.
//
// Strict returns the first finding as an error, scanning node0's view before
// node1's and each scanner in family order, so the message is deterministic.
// Lenient returns every distinct finding as a warning (#1960 — a persisted or
// peer-synced config must still boot).
func validateDuplicateNamesExpandedAST(tree *ConfigTree, lenient bool, preWarnings []string) ([]string, error) {
	if tree == nil {
		return nil, nil
	}

	alreadyReported := make(map[string]bool, len(preWarnings))
	for _, w := range preWarnings {
		alreadyReported[w] = true
	}

	var warnings []string
	emitted := map[string]bool{}

	for _, clone := range effectiveNodeViews(tree, gateNodeViewOpts{}) {
		for _, scan := range dupNameScannersExpanded {
			// The scanner is always run in LENIENT mode so it returns EVERY
			// finding rather than stopping at the first. The strict verdict is
			// applied here instead: a strict caller turns the first finding
			// into the error. Running the scanner strictly would surface only
			// one finding per view and make the union order-dependent.
			found, err := scan(clone, true)
			if err != nil {
				// Unreachable in lenient mode by construction; treated as an
				// empty view rather than swallowed silently in a way that
				// could hide a future scanner that errors on both paths.
				continue
			}
			for _, f := range found {
				if alreadyReported[f] || emitted[f] {
					continue
				}
				emitted[f] = true
				warnings = append(warnings, f)
			}
		}
	}

	if len(warnings) == 0 {
		return nil, nil
	}
	// Sorted so the strict first-error and the lenient warning order are a
	// function of the FINDINGS, not of node-view or scanner iteration order.
	sort.Strings(warnings)

	if !lenient {
		return nil, fmt.Errorf("%s: authored inside an applied group, where the "+
			"pre-expansion duplicate-name gates cannot see it — the group body is "+
			"appended wholesale by apply-groups, so both instances survive "+
			"expansion (#6455)", warnings[0])
	}
	out := make([]string, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, w+" (authored inside an applied group; #6455)")
	}
	return out, nil
}

// concatWarnings flattens the pre-expansion duplicate-name warning slices into
// the one set validateDuplicateNamesExpandedAST deduplicates against.
//
// A helper rather than three appends at each of the two compile call sites: the
// dedup is only correct if it sees EVERY pre-expansion gate's output, and a
// call site that forgot one would silently double-report that gate's findings
// on the lenient path. One argument list, checked in one place.
func concatWarnings(sets ...[]string) []string {
	n := 0
	for _, s := range sets {
		n += len(s)
	}
	if n == 0 {
		return nil
	}
	out := make([]string, 0, n)
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}
