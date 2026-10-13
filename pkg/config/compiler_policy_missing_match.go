package config

import (
	"fmt"
	"strings"
)

// compiler_policy_missing_match.go carries the #3044 reject-at-commit gate
// for a security policy whose `match` clause is MISSING one of the three
// mandatory Junos match dimensions — source-address, destination-address,
// or application — or that omits the `match` block entirely.
//
// The defect: Junos/vSRX requires every security policy `match` to specify
// all three core dimensions (source-address, destination-address, and
// application); a policy missing any of them is rejected at commit. xpf's
// policy compiler (compilePolicy in compiler_security.go) instead treats
// the whole `match` block — and every leaf within it — as OPTIONAL: the
// fields are filled only when matchNode != nil, and an absent
// source-address / destination-address / application simply leaves the
// corresponding slice empty. The userspace dataplane then interprets an
// empty slice as match-ANY (capabilities.go returns a nil app-term list
// for "no apps"; userspace-dp/src/policy.rs compiles an empty app list as
// match_any:true and defaults source/destination_*_match_any to true when
// the literal+book sets are empty). No commit-time validation requires the
// three dimensions.
//
// Why that is dangerous: a partial policy is SILENTLY BROADER than typed.
// `match source-address corp; then permit` permits `corp -> any:any`
// (every destination, every application); a policy with no `match` block
// at all becomes a zone-pair-wide permit (or deny). A single dropped line
// in an automation template widens a narrow rule to all traffic — a
// fail-OPEN for a permit policy, an over-broad block for a deny policy.
// On Junos this configuration cannot commit; on xpf it commits and ships
// a wildcard. Surfacing it (reject at commit) restores Junos parity and is
// the safe choice.
//
// Contract (Junos parity): the three dimensions are REQUIRED, and a
// missing dimension is treated DIFFERENTLY from an explicit wildcard. An
// operator who wants any-source / any-destination / any-application must
// write it explicitly — `match { source-address any; destination-address
// any; application any; }` — exactly as Junos demands. Only the absence of
// the leaf is rejected; `any` (or `any-ipv4` / `any-ipv6`, an address
// book name, a literal CIDR, a named application / application-set) all
// satisfy the requirement. `source-address-excluded` /
// `destination-address-excluded` are MODIFIERS of source/destination-
// address, not substitutes, so they do not by themselves satisfy the
// source-address / destination-address requirement (Junos requires the
// base address leaf alongside the excluded modifier).
//
// This is an AST pre-walk (not a SchemaValidate typed leaf, and not a
// typed-*Config validator) for the same reasons the #3113 unsupported-
// match-leaf gate (validatePolicyMatchLeavesStrict) is: a missing leaf
// leaves no trace in the typed *Config (the empty slice is
// indistinguishable from an explicit-any that also resolves to match-any),
// and SchemaValidate is opt-in per known leaf and cannot REJECT an absence.
// The walk runs on the group-expanded, inactive-pruned tree, so an
// apply-groups-inherited match dimension counts toward the requirement and
// an `inactive:` policy is ignored for free.
//
// Both zone-pair (`from-zone`/`to-zone`) and `global` policies are covered.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// policy is a hard compile error naming the policy scope, the policy, and
// every missing dimension, directing the operator to add it (write `any`
// for an intentional wildcard).
//
// Lenient path (load / peer-sync, lenient=true): every offending policy is
// returned as a warning and compilation continues — an already-persisted
// or peer-synced config that an older binary silently accepted still BOOTS
// (#1960 fail-closed-on-load class). The policy keeps its pre-existing
// match-any-for-missing compilation exactly as before this gate, now
// flagged. Same doctrine as validatePolicyMatchLeavesStrict.
//
// #6526 extends the file to the SECOND way a dimension can fail to constrain
// anything: a dimension written with NO OPERAND (`source-address;`, or a
// `set ... match source-address` line with the value left off). The gate above
// decides presence from the leaf NAME, so a valueless leaf satisfied it while
// compiling to the byte-identical empty match-ANY slice the omitted form
// produces — the reject gate protected a claim about VALUES with a check on
// NAMES. policyValuelessMatchDimensions closes that by asking
// firewallMatchValues (the SAME reader compilePolicy uses) whether the
// dimension carries anything, and covers all FIVE value-bearing dimensions:
// source-address, destination-address, application, plus the scoped-global
// from-zone / to-zone (whose empty set collapses a global policy to the
// all-zones wildcard). Same strict-reject / lenient-warn doctrine, and both
// findings feed compilePolicy's #5575 LenientContentDropped poison so a
// leniently-loaded valueless policy is published as never-match rather than as
// a silently widened permit.

// requiredPolicyMatchLeaves are the three Junos-mandatory match dimensions
// every active security policy must specify. Kept in declaration order so
// the error message lists missing dimensions deterministically.
var requiredPolicyMatchLeaves = []string{
	"source-address",
	"destination-address",
	"application",
}

// policyMissingRequiredMatchDimensions returns the Junos-mandatory match
// dimensions (source-address, destination-address, application) ABSENT from a
// policy node's UNION of `match {}` blocks, in declaration order; an empty
// result means every required dimension is present. It is the single source of
// truth shared by the #3044 strict gate (validatePolicyRequiredMatchStrict) and
// compilePolicy's #5575 fail-closed LenientContentDropped flag, so the reject
// gate and the runtime poison decision can never diverge on which policies omit
// a dimension.
//
// #3842: it unions the dimensions across EVERY `match {}` block
// (policyMatchChildren), not just the first via FindChild. Junos merges
// duplicate match blocks, so a policy whose required dimensions are split
// across two blocks (e.g. source/destination-address in one, application in a
// load-merged second) is complete once merged — a FindChild-first read saw only
// the first block and would either spuriously flag a complete policy or,
// symmetrically, let a widened one through depending on block order.
func policyMissingRequiredMatchDimensions(polNode *Node) []string {
	present := map[string]bool{}
	for _, m := range policyMatchChildren(polNode) {
		present[m.Name()] = true
	}
	var missing []string
	for _, req := range requiredPolicyMatchLeaves {
		if !present[req] {
			missing = append(missing, req)
		}
	}
	return missing
}

// valueBearingPolicyMatchLeaves are the security-policy `match` dimensions
// whose SEMANTICS are carried by their operand(s) — the leaves compilePolicy
// reads with firewallMatchValues into a match set that the userspace matcher
// interprets as match-ANY when empty. Kept in declaration order so the #6526
// error message lists valueless dimensions deterministically.
//
// from-zone / to-zone are the scoped-global match context (#3148/#4626 M03)
// and are value-bearing ONLY under a `security policies global` policy; under
// a zone-pair policy they are not registered match siblings at all and the
// #3113 unsupported-match-leaf gate (which runs FIRST in runPreWalkGates)
// rejects them outright, so policyValuelessMatchDimensions skips them there
// rather than double-attributing one typo to two gates.
//
// Deliberately EXCLUDED: source-address-excluded / destination-address-excluded.
// Those are boolean MODIFIER leaves that legitimately carry no operand
// (compilePolicy sets a bool off the leaf name alone), so an emptiness check
// on them would reject valid Junos.
var valueBearingPolicyMatchLeaves = []string{
	"source-address",
	"destination-address",
	"application",
	"from-zone",
	"to-zone",
}

// policyValuelessMatchDimensions returns every value-bearing `match` dimension
// that is PRESENT BY NAME in a policy node's UNION of `match {}` blocks but
// whose accumulated value set is EMPTY, in declaration order; an empty result
// means every present dimension actually constrains something. isGlobal marks a
// `security policies global` policy so the global-only from-zone/to-zone match
// context is inspected exactly where compilePolicy honours it.
//
// #6526 — the defect this closes. policyMissingRequiredMatchDimensions above
// decides presence from the leaf NAME (`present[m.Name()] = true`), while the
// reader compilePolicy actually uses — firewallMatchValues
// (compiler_firewall.go) — SKIPS blank tokens, and its own doc comment states
// the conflicting definition: "an empty result means criterion absent". A leaf
// written with NO operand therefore satisfies the #3044 name-based gate and
// compiles to the BYTE-IDENTICAL empty slice the omitted form produces:
//
//	match { source-address; destination-address any; application any; }
//	set security policies from-zone t to-zone u policy p1 match source-address
//
// both yield Match.SourceAddresses == [] (n=0), which the userspace matcher
// reads as match-ANY — so `then permit` permits EVERY source. The same shape
// collapses a scoped-global `match from-zone` / `match to-zone` to the
// all-zones wildcard. Both parser shapes produce it: hierarchically the leaf is
// Keys=["source-address"] with no children; via ParseSetCommand + SetPath the
// flat path lands on the same node. The gate protected a claim about VALUES
// with a check on NAMES; this predicate closes the gap by asking
// firewallMatchValues — the SAME reader compilePolicy uses — whether the
// dimension carries anything, so the reject gate and the compiler can never
// disagree about what "present" means.
//
// Union semantics (#3842 parity): a dimension is flagged only when the values
// accumulated across EVERY `match {}` block are empty — precisely the condition
// under which the compiled slice is empty and the dimension widens. A policy
// that writes `source-address;` in one block and `source-address 10.0.0.0/8;`
// in a duplicate block compiles to [10.0.0.0/8] and is NOT widened, so it is
// not flagged; that mirrors how policyMissingRequiredMatchDimensions unions
// presence across blocks.
func policyValuelessMatchDimensions(polNode *Node, isGlobal bool) []string {
	children := policyMatchChildren(polNode)
	var valueless []string
	for _, leaf := range valueBearingPolicyMatchLeaves {
		if globalOnlyPolicyMatchLeaves[leaf] && !isGlobal {
			continue
		}
		seen, valued := false, false
		for _, m := range children {
			if m.Name() != leaf {
				continue
			}
			seen = true
			if len(firewallMatchValues(m)) > 0 {
				valued = true
			}
		}
		if seen && !valued {
			valueless = append(valueless, leaf)
		}
	}
	return valueless
}

// validatePolicyRequiredMatchStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `match` clause either
//
//   - OMITS a required dimension (source-address, destination-address,
//     application) or omits the `match` block entirely (#3044), or
//   - writes a value-bearing dimension with NO OPERAND, so the dimension
//     compiles to the same empty match-ANY set the omitted form produces
//     (#6526 — see policyValuelessMatchDimensions).
//
// Covers both zone-pair and global policies. The two failure modes share ONE
// walk (so they can never diverge on scope — the duplicate-block and dual-AST
// coverage below applies to both) but emit DISTINCT messages under DISTINCT
// lenient flags, so an operator (and a test) can tell "you did not write the
// criterion" apart from "you wrote it and left the value off". See the file
// header for the contract and rationale.
func validatePolicyRequiredMatchStrict(nodes []*Node, lenientMissing, lenientValueless bool) ([]string, error) {
	var warnings []string
	report := func(msg string, lenient bool) error {
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}
	emit := func(scope, policyName string, missing []string) error {
		return report(fmt.Sprintf(
			"security policies %s policy %q match is missing required "+
				"criterion %s (Junos requires every security policy to specify "+
				"source-address, destination-address, AND application; a missing "+
				"dimension is silently compiled as match-ANY, WIDENING the policy "+
				"to traffic the operator did not intend — a fail-open for permit, "+
				"an over-broad block for deny) — add the missing criterion, using "+
				"the explicit `any` keyword for an intentional wildcard (#3044)",
			scope, policyName, strings.Join(quoteAll(missing), ", "),
		), lenientMissing)
	}
	// emitValueless rejects a match dimension written with NO operand (#6526).
	// Kept textually distinct from emit above — the two conditions are one
	// keystroke apart for an operator but have different fixes, and a shared
	// message would make them indistinguishable to anything asserting on it.
	emitValueless := func(scope, policyName string, valueless []string) error {
		return report(fmt.Sprintf(
			"security policies %s policy %q match criterion %s is present but "+
				"carries NO value (the leaf was written with no operand, e.g. "+
				"`source-address;` or a `set ... match source-address` line with "+
				"the value omitted) — an empty match dimension compiles to the "+
				"SAME match-ANY as omitting the criterion entirely, silently "+
				"WIDENING the policy to traffic the operator did not intend (a "+
				"fail-open for permit, an over-broad block for deny; for a global "+
				"policy's from-zone/to-zone it collapses the scope to the "+
				"all-zones wildcard) — supply the intended value, using the "+
				"explicit `any` keyword for an intentional wildcard (#6526)",
			scope, policyName, strings.Join(quoteAll(valueless), ", "),
		), lenientValueless)
	}

	checkPolicy := func(scope, policyName string, polNode *Node, isGlobal bool) error {
		// Missing-entirely is reported first: it is the more fundamental
		// authoring error, and on the strict path the first finding is the
		// returned error.
		if missing := policyMissingRequiredMatchDimensions(polNode); len(missing) > 0 {
			if err := emit(scope, policyName, missing); err != nil {
				return err
			}
		}
		if valueless := policyValuelessMatchDimensions(polNode, isGlobal); len(valueless) > 0 {
			if err := emitValueless(scope, policyName, valueless); err != nil {
				return err
			}
		}
		return nil
	}

	// #3562: iterate EVERY top-level `security` node and EVERY `policies`
	// sibling, not the first match at any level. parseStatements APPENDS a
	// repeated top-level block instead of merging it (parser.go) and
	// compileExpanded compiles every `security` root, so a partial-match policy
	// in a SECOND duplicate `security {}` (or duplicate `policies {}`) block
	// would bypass a first-`security`/first-`policies` walk while the compiler
	// still compiled it and silently widened it to match-ANY. Descending with
	// forEachChild at security/policies closes that multi-level duplicate-block
	// bypass. The inner per-policy required-dimension check (checkPolicy) is
	// unchanged.
	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := checkPolicy("global", polInst.name, polInst.node, true); err != nil {
							return err
						}
					}
				case "from-zone":
					// Mirror compilePolicies' two AST shapes.
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						// Hierarchical: Keys=["from-zone","trust","to-zone","untrust"]
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						// Flat set: from-zone → <name> → to-zone → <name> → policy ...
						for _, fzSub := range child.Children {
							for _, tzNode := range fzSub.FindChildren("to-zone") {
								if len(tzNode.Keys) >= 2 {
									pairs = append(pairs, zonePair{fzSub.Name(), tzNode.Keys[1], tzNode})
									continue
								}
								for _, tzSub := range tzNode.Children {
									pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
								}
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := checkPolicy(scope, polInst.name, polInst.node, false); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// quoteAll wraps each token in %q-style quotes for the error message.
func quoteAll(toks []string) []string {
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		out = append(out, fmt.Sprintf("%q", t))
	}
	return out
}
