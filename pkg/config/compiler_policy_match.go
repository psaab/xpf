package config

import "fmt"

// compiler_policy_match.go carries the #3113 reject-at-commit gate for a
// security-policy `match` clause that carries an UNSUPPORTED vSRX match
// leaf (e.g. `dynamic-application`, `url-category`, `source-identity`).
//
// The defect: Junos SRX security policies match traffic with a rich set
// of `match` criteria — beyond the L3/L4 set xpf enforces, vSRX accepts
// unified-policy / identity / L7 leaves like `dynamic-application`,
// `url-category`, and `source-identity`. xpf's policy compiler
// (compilePolicy in compiler_security.go) only switches on the supported
// subset — `source-address`, `destination-address`,
// `source-address-excluded`, `destination-address-excluded`, and
// `application`. Any other `match` child falls out of the switch with NO
// error and is SILENTLY DROPPED. The set-schema (schema_security.go) does
// not list the unsupported leaves and schema_walk.go returns nil for
// unknown keywords by design, so nothing rejects them either.
//
// Why that is dangerous: dropping a match criterion WIDENS the policy.
// A rule the operator wrote to match only (say) a single
// `dynamic-application` compiles as if that constraint were absent — the
// committed policy becomes a broad L3/L4 permit (or deny) over every
// application, permitting/denying traffic the operator never intended.
// For a security appliance an unimplemented match constraint that is
// silently discarded turns a constrained rule into an over-broad one — a
// fail-OPEN. Surfacing it (reject at commit) is the safe choice.
//
// Full support for these match types (typed fields + capability gate +
// Rust enforcement) is a substantial, separate feature. Until it lands
// the SAFE behaviour is to REJECT an unsupported `match` leaf at commit
// rather than silently widen the policy — mirroring the campaign's
// reject-at-commit pattern for unsupported-but-parsed stanzas
// (#3079 NAT rule-set interface/routing-instance scope, #3055 reserved
// zone names, #3060 bare `then log`, #2933 secure-tunnel bind-interface
// collision). Same #1960 strict-with-lenient doctrine.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf, and not a
// typed-Config validator) for two reasons:
//
//   - The unsupported leaf is the very thing the compiler drops, so by
//     the time the typed *Config exists the leaf is already gone from
//     PolicyMatch — only the raw AST still carries it.
//   - SchemaValidate is opt-in per known leaf and returns nil for unknown
//     keywords by design (schema_walk.go), so it cannot REJECT
//     `match dynamic-application ...`. Every other reject-at-commit-for-
//     unsupported gate (validateSecureTunnelBindInterfaceAST,
//     validateUnsupportedInterfaceStanzasAST) is likewise an AST pre-walk
//     in compileExpanded. The walk runs on the group-expanded,
//     inactive-pruned tree, so an apply-groups-inherited match leaf is
//     caught and an `inactive:` policy is ignored for free.
//
// Both zone-pair (`from-zone`/`to-zone`) and `global` policies are
// covered.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// leaf is a hard compile error naming the policy scope, the policy, and
// the unsupported leaf, and directing the operator to remove it.
//
// Lenient path (load / peer-sync, lenient=true): every offending leaf is
// returned as a warning and compilation continues — an already-persisted
// or peer-synced config that an older binary silently accepted still
// BOOTS (#1960 fail-closed-on-load class). The leaf is NOT removed from
// the tree; it stays dropped by the compiler exactly as before this gate
// (the pre-existing behaviour), now flagged. Same doctrine as
// validateUnsupportedInterfaceStanzasAST's no-prune lenient handling.

// supportedPolicyMatchLeaves is the EXACT set of `match` leaves the policy
// compiler (compilePolicy in compiler_security.go) enforces. Anything in a
// policy `match` block outside this allowlist is silently dropped today
// and is rejected by validatePolicyMatchLeavesStrict. Keep this in lockstep
// with compilePolicy's `match` switch.
var supportedPolicyMatchLeaves = map[string]bool{
	"source-address":               true,
	"destination-address":          true,
	"source-address-excluded":      true,
	"destination-address-excluded": true,
	"application":                  true,
}

// globalOnlyPolicyMatchLeaves are `match` leaves the compiler enforces ONLY
// under a GLOBAL policy: a Junos global policy may carry optional from-zone/
// to-zone match context (#3148) to scope it to one zone pair (or one wildcard
// side) instead of every zone pair. They are meaningless under a zone-pair
// policy (whose zones come from the surrounding from-zone/to-zone stanza), so
// the strict gate still rejects them there. Keep in lockstep with
// compilePolicy's `match` switch (compiler_security.go).
var globalOnlyPolicyMatchLeaves = map[string]bool{
	"from-zone": true,
	"to-zone":   true,
}

// unsupportedPolicyMatchLeaves enumerates the KNOWN vSRX `match` leaves xpf
// does not enforce. #3113 rejects them when they appear as a DIRECT child of
// `match`. #3142 closes the multi-value-leaf escape: `match application` (and
// the other `multi:true` match leaves) absorb every trailing non-sibling
// token onto the SAME node (the #2419 flat-set collapse — values land in
// child.Keys[1:] and/or child sub-nodes, not as siblings of `match`). So
//
//	set ... policy p match application any dynamic-application junos:FTP
//
// compiles to one `application` leaf whose tail tokens are
// `[any dynamic-application junos:FTP]`. The #3113 direct-child scan only
// sees the supported `application` leaf and never inspects the tail, so the
// unsupported `dynamic-application` criterion escapes the gate and the policy
// silently arms as a broad application match — the same fail-open #3113
// closes, reached via the multi-value-leaf path.
//
// These keywords are not legitimate application names (an app value is
// `junos-http`, `junos:FTP`, a user-defined app, or `any` — never one of
// these match-dimension keywords), so a token from this set appearing in a
// supported match leaf's collapsed tail is unambiguously the unsupported
// criterion masquerading as a value, and is rejected exactly as a direct
// child would be. Keep in lockstep with the vSRX match dimensions xpf does
// not yet enforce.
var unsupportedPolicyMatchLeaves = map[string]bool{
	"dynamic-application":       true,
	"url-category":              true,
	"source-identity":           true,
	"dynamic-application-group": true, // #11078: Junos sibling of dynamic-application
	"source-end-user-profile":   true, // #11078: Junos sibling of source-identity
}

// swallowedStructuralMatchTokens are structural policy `match` keywords that
// are legitimate ONLY as their own match leaf, never as an operand of a
// multi:true match leaf (application / source-address / destination-address).
//
// #3673 closes the sibling of the #3142 escape for the zone-context tokens.
// Under a ZONE-PAIR policy match, from-zone/to-zone are NOT registered `match`
// siblings (schema_security.go — the zone pair comes from the surrounding
// from-zone/to-zone stanza, not a match dimension). A flat-set or bracketed
// list that writes them after a value therefore collapses them onto the
// preceding multi-value leaf's tail (the #2419 collapse): e.g.
//
//	set ... from-zone A to-zone B policy p match application any from-zone C
//	set ... from-zone A to-zone B policy p match application [ junos-http from-zone ]
//
// both yield one `application` leaf whose tail carries from-zone (and its zone
// operand). The #3113 direct-child scan sees only the supported `application`
// leaf; from-zone/C are then consumed as bogus application operands.
//
// Today the undefined-application gate (#3144) and, for a source-address /
// destination-address tail, the address-definedness gate reject the unknown
// token — but ONLY because it is not a defined application/address. An operator
// who defines an application (or address-book entry) literally named
// "from-zone"/"to-zone" satisfies those gates, and the reserved keyword then
// commits silently as a bogus operand (widening or disarming the policy — a
// fail-open). from-zone/to-zone are never valid application or address values,
// so a token from this set in a supported multi-value leaf's collapsed tail is
// unambiguously a reserved match keyword masquerading as an operand and is
// rejected exactly as the unsupported leaves above (extending #3113/#3142 to
// the zone-context tokens).
//
// Reachable only under a ZONE-PAIR policy: under a GLOBAL policy match
// from-zone/to-zone ARE registered siblings (#3148, globalOnlyPolicyMatchLeaves
// above), so the flat-set/bracket collapse stops at them and they become their
// own legitimate match leaf — this tail case cannot arise in global scope.
var swallowedStructuralMatchTokens = map[string]bool{
	"from-zone": true,
	"to-zone":   true,
}

// policyMatchLeafFinding describes one unsupported / swallowed policy `match`
// leaf violation (#3113/#3142/#3673). For a plain unsupported leaf (or an
// unsupported keyword collapsed onto a multi-value leaf's tail), swallowed is
// false and leaf names the offending leaf/keyword. For a #3673 structural
// keyword absorbed as an operand, swallowed is true, leaf names the multi-value
// leaf that absorbed it, and tok names the reserved keyword.
type policyMatchLeafFinding struct {
	swallowed bool
	leaf      string
	tok       string
}

// policyUnsupportedMatchLeafFindings returns every unsupported / swallowed
// `match` leaf violation in a policy node's UNION of `match {}` blocks, in
// declaration order. It is the single source of truth shared by the #3113
// strict gate (validatePolicyMatchLeavesStrict) and compilePolicy's #5575
// fail-closed LenientContentDropped flag: the strict gate turns each finding
// into a reject/warning while compilePolicy only needs to know a policy has ANY
// finding (so its dropped-leaf-widened match compiles fail-closed). Sharing one
// walk keeps the reject gate and the runtime poison decision from diverging on
// the #3142 collapsed-tail and #3673 swallowed-keyword escapes.
//
// #3842: inspects EVERY `match {}` block (policyMatchChildren), not just the
// first via FindChild — a duplicate inner match block (load merge/override
// appends a second `match` child) is compiled by compilePolicy and can carry an
// unsupported leaf.
func policyUnsupportedMatchLeafFindings(polNode *Node, isGlobal bool) []policyMatchLeafFinding {
	var out []policyMatchLeafFinding
	for _, m := range policyMatchChildren(polNode) {
		leaf := m.Name()
		// #3148: from-zone/to-zone are supported match context for a global
		// policy only; under a zone-pair policy they fall through to the
		// unsupported finding below.
		if isGlobal && globalOnlyPolicyMatchLeaves[leaf] {
			continue
		}
		if supportedPolicyMatchLeaves[leaf] {
			// #3142: a multi:true match leaf (application/source-address/
			// destination-address) absorbs trailing non-sibling tokens onto its
			// own node (Keys[1:] + child sub-nodes — the #2419 collapse). An
			// unsupported match-leaf keyword written after the supported leaf's
			// value lands in this tail, invisible to a direct-child scan. Flag
			// any known unsupported match-leaf keyword found in the collapsed
			// tail (a real value is never one of these keywords, so legit
			// `application [ junos-http junos-https ]` is not over-flagged).
			for _, tok := range firewallMatchValues(m) {
				if unsupportedPolicyMatchLeaves[tok] {
					out = append(out, policyMatchLeafFinding{leaf: tok})
				}
				// #3673: from-zone/to-zone are not zone-pair match siblings, so
				// they collapse onto this multi-value leaf's tail and are
				// consumed as bogus application/address operands. Flag them as a
				// reserved keyword masquerading as a value.
				if swallowedStructuralMatchTokens[tok] {
					out = append(out, policyMatchLeafFinding{swallowed: true, leaf: leaf, tok: tok})
				}
			}
			continue
		}
		out = append(out, policyMatchLeafFinding{leaf: leaf})
	}
	return out
}

// validatePolicyMatchLeavesStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `match` clause
// carries a leaf the compiler does not enforce (see file header). Covers
// both zone-pair and global policies.
func validatePolicyMatchLeavesStrict(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	// report routes a formatted rejection through the strict/lenient split: a
	// hard error on commit / commit-check, a collected warning on load /
	// peer-sync (#1960 no-brick).
	report := func(msg string) error {
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}
	emit := func(scope, policyName, leaf string) error {
		return report(fmt.Sprintf(
			"security policies %s policy %q match %q is not supported "+
				"(xpf enforces only source-address, destination-address, "+
				"source-address-excluded, destination-address-excluded, and "+
				"application; an unsupported match leaf is silently dropped, "+
				"WIDENING the policy to a broad L3/L4 match the operator did "+
				"not intend — a fail-open) — remove the %q match criterion "+
				"(#3113)",
			scope, policyName, leaf, leaf,
		))
	}
	// emitSwallowed rejects a structural match keyword (from-zone/to-zone)
	// absorbed as an operand of a supported multi-value leaf's collapsed tail
	// (#3673). `leaf` names the multi-value leaf that swallowed the keyword
	// (application / source-address / destination-address); `tok` is the
	// reserved keyword.
	emitSwallowed := func(scope, policyName, leaf, tok string) error {
		return report(fmt.Sprintf(
			"security policies %s policy %q match %s absorbed the reserved "+
				"match keyword %q as an operand (a flat-set or bracketed list "+
				"collapsed a structural match keyword onto the %s leaf — the "+
				"#2419 collapse); from-zone/to-zone are match context, never an "+
				"application or address value, so the keyword is silently "+
				"consumed as a bogus operand (widening or disarming the policy — "+
				"a fail-open) — write %q as its own match leaf or remove it "+
				"(#3673)",
			scope, policyName, leaf, tok, leaf, tok,
		))
	}

	checkPolicy := func(scope, policyName string, polNode *Node, isGlobal bool) error {
		for _, f := range policyUnsupportedMatchLeafFindings(polNode, isGlobal) {
			if f.swallowed {
				if err := emitSwallowed(scope, policyName, f.leaf, f.tok); err != nil {
					return err
				}
				continue
			}
			if err := emit(scope, policyName, f.leaf); err != nil {
				return err
			}
		}
		return nil
	}

	// #3562: iterate EVERY top-level `security` node and EVERY `policies`
	// sibling, not the first match at any level. parseStatements APPENDS a
	// repeated top-level block instead of merging it (parser.go) and
	// compileExpanded compiles every `security` root, so an offending policy in
	// a SECOND duplicate `security {}` (or duplicate `policies {}`) block would
	// bypass a first-`security`/first-`policies` walk while the compiler still
	// compiled it and silently dropped the unsupported match leaf. Descending
	// with forEachChild at security/policies closes that multi-level
	// duplicate-block bypass. The inner per-policy match-leaf check (checkPolicy)
	// is unchanged.
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
							tzNode := fzSub.FindChild("to-zone")
							if tzNode == nil {
								// This prewalk assigns scope only to real pairs. The
								// compiler records and poisons a missing-to-zone
								// source context instead of inventing a pair scope.
								continue
							}
							for _, tzSub := range tzNode.Children {
								pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
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
