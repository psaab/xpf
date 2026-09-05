package config

import "fmt"

// #7525: reject an EMPTY security identity at commit.
//
// A security zone, a zone-pair's from-zone/to-zone, and a policy are all
// NAMES, and an empty one is not a name. Four of them committed cleanly and
// then diverged from what the operator wrote:
//
//	set security zones security-zone ""
//	set security policies from-zone "" to-zone trust policy p ...
//	set security policies from-zone trust to-zone "" policy p ...
//	set security policies from-zone trust to-zone untrust policy "" ...
//
// WHY IT MATTERS, AND WHY THE TWO HALVES DIVERGE. On the Go side
// sortDedupZones (types_security.go) STRIPS the empty string from a zone set,
// and ZoneScopeSetLabel then renders an empty set as the idiomatic Junos
// "any". So an empty zone identity does not fail — it WIDENS, to every zone,
// which for a permit is a fail-open. The Rust preflight, meanwhile, rejects a
// concrete empty reference outright. The same config is therefore silently
// widened by one half and refused by the other, and the operator learns about
// it at runtime rather than at the commit where they can act.
//
// REJECTED BEFORE NORMALIZATION, deliberately. sortDedupZones is exactly the
// step that makes the mistake unobservable: once it has run there is no empty
// string left to complain about, only a wildcard indistinguishable from one
// the operator meant. The check has to sit on the AST, ahead of it.
//
// The global-scope case (`security policies global policy p match from-zone ""`)
// is NOT handled here — #6526 already rejects it, by a different route and
// with a message that names this exact widening ("for a global policy's
// from-zone/to-zone it collapses the scope to the all-zones wildcard").
// Duplicating it would give one config two errors for one mistake.
//
// Strict (commit / commit-check): hard-reject, naming the identity. Lenient
// (load / peer-sync): warn so an already-persisted or peer-synced config still
// boots (#1960) — the value keeps today's widening compilation, now flagged.
func validateNonEmptySecurityIdentities(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// forEachChild at every level rather than the first match, for the #3562
	// duplicate-block reason: parseStatements APPENDS a repeated block instead
	// of merging it, and the compiler iterates siblings at each level it
	// descends. A first-match-only walk is bypassable by a benign first
	// `security {}` followed by a second carrying the empty identity.
	return warnings, forEachChild(nodes, "security", func(sec *Node) error {
		if err := forEachChild(sec.Children, "zones", func(zones *Node) error {
			for _, z := range zoneGroupInstances8794(zones.FindChildren("security-zone")) {
				if z.name != "" {
					continue
				}
				if err := emit(
					"security zones security-zone \"\": a zone name cannot be empty. " +
						"An empty zone identity is stripped during normalization " +
						"(sortDedupZones) and an empty zone set renders and matches as " +
						"the all-zones wildcard `any`, so the zone silently WIDENS " +
						"instead of failing — while the userspace dataplane's preflight " +
						"rejects the same empty reference outright (#7525). Name the " +
						"zone, or remove the stanza"); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}

		return forEachChild(sec.Children, "policies", func(pols *Node) error {
			// The zone-pair AST has TWO shapes and this walk must read BOTH,
			// exactly as compileSecurityPolicies does. A first version read only
			// the nested one and silently missed every empty to-zone and every
			// empty policy name under a flat-set or hierarchical pair — the
			// tests said so, which is why the shapes were dumped rather than
			// assumed:
			//
			//   Keys=["from-zone","trust","to-zone","untrust"]   one node
			//   from-zone -> <name> -> to-zone -> <name> -> policy
			//
			// Reading only one shape is the #2419-class defect: a gate that
			// covers the spelling the author happened to test.
			for _, fz := range pols.FindChildren("from-zone") {
				type pair struct {
					from, to string
					node     *Node
				}
				var pairs []pair
				if len(fz.Keys) >= 4 {
					pairs = append(pairs, pair{fz.Keys[1], fz.Keys[3], fz})
				} else {
					for _, fzSub := range fz.Children {
						tzNode := fzSub.FindChild("to-zone")
						if tzNode == nil {
							continue
						}
						for _, tzSub := range tzNode.Children {
							pairs = append(pairs, pair{fzSub.Name(), tzSub.Name(), tzSub})
						}
					}
				}
				for _, zp := range pairs {
					if zp.from == "" {
						if err := emit(
							"security policies from-zone \"\": a zone-pair's from-zone " +
								"cannot be empty. It is stripped during normalization and " +
								"an empty zone set matches as `any`, so the pair silently " +
								"applies to EVERY source zone rather than failing — a " +
								"fail-open for a `then permit` policy (#7525)"); err != nil {
							return err
						}
					}
					if zp.to == "" {
						if err := emit(
							"security policies from-zone %q to-zone \"\": a zone-pair's "+
								"to-zone cannot be empty. It is stripped during "+
								"normalization and an empty zone set matches as `any`, so "+
								"the pair silently applies to EVERY destination zone "+
								"rather than failing (#7525)", zp.from); err != nil {
							return err
						}
					}
					for _, p := range namedInstances(zp.node.FindChildren("policy")) {
						if p.name != "" {
							continue
						}
						if err := emit(
							"security policies from-zone %q to-zone %q policy \"\": a "+
								"policy name cannot be empty. An unnamed policy cannot be "+
								"referenced, cleared, or reported by `show security "+
								"policies`, and its ordinal position becomes its only "+
								"identity (#7525)", zp.from, zp.to); err != nil {
							return err
						}
					}
				}
			}
			for _, g := range pols.FindChildren("global") {
				for _, p := range namedInstances(g.FindChildren("policy")) {
					if p.name != "" {
						continue
					}
					if err := emit(
						"security policies global policy \"\": a policy name cannot be " +
							"empty. An unnamed policy cannot be referenced, cleared, or " +
							"reported by `show security policies`, and its ordinal " +
							"position becomes its only identity (#7525)"); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
}
