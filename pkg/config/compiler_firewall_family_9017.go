package config

import (
	"fmt"
	"sort"
	"strings"
)

// #9017: AN UNDECLARED ADDRESS-FAMILY TOKEN SILENTLY VOIDED THE WHOLE FILTER.
//
//	set firewall family any   filter BLOCK term T1 then discard   -> 0 filters
//	set firewall family inett filter BAD   term T1 then discard   -> 0 filters
//
// Both committed clean, rendered in `show`, and enforced nothing. `family any`
// is fixed by declaring it (schema_firewall_family_any_9017.go) so the flat-set
// path can nest it and reach compiler_firewall.go's existing `case "any"`. This
// file is the OTHER half, and it is the one that generalises: without it, the
// next typo repeats the defect exactly.
//
// WHY NOT `closedWorld: true` ON THE COMPOUND KEY. That was the first attempt
// and it is wrong: the flag INHERITS down the subtree, so arming it at `family`
// closed the entire filter grammar and began rejecting `from
// source-prefix-list trusted` -- valid configuration that ships in the CLI
// tests. The gate below is scoped to the family token and nothing else.
//
// THE PERMITTED SET IS READ FROM THE SCHEMA, not hardcoded. Declaring a fourth
// family permits it in the gates automatically; a hardcoded list would be a
// second place to remember, and the first thing anyone would forget. (The
// compileFirewall dest switch still needs an explicit arm for the new family —
// SPARK-F2; see TestDeclaredFamilyDestArms9883.)

// firewallFamilyTokens9017 returns the address families `firewall family`
// declares, sorted, for use in the gate and its message.
func firewallFamilyTokens9017() []string {
	fam := schemaFirewall.children["family"]
	if fam == nil {
		return nil
	}
	out := make([]string, 0, len(fam.children))
	for k := range fam.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// #9883: the NOTHING claim above is enforced by compileFirewall, not just
// observed on the flat-set path. Before the quarantine, the braced spelling
// (`firewall { family inett { filter BAD { ... } } }`) folded the filter into
// FiltersInet on the tolerant path while this gate's message told the operator
// it enforces no rule at all — an inverted diagnostic. compileFirewall now
// SKIPS undeclared families (quarantine: out of BOTH pools) and the #3884
// collision gate ignores them too, so the message is true on every route and
// the two gates cannot contradict each other on `inett/X` + `inet/X`.
// firewallFamilyPermitted9017 builds the schema-read permitted set the #9017 gate
// below and the #3884/#4296 quarantines consult — declaring a fourth family
// permits it in the gates automatically. compileFirewall's dest switch needs a
// matching explicit arm (SPARK-F2), pinned by TestDeclaredFamilyDestArms9883.
func firewallFamilyPermitted9017() map[string]bool {
	permitted := map[string]bool{}
	for _, f := range firewallFamilyTokens9017() {
		permitted[f] = true
	}
	return permitted
}

// firewallFamilyMember is one address-family member under a `firewall family`
// node: the node carrying the member's `filter` subtree plus the tokens that
// identify it. Built by firewallFamilyMembers9883, the single shape-aware
// extractor shared by compileFirewall and the #3884 / #4296 / #9017 gates.
type firewallFamilyMember struct {
	// AfNode carries the member's `filter` subtree.
	AfNode *Node
	// Af is the effective family token: famNode.Keys[1] for the packed shape
	// (`family inet { ... }`), the child NAME (Keys[0]) for the set-command
	// shape (`family { inet { ... } }`).
	Af string
	// Residue carries trailing keys on STRUCTURED member nodes only
	// (len(Children) > 0): extra tokens that must ALSO be declared, e.g. the
	// `inet` in a malformed `family { inett inet { filter F } }` child. A
	// collapsed flat-set leaf (`["inett","filter","BAD",...]`, no children)
	// carries no residue — its tail is the flattened remainder of the set
	// command, not family tokens, and flagging it would spam one warning per
	// path fragment.
	Residue []string
}

// firewallFamilyMembers9883 walks a `family` node across BOTH AST shapes and
// returns one member per address family. It is the ONLY firewall-family
// extractor: compileFirewall, validateFirewallFilterFamilyCollisionsAST
// (#3884), validateFirewallFilterFamilyAnyMatchesAST (#4296) and
// validateFirewallFilterFamilyTokensAST (#9017) all consume it, so the token
// the compiler installs under is always a token the gates judged.
//
// The sharing is load-bearing, not cosmetic. Before it, the compiler preferred
// the SECOND key of a set-shape child (`af = afNode.Keys[1]`) while the token
// gate read the name (Keys[0]) only: `family { inett inet { filter F } }` (a
// peer-synced / hand-built AST) installed F into FiltersInet while the gate
// warned it compiles to NOTHING (quarantine bypass + message lie), and the
// converse `family { inet inett { ... } }` escaped every gate and committed a
// strict silent void. No valid producer emits a multi-key family child (the
// parser and SetPath always mint single-key children — a flat-set unknown
// collapses to a LEAF, never a structured multi-key node), so the residue arm
// only ever fires on malformed / peer-synced trees.
//
// #4827: Name() safely returns "" for an empty Keys slice, so a corrupted
// persisted node (configstore JSON has no Node validator) yields Af "" — which
// quarantines / gets flagged — instead of panicking (#1960 doctrine).
func firewallFamilyMembers9883(famNode *Node) []firewallFamilyMember {
	if famNode == nil {
		return nil
	}
	if len(famNode.Keys) >= 2 {
		// Packed shape: `family inet { ... }` — one node, family on Keys[1].
		m := firewallFamilyMember{AfNode: famNode, Af: famNode.Keys[1]}
		if len(famNode.Keys) > 2 && len(famNode.Children) > 0 {
			m.Residue = famNode.Keys[2:]
		}
		return []firewallFamilyMember{m}
	}
	// Set-command shape: `family { inet { ... } ... }` — the family name rides
	// on each CHILD. The effective token is the child NAME (Keys[0]), never
	// Keys[1]: preferring the second key let a malformed leading token smuggle
	// a declared trailing token past the gate into the install path (above).
	var out []firewallFamilyMember
	for _, ch := range famNode.Children {
		if ch == nil {
			continue
		}
		m := firewallFamilyMember{AfNode: ch, Af: ch.Name()}
		if len(ch.Keys) > 1 && len(ch.Children) > 0 {
			m.Residue = ch.Keys[1:]
		}
		out = append(out, m)
	}
	return out
}

// firewallFamilyQuarantined9883 reports whether the member compiles to NOTHING:
// its effective token is undeclared, or a structured member carries an
// undeclared trailing token. An empty permitted set declines to judge (the
// schema could not be read — quarantining everything would be a total filter
// outage), mirroring the #9017 gate. The decline-to-judge FOLD (into IPv4 via
// compileFirewall's default) is never silent: the #9017 gate warns loud
// (lenient) / hard-rejects (strict) on an empty permitted set whenever a
// firewall family is present (#9883 GPT-LOW).
func firewallFamilyQuarantined9883(m firewallFamilyMember, permitted map[string]bool) bool {
	if len(permitted) == 0 {
		return false
	}
	if !permitted[m.Af] {
		return true
	}
	for _, t := range m.Residue {
		if !permitted[t] {
			return true
		}
	}
	return false
}

// validateFirewallFilterFamilyTokensAST rejects a `firewall family <token>`
// whose token is not a declared address family.
//
// Strict (commit / commit-check) hard-rejects. Lenient (Store.Load /
// Store.SyncApply) warns, so a config an older binary persisted, or a peer
// sends, still BOOTS (#1960 no-brick doctrine) — the same split the #3884
// family-collision gate beside it uses.
//
// It runs on the AST rather than on the typed config for the reason the defect
// exists at all: an unknown family compiles to NOTHING (#9883 quarantine in
// compileFirewall), so by the time fw.FiltersInet exists there is no trace of
// it left to validate.
func validateFirewallFilterFamilyTokensAST(nodes []*Node, lenient bool) ([]string, error) {
	permitted := firewallFamilyPermitted9017()
	if len(permitted) == 0 {
		// #9883 GPT-LOW: the schema could not be read, so BOTH the quarantine
		// (firewallFamilyQuarantined9883 declines to judge above) AND this gate
		// are disabled — and compileFirewall's IPv4 default restores the
		// pre-#9883 wrong-family fold SILENTLY. Never silent: fail loud here
		// (the compiler has no warnings channel, so this gate is the only
		// voice). Strict hard-rejects — a commit must not proceed on an
		// unreadable schema; lenient warns so boot/peer-sync still proceed
		// (#1960) but the operator sees the fail-open risk. Only when a
		// firewall family is present — with no families there is nothing to
		// fold and nothing at risk.
		for _, fwNode := range nodes {
			if fwNode == nil || fwNode.Name() != "firewall" {
				continue
			}
			if len(fwNode.FindChildren("family")) > 0 {
				msg := "firewall family schema unreadable — cannot validate family tokens; " +
					"unknown families will fold into IPv4 instead of quarantining " +
					"(pre-#9883 fail-open risk) (#9883)"
				if lenient {
					return []string{msg}, nil
				}
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, nil
	}

	var warnings []string
	for _, fwNode := range nodes {
		if fwNode == nil || fwNode.Name() != "firewall" {
			continue
		}
		for _, famNode := range fwNode.FindChildren("family") {
			// The shared extractor: the tokens judged here are exactly the
			// tokens compileFirewall installs under (effective token plus
			// trailing tokens on structured nodes), so gate and compiler
			// cannot disagree on any shape.
			for _, m := range firewallFamilyMembers9883(famNode) {
				toks := make([]string, 0, 1+len(m.Residue))
				toks = append(toks, m.Af)
				toks = append(toks, m.Residue...)
				for _, tok := range toks {
					if permitted[tok] {
						continue
					}
					msg := fmt.Sprintf("firewall family %q is not a known address family "+
						"(known: %s) — the filter under it compiles to NOTHING: it commits "+
						"clean, renders in `show configuration`, and enforces no rule at all "+
						"(#9017)", tok, strings.Join(firewallFamilyTokens9017(), ", "))
					if lenient {
						warnings = append(warnings, msg)
						continue
					}
					return warnings, fmt.Errorf("%s", msg)
				}
			}
		}
	}
	return warnings, nil
}
