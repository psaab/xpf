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
// family permits it here automatically; a hardcoded list would be a second
// place to remember, and the first thing anyone would forget.

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
// firewallFamilyPermitted9017 builds the schema-read permitted set both the
// gate below and those two quarantines consult — declaring a fourth family
// permits it in all three places automatically.
func firewallFamilyPermitted9017() map[string]bool {
	permitted := map[string]bool{}
	for _, f := range firewallFamilyTokens9017() {
		permitted[f] = true
	}
	return permitted
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
		// The schema could not be read. Refusing every family here would turn a
		// lookup failure into a total outage, so decline to judge.
		return nil, nil
	}

	var warnings []string
	for _, fwNode := range nodes {
		if fwNode == nil || fwNode.Name() != "firewall" {
			continue
		}
		for _, famNode := range fwNode.FindChildren("family") {
			// Both parser shapes, exactly as compiler_firewall.go reads them:
			// `family inet { … }` is one node with Keys ["family","inet"], and
			// the set-command shape `family { inet { … } }` carries the family
			// name on each CHILD.
			var tokens []string
			if len(famNode.Keys) >= 2 {
				tokens = append(tokens, famNode.Keys[1])
			} else {
				for _, ch := range famNode.Children {
					if ch != nil && ch.Name() != "" {
						tokens = append(tokens, ch.Name())
					}
				}
			}
			for _, tok := range tokens {
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
	return warnings, nil
}
