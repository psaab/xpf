package natshow

import "strings"

// match_addresses_7363.go — #7363.
//
// The rule-detail renderers computed a side's displayed address match from the
// SINGULAR field alone:
//
//	dstMatch := "0.0.0.0/0"
//	if rule.Match.DestinationAddress != "" { dstMatch = rule.Match.DestinationAddress }
//
// That is wrong in BOTH directions, which is why it is not a variant of the
// #6534 exclusion-annotation work:
//
//   - A rule scoped ONLY by `match destination-address-name` rendered as
//     `0.0.0.0/0` — i.e. as matching EVERY destination — because the
//     address-book form never touches the CIDR field. Over-broad, and in the
//     direction an operator reads as "this rule is dangerously wide".
//   - A rule with a bracket list `[ A B C ]` rendered only `A`, because the
//     singular field holds the first element for back-compat and the plural
//     holds all. Under-broad, and the operator is shown a narrower scope than
//     is configured.
//
// The rule may be installed perfectly in both cases: this surface misdescribes
// WHICH TRAFFIC IT MATCHES, independently of whether the dataplane agrees.

// natMatchAddresses renders one side's complete address match.
//
// THE PLURAL SUPERSEDES THE SINGULAR RATHER THAN JOINING IT. `SourceAddress` is
// the FIRST element of `SourceAddresses` (and likewise for the name pair and
// the destination side), kept for back-compat — so concatenating the two would
// print the first element twice on every bracket-list rule. Reading the plural
// when it is populated and falling back to the singular otherwise is the only
// combination that is correct for both the old and new shapes.
//
// The empty result is the caller's "any" case and is left to the caller to
// spell, because the two renderers use the same literal for a different reason
// (there is no v6 wildcard here) and folding it in would hide which one is
// being printed.
func natMatchAddresses(cidrs []string, names []string) string {
	var out []string
	out = append(out, cidrs...)
	// Address-book names are rendered alongside the CIDRs rather than in place
	// of them: Junos permits a rule to carry both, and dropping either half
	// would reintroduce this defect for the mixed case.
	out = append(out, names...)
	return strings.Join(out, " ")
}
