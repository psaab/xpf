package config

// #9620 H9: `term t1 then count C1 discard;` in a firewall filter commits clean
// and compiles to a term with NO action and NO counter, where the braced
// spelling gives `Action=discard Count=C1`.
//
// The fold needs the pair `(term, then)` admitted to compactNormalizeInScope.
// Admitting it outright was measured and REFUSED, twice, because the admission
// registry keys on the STRING pair and `term then` names two unrelated places:
//
//	firewall        family inet filter f1 term t1 then …   <- the member to fix
//	policy-options  policy-statement P term t1 then …      <- compiles correctly today
//
// At policy-options the fold leaves the actions after `accept` on the `then`
// node's keys and the policy compiler keeps only `accept`, so a working config
// starts losing statements. That is why the pair sat excluded with a note
// saying the firewall member "needs a remedy scoped to the firewall term".
//
// The schema already draws the line the registry cannot. The two `term` nodes
// are distinct, and their `then` children disagree on exactly the flag that
// decides whether a packed run may be split at all:
//
//	firewall term -> then.packedStatements == true
//	policy   term -> then.packedStatements == false
//
// So the scope is taken from the schema rather than from a second keyword list:
// an admitted pair named here is live only where the HEAD itself declares
// packedStatements. That is the same move #9801/#9831 made for the zone-scoped
// group merge -- scope a rule by where it sits in the schema, not by its
// keyword -- and it needs no new registry concept and no signature change.
//
// Deliberately keyed to the one pair that needs it. Applying the rule to EVERY
// admitted pair would silently un-admit every head that does not declare
// packedStatements, which is a much larger behaviour change than the member it
// is here to fix, and one no cell in this package would have shown.
func headDeclaresPacked9620(containerKeyword, head string, headSchema *schemaNode) bool {
	if containerKeyword != "term" || head != "then" {
		return true
	}
	return headSchema != nil && headSchema.packedStatements
}
