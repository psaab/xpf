package config

import (
	"fmt"
	"sort"
	"strings"
)

// #16459: the `applications` level was open-world above the #9595
// application-body gate.
//
// A misspelt keyword at that level strict-committed clean with zero
// warnings and silently dropped the line:
//
//	set applications application app-x protocol tcp
//	set applications applicaiton app-x destination-port 8443
//
// puts the second line under an `applicaiton` node, which is never
// compiled. app-x becomes {tcp, no port}, the policy expands it to all
// TCP, and a permit referencing app-x applies on every port. The
// body-level gate (#9595) rejects the same typo one level down
// (`destination-prot` inside an application body), but it inspects
// app.UnknownDirectTokens / UnknownTermLeaves of an application node,
// and a misspelt `application` keyword never creates one. The mirror
// shapes are `application-setzq`, `aplication`, `applicaton` and any
// other unknown child directly under `applications`.
//
// WHY NOT closedWorld ON schemaApplications: that flag INHERITS (see
// #9017), so arming it on `applications` would close every level below
// it. It was measured: the flat-set chain
// `set applications application app-x protocol tcp destination-port 8443`
// is rejected ("unknown configuration keyword destination-port") because
// the schema walk returns early below `protocol` (children: nil) and
// never sees the chained leaf the compiler does read, and the
// hierarchical term form `term t1 { protocol tcp; }` is rejected
// ("unknown configuration keyword protocol") because `term` is declared
// children: nil (its body is an opaque token stream parsed by
// parseApplicationTerms), so the inherited walk judges term leaves
// against no grammar. The shipped spellings must stay accepted, so this
// gate is scoped to exactly the `applications` level and inherits
// nothing. The permitted set is READ FROM THE SCHEMA (#9017's rule),
// so a keyword declared later is permitted automatically.
//
// It runs on the AST (pre-walk, after group expansion, before section
// compilation) for the reason the defect exists at all: an unknown
// child at this level compiles to NOTHING, so by the time
// cfg.Applications exists there is no trace of the dropped token left
// to validate. That also covers a definition whose EVERY line is
// misspelt (no application is compiled at all).
//
// Strict (commit / commit-check) hard-rejects the first offender.
// Lenient (Store.Load / Store.SyncApply) warns once per distinct
// finding so an already-persisted or peer-synced config still BOOTS
// (#1960); compilation continues with the pre-#16459 behaviour there
// (the dropped line stays dropped — the warning is the diagnostic,
// exactly as the sibling AST gates #9017/#9552/#16450 do).
//
// Apply statements (apply-groups / apply-groups-except / apply-macro,
// #7029) are Junos meta statements permitted at any hierarchy point and
// are never judged. Quoted/bracketed tokens are authored values, never
// statement heads (#9635).

// applicationsLevelChildTokens16459 returns the statement keywords
// declared directly under `applications`, sorted, or nil if the schema
// node is missing.
func applicationsLevelChildTokens16459() []string {
	if schemaApplications == nil {
		return nil
	}
	out := make([]string, 0, len(schemaApplications.children))
	for k := range schemaApplications.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateApplicationsLevelChildrenAST16459 is the #16459 gate. See file doc.
func validateApplicationsLevelChildrenAST16459(nodes []*Node, lenient bool) ([]string, error) {
	declared := applicationsLevelChildTokens16459()
	if len(declared) == 0 {
		// Schema unreadable: decline to judge rather than refuse every
		// applications config (mirrors #9323/#9552/#16450).
		return nil, nil
	}
	permitted := make(map[string]bool, len(declared))
	for _, tok := range declared {
		permitted[tok] = true
	}
	var warnings []string
	seen := map[string]bool{}
	check := func(tok string) error {
		if tok == "" || permitted[tok] || routingInstanceApplyMetaKeyword9323(tok) {
			return nil
		}
		msg := fmt.Sprintf("applications: unknown child %q (#16459): "+
			"the compiler reads only %s here; remove the typo — the line is dropped and any application it belonged to compiles without it",
			tok, strings.Join(declared, ", "))
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
		return nil
	}
	for _, node := range nodes {
		if node == nil || node.Name() != "applications" {
			continue
		}
		// Packed/elided level: `applications applicaiton app-x ...`
		// as one leaf carries its first statement head on Keys[1].
		if len(node.Keys) >= 2 && len(node.Children) == 0 {
			if node.KeyQuoted(1) || node.KeyBracketed(1) {
				continue
			}
			if err := check(node.Keys[1]); err != nil {
				return warnings, err
			}
			continue
		}
		for _, child := range node.Children {
			if child == nil {
				continue
			}
			name := child.Name()
			if routingInstanceApplyMetaKeyword9323(name) {
				continue
			}
			if err := check(name); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}
