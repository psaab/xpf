package config

import (
	"fmt"
	"strings"
)

// Unknown NAT `match` leaves — #9877.
//
// A NAT rule whose `match` block carries a leaf the compiler does not read — a
// typo'd `soruce-address` beside a valid `source-address` — used to compile as
// if the operator had authored only the surviving dimensions, with no
// operator-facing warning on the tolerant path. The match switches record such
// leaves on the typed rule (NATRule.UnknownMatchLeaves /
// StaticNATRule.UnknownMatchLeaves); this gate binds the record to the harm:
//
//   - strict commit / commit-check: hard-reject naming the dropped leaves.
//     (SchemaValidate's closedWorld match subtrees reject first at the commit
//     boundary; this gate is what rejects direct CompileConfig callers and
//     what gives the tolerant path its warning text.)
//   - lenient load / peer-sync: downgrade to a cfg.Warnings entry PER MARKED
//     RULE (the uniform gates' shared lenientDestNATAddresses flag, #1960
//     no-brick). Enumeration, not first-error: a single warning would leave a
//     second skipped rule — or a widened exemption — silent. Scope expansion
//     shares rule pointers across expanded rule-sets, so the enumerator
//     dedupes by pointer and warns once per authored rule.
//
// Written against the RECORDED drop rather than the AST on purpose: the switch
// that dropped the leaf is the single allowlist, so the gate cannot drift from
// it the way a second AST allowlist could.
//
// Precedence vs #8430: this gate runs FIRST. A typo-ONLY match (`match {
// soruce-address ...; }`) is both unknown-leaf and unconstrained; the
// unknown-leaf diagnosis names the cause while the #8430 text would call it an
// empty match the operator never authored. validateNATRuleMatchConstrainedStrict
// therefore suppresses rules carrying unknown leaves — one mistake, one
// warning per rule — and this gate's message states the unconstrained
// consequence when the surviving match constrains nothing, so the suppression
// loses no information.
//
// Overlap with #9874 (parent ruling: DISARM-WINS): a source rule carrying
// BOTH markers (a typo-only match is also unconstrained) is NOT skipped — it
// ships as the #9874 fail-closed drop tombstone (see
// SourceNATRuleExcludedReason). Unknown operator intent fails closed (deny:
// drop + stop) rather than falling through to subsequent rules. The messages
// below report the ACTUAL disposition per kind, including that a total-loss
// exemption drops (the poison takes effect before `off`) rather than
// exempting.
func validateNATUnknownMatchLeavesStrict(cfg *Config) error {
	if v := enumerateNATUnknownMatchLeaves(cfg); len(v) > 0 {
		return v[0]
	}
	return nil
}

// enumerateNATUnknownMatchLeaves returns one violation per DISTINCT marked
// rule, in walk order (source, destination, static; config order within).
// Strict keeps the first; the tolerant path warns each. Dedupe is by rule
// pointer: scope expansion shares the same *NATRule across every expanded
// (from × to) rule-set, so without it one authored rule would warn once per
// expansion.
func enumerateNATUnknownMatchLeaves(cfg *Config) []error {
	if cfg == nil {
		return nil
	}
	var out []error
	seenNAT := make(map[*NATRule]bool)
	emitNAT := func(kind, ruleSet string, r *NATRule) {
		if r == nil || len(r.UnknownMatchLeaves) == 0 || seenNAT[r] {
			return
		}
		seenNAT[r] = true
		out = append(out, natUnknownMatchLeavesError(kind, ruleSet, r))
	}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, r := range rs.Rules {
			emitNAT("source", rs.Name, r)
		}
	}
	if d := cfg.Security.NAT.Destination; d != nil {
		for _, rs := range d.RuleSets {
			if rs == nil {
				continue
			}
			for _, r := range rs.Rules {
				emitNAT("destination", rs.Name, r)
			}
		}
	}
	seenStatic := make(map[*StaticNATRule]bool)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, r := range rs.Rules {
			if r == nil || len(r.UnknownMatchLeaves) == 0 || seenStatic[r] {
				continue
			}
			seenStatic[r] = true
			out = append(out, natUnknownMatchLeavesStaticError(rs.Name, r))
		}
	}
	return out
}

// natUnknownMatchLeavesError renders the #9877 violation for one source or
// destination rule: the dropped leaves plus the ACTUAL disposition — what the
// dataplane does with this rule, not a generic template. The disposition
// matrix:
//
//   - keyable exemption (off, match survives keyed): installs, wider than
//     authored.
//   - source total-loss (off or not): ships as the #9874 fail-closed drop —
//     matched traffic is dropped and evaluation stops. The poison takes
//     effect before `off` (match_rules.rs), so a total-loss exemption drops
//     rather than exempting.
//   - destination exemption without a key: skipped, reported as unkeyable.
//   - anything else non-off: skipped (not installed).
func natUnknownMatchLeavesError(kind, ruleSet string, r *NATRule) error {
	quoted := make([]string, len(r.UnknownMatchLeaves))
	for i, l := range r.UnknownMatchLeaves {
		quoted[i] = `"` + l + `"`
	}
	constrained := natMatchIsConstrained(r.Match)
	var disposition string
	switch {
	case r.Then.Off && kind == "destination" && !dnatRuleHasDestinationKey(r):
		disposition = "This is an exemption (`off`) whose destination key was dropped: the exemption cannot be keyed so it is not installed (fail-closed)."
	case r.Then.Off && constrained:
		disposition = "This is an exemption (`off`): it installs matching only the surviving dimensions — wider than authored."
	case r.Then.Off:
		// Unconstrained source: a destination-off this empty is unkeyable
		// (caught above), so this arm is source-only. LenientMatchDropped
		// is set (match authored, nothing constrains) and the rule ships.
		disposition = "This is an exemption (`off`) whose surviving match constrains nothing: it ships as a fail-closed drop — matching traffic is dropped and rule evaluation stops (the empty-match poison takes effect before the exemption), NOT exempted."
	case constrained:
		disposition = "The rule no longer matches what was authored; it is not installed (fail-closed)."
	case kind == "source":
		disposition = "The surviving match constrains nothing; the rule ships as a fail-closed drop — matching traffic is dropped and rule evaluation stops (#9874 tombstone)."
	default: // destination/static total-loss: skipped.
		disposition = "The surviving match constrains nothing; the rule is not installed (fail-closed)."
	}
	return fmt.Errorf("security nat %s rule-set %q rule %q: match dropped unknown leaves [%s]. %s (#9877)",
		kind, ruleSet, r.Name, strings.Join(quoted, ", "), disposition)
}

// natUnknownMatchLeavesStaticError renders the #9877 violation for one static
// rule. Static has no exemptions and no #9874 marker: every marked rule is
// skipped.
func natUnknownMatchLeavesStaticError(ruleSet string, r *StaticNATRule) error {
	quoted := make([]string, len(r.UnknownMatchLeaves))
	for i, l := range r.UnknownMatchLeaves {
		quoted[i] = `"` + l + `"`
	}
	var disposition string
	if staticNATMatchIsConstrained(r) {
		disposition = "The rule no longer matches what was authored; it is not installed (fail-closed)."
	} else {
		disposition = "The surviving match constrains nothing; the rule is not installed (fail-closed)."
	}
	return fmt.Errorf("security nat static rule-set %q rule %q: match dropped unknown leaves [%s]. %s (#9877)",
		ruleSet, r.Name, strings.Join(quoted, ", "), disposition)
}

// staticNATMatchIsConstrained reports whether a static NAT rule's compiled match
// carries any criterion. Message nuance only (the #9877 verdict does not depend
// on it): it lets the gate distinguish a partially-lost static match from one
// that constrains nothing.
func staticNATMatchIsConstrained(r *StaticNATRule) bool {
	if r == nil {
		return false
	}
	if r.Match != "" || r.SourceAddress != "" || r.MatchDestinationPort != 0 {
		return true
	}
	if len(r.SourceAddresses) > 0 {
		return true
	}
	// #6673: an empty MatchAddresses entry is a selection, not a prefix.
	for _, a := range r.MatchAddresses {
		if a != "" {
			return true
		}
	}
	return false
}
