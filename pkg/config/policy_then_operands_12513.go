package config

import (
	"fmt"
	"strconv"
)

// Term-line `then` operands for the value-carrying actions beyond the #12070
// next-hop/prepend pair (#12513). parsePolicyTermInlineKeys hands
// `term t then <action> <value>` to the action's operand case, keeps evidence
// for operands its typed field cannot hold, and the compiled-term gate
// validates both the evidence and the typed fields with the term-level
// `then` schema validators, so every spelling meets the same checks.

// policyTermThenValueActions12513 names the value-carrying `then` actions
// whose term-line spelling the inline dispatch hands to their operand cases.
// next-hop and as-path-prepend keep their #12070 dispatch.
var policyTermThenValueActions12513 = map[string]bool{
	"community": true, "load-balance": true, "local-preference": true,
	"metric": true, "metric-type": true, "origin": true,
}

// policyTermMainSwitchKeyword12513 reports whether the main switch of
// parsePolicyTermInlineKeys interprets tok itself: a clause or then-action
// keyword, or a from-match word.
func policyTermMainSwitchKeyword12513(tok string) bool {
	return policyTermThenInlineKeywords[tok] || policyTermFromMatchInlineKeywords12070[tok]
}

// policyThenOperandMissing12513 checks the operand slot of the value-carrying
// action at keys[at]; for community it is the slot after an add, delete, or
// set operation. It returns the token in that slot ("" past the end) and
// whether the slot holds no operand: it is empty, or it holds a word the main
// switch interprets.
func policyThenOperandMissing12513(keys []string, at int) (string, bool) {
	slot := at + 1
	if keys[at] == "community" && slot < len(keys) {
		switch keys[slot] {
		case "add", "delete", "set":
			slot++
		}
	}
	if slot >= len(keys) {
		return "", true
	}
	return keys[slot], policyTermMainSwitchKeyword12513(keys[slot])
}

// recordInvalidPolicyThenOperand12513 keeps the first operand the inline
// parser cannot store for validatePolicyThenOperandsStrict.
func recordInvalidPolicyThenOperand12513(term *PolicyTerm, leaf, value string) {
	if term.invalidThenOperand12513 == "" {
		term.invalidThenOperand12513 = leaf
		term.invalidThenOperandValue12513 = value
	}
}

// policyThenScalarOperand12513 consumes the token after the scalar `then`
// action at keys[*i], whatever it is, and records an operand missing at the
// end of the keys.
func policyThenScalarOperand12513(term *PolicyTerm, keys []string, i *int) (string, bool) {
	if *i+1 >= len(keys) {
		recordInvalidPolicyThenOperand12513(term, keys[*i], "")
		return "", false
	}
	*i++
	return keys[*i], true
}

// readPolicyThenCommunityValues12513 appends the `then community` value at
// keys[start] to dst and, when that value opens a bracketed list, the rest of
// the list: reading one token dropped every later member (#2902). A later
// member the main switch interprets ends the list unconsumed, so a bracketed
// `reject` keeps its action on tolerant paths, and is recorded for strict
// rejection. It returns the values and the index of the last one consumed.
func readPolicyThenCommunityValues12513(term *PolicyTerm, dst, keys []string, bracketed []bool, start int) ([]string, int) {
	dst, end := append(dst, keys[start]), start
	if start >= len(bracketed) || !bracketed[start] {
		return dst, end
	}
	for next := start + 1; next < len(keys) && next < len(bracketed) && bracketed[next]; next++ {
		if policyTermMainSwitchKeyword12513(keys[next]) {
			recordInvalidPolicyThenOperand12513(term, "community", keys[next])
			break
		}
		dst, end = append(dst, keys[next]), next
	}
	return dst, end
}

// validatePolicyThenValueOperands12513 is the #12513 half of
// validatePolicyThenOperandsStrict for one compiled term. It rejects operand
// evidence kept by parsePolicyTermInlineKeys, then applies the schema
// validators to the compiled local-preference, metric, metric-type, and
// origin values.
func validatePolicyThenValueOperands12513(cfg *Config, policy string, term *PolicyTerm) error {
	if leaf := term.invalidThenOperand12513; leaf != "" {
		value := term.invalidThenOperandValue12513
		return fmt.Errorf(
			"policy-options policy-statement %q term %q then %s: invalid value %q: %s",
			policy, term.Name, leaf, value, policyThenOperandReason12513(cfg, leaf, value))
	}
	if term.HasLocalPreference {
		if err := checkPolicyThenOperand12513(cfg, policy, term.Name, "local-preference", strconv.Itoa(term.LocalPreference)); err != nil {
			return err
		}
	}
	if term.HasMetric {
		if err := checkPolicyThenOperand12513(cfg, policy, term.Name, "metric", strconv.Itoa(term.Metric)); err != nil {
			return err
		}
	}
	if term.MetricType != 0 {
		if err := checkPolicyThenOperand12513(cfg, policy, term.Name, "metric-type", strconv.Itoa(term.MetricType)); err != nil {
			return err
		}
	}
	if term.Origin != "" {
		if err := checkPolicyThenOperand12513(cfg, policy, term.Name, "origin", term.Origin); err != nil {
			return err
		}
	}
	return nil
}

func checkPolicyThenOperand12513(cfg *Config, policy, termName, leaf, value string) error {
	validate := policyThenLeafValidator12513(leaf)
	if validate == nil {
		return fmt.Errorf(
			"policy-options policy-statement %q term %q then %s: the schema declares no validator for this leaf",
			policy, termName, leaf)
	}
	if err := validate(value, cfg); err != nil {
		return fmt.Errorf(
			"policy-options policy-statement %q term %q then %s: invalid value %q: %v",
			policy, termName, leaf, value, err)
	}
	return nil
}

// policyThenOperandReason12513 explains kept operand evidence. Typed leaves
// reuse their schema validator, so the reason matches the child spelling's.
func policyThenOperandReason12513(cfg *Config, leaf, value string) string {
	if validate := policyThenLeafValidator12513(leaf); validate != nil {
		if err := validate(value, cfg); err != nil {
			return err.Error()
		}
	}
	if value == "" {
		return "missing value"
	}
	return fmt.Sprintf("%q is a policy keyword, not a %s value", value, leaf)
}

// policyThenLeafValidator12513 returns the schema validator of a term-level
// `then` leaf (nil for an untyped or unknown leaf).
func policyThenLeafValidator12513(leaf string) LeafValidator {
	if node := resolveSchemaChild(policyTermThenSchema8939(), leaf); node != nil {
		return node.validator
	}
	return nil
}
