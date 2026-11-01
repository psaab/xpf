package nftables

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #18746: the #16841 zero-hop-limit local DROP (EmitZeroHopLimitLocalDrop)
// heads every input chain xpf replaces. It filters only IPv6 hop-limit-0
// packets to local or anycast destinations, so it says nothing about whether a
// table enforces host-inbound policy. TableEnforcing and TableDropsInput
// count rules and DROP verdicts, so they must not count it.
//
// The match is EXACT: the full expression sequence, every field, and the
// anonymous set's exact contents. Only that rule is excluded. Misreading in
// the other direction, a real enforcing DROP taken for the zero-hop rule,
// would read as drift and trigger a reinstall. That is the fail-safe
// direction, so the matcher prefers exactness over breadth: any near-miss
// counts as a real rule.

// zeroHopLimitLocalDropKernelNames is the kernel's expression list for the
// zero-hop rule, as readRuleExprNames reports it. The verdict is an immediate.
var zeroHopLimitLocalDropKernelNames = []string{
	"meta", "cmp", "payload", "cmp", "fib", "byteorder", "lookup", "immediate",
}

// isZeroHopLimitLocalDropRule reports whether rule is EXACTLY the #16841
// zero-hop rule. rule.Exprs is GetRules' typed decode, which lacks the
// byteorder: v0.3.0 drops it. kernelNames is the kernel's expression list for
// the same rule. setElements reads a set of the rule's table by name.
func isZeroHopLimitLocalDropRule(rule *nftables.Rule, kernelNames []string, setElements func(name string) ([]nftables.SetElement, error)) (bool, error) {
	if !slices.Equal(kernelNames, zeroHopLimitLocalDropKernelNames) {
		return false, nil
	}
	// The typed decode: the guard, the hop-limit match, the fib, (byteorder
	// dropped), the lookup, the DROP verdict.
	want := append(append(nfprotoGuard(famV6), hopLimitZeroExprs()...), fibDaddrAddrType())
	if len(rule.Exprs) != len(want)+2 {
		return false, nil
	}
	fam := byte(nftables.TableFamilyINet)
	for i, w := range want {
		wantBytes, err := expr.Marshal(fam, w)
		if err != nil {
			return false, fmt.Errorf("marshal zero-hop expression %d: %w", i, err)
		}
		gotBytes, err := expr.Marshal(fam, rule.Exprs[i])
		if err != nil {
			return false, fmt.Errorf("marshal installed expression %d: %w", i, err)
		}
		if !bytes.Equal(wantBytes, gotBytes) {
			return false, nil
		}
	}
	lookup, ok := rule.Exprs[len(want)].(*expr.Lookup)
	if !ok || lookup.SourceRegister != 1 || lookup.IsDestRegSet || lookup.DestRegister != 0 || lookup.Invert ||
		!strings.HasPrefix(lookup.SetName, "__set") {
		return false, nil
	}
	verdict, ok := rule.Exprs[len(want)+1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop || verdict.Chain != "" {
		return false, nil
	}
	elements, err := setElements(lookup.SetName)
	if err != nil {
		return false, fmt.Errorf("read zero-hop set %s: %w", lookup.SetName, err)
	}
	return setElementKeysEqual(elements, fibLocalOrAnycastElements()), nil
}

// setElementKeysEqual reports whether two set-element lists hold exactly the
// same keys, in any order, with no interval or verdict data.
func setElementKeysEqual(got, want []nftables.SetElement) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(want))
	for _, e := range want {
		seen[string(e.Key)]++
	}
	for _, e := range got {
		if e.IntervalEnd || len(e.KeyEnd) != 0 || e.VerdictData != nil || len(e.Val) != 0 {
			return false
		}
		k := string(e.Key)
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}

// inputRulesBeyondZeroHop returns the rules of tbl's input chain other than the
// exact #16841 zero-hop rule. Every rule handle must appear in the kernel
// expression dump. If one does not, it is an error: unreadable proves nothing.
func inputRulesBeyondZeroHop(c *nftables.Conn, tbl *nftables.Table, chain *nftables.Chain, rules []*nftables.Rule) ([]*nftables.Rule, error) {
	namesByHandle, err := readRuleExprNames(c, tbl, chain.Name)
	if err != nil {
		return nil, fmt.Errorf("read %s %s rule expressions: %w", tbl.Name, chain.Name, err)
	}
	setElements := func(name string) ([]nftables.SetElement, error) {
		set, err := c.GetSetByName(tbl, name)
		if err != nil {
			return nil, err
		}
		return c.GetSetElements(set)
	}
	out := make([]*nftables.Rule, 0, len(rules))
	for _, rule := range rules {
		names, ok := namesByHandle[rule.Handle]
		if !ok {
			return nil, fmt.Errorf("%s %s rule handle %d absent from the expression dump", tbl.Name, chain.Name, rule.Handle)
		}
		zeroHop, err := isZeroHopLimitLocalDropRule(rule, names, setElements)
		if err != nil {
			return nil, err
		}
		if !zeroHop {
			out = append(out, rule)
		}
	}
	return out, nil
}
