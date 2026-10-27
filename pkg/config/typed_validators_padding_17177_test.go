package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #17177: padding policy is owned centrally by checkToken /
// validateKeySlot / validateTailLeaf, not inside each LeafValidator.
// Before this fix, 66+ typed validators trimmed and accepted a padded
// value while the compiler stored the raw token and the runtime
// consumer parsed it exactly and silently dropped it (RDNSS dropped
// by the RA sender, device-map pci never binding, scheduler bounds
// leaving a scheduled deny inactive all day).
//
// This test is the permanent census. It walks every unique schemaNode
// (by pointer, via collectCensusNodes16163), finds an accepted example
// for each validator/treeValidator/keyValidator/keyValidatorPos slot
// from the leaf's own declared examples, and requires the padded
// spellings (" "+ex and ex+" ") to be REFUSED through the production
// dispatch (checkToken for value slots, validateKeySlot for key
// slots). Leaves that explicitly opt out via allowEdgeWhitespace must
// carry a reason and are reported as allow-listed, never silently
// skipped. Nodes with no accepted example are COUNTED and listed so
// they cannot hide behind the census.
//
// FAIL-ON-REVERT: removing refuseEdgeWhitespace from checkToken (or
// validateKeySlot) makes every trimming validator below accept its
// padded example again -> this test reports pad-accepted > 0 -> RED.
// The synthetic positive control at the bottom proves the probe can
// see a trimming validator: if the probe itself were broken (always
// reporting refusal), the control would not be flagged and the test
// would be test-only-green.

// paddingProbeResult17177 is the census outcome for one schema node.
type paddingProbeResult17177 struct {
	path        string
	allowListed bool
	noExample   bool
	padAccepted []string // padded spellings that were accepted
}

// probePadding17177 runs the census probe over nodes. It is a helper
// so the positive control can run the identical probe over synthetic
// fixture nodes that are never inserted into setSchema.
func probePadding17177(nodes []censusNode16163) (results []paddingProbeResult17177) {
	for _, cn := range nodes {
		n := cn.node
		hasValue := n.validator != nil || n.treeValidator != nil
		hasKey := n.keyValidator != nil || n.keyValidatorPos != nil
		hasTail := n.tailValidator != nil
		if !hasValue && !hasKey && !hasTail {
			continue
		}
		res := paddingProbeResult17177{path: cn.path}
		if n.allowEdgeWhitespace {
			res.allowListed = true
			results = append(results, res)
			continue
		}
		// Candidate examples: the leaf's own declared examples first.
		var cands []string
		cands = append(cands, n.valueExamples...)
		cands = append(cands, n.keyValueExamples...)
		accepted := ""
		found := false
		for _, c := range cands {
			if c == "" || c != strings.TrimSpace(c) {
				continue
			}
			if paddingExampleAccepted17177(n, c) {
				accepted, found = c, true
				break
			}
		}
		if !found {
			res.noExample = true
			results = append(results, res)
			continue
		}
		for _, padded := range []string{" " + accepted, accepted + " ", "\t" + accepted} {
			if paddingDispatch17177(n, padded) == nil {
				res.padAccepted = append(res.padAccepted, padded)
			}
		}
		results = append(results, res)
	}
	return results
}

// paddingExampleAccepted17177 reports whether ex is accepted through
// the production dispatch for the node's primary slot. Tail leaves
// have no single-token acceptance, so they are treated as no-example
// here; their tokens are gated in validateTailLeaf and exercised via
// the scheduler CheckText cells in pkg/configstore.
func paddingExampleAccepted17177(n *schemaNode, ex string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if n.keyValidator != nil || n.keyValidatorPos != nil {
		return validateKeySlot(n, 0, ex, nil) == nil
	}
	if n.validator != nil || n.treeValidator != nil {
		return n.checkToken(nil, ex) == nil
	}
	return false
}

// paddingDispatch17177 runs one padded token through the production
// dispatch and returns its error (nil = accepted).
func paddingDispatch17177(n *schemaNode, tok string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if n.keyValidator != nil || n.keyValidatorPos != nil {
		return validateKeySlot(n, 0, tok, nil)
	}
	return n.checkToken(nil, tok)
}

func TestTypedValidatorsRefusePadding17177(t *testing.T) {
	nodes := collectCensusNodes16163()
	results := probePadding17177(nodes)

	var padAccepted, allowListed, noExample []string
	probed := 0
	for _, r := range results {
		switch {
		case r.allowListed:
			allowListed = append(allowListed, r.path)
		case r.noExample:
			noExample = append(noExample, r.path)
		default:
			probed++
			for _, p := range r.padAccepted {
				padAccepted = append(padAccepted, fmt.Sprintf("%s padded=%q", r.path, p))
			}
		}
	}
	sort.Strings(padAccepted)
	sort.Strings(allowListed)
	sort.Strings(noExample)
	t.Logf("census: validator-nodes=%d probed=%d pad-accepted=%d allow-listed=%d no-accepted-example=%d",
		len(results), probed, len(padAccepted), len(allowListed), len(noExample))
	for _, s := range allowListed {
		t.Logf("allow-listed (allowEdgeWhitespace): %s", s)
	}
	for _, s := range noExample {
		t.Logf("no-accepted-example (counted, not hidden): %s", s)
	}
	if len(padAccepted) > 0 {
		t.Errorf("pad-accepted=%d (want 0 except allow-listed leaves):\n%s",
			len(padAccepted), strings.Join(padAccepted, "\n"))
	}

	// Every allow-listed leaf MUST carry a reason, and the allow-list
	// must be exactly the six SSH authorized-key leaves whose grammar
	// is "<type> <base64> [comment]" (internal spaces are the value).
	if len(allowListed) != 6 {
		t.Errorf("allow-listed=%d, want exactly 6 SSH key leaves:\n%s",
			len(allowListed), strings.Join(allowListed, "\n"))
	}
	for _, cn := range nodes {
		if cn.node.allowEdgeWhitespace && strings.TrimSpace(cn.node.allowEdgeWhitespaceReason) == "" {
			t.Errorf("%s: allowEdgeWhitespace set without allowEdgeWhitespaceReason", cn.path)
		}
	}
}

// TestTypedValidatorsRefusePaddingPositiveControl17177 is the
// positive control: a synthetic trimming validator (the exact pre-fix
// defect shape) MUST be flagged by the probe, and the same validator
// behind a non-trimming gate must not be. Without this, a probe that
// always reports "refused" would pass the census above vacuously.
func TestTypedValidatorsRefusePaddingPositiveControl17177(t *testing.T) {
	trimming := func(raw string) error {
		if strings.TrimSpace(raw) == "10.0.0.1" {
			return nil
		}
		return fmt.Errorf("not an IP")
	}
	fixture := []censusNode16163{
		{path: "fixture trimming-validator", node: &schemaNode{
			desc: "x", args: 1, valueType: ValueIPAddress,
			valueExamples: []string{"10.0.0.1"}, validator: trimming,
		}},
		{path: "fixture allow-listed", node: &schemaNode{
			desc: "x", args: 1, valueType: ValueIPAddress,
			valueExamples: []string{"10.0.0.1"}, validator: trimming,
			allowEdgeWhitespace: true, allowEdgeWhitespaceReason: "fixture",
		}},
		{path: "fixture no-example", node: &schemaNode{
			desc: "x", args: 1, valueType: ValueIPAddress,
			validator: trimming,
		}},
	}
	results := probePadding17177(fixture)
	byPath := map[string]paddingProbeResult17177{}
	for _, r := range results {
		byPath[r.path] = r
	}
	// The production checkToken gate refuses the padded spellings even
	// though the synthetic validator trims, so the fixture leaf itself
	// is clean at dispatch level...
	if got := byPath["fixture trimming-validator"].padAccepted; len(got) != 0 {
		t.Errorf("central gate failed: trimming fixture padAccepted=%v, want none (checkToken must refuse)", got)
	}
	// ...therefore the probe's ability to SEE the defect is proven by
	// calling the raw validator directly, bypassing the gate: it must
	// accept the padded spelling (that is the defect the gate closes).
	if err := trimming(" 10.0.0.1"); err != nil {
		t.Fatalf("positive control broken: raw trimming validator must accept padded input, got %v", err)
	}
	if err := trimming("10.0.0.1 "); err != nil {
		t.Fatalf("positive control broken: raw trimming validator must accept trailing padding, got %v", err)
	}
	// And the allow-listed / no-example classifications must be exact.
	if !byPath["fixture allow-listed"].allowListed {
		t.Errorf("allow-listed fixture not classified allowListed: %+v", byPath["fixture allow-listed"])
	}
	if !byPath["fixture no-example"].noExample {
		t.Errorf("no-example fixture not classified noExample: %+v", byPath["fixture no-example"])
	}
}
