package config

import (
	"fmt"
	"strings"
	"testing"
)

// White-box tests for the generic walker's special-case rows that PR 1's
// typed schedulers leaves don't themselves exercise. These pin the walker
// contract (the schema-feature→AST-match table in the #1319 plan §6.4) so
// PR 2..N can type `multi` value-tail leaves and rely on the behaviour.

// rangeWalkTree builds an AST + a synthetic typed `multi && children==nil`
// leaf, then runs the leaf validator path directly. We construct the leaf
// schema in-test rather than typing a production leaf (PR 1 ships no typed
// multi leaf), so the contract is verified without expanding scope.
func runMultiValueTail(t *testing.T, leafKeys []string) error {
	t.Helper()
	// Typed multi leaf accepting bare integers in [0..65535] (port-like),
	// no schema children → value-tail/range shape. rangeSeparator opts it
	// in to `<a> to <b>` range handling — this synthetic leaf models a
	// port-range leaf, the only class for which `to` is a separator
	// (#4556 L-01).
	leafSchema := &schemaNode{
		args:           1,
		multi:          true,
		valueType:      ValueInteger,
		validator:      ValidateInteger(0, 65535),
		rangeSeparator: true,
	}
	parent := &schemaNode{children: map[string]*schemaNode{
		"destination-port": leafSchema,
	}}
	node := &Node{Keys: leafKeys, IsLeaf: true}
	return walkSchemaNode(node, parent, nil, nil, []*Node{node}, false)
}

func TestWalker_MultiValueTail_AcceptsRange(t *testing.T) {
	// `destination-port 20000 to 20003`: both endpoints validated, `to`
	// treated as a separator.
	if err := runMultiValueTail(t, []string{"destination-port", "20000", "to", "20003"}); err != nil {
		t.Fatalf("expected valid port range, got %v", err)
	}
}

func TestWalker_MultiValueTail_AcceptsSingle(t *testing.T) {
	if err := runMultiValueTail(t, []string{"destination-port", "20000"}); err != nil {
		t.Fatalf("expected valid single port, got %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsBadEndpoint(t *testing.T) {
	// 99999 is out of [0..65535]; the range branch validates every value
	// token, so the high endpoint must be rejected (not silently passed as
	// an "unknown modifier" or ignored).
	err := runMultiValueTail(t, []string{"destination-port", "20000", "to", "99999"})
	if err == nil {
		t.Fatal("expected error for out-of-range high endpoint")
	}
	if !strings.Contains(err.Error(), "99999") {
		t.Fatalf("error should quote the bad endpoint: %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsBadLowEndpoint(t *testing.T) {
	err := runMultiValueTail(t, []string{"destination-port", "abc", "to", "20003"})
	if err == nil {
		t.Fatal("expected error for non-integer low endpoint")
	}
	if !strings.Contains(err.Error(), "abc") {
		t.Fatalf("error should quote the bad endpoint: %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsMissingValue(t *testing.T) {
	err := runMultiValueTail(t, []string{"destination-port"})
	if err == nil {
		t.Fatal("expected error for missing value")
	}
	if !strings.Contains(err.Error(), "missing value") {
		t.Fatalf("error should describe missing value: %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsDanglingSeparator(t *testing.T) {
	for _, keys := range [][]string{
		{"destination-port", "to"},
		{"destination-port", "to", "20000"},
		{"destination-port", "20000", "to"},
		{"destination-port", "20000", "to", "to", "20003"},
	} {
		err := runMultiValueTail(t, keys)
		if err == nil {
			t.Fatalf("expected error for malformed range %v", keys)
		}
		if !strings.Contains(err.Error(), "missing value") {
			t.Fatalf("error should describe missing value for %v: %v", keys, err)
		}
	}
}

// runMultiValueNoRange drives validateMultiValueLeaf on a typed multi leaf
// that does NOT opt in to rangeSeparator (the class of every production leaf
// that actually reaches this walker — name-server, virtual-address,
// dns-server-address, session-log flags). Its validator accepts any non-empty
// token so a value literally spelled "to" is a legitimate member, letting us
// pin that `to` is NOT special-cased as a range separator here (#4556 L-01).
func runMultiValueNoRange(t *testing.T, leafKeys []string) error {
	t.Helper()
	leafSchema := &schemaNode{
		args:      1,
		multi:     true,
		valueType: ValueIdentifier,
		validator: func(raw string) error {
			if raw == "" {
				return fmt.Errorf("empty value")
			}
			return nil
		},
	}
	parent := &schemaNode{children: map[string]*schemaNode{
		"member": leafSchema,
	}}
	node := &Node{Keys: leafKeys, IsLeaf: true}
	return walkSchemaNode(node, parent, nil, nil, []*Node{node}, false)
}

// TestWalker_MultiValueTail_NonRangeToNotFalseRejected is the #4556 L-01
// RED-on-revert discriminator: on a leaf WITHOUT rangeSeparator, a value token
// literally "to" is validated as an ordinary member and accepted, not treated
// as a range separator. On revert of the gate, `to` is caught as a separator
// so `["to"]` and `["a","to"]` fail with "missing value" → RED.
func TestWalker_MultiValueTail_NonRangeToNotFalseRejected(t *testing.T) {
	for _, keys := range [][]string{
		{"member", "to"},
		{"member", "alpha", "to"},
		{"member", "to", "beta"},
	} {
		if err := runMultiValueNoRange(t, keys); err != nil {
			t.Fatalf("non-range leaf with member %v must accept a literal \"to\" value, got %v", keys, err)
		}
	}
}

// --- #4313 closed-world mechanism white-box tests ---
//
// PR-A lands the per-subtree closed-world MECHANISM only; no production
// schemaNode sets closedWorld yet, so these synthetic subtrees are the
// sole coverage. Build an OPEN-WORLD root with two container children —
// one flagged closedWorld, one left default — each modeling a single
// child keyword, and drive the generic walker from the top-level open
// entry (closed=false) exactly as SchemaValidate does. This exercises the
// closed-world inheritance fold (walkSchemaNode's childClosed) end to end.

func runClosedWorldWalk(t *testing.T, top *Node) error {
	t.Helper()
	root := &schemaNode{children: map[string]*schemaNode{
		// closedsub opts in: unmodeled children are rejected. Its modeled
		// child container `sub` does NOT set the flag — it relies on
		// inheritance to stay closed.
		"closedsub": {
			closedWorld: true,
			children: map[string]*schemaNode{
				"known": {},
				"sub":   {children: map[string]*schemaNode{"deep": {}}},
			},
		},
		// opensub keeps the default (open-world): unmodeled children are
		// silently accepted, matching every production subtree in PR-A.
		"opensub": {
			children: map[string]*schemaNode{"known": {}},
		},
	}}
	return walkSchemaChildren([]*Node{top}, root, nil, nil, false)
}

func TestClosedWorld_RejectsUnmodeledUnderClosedSubtree(t *testing.T) {
	// The ONE behavioural change: an unmodeled keyword under a closedWorld
	// subtree is rejected instead of silently dropped. RED on revert of the
	// gate (returns nil, silent-accept).
	top := &Node{Keys: []string{"closedsub"}, Children: []*Node{{Keys: []string{"bogus"}}}}
	err := runClosedWorldWalk(t, top)
	if err == nil {
		t.Fatal("expected rejection of unmodeled keyword under closed-world subtree")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error should name the keyword and closed-world: %v", err)
	}
}

func TestClosedWorld_AcceptsModeledUnderClosedSubtree(t *testing.T) {
	// Only UNMODELED keywords are rejected — a modeled leaf under the same
	// closed-world subtree still validates.
	top := &Node{Keys: []string{"closedsub"}, Children: []*Node{{Keys: []string{"known"}}}}
	if err := runClosedWorldWalk(t, top); err != nil {
		t.Fatalf("modeled keyword under closed-world subtree must be accepted: %v", err)
	}
}

func TestClosedWorld_SilentlyAcceptsUnmodeledUnderOpenSubtree(t *testing.T) {
	// The default (closedWorld=false) subtree keeps pre-#4313 behaviour: an
	// unmodeled keyword is silently accepted (returns nil). Same input shape
	// as the closed subtree above, opposite disposition, decided solely by
	// the closedWorld flag — this is the RED-on-revert discriminator and the
	// proof that no open-world (i.e. every production) subtree is affected.
	top := &Node{Keys: []string{"opensub"}, Children: []*Node{{Keys: []string{"bogus"}}}}
	if err := runClosedWorldWalk(t, top); err != nil {
		t.Fatalf("unmodeled keyword under open-world subtree must be silently accepted: %v", err)
	}
}

func TestClosedWorld_InheritsToDescendants(t *testing.T) {
	// closedWorld is set on `closedsub`; its modeled child container `sub`
	// does NOT set it. Closed-world is inherited down every level, so an
	// unmodeled grandchild is still rejected while the modeled one passes.
	reject := &Node{Keys: []string{"closedsub"}, Children: []*Node{
		{Keys: []string{"sub"}, Children: []*Node{{Keys: []string{"nope"}}}},
	}}
	if err := runClosedWorldWalk(t, reject); err == nil {
		t.Fatal("closed-world must inherit into modeled descendant containers")
	}
	accept := &Node{Keys: []string{"closedsub"}, Children: []*Node{
		{Keys: []string{"sub"}, Children: []*Node{{Keys: []string{"deep"}}}},
	}}
	if err := runClosedWorldWalk(t, accept); err != nil {
		t.Fatalf("modeled grandchild under inherited closed-world must pass: %v", err)
	}
}
