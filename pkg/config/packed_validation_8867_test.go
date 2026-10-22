package config

import (
	"strings"
	"testing"
)

// Issue 8867: SchemaValidate walked the UN-NORMALIZED tree, so a typed leaf
// authored in the packed spelling reached commit with no validation at all.
// The compiler normalizes the same pairs and therefore COMPILES their values,
// so the value took effect while its validator never ran.
//
// Measured before the fix, over the validator-bearing typed leaves reachable at
// a pair admitted to compactNormalizeInScope:
//
//	161 leaves: 146 rejected braced and ACCEPTED packed, 15 validated on both
//
// The 15 are why this is a claim about the packed path and not about
// validation in general.

// packedValidation8867 pairs a braced spelling with the packed spelling of the
// same statement. Both must reach the same verdict.
type packedValidation8867 struct {
	name      string
	braced    string
	packed    string
	badValue  string
	goodValue string
}

func packedValidationCases8867() []packedValidation8867 {
	return []packedValidation8867{
		{
			name:      "cos scheduler transmit-rate",
			braced:    "class-of-service { schedulers { be { transmit-rate %s; } } }",
			packed:    "class-of-service { schedulers be transmit-rate %s; }",
			badValue:  "asd",
			goodValue: "1g",
		},
		{
			name:      "cos scheduler priority",
			braced:    "class-of-service { schedulers { be { priority %s; } } }",
			packed:    "class-of-service { schedulers be priority %s; }",
			badValue:  "foo",
			goodValue: "high",
		},
		{
			name:      "applications inactivity-timeout",
			braced:    "applications { application a1 { inactivity-timeout %s; } }",
			packed:    "applications { application a1 inactivity-timeout %s; }",
			badValue:  "notanumber",
			goodValue: "300",
		},
	}
}

func TestPackedSpellingIsValidated8867(t *testing.T) {
	check := func(t *testing.T, text string) error {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
		}
		_, _ = CompileConfigLenient(tree)
		tree2, _ := NewParser(text).Parse()
		return SchemaValidate(tree2)
	}

	for _, c := range packedValidationCases8867() {
		t.Run(c.name, func(t *testing.T) {
			// The braced arm is the reference. If it ever stopped rejecting,
			// the packed assertion below would be measuring nothing.
			if err := check(t, strings.Replace(c.braced, "%s", c.badValue, 1)); err == nil {
				t.Fatalf("braced reference ACCEPTS %q — the packed comparison is vacuous", c.badValue)
			}
			if err := check(t, strings.Replace(c.packed, "%s", c.badValue, 1)); err == nil {
				t.Errorf("packed spelling accepts %q that the braced spelling rejects — the commit gate is bypassable by spelling", c.badValue)
			}
			// NON-VACUITY: the gate must still accept a VALID value in the
			// packed spelling. A fix that rejected everything packed would
			// satisfy the assertion above and break the product.
			if err := check(t, strings.Replace(c.packed, "%s", c.goodValue, 1)); err != nil {
				t.Errorf("packed spelling REJECTS the valid value %q: %v", c.goodValue, err)
			}
		})
	}
}

// SchemaValidate runs on the operator's candidate tree, which the caller
// persists. Folding compact stanzas to validate them must therefore happen on a
// copy: normalizing in place would rewrite the stored configuration as a side
// effect of checking it, silently changing what `show configuration` renders.
func TestValidationDoesNotMutateCallerTree8867(t *testing.T) {
	const text = "class-of-service { schedulers be transmit-rate 1g; }"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs[0])
	}
	before := tree.Format()
	if !strings.Contains(before, "schedulers be transmit-rate") {
		t.Fatalf("fixture is not packed as intended: %q", before)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("valid packed statement rejected: %v", err)
	}
	if after := tree.Format(); after != before {
		t.Errorf("SchemaValidate MUTATED the caller's tree.\n before: %q\n after:  %q", before, after)
	}
}

// THE NEGATIVE CONTROL, NAMED. The census found 15 of 161 leaves already
// validated in BOTH spellings, and that number is what makes the finding a
// claim about the packed path rather than about validation in general. Left as
// a bare count it is asserted rather than auditable, so here they are — every
// one a leaf under an arg-taking named-instance container, which is the shape
// whose packed statement the walk could already reach:
//
//	interface dead-interval        interface hello-interval
//	interface interface-type       interface priority
//	interface retransmit-interval  nat-prefix lifetime
//	nat64prefix lifetime           prefix preferred-lifetime
//	prefix valid-lifetime          qualified-next-hop preference
//	route preference               shaping-rate burst-size
//	static-binding fixed-address   transport protocol
//	unit vlan-id
//
// A reader can re-derive the split by running the census in the issue rather
// than taking 146/15 on trust.
//
// AND THE COUNT IS NOT COMPARABLE TO ITS NEIGHBOURS, which is how a reader
// mistakes one for another. Three different predicates of the same order:
//
//	311  validators ARMED per the #8853 inert-validator ratchet, counted
//	     against isTypedLeaf() on the BRACED path — it counts neither path's
//	     behaviour on the packed spelling
//	182  admitted pairs carrying a validator (lane-8526's predicate)
//	161  validator-bearing typed leaves reachable at an admitted pair, of
//	     which 146 were bypassable (this cell's predicate)
//
// None of the three is a subset of another by construction.

// A cfg/refs-dependent validator is where folding is most likely to change
// behaviour, because collectSchemaRefs runs on the tree AFTER normalization:
// a definition authored in the packed spelling could start satisfying a
// reference that previously failed. Measured, with a live control — it does
// NOT, because `class-of-service forwarding-classes` is not an admitted pair,
// so the definition is still dropped and rejecting the reference stays
// consistent with the compile.
//
// The control is the point. Without the "no definition" row, three "accepted"
// results would be indistinguishable from a validator that never fired — which
// is exactly what the first version of this probe did, using a path with no
// treeValidator on it at all.
func TestCrossReferenceValidatorUnaffectedByFolding8867(t *testing.T) {
	const ref = "firewall { family inet { filter f1 { term t1 { then { forwarding-class xpffc; } } } } }"
	rejects := func(text string) bool {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse: %v", perrs[0])
		}
		_, _ = CompileConfigLenient(tree)
		tree2, _ := NewParser(text).Parse()
		return SchemaValidate(tree2) != nil
	}

	// LIVE CONTROL: with no definition anywhere, the reference MUST reject.
	// If this ever stops rejecting, every row below is measuring nothing.
	if !rejects(ref) {
		t.Fatal("the cross-reference validator did not fire on an undefined forwarding class — " +
			"this cell cannot distinguish anything until it does")
	}
	if rejects("class-of-service { forwarding-classes { queue 0 xpffc; } }\n" + ref) {
		t.Error("a BRACED forwarding-class definition failed to satisfy the reference")
	}
	if !rejects("class-of-service forwarding-classes queue 0 xpffc;\n" + ref) {
		t.Error("a PACKED forwarding-class definition now satisfies the reference. That is a " +
			"behaviour change from folding: it may well be correct, but it is not what this " +
			"change measured, and the admission that caused it needs its own adjudication")
	}
}
