package config

import (
	"fmt"
	"strings"
	"testing"
)

// #6693 — five NAT `match` address arms dropped every prefix past the first in
// the MIXED AST shape.
//
// THE SHAPE, and why it went unfound. The arms read the node with an either/or:
// `Keys[1:]` OR the children, never both. That is correct for every spelling
// that puts the whole list in ONE slot — bracket, compact tail, block, repeated
// siblings — which is exactly the set a previous investigation enumerated
// before recording a NEGATIVE RESULT ("the shape is not reachable from any
// config spelling I can author", and "a fix would be unfalsifiable").
//
// The unenumerated spelling is a value in the identifier slot BESIDE a block:
//
//	match { source-address 10.0.0.0/8 { 192.0.2.0/24; } }
//	  -> Keys=["source-address","10.0.0.0/8"], Children=[["192.0.2.0/24"]]
//
// parseStatement's `case TokenLBrace` keeps every key token AND the block, so
// `len(m.Keys) >= 2` is true and the `else if` is structurally unreachable.
// It commits CLEAN — these leaves are untyped (`args: 1, multi: true,
// children: nil`, no validator) in an open-world subtree, so the schema walker
// has nothing to reject — and `192.0.2.0/24` never reaches the dataplane.
//
// It is NOT reachable from flat-set, which is why the earlier enumeration was
// consistent with itself: for a `multi` leaf with no children SetPath always
// emits a LEAF at the same level and never descends, so the flat replay can
// only ever produce packed Keys or sibling leaves. Hierarchical text — a config
// file, `load merge`, `load override`, a peer-synced tree — reaches it trivially.
//
// This is the #4121 defect, fixed there for `security policies … match`, at five
// NAT sites that were not swept at the time. The four SIBLING arms in the same
// switch already read both slots.

// natMixed6693 renders one NAT rule whose named match leaf carries v1 in the
// identifier slot and v2 in a block.
func natMixed6693(natType, leaf, v1, v2 string) string {
	return natRuleBody6693(natType, leaf, fmt.Sprintf("%s %s { %s; }", leaf, v1, v2))
}

// natRuleBody6693 renders one NAT rule of the given kind whose `match` body is
// exactly matchBody. leaf names the arm under test, which is only used to decide
// whether the completing sibling below would collide with it.
func natRuleBody6693(natType, leaf, matchBody string) string {
	var from string
	switch natType {
	case "source":
		from = "from zone trust;\n                to zone untrust;"
	case "destination":
		from = "from zone untrust;"
	default:
		from = "from zone untrust;"
	}
	then := "then { source-nat interface; }"
	switch natType {
	case "destination":
		then = "then { destination-nat pool p1; }"
	case "static":
		then = "then { static-nat prefix 10.0.1.1/32; }"
	}
	extra := ""
	if natType == "destination" {
		extra = `
    nat { destination { pool p1 { address 10.0.1.1/32; } } }`
	}
	// A static-NAT rule with no `match destination-address` is rejected at strict
	// commit by #7216 ("the selected external prefix is MISSING"), regardless of
	// anything this fixture is testing. Left off, the strict leg of every static
	// subtest would fail for a reason that has nothing to do with the mixed
	// shape — and, worse, in the MALFORMED-tail subtest it would produce a
	// rejection that looks like the gate firing on the tail. That is exactly the
	// "a strict gate firing first can mask an unvalidated tail" hazard, so the
	// rule is completed with a valid, unrelated external prefix.
	sibling := ""
	if natType == "static" && leaf != "destination-address" {
		sibling = " destination-address 198.51.100.1/32;"
	}
	return fmt.Sprintf(`
security {
    zones { security-zone trust; security-zone untrust; }%s
    nat {
        %s {
            rule-set rs1 {
                %s
                rule r1 {
                    match { %s%s }
                    %s
                }
            }
        }
    }
}
`, extra, natType, from, matchBody, sibling, then)
}

func compileNAT6693(t *testing.T, text string) *Config {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v\n%s", errs, text)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, text)
	}
	return cfg
}

// natArm6693 names one of the five arms, the compiled list it feeds, and the
// singular back-compat field it also sets. It is a package-level table so every
// test below iterates the SAME five arms — a sixth arm added to one test and not
// the others would be a coverage claim that is only true of one property.
type natArm6693 struct {
	name    string
	natType string
	leaf    string
	// list returns the compiled slice this arm accumulates into.
	list func(*Config) []string
}

func natArms6693() []natArm6693 {
	return []natArm6693{
		{
			name: "source-nat/source-address", natType: "source", leaf: "source-address",
			list: func(c *Config) []string { return c.Security.NAT.Source[0].Rules[0].Match.SourceAddresses },
		},
		{
			name: "source-nat/destination-address", natType: "source", leaf: "destination-address",
			list: func(c *Config) []string { return c.Security.NAT.Source[0].Rules[0].Match.DestinationAddresses },
		},
		{
			name: "destination-nat/destination-address", natType: "destination", leaf: "destination-address",
			list: func(c *Config) []string {
				return c.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationAddresses
			},
		},
		{
			name: "destination-nat/source-address", natType: "destination", leaf: "source-address",
			list: func(c *Config) []string { return c.Security.NAT.Destination.RuleSets[0].Rules[0].Match.SourceAddresses },
		},
		{
			name: "static-nat/source-address", natType: "static", leaf: "source-address",
			list: func(c *Config) []string { return c.Security.NAT.Static[0].Rules[0].SourceAddresses },
		},
	}
}

// TestEveryNATMatchArmReadsBothSlots_6693 covers all five arms, one subtest
// each, so a partial revert names WHICH arm regressed rather than failing one
// lump assertion.
//
// BOTH compile paths, per arm, because the issue asks for the tolerant path to
// be checked SEPARATELY: a strict gate firing first would mask an unvalidated
// tail, and conversely a fix proven only on the lenient path says nothing about
// what an operator's `commit` produces. Here the mixed shape is VALID config, so
// both paths must accept it AND both must see both prefixes — asserting the two
// AGREE first, then that they equal the authored pair.
func TestEveryNATMatchArmReadsBothSlots_6693(t *testing.T) {
	const v1, v2 = "10.0.0.0/8", "192.0.2.0/24"

	for _, tc := range natArms6693() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			text := natMixed6693(tc.natType, tc.leaf, v1, v2)

			strictTree, errs := NewParser(text).Parse()
			if len(errs) > 0 {
				t.Fatalf("fixture parse errors: %v\n%s", errs, text)
			}
			strictCfg, err := CompileConfig(strictTree)
			if err != nil {
				t.Fatalf("STRICT commit rejected a valid mixed-shape rule: %v\n%s", err, text)
			}
			strictGot := tc.list(strictCfg)
			lenientGot := tc.list(compileNAT6693(t, text))

			if len(strictGot) != len(lenientGot) {
				t.Fatalf("strict and lenient disagree on the mixed shape: strict=%v lenient=%v",
					strictGot, lenientGot)
			}
			for i := range strictGot {
				if strictGot[i] != lenientGot[i] {
					t.Fatalf("strict and lenient disagree at index %d: strict=%v lenient=%v",
						i, strictGot, lenientGot)
				}
			}
			if len(strictGot) != 2 || strictGot[0] != v1 || strictGot[1] != v2 {
				t.Errorf("mixed shape compiled to %v, want [%s %s] — the child tail was dropped, "+
					"so the rule silently matches less traffic than authored", strictGot, v1, v2)
			}
		})
	}
}

// TestMixedShapeAgreesWithTheOneSlotSpellings_6693 is the equivalence half. The
// same two prefixes must compile identically however they are spelled — that is
// the property, and it is what makes the fix a correction rather than a new
// reading of its own.
//
// The one-slot spellings are the GREEN CONTROL as well: they were correct
// before this change and must stay correct, so a fix that broke them to make
// the mixed shape work cannot pass.
//
// Run for ALL FIVE arms, not just one: the issue asks for the pure-bracketed,
// pure-nested and mixed shapes to be covered per arm, and five readers were
// edited. A one-arm equivalence proof would leave four of them asserted only by
// the mixed-shape test, which cannot see a reader that started dropping the
// BRACKET tail instead.
//
// Agreement is asserted between the spellings FIRST and against the authored
// literal second. Pinning one spelling to a hand-written expectation would
// encode which side is trusted, and in this family the trusted side has been the
// broken one before (#7457).
func TestMixedShapeAgreesWithTheOneSlotSpellings_6693(t *testing.T) {
	const v1, v2 = "10.0.0.0/8", "192.0.2.0/24"

	// Deterministic order so a failure names the same spelling every run.
	order := []string{"mixed", "bracket", "compact", "block", "repeat"}

	for _, tc := range natArms6693() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spelling := map[string]string{
				"mixed":   fmt.Sprintf("%s %s { %s; }", tc.leaf, v1, v2),
				"bracket": fmt.Sprintf("%s [ %s %s ];", tc.leaf, v1, v2),
				"compact": fmt.Sprintf("%s %s %s;", tc.leaf, v1, v2),
				"block":   fmt.Sprintf("%s { %s; %s; }", tc.leaf, v1, v2),
				"repeat":  fmt.Sprintf("%s %s; %s %s;", tc.leaf, v1, tc.leaf, v2),
			}

			var ref []string
			var refName string
			for _, name := range order {
				got := tc.list(compileNAT6693(t, natRuleBody6693(tc.natType, tc.leaf, spelling[name])))
				if ref == nil {
					ref, refName = got, name
					continue
				}
				if len(got) != len(ref) {
					t.Fatalf("%s spelling compiled to %v but %s spelling compiled to %v — "+
						"one config text, two match sets", name, got, refName, ref)
				}
				for i := range got {
					if got[i] != ref[i] {
						t.Fatalf("%s spelling compiled to %v but %s spelling compiled to %v "+
							"(differ at index %d)", name, got, refName, ref, i)
					}
				}
			}
			if len(ref) != 2 || ref[0] != v1 || ref[1] != v2 {
				t.Errorf("every spelling agrees on %v, but the authored pair is [%s %s]", ref, v1, v2)
			}
		})
	}
}

// TestMixedShapeKeepsTheScalarBackCompat_6693 pins the singular field the
// arms also set. It is what the NAT64 fixtures and the peer-sync path read, and
// a reader change that accumulated correctly while dropping the scalar would
// pass every assertion above.
func TestMixedShapeKeepsTheScalarBackCompat_6693(t *testing.T) {
	cfg := compileNAT6693(t, natMixed6693("source", "source-address", "10.0.0.0/8", "192.0.2.0/24"))
	if got := cfg.Security.NAT.Source[0].Rules[0].Match.SourceAddress; got != "10.0.0.0/8" {
		t.Errorf("scalar SourceAddress = %q, want the FIRST value 10.0.0.0/8", got)
	}
}

// TestNATMatchReaderKeepsAnAuthoredEmpty_6693 is the guard for the reader
// CHOICE, and it exists because the obvious choice is wrong.
//
// `firewallMatchValues` is what the four sibling arms in the same switch use,
// and switching these five to it turned five #7216 subtests from reject to
// commit-clean: it DROPS empty tokens, so an authored `match source-address ""`
// never reached the compiled list and the gate that rejects an empty selected
// prefix had nothing to see. Fixing a fail-closed drop by opening a fail-open
// hole is worse than the drop.
//
// So the property is: an authored empty must survive into the list, in BOTH
// slots. Asserted here directly rather than only through the #7216 gate, so a
// future change to that gate cannot silently retire this constraint.
func TestNATMatchReaderKeepsAnAuthoredEmpty_6693(t *testing.T) {
	cases := map[string]*Node{
		"empty in the identifier slot": {Keys: []string{"source-address", ""}},
		"empty in the child slot": {
			Keys:     []string{"source-address"},
			Children: []*Node{{Keys: []string{""}}},
		},
		"empty beside a real value": {
			Keys:     []string{"source-address", ""},
			Children: []*Node{{Keys: []string{"10.0.0.0/8"}}},
		},
	}
	for name, n := range cases {
		got := natMatchAddressValues(n)
		found := false
		for _, v := range got {
			if v == "" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: reader returned %v with no empty entry — the #7216 gate "+
				"reasons from this list, so dropping the empty makes an inert rule "+
				"commit clean", name, got)
		}
	}
}

// TestNATMatchReaderSynthesizesNothing_6693 is the other half of the reader
// choice, and it rules out the OTHER in-tree candidate.
//
// `multiLeafAuthoredValues` (#6673) keeps empties — which is what the test above
// wants — but it synthesizes ONE empty value for a node with no value slot at
// all, to keep `values[0] == nodeVal(n)` total for a SELECTION leaf. These arms
// have no such scalar invariant, and a bare `source-address;` compiling to [""]
// would make the Rust `source_constrained` flag true over a prefix that parses
// as nothing — so the rule matches NOTHING instead of leaving the criterion
// absent. A fail-closed outage in place of an absent match.
func TestNATMatchReaderSynthesizesNothing_6693(t *testing.T) {
	if got := natMatchAddressValues(&Node{Keys: []string{"source-address"}}); len(got) != 0 {
		t.Errorf("a value-less leaf yielded %v; it must yield nothing, not a synthesized "+
			"empty — an empty entry here constrains the rule to match nothing", got)
	}
	if got := natMatchAddressValues(nil); got != nil {
		t.Errorf("nil node yielded %v, want nil", got)
	}
}

// TestNATMatchReaderTakesEveryChildKey_6693 pins the #6714 property: the same
// token sequence must not read differently depending on which side of the AST
// it landed on. `source-address { a b; }` puts two tokens on ONE child node;
// reading only child.Name() would take `a` and drop `b`, while the identical
// tokens in the identifier slot yield both.
func TestNATMatchReaderTakesEveryChildKey_6693(t *testing.T) {
	n := &Node{
		Keys:     []string{"source-address"},
		Children: []*Node{{Keys: []string{"10.0.0.0/8", "192.0.2.0/24"}}},
	}
	got := natMatchAddressValues(n)
	if len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.0.2.0/24" {
		t.Errorf("multi-token child read as %v, want both tokens", got)
	}
}

// TestMixedShapeValuesReachTheCommitGates_6693 is the fail-open half that the
// drop also caused, and it is a distinct property from the narrowing.
//
// The strict literal gates (validateNATMatchAddressLiteralsStrict #7145,
// validateDestinationNATAddressesStrict #3228, and the static-NAT gate) all walk
// the COMPILED list, so a dropped child tail escaped every one of them: a
// malformed prefix in the second slot committed clean. Asserted per arm, because
// each arm is reached by a different gate and a fix that widened four readers
// would still leave one arm's tail unvalidated.
//
// The LENIENT leg is the #1960 no-brick half and it is not decoration. A box can
// already hold a committed config with a malformed tail — before this change the
// tail never reached a gate — and `FormatSet` renders that config back in the
// packed spelling, so the tolerant load / peer-sync path must keep ACCEPTING it
// (with the value carried through for the runtime to drop) rather than refusing
// to load. Strict MAY reject; tolerant MUST NOT brick.
func TestMixedShapeValuesReachTheCommitGates_6693(t *testing.T) {
	const good, bad = "10.0.0.0/8", "999.1.1.1/24"

	for _, tc := range natArms6693() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			text := natMixed6693(tc.natType, tc.leaf, good, bad)

			tree, errs := NewParser(text).Parse()
			if len(errs) > 0 {
				t.Fatalf("fixture parse errors: %v", errs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("a malformed prefix in the CHILD slot committed clean; the literal gate " +
					"reasons from the compiled list, so a dropped tail escapes it")
			}
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("rejected, but the message does not name the offending tail value: %v", err)
			}

			lenientTree, errs := NewParser(text).Parse()
			if len(errs) > 0 {
				t.Fatalf("fixture parse errors: %v", errs)
			}
			cfg, lerr := CompileConfigLenient(lenientTree)
			if lerr != nil {
				t.Fatalf("the TOLERANT path refused a config a box can already hold: %v — "+
					"a peer-sync / startup load that rejects here bricks the node (#1960)", lerr)
			}
			got := tc.list(cfg)
			if len(got) != 2 || got[0] != good || got[1] != bad {
				t.Errorf("tolerant load compiled to %v, want [%s %s] — the tolerant path must "+
					"carry the authored values through, not silently narrow the rule", got, good, bad)
			}
		})
	}
}

// TestMixedShapeAgreesWithItsOwnPersistedRendering_6693 is the sharpest statement
// of the defect, and it is a property no single-tree assertion can express: the
// mixed shape must mean the SAME THING before and after a save/load cycle.
//
// `ConfigTree.Format()` renders the mixed shape back verbatim (the value stays in
// the identifier slot, the tail stays in the block), while `FormatSet()` — the
// spelling the configstore persists and the CLI replays — renders it PACKED:
//
//	set … match source-address 10.0.0.0/8 192.0.2.0/24
//
// Both re-parse to a one-slot shape the either/or reader handled correctly. So
// before this change, one config had TWO meanings: as authored it matched only
// 10.0.0.0/8, and after any round-trip through the persisted set spelling it
// matched both. A rule silently WIDENS on the next reboot, or an operator's
// `show | compare` shows no change while the compiled match set moved.
//
// Asserting the three readings AGREE — rather than pinning any one of them to a
// hand-written expectation — is deliberate: pinning encodes which spelling is
// trusted, and the whole family of these defects has been cases where the
// trusted side was the broken one.
func TestMixedShapeAgreesWithItsOwnPersistedRendering_6693(t *testing.T) {
	const v1, v2 = "10.0.0.0/8", "192.0.2.0/24"

	for _, tc := range natArms6693() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			text := natMixed6693(tc.natType, tc.leaf, v1, v2)
			tree, errs := NewParser(text).Parse()
			if len(errs) > 0 {
				t.Fatalf("fixture parse errors: %v", errs)
			}
			authored := tc.list(compileNAT6693(t, text))

			viaBrace := tc.list(compileNAT6693(t, tree.Format()))
			viaSet := natCompileSetLines6693(t, tree.FormatSet())

			same := func(label string, got []string) {
				t.Helper()
				if len(got) != len(authored) {
					t.Fatalf("%s reading disagrees with the authored tree: %v vs %v — one config, "+
						"two meanings across a save/load cycle", label, got, authored)
				}
				for i := range got {
					if got[i] != authored[i] {
						t.Fatalf("%s reading disagrees with the authored tree at %d: %v vs %v",
							label, i, got, authored)
					}
				}
			}
			same("Format() brace", viaBrace)
			same("FormatSet() packed", tc.list(viaSet))

			if len(authored) != 2 || authored[0] != v1 || authored[1] != v2 {
				t.Errorf("all three readings agree on %v, but the authored pair is [%s %s]",
					authored, v1, v2)
			}
		})
	}
}

// natCompileSetLines6693 replays a `set`-spelling config through ParseSetCommand
// + SetPath, which is how the CLI and `load set` build a tree — NOT NewParser,
// which treats newlines as whitespace and would merge every line into one node.
func natCompileSetLines6693(t *testing.T, setText string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range strings.Split(setText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile replayed set config: %v", err)
	}
	return cfg
}
