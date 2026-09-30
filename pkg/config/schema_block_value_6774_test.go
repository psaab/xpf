package config

import (
	"reflect"
	"strings"
	"testing"
)

// #6774: `security policies default-policy` is a CHOICE CONTAINER in Junos —
// `permit-all` / `deny-all` / `reject-all` are alternative sub-statements, and
// Junos itself DISPLAYS the stanza as `default-policy { deny-all; }`. This
// schema models it as a valued leaf so the flat-set spelling works, and the
// compiler accommodates BOTH shapes deliberately
// (compiler_security_policy.go). Strict SchemaValidate read the value only
// from Keys[1:], so it rejected the block spelling with "missing value" — an
// operator pasting canonical Junos could not commit a configuration that the
// compiler compiles correctly and that the TOLERATED Load/SyncApply path
// (which downgrades the gate to a warning, #1960) already applies.
//
// #7568 is tested alongside it because the two defects are the same question
// asked of different code: what does `keyword { value; }` mean to the walker,
// and to the compiler.

func mustParseTree6774(t *testing.T, cfg string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(cfg).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v\n--- config ---\n%s", perrs, cfg)
	}
	return tree
}

func defaultPolicyBlock(action string) string {
	return "security {\n    policies {\n        default-policy {\n            " + action + ";\n        }\n    }\n}"
}

func defaultPolicyFlat(action string) string {
	return "security {\n    policies {\n        default-policy " + action + ";\n    }\n}"
}

// TestDefaultPolicyBlockFormCommits is the fail-on-revert proof: the
// hierarchical block spelling must pass strict validation AND compile to the
// same action as the flat spelling.
func TestDefaultPolicyBlockFormCommits_6774(t *testing.T) {
	for _, action := range []string{"permit-all", "deny-all", "reject-all"} {
		blkTree := mustParseTree6774(t, defaultPolicyBlock(action))
		blkCfg, err := CompileConfig(blkTree)
		if err != nil {
			t.Fatalf("%s: block form failed to compile: %v", action, err)
		}
		if verr := SchemaValidate(blkTree, blkCfg); verr != nil {
			t.Fatalf("%s: strict validation REJECTED the canonical Junos block "+
				"spelling `default-policy { %s; }`: %v", action, action, verr)
		}
	}
}

// TestDefaultPolicyBlockAndFlatFormsAgree binds the two spellings to EACH
// OTHER rather than pinning either to a literal action constant. If a future
// change made one spelling mean something different, pinning the block form to
// a constant would only catch it on the side the test happened to encode.
func TestDefaultPolicyBlockAndFlatFormsAgree_6774(t *testing.T) {
	for _, action := range []string{"permit-all", "deny-all", "reject-all"} {
		flatTree := mustParseTree6774(t, defaultPolicyFlat(action))
		blkTree := mustParseTree6774(t, defaultPolicyBlock(action))

		flatCfg, ferr := CompileConfig(flatTree)
		blkCfg, berr := CompileConfig(blkTree)
		if ferr != nil || berr != nil {
			t.Fatalf("%s: compile flat=%v block=%v", action, ferr, berr)
		}
		if flatCfg.Security.DefaultPolicy != blkCfg.Security.DefaultPolicy {
			t.Fatalf("%s: the two Junos spellings disagree: flat=%v block=%v",
				action, flatCfg.Security.DefaultPolicy, blkCfg.Security.DefaultPolicy)
		}
		// And the whole compiled config must match, so the block form cannot
		// be quietly setting something extra.
		if !reflect.DeepEqual(flatCfg.Security, blkCfg.Security) {
			t.Fatalf("%s: block and flat spellings produced different SecurityConfig", action)
		}
	}
}

// TestDefaultPolicyBlockRejectsAmbiguousAndInvalid is the TIGHTEN half. The
// opt-in must not become "accept whatever is in the block".
func TestDefaultPolicyBlockRejectsAmbiguousAndInvalid_6774(t *testing.T) {
	cases := []struct{ name, cfg, wantSubstr string }{
		{
			// Two choices are ambiguous and must be rejected with a
			// cardinality diagnostic instead of being treated as missing.
			name: "two-actions",
			cfg: "security {\n    policies {\n        default-policy {\n" +
				"            deny-all;\n            permit-all;\n        }\n    }\n}",
			wantSubstr: "expected exactly one block value, found 2 children",
		},
		{
			// The block value must be VALIDATED, not merely accepted.
			name:       "invalid-action",
			cfg:        defaultPolicyBlock("bogus-all"),
			wantSubstr: "bogus-all",
		},
		{
			name:       "empty-block",
			cfg:        "security {\n    policies {\n        default-policy {\n        }\n    }\n}",
			wantSubstr: "missing value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := mustParseTree6774(t, tc.cfg)
			cfg, _ := CompileConfig(tree)
			err := SchemaValidate(tree, cfg)
			if err == nil {
				t.Fatalf("strict validation ACCEPTED %s; malformed block form must be rejected",
					tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSubstr)
			}
		})
	}
}

// TestBlockValueIsOptInNotBlanketRelaxation is the over-application control,
// and the most important cell here. A census of setSchema found 42 distinct
// typed leaves where the COMPILER tolerates a block form (incidentally, via
// the generic nodeVal helper) that the schema rejects. For those the schema is
// RIGHT — `mtu { 1500; }` is not Junos — so the #6774 fix must stay opt-in.
// Without this test, replacing the blockValue check with an unconditional
// fallback would pass every other test in this file.
func TestBlockValueIsOptInNotBlanketRelaxation_6774(t *testing.T) {
	cfg := "interfaces {\n    ge-0/0/0 {\n        mtu {\n            1500;\n        }\n    }\n}"
	tree := mustParseTree6774(t, cfg)
	compiled, _ := CompileConfig(tree)
	if err := SchemaValidate(tree, compiled); err == nil {
		t.Fatal("strict validation accepted `mtu { 1500; }`: the block-form " +
			"allowance leaked from the opted-in leaf to every typed leaf, which " +
			"relaxes the gate on ~42 leaves where the block spelling is not Junos")
	}
	// Control: the same leaf in its real spelling must still commit, so the
	// test above cannot pass merely because everything about mtu is broken.
	okTree := mustParseTree6774(t, "interfaces {\n    ge-0/0/0 {\n        mtu 1500;\n    }\n}")
	okCfg, err := CompileConfig(okTree)
	if err != nil {
		t.Fatalf("control: `mtu 1500` failed to compile: %v", err)
	}
	if verr := SchemaValidate(okTree, okCfg); verr != nil {
		t.Fatalf("control: `mtu 1500` was rejected: %v", verr)
	}
}

// TestSingleBlockValueShape pins the helper's strictness directly.
func TestSingleBlockValueShape_6774(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want string
		ok   bool
	}{
		{"one-child-one-token", &Node{Keys: []string{"default-policy"}, Children: []*Node{{Keys: []string{"deny-all"}}}}, "deny-all", true},
		{"no-children", &Node{Keys: []string{"default-policy"}}, "", false},
		{"two-children", &Node{Keys: []string{"default-policy"}, Children: []*Node{{Keys: []string{"deny-all"}}, {Keys: []string{"permit-all"}}}}, "", false},
		{"child-with-two-tokens", &Node{Keys: []string{"default-policy"}, Children: []*Node{{Keys: []string{"deny-all", "extra"}}}}, "", false},
		{"child-with-own-block", &Node{Keys: []string{"default-policy"}, Children: []*Node{{Keys: []string{"deny-all"}, Children: []*Node{{Keys: []string{"x"}}}}}}, "", false},
	}
	for _, tc := range cases {
		got, ok := singleBlockValue(tc.node)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: singleBlockValue = (%q,%v), want (%q,%v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestDefaultPolicySchemaAcceptanceMatchesCompilerSupport_6774 binds the two
// sides to EACH OTHER rather than pinning "the block form is accepted" to a
// literal.
//
// The property is an agreement: the strict schema must accept exactly the
// spellings that compiler_security_policy.go deliberately HONOURS. Pinning
// the schema side alone would keep passing if someone later narrowed the
// compiler's `default-policy { deny-all; }` branch — the schema would then be
// accepting a spelling that silently does nothing, which is a worse failure
// than the rejection this issue fixed.
//
// "Honoured" is measured against a baseline config with no default-policy
// stanza at all. Note that deny-all cannot discriminate — it is also the
// unset default (fail-closed, #3065) — so the honoured direction is asserted
// with permit-all and reject-all, which both differ from the baseline. That
// is stated rather than papered over: a table row that cannot fail is not
// evidence, and including deny-all silently would make this look like three
// discriminating cases when it is two.
func TestDefaultPolicySchemaAcceptanceMatchesCompilerSupport_6774(t *testing.T) {
	baseTree := mustParseTree6774(t, "security {\n    policies {\n    }\n}")
	baseCfg, err := CompileConfig(baseTree)
	if err != nil {
		t.Fatalf("baseline compile: %v", err)
	}
	baseline := baseCfg.Security.DefaultPolicy

	spellings := map[string]func(string) string{
		"flat":  defaultPolicyFlat,
		"block": defaultPolicyBlock,
	}
	// Only actions that DIFFER from the unset default can prove the compiler
	// honoured the stanza.
	for _, action := range []string{"permit-all", "reject-all"} {
		for name, render := range spellings {
			tree := mustParseTree6774(t, render(action))
			cfg, cerr := CompileConfig(tree)
			if cerr != nil {
				t.Fatalf("%s/%s: compile: %v", name, action, cerr)
			}
			compilerHonours := cfg.Security.DefaultPolicy != baseline
			schemaAccepts := SchemaValidate(tree, cfg) == nil

			if compilerHonours != schemaAccepts {
				t.Fatalf("%s spelling of %q: compiler honours it = %v, but strict "+
					"schema accepts it = %v. These must agree: a spelling the "+
					"compiler applies and the schema rejects cannot be committed "+
					"(the #6774 defect), and a spelling the schema accepts but the "+
					"compiler ignores commits clean and does nothing.",
					name, action, compilerHonours, schemaAccepts)
			}
			if !compilerHonours {
				t.Fatalf("%s spelling of %q was not honoured by the compiler at all; "+
					"the fixture no longer discriminates", name, action)
			}
		}
	}
}
