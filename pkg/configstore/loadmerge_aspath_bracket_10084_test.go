package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func asPathNode10084(t *testing.T, tree *config.ConfigTree) *config.Node {
	t.Helper()
	policyOptions := tree.FindChild("policy-options")
	if policyOptions == nil {
		t.Fatalf("candidate has no policy-options root; set output:\n%s", tree.FormatSet())
	}
	for _, node := range policyOptions.FindChildren("as-path") {
		if len(node.Keys) >= 2 && node.Keys[1] == "AP1" {
			return node
		}
	}
	t.Fatalf("candidate has no as-path AP1; set output:\n%s", tree.FormatSet())
	return nil
}

func strictBracketDiagnostic10084(t *testing.T, entry string, tree *config.ConfigTree) error {
	t.Helper()
	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatalf("%s: strict commit accepted unquoted leading-bracket regex", entry)
	}
	if !strings.Contains(err.Error(), "as-path AP1") {
		t.Errorf("%s: rejection does not name AP1: %v", entry, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "quot") {
		t.Errorf("%s: rejection does not prescribe quoting: %v", entry, err)
	}
	return err
}

// TestLoadMergeHierarchicalPreservesLeafBracketProvenance10084 guards the
// exact lossy path from #10084: the hierarchical parser records the bracket on
// the as-path leaf, then LoadMergeAs must retain it while replaying the tree.
// The public FormatSet output remains unchanged, so this also proves the
// #6668 display pin is not being used as the repair mechanism.
func TestLoadMergeHierarchicalPreservesLeafBracketProvenance10084(t *testing.T) {
	const input = `policy-options { as-path AP1 [0-9]+; }`

	direct, errs := config.NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("direct parse: %v", errs)
	}
	directNode := asPathNode10084(t, direct)
	if !directNode.KeyBracketed(2) {
		t.Fatalf("direct parser did not record bracket provenance: Keys=%q mask=%v", directNode.Keys, directNode.KeysBracketed)
	}
	if got := direct.FormatSet(); got != "set policy-options as-path AP1 0-9 +\n" {
		t.Fatalf("public FormatSet changed the #6668 no-churn contract: %q", got)
	}
	if got := direct.FormatSetForLoadMerge(); got != "set policy-options as-path AP1 [ 0-9 ] +\n" {
		t.Fatalf("load-merge renderer did not carry the leaf bracket: %q", got)
	}

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadMergeAs("", input); err != nil {
		t.Fatalf("LoadMergeAs hierarchical: %v", err)
	}

	gotNode := asPathNode10084(t, s.candidate)
	if !gotNode.KeyBracketed(2) {
		t.Fatalf("LoadMergeAs dropped leaf bracket provenance: Keys=%q mask=%v", gotNode.Keys, gotNode.KeysBracketed)
	}
	if got, want := s.candidate.Format(), direct.Format(); got != want {
		t.Fatalf("hierarchical LoadMerge changed the authored tree\nwant:\n%s\ngot:\n%s", want, got)
	}
	if got, want := s.candidate.FormatSet(), direct.FormatSet(); got != want {
		t.Fatalf("hierarchical LoadMerge changed public display-set output\nwant:\n%s\ngot:\n%s", want, got)
	}
	strictBracketDiagnostic10084(t, "LoadMerge-hierarchical", s.candidate)
}

// TestLoadMergeHierarchicalBracketParity10084 keeps the fixed path aligned with
// the raw hierarchical install and flat replay paths covered by #9881: the
// same authored regex must receive the same strict verdict, while the quoted
// twin remains a valid literal regex.
func TestLoadMergeHierarchicalBracketParity10084(t *testing.T) {
	const unquoted = `policy-options { as-path AP1 [0-9]+; }`
	const quoted = `policy-options { as-path AP1 "[0-9]+"; }`
	const quotedInsideBracket = `policy-options { as-path AP1 [ "65000" ]; }`

	type authoringLeg struct {
		name  string
		build func(*testing.T) *config.ConfigTree
	}
	legs := []authoringLeg{
		{
			name: "hierarchical-load-merge",
			build: func(t *testing.T) *config.ConfigTree {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if err := s.LoadMergeAs("", unquoted); err != nil {
					t.Fatalf("LoadMergeAs: %v", err)
				}
				return s.candidate
			},
		},
		{
			name: "hierarchical-load-override",
			build: func(t *testing.T) *config.ConfigTree {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if err := s.LoadOverrideAs("", unquoted); err != nil {
					t.Fatalf("LoadOverrideAs: %v", err)
				}
				return s.candidate
			},
		},
		{
			name: "flat-load-merge",
			build: func(t *testing.T) *config.ConfigTree {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if err := s.LoadMergeAs("", "set policy-options as-path AP1 [0-9]+\n"); err != nil {
					t.Fatalf("flat LoadMergeAs: %v", err)
				}
				return s.candidate
			},
		},
		{
			name: "flat-load-set",
			build: func(t *testing.T) *config.ConfigTree {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if _, err := s.LoadSet("set policy-options as-path AP1 [0-9]+\n"); err != nil {
					t.Fatalf("LoadSet: %v", err)
				}
				return s.candidate
			},
		},
		{
			name: "interactive-set",
			build: func(t *testing.T) *config.ConfigTree {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if err := s.SetFromInput("policy-options as-path AP1 [0-9]+"); err != nil {
					t.Fatalf("SetFromInput: %v", err)
				}
				return s.candidate
			},
		},
		{
			name: "direct-hierarchical-parse",
			build: func(t *testing.T) *config.ConfigTree {
				tree, errs := config.NewParser(unquoted).Parse()
				if len(errs) > 0 {
					t.Fatalf("direct parse: %v", errs)
				}
				return tree
			},
		},
	}

	var wantFormat, wantSet, wantErr string
	for _, leg := range legs {
		t.Run(leg.name, func(t *testing.T) {
			tree := leg.build(t)
			node := asPathNode10084(t, tree)
			if !node.KeyBracketed(2) {
				t.Fatalf("authoring leg dropped bracket provenance: Keys=%q mask=%v", node.Keys, node.KeysBracketed)
			}
			if wantFormat == "" {
				wantFormat, wantSet = tree.Format(), tree.FormatSet()
			} else {
				if got := tree.Format(); got != wantFormat {
					t.Fatalf("compiled authored tree differs from baseline\nwant:\n%s\ngot:\n%s", wantFormat, got)
				}
				if got := tree.FormatSet(); got != wantSet {
					t.Fatalf("public display-set differs from baseline\nwant:\n%s\ngot:\n%s", wantSet, got)
				}
			}
			err := strictBracketDiagnostic10084(t, leg.name, tree)
			if wantErr == "" {
				wantErr = err.Error()
			} else if got := err.Error(); got != wantErr {
				t.Fatalf("strict diagnostic differs from baseline\nwant: %s\ngot:  %s", wantErr, got)
			}
		})
	}

	quotedStore := newTestStore(t)
	if err := quotedStore.EnterConfigure(); err != nil {
		t.Fatalf("quoted EnterConfigure: %v", err)
	}
	if err := quotedStore.LoadMergeAs("", quoted); err != nil {
		t.Fatalf("quoted LoadMergeAs: %v", err)
	}
	cfg, err := config.CompileConfig(quotedStore.candidate)
	if err != nil {
		t.Fatalf("quoted regex was rejected: %v", err)
	}
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != `[0-9]+` {
		t.Fatalf("quoted regex compiled as %+v, want Regex=%q", ap, `[0-9]+`)
	}

	quotedInsideStore := newTestStore(t)
	if err := quotedInsideStore.EnterConfigure(); err != nil {
		t.Fatalf("quoted-inside-bracket EnterConfigure: %v", err)
	}
	if err := quotedInsideStore.LoadMergeAs("", quotedInsideBracket); err != nil {
		t.Fatalf("quoted-inside-bracket LoadMergeAs: %v", err)
	}
	quotedInsideNode := asPathNode10084(t, quotedInsideStore.candidate)
	if !quotedInsideNode.KeyBracketed(2) || !quotedInsideNode.KeyQuoted(2) {
		t.Fatalf("quoted-inside-bracket provenance changed: Keys=%q bracketed=%v quoted=%v",
			quotedInsideNode.Keys, quotedInsideNode.KeysBracketed, quotedInsideNode.KeysQuoted)
	}
	cfg, err = config.CompileConfig(quotedInsideStore.candidate)
	if err != nil {
		t.Fatalf("quoted-inside-bracket regex was rejected: %v", err)
	}
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "65000" {
		t.Fatalf("quoted-inside-bracket regex compiled as %+v, want Regex=%q", ap, "65000")
	}
}

// TestLoadMergeHierarchicalBareControl10084 pins the no-bracket control. The
// internal renderer is allowed to add delimiters only when the leaf carries
// positive provenance; an ordinary bare as-path stays bare and compiles as it
// did before #10084.
func TestLoadMergeHierarchicalBareControl10084(t *testing.T) {
	const input = `policy-options { as-path AP1 0-9 +; }`
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadMergeAs("", input); err != nil {
		t.Fatalf("LoadMergeAs: %v", err)
	}
	if got := s.candidate.FormatSet(); got != "set policy-options as-path AP1 0-9 +\n" {
		t.Fatalf("bare control changed display-set output: %q", got)
	}
	node := asPathNode10084(t, s.candidate)
	if node.KeyBracketed(2) {
		t.Fatalf("bare control acquired bracket provenance: Keys=%q mask=%v", node.Keys, node.KeysBracketed)
	}
	cfg, err := config.CompileConfig(s.candidate)
	if err != nil {
		t.Fatalf("bare control was rejected: %v", err)
	}
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "0-9 +" {
		t.Fatalf("bare control compiled as %+v, want Regex=%q", ap, "0-9 +")
	}
}
