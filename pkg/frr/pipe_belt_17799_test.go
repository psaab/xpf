package frr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNoDeadPipeRewrite17799 pins #17799's cleanup: on the ordinary
// pipe-check path the community translator already emits pipe-safe
// regexes (since #17977 that includes refusing bracket classes such
// as `[^| ]` whose spelling carries "| "), the AS-path translator
// removes grouping whitespace around alternation, and neighbor
// descriptions are refused/omitted. A second unused render belt must
// not be kept as if it covered those paths.
func TestNoDeadPipeRewrite17799(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse production source %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == "rewriteFRRPipeSequences" {
				t.Fatalf("dead rewriteFRRPipeSequences declaration remains in %s; remove it or wire it into a production render path", name)
			}
		}
	}
}

// TestPipeOperands17799 exercises the actual free-text rendering
// paths: AS-path regexes are translated before render, community
// regexes are pipe-safe/refused on the ordinary pipe-check path
// (bracket classes spelling "| " such as `[^| ]` are refused per
// #17977), and neighbor descriptions are refused/omitted.
// Controls pin regular regex rendering and the existing pipe gates.
func TestPipeOperands17799(t *testing.T) {
	// AS-path alternation with grouping whitespace is normalized by
	// TranslateJunosASPathRegex before reaching the renderer.
	po := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"PIPEY": {Name: "PIPEY", Regex: "65000 | 65001"},
		},
	}
	got := New().generatePolicyOptions(po)
	want := "bgp as-path access-list PIPEY permit ^(65000|65001)$\n"
	if !strings.Contains(got, want) {
		t.Errorf("as-path render = %q, want pipe-free alternation %q", got, want)
	}
	if strings.Contains(got, "| ") {
		t.Errorf("as-path render still contains vty pipe sequence: %q", got)
	}

	// Control: pipe-free AS-path regex keeps its established spelling.
	poOK := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"PLAIN": {Name: "PLAIN", Regex: "65000"},
		},
	}
	gotOK := New().generatePolicyOptions(poOK)
	if !strings.Contains(gotOK, "bgp as-path access-list PLAIN permit ^65000$\n") {
		t.Errorf("control as-path regex changed:\n%s", gotOK)
	}

	// Control: the no-space spelling a|b remains an ordinary alternation.
	poNoSpace := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"NO_SPACE": {Name: "NO_SPACE", Regex: "65000|65001"},
		},
	}
	gotNoSpace := New().generatePolicyOptions(poNoSpace)
	if !strings.Contains(gotNoSpace, "bgp as-path access-list NO_SPACE permit ^(65000|65001)$\n") {
		t.Errorf("control a|b alternation changed:\n%s", gotNoSpace)
	}
	if strings.Contains(gotNoSpace, "| ") {
		t.Errorf("no-space alternation acquired a vty pipe sequence:\n%s", gotNoSpace)
	}

	// Escaped pipes are not grouped alternations. The community translator
	// refuses this unsupported escape instead of rewriting it.
	gotEscaped := New().generatePolicyOptions(&config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"ESCAPED": {Name: "ESCAPED", Members: []string{`65000:\|`}},
		},
	})
	if strings.Contains(gotEscaped, "ESCAPED permit") || strings.Contains(gotEscaped, "| ") {
		t.Errorf("escaped-pipe control rendered an untranslatable member:\n%s", gotEscaped)
	}

	// A bracket expression containing a literal space is also unrenderable
	// because it can match the separator in FRR's joined community string.
	gotBracketSpace := New().generatePolicyOptions(&config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"BRACKET_SPACE": {Name: "BRACKET_SPACE", Members: []string{`65000:[| ]`}},
		},
	})
	if strings.Contains(gotBracketSpace, "BRACKET_SPACE permit") || strings.Contains(gotBracketSpace, "| ") {
		t.Errorf("bracket-space control rendered an untranslatable member:\n%s", gotBracketSpace)
	}

	// Control: community member with "| " still fails closed (no render).
	poComm := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"OP": {Name: "OP", Members: []string{"^((56) | (78)):(.*)$"}},
		},
	}
	gotComm := New().generatePolicyOptions(poComm)
	if strings.Contains(gotComm, "| ") || strings.Contains(gotComm, "OP permit") {
		t.Errorf("community pipe control regressed:\n%s", gotComm)
	}
	// A bracketed pipe with no space remains a literal community regex
	// control and is rendered through the production translator.
	gotBracket := New().generatePolicyOptions(&config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"BRACKET": {Name: "BRACKET", Members: []string{"65000:[|]"}},
		},
	})
	if !strings.Contains(gotBracket, "BRACKET permit") || strings.Contains(gotBracket, "| ") {
		t.Errorf("bracket-pipe control changed:\n%s", gotBracket)
	}

	// Control: BGP neighbor description with "| " is still omitted,
	// while a plain description survives.
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, Description: "uplink | primary"},
			{Address: "10.0.3.1", PeerAS: 65003, Description: "plain peer"},
		},
	}
	gotBGP := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(gotBGP, "| ") || strings.Contains(gotBGP, "10.0.2.1 description") {
		t.Errorf("neighbor description pipe control regressed:\n%s", gotBGP)
	}
	if !strings.Contains(gotBGP, "neighbor 10.0.3.1 description plain peer\n") {
		t.Errorf("plain neighbor description control changed:\n%s", gotBGP)
	}
}
