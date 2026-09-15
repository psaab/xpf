package config

import (
	"strings"
	"testing"
)

// #9881. An UNQUOTED leading-bracket as-path regex is lexed as list sugar and
// silently compiles to a different, still-valid POSIX regex: `[0-9]+` becomes
// `0-9 +`.
//
// Mechanism (measured on base 2456a1fcb): the lexer's skip loop consumes the
// leading `[` as a bracket-list delimiter (lexer.go bracketDepth++), and the
// #8453 mid-token rule is gated on bracketDepth == 0 so it never fires while
// reading `0-9`. The tail joins to `0-9 +`, which is valid POSIX ERE, so the
// #6686 strict gate (empty/invalid only) passes it. Faithful reconstruction
// is impossible post-lex — `[0-9]+` and `[0-9] +` lex identically — so the
// strict gate REJECTS an unquoted-bracketed tail with a quote-the-regex
// diagnostic instead of guessing.
//
// #8453 fixed MID-token brackets only and its comment declares the leading
// case out of scope ("still requires quoting"). This file enforces that
// requirement at commit. The signal is bracket PROVENANCE (Node.KeysBracketed,
// carried from the lexer's tokInBracket), never the regex text: the mangled
// form is byte-identical to a legitimately-authored bare `0-9 +`.

// buildFlat9881 builds a tree through the production flat-set pair — the same
// parser+setter Store.SetFromInputAs uses for every operator `set`.
func buildFlat9881(t *testing.T, line string) *ConfigTree {
	t.Helper()
	path, quoted, grouped, err := ParseSetCommandGrouped(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	tree := &ConfigTree{}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
		t.Fatalf("set %q: %v", line, err)
	}
	return tree
}

// buildHier9881 builds a tree through the hierarchical parser.
func buildHier9881(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", src, errs[0])
	}
	return tree
}

// strictRejects9881 asserts the strict commit path rejects with a diagnostic
// naming the as-path and prescribing quoting.
func strictRejects9881(t *testing.T, label, aspath string, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("%s: strict commit ACCEPTED an unquoted leading-bracket as-path regex — "+
			"it compiles to a different, still-valid pattern with zero warnings (#9881)", label)
	}
	if !strings.Contains(err.Error(), "as-path "+aspath) {
		t.Errorf("%s: strict rejection does not name the as-path: %v", label, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "quot") {
		t.Errorf("%s: strict rejection prescribes no quoting remedy: %v", label, err)
	}
}

// TestLeadingBracketUnquotedRejectedStrict_9881 pins the two spellings against
// each other: the unquoted leading-bracket form must be REFUSED (this test)
// while the quoted twin commits with the regex intact (next test).
//
// FAIL-ON-REVERT: deleting the RegexUnquotedBracket branch from the strict
// gate makes every leg return nil and reds.
func TestLeadingBracketUnquotedRejectedStrict_9881(t *testing.T) {
	flat := func(line string) *ConfigTree { return buildFlat9881(t, line) }
	hier := func(src string) *ConfigTree { return buildHier9881(t, src) }
	for _, tc := range []struct {
		name  string
		build func() *ConfigTree
	}{
		{"set flat", func() *ConfigTree {
			return flat(`set policy-options as-path AP1 [0-9]+`)
		}},
		{"hierarchical instance", func() *ConfigTree {
			return hier(`policy-options { as-path AP1 [0-9]+; }`)
		}},
		{"hierarchical brace body", func() *ConfigTree {
			return hier(`policy-options { as-path AP1 { [0-9]+; } }`)
		}},
		// The single-token fully-bracketed form. `[0-9]` as a regex is a
		// character class; stripped to `0-9` it is a literal — the same
		// miscompile in one token, not harmless sugar.
		{"single-token brackets", func() *ConfigTree {
			return flat(`set policy-options as-path AP1 [0-9]`)
		}},
		// The full-tail gratuitous-list form. The brackets wrap the whole
		// value, so the join equals the bare spelling — but at a
		// single-value REGEX position brackets are pattern syntax, never
		// grouping (Junos single-value leaves do not take lists), and the
		// diagnostic covers both readings: quote the pattern, or drop the
		// brackets. Deliberately rejected (H1 adjudication on this lane).
		{"full-tail brackets", func() *ConfigTree {
			return hier(`policy-options { as-path AP1 [ .* 65000 .* ]; }`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strictRejects9881(t, tc.name, "AP1", tc.build())
		})
	}
}

// TestLeadingBracketLenientWarns_9881 is the #1960 no-brick half: the tolerant
// load / peer-sync path must WARN (naming the as-path) and still boot.
func TestLeadingBracketLenientWarns_9881(t *testing.T) {
	tree := buildHier9881(t, `policy-options { as-path AP1 [0-9]+; }`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load REJECTED an already-persisted config (#1960 brick): %v", err)
	}
	if !warnMentions(cfg.Warnings, "as-path AP1") {
		t.Errorf("tolerant load produced no as-path warning; warnings=%v", cfg.Warnings)
	}
}

// TestLeadingBracketQuotedCommits_9881 is the accept twin: the quoted regex is
// one lexer string token, carries no bracket provenance, and must compile to
// exactly the authored pattern.
func TestLeadingBracketQuotedCommits_9881(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() *ConfigTree
	}{
		{"set flat", func() *ConfigTree {
			return buildFlat9881(t, `set policy-options as-path AP1 "[0-9]+"`)
		}},
		{"hierarchical", func() *ConfigTree {
			return buildHier9881(t, `policy-options { as-path AP1 "[0-9]+"; }`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build())
			if err != nil {
				t.Fatalf("%s: strict commit rejected the QUOTED regex: %v", tc.name, err)
			}
			ap := cfg.PolicyOptions.ASPaths["AP1"]
			if ap == nil {
				t.Fatalf("%s: no as-path compiled", tc.name)
			}
			if ap.Regex != `[0-9]+` {
				t.Errorf("%s: compiled Regex=%q, want the authored %q", tc.name, ap.Regex, `[0-9]+`)
			}
		})
	}
}

// TestMangledFormIsValidPOSIXPremise_9881 pins the load-bearing premise: the
// mangled join `0-9 +` is a VALID POSIX ERE, which is why the gate must key
// on bracket provenance and why no validity tightening can close this.
func TestMangledFormIsValidPOSIXPremise_9881(t *testing.T) {
	if err := ValidASPathRegex("0-9 +"); err != nil {
		t.Fatalf("premise broken: the mangled form is now invalid (%v) — the gate "+
			"could key on validity and the provenance plumbing would be dead weight", err)
	}
	if got := ASPathRegexFromTokens([]string{"0-9", "+"}); got != "0-9 +" {
		t.Fatalf("ASPathRegexFromTokens([0-9 +]) = %q, want %q", got, "0-9 +")
	}
}

// TestMidTokenAndMultitokenUnaffected_9881 is the commit-layer agreement with
// #8453 and #6686: values that carry no bracket provenance must keep
// committing, with the regex intact. The #8453 cells only ran CompileConfig
// through the lenient-tolerant shape; this runs the STRICT verdict.
func TestMidTokenAndMultitokenUnaffected_9881(t *testing.T) {
	for _, tc := range []struct{ line, hier, want string }{
		{`set policy-options as-path AP1 .*65000[0-9]*`,
			`policy-options { as-path AP1 .*65000[0-9]*; }`,
			`.*65000[0-9]*`},
		{`set policy-options as-path AP1 .* 65000 .*`,
			`policy-options { as-path AP1 .* 65000 .*; }`,
			`.* 65000 .*`},
	} {
		for _, built := range []struct {
			name string
			tree *ConfigTree
		}{
			{"set flat", buildFlat9881(t, tc.line)},
			{"hierarchical", buildHier9881(t, tc.hier)},
		} {
			cfg, err := CompileConfig(built.tree)
			if err != nil {
				t.Fatalf("%s %q: strict commit rejected a provenance-clean regex: %v",
					built.name, tc.want, err)
			}
			if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != tc.want {
				t.Fatalf("%s %q: compiled %+v, want Regex=%q", built.name, tc.want, ap, tc.want)
			}
		}
	}
}

// TestQuotedInsideBracketsAccepted_9881 pins the quoted-ness carve-out: a
// value authored quoted inside brackets has faithful text — the quotes defeat
// the bracket bit — so it must commit.
func TestQuotedInsideBracketsAccepted_9881(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() *ConfigTree
	}{
		{"set flat", func() *ConfigTree {
			return buildFlat9881(t, `set policy-options as-path AP1 [ "[0-9]+" ]`)
		}},
		{"hierarchical", func() *ConfigTree {
			return buildHier9881(t, `policy-options { as-path AP1 [ "[0-9]+" ]; }`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build())
			if err != nil {
				t.Fatalf("%s: strict commit rejected a QUOTED value in brackets: %v", tc.name, err)
			}
			if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != `[0-9]+` {
				t.Fatalf("%s: compiled %+v, want Regex=%q", tc.name, ap, `[0-9]+`)
			}
		})
	}
}

// TestDuplicateSetLaterGroupingWins_9881 pins the dedup-arm restamp: two set
// commands with identical key TEXT but different grouping are not the same
// statement, so the LATER one re-stamps the bracket mask — in both orders.
func TestDuplicateSetLaterGroupingWins_9881(t *testing.T) {
	set := func(tree *ConfigTree, line string) {
		t.Helper()
		path, quoted, grouped, err := ParseSetCommandGrouped(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	t.Run("bare then bracketed rejects", func(t *testing.T) {
		tree := &ConfigTree{}
		set(tree, `set policy-options as-path AP1 0-9 +`)
		set(tree, `set policy-options as-path AP1 [0-9]+`)
		strictRejects9881(t, "bare-then-bracketed", "AP1", tree)
	})
	t.Run("bracketed then bare commits", func(t *testing.T) {
		tree := &ConfigTree{}
		set(tree, `set policy-options as-path AP1 [0-9]+`)
		set(tree, `set policy-options as-path AP1 0-9 +`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("a re-issued BARE line kept the stale bracket bit and was refused: %v", err)
		}
		if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "0-9 +" {
			t.Fatalf("compiled %+v, want the faithfully-joined bare Regex", ap)
		}
	})
}

// TestProvenancelessTailStillCompiles_9881 pins unknown-means-accept: a tree
// with no bracket provenance at all (legacy persisted config, synthesized
// path, pre-provenance replay) behaves exactly as before — the gate fires
// only on a POSITIVE bracket bit, never on its absence.
func TestProvenancelessTailStillCompiles_9881(t *testing.T) {
	builders := map[string]func() *ConfigTree{
		"legacy set pair": func() *ConfigTree {
			path, err := ParseSetCommand(`set policy-options as-path AP1 0-9 +`)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tree := &ConfigTree{}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("setpath: %v", err)
			}
			return tree
		},
		"hand-built node": func() *ConfigTree {
			return &ConfigTree{Children: []*Node{
				{Keys: []string{"policy-options"}, Children: []*Node{
					{Keys: []string{"as-path", "AP1", "0-9", "+"}, IsLeaf: true},
				}},
			}}
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfig(build())
			if err != nil {
				t.Fatalf("%s: strict commit refused a provenance-less tail: %v", name, err)
			}
			if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "0-9 +" {
				t.Fatalf("%s: compiled %+v, want Regex=%q", name, ap, "0-9 +")
			}
		})
	}
}

// TestBracketFlagFollowsTheWinningSource_9881 pins the precedence mirror: the
// compiler prefers a non-empty instance tail and otherwise keeps the LAST
// non-empty brace entry — the flag must come from that same winning span, so
// a bracketed but IGNORED span never refuses a config whose effective regex
// is clean.
func TestBracketFlagFollowsTheWinningSource_9881(t *testing.T) {
	inst := func(tail []string, tailBracket []bool, entries ...*Node) *ConfigTree {
		n := &Node{Keys: append([]string{"as-path", "AP1"}, tail...)}
		n.setKeysBracketed(append([]bool{false, false}, tailBracket...))
		n.Children = entries
		return &ConfigTree{Children: []*Node{
			{Keys: []string{"policy-options"}, Children: []*Node{n}},
		}}
	}
	entry := func(keys []string, bracket []bool) *Node {
		n := &Node{Keys: keys, IsLeaf: true}
		n.setKeysBracketed(bracket)
		return n
	}
	t.Run("clean tail shadows bracketed body", func(t *testing.T) {
		tree := inst([]string{".*"}, []bool{false},
			entry([]string{"0-9", "+"}, []bool{true, false}))
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("a shadowed (ignored) bracketed body refused the commit: %v", err)
		}
		if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != ".*" {
			t.Fatalf("compiled %+v, want the winning tail Regex", ap)
		}
	})
	t.Run("last body entry wins clean", func(t *testing.T) {
		tree := inst(nil, nil,
			entry([]string{"0-9", "+"}, []bool{true, false}),
			entry([]string{".*"}, []bool{false}))
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("an overwritten bracketed entry refused the commit: %v", err)
		}
	})
	t.Run("last body entry wins bracketed", func(t *testing.T) {
		tree := inst(nil, nil,
			entry([]string{".*"}, []bool{false}),
			entry([]string{"0-9", "+"}, []bool{true, false}))
		strictRejects9881(t, "last-wins-bracketed", "AP1", tree)
	})
}

// TestCopyRenameClearsBracketProvenance_9881 pins the re-key rule: a copied or
// renamed node takes a NEW identity from the destination path, so the
// source's per-key bracket mask no longer describes it and must be dropped —
// "unknown", never a stale true refusing a key that was never bracketed.
func TestCopyRenameClearsBracketProvenance_9881(t *testing.T) {
	build := func() *ConfigTree {
		return buildFlat9881(t, `set policy-options as-path AP1 [0-9]+`)
	}
	t.Run("copy", func(t *testing.T) {
		tree := build()
		if err := tree.CopyPath(
			[]string{"policy-options", "as-path", "AP1", "0-9", "+"},
			[]string{"policy-options", "as-path", "AP2", "0-9", "+"}); err != nil {
			t.Fatalf("copy: %v", err)
		}
		// Delete the still-bracketed source so the verdict isolates the copy.
		// The as-path schema takes args:2, so the definition deletes by NAME.
		if err := tree.DeletePath(
			[]string{"policy-options", "as-path", "AP1"}); err != nil {
			t.Fatalf("delete source: %v", err)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("a copied node carried a stale bracket bit and was refused: %v", err)
		}
	})
	t.Run("rename", func(t *testing.T) {
		tree := build()
		if err := tree.RenamePath(
			[]string{"policy-options", "as-path", "AP1", "0-9", "+"},
			[]string{"policy-options", "as-path", "AP2", "0-9", "+"}); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("a renamed node carried a stale bracket bit and was refused: %v", err)
		}
	})
}

// TestMemberDeleteKeepsBracketLockstep_9881 pins the delete-side lockstep: the
// surviving keys keep their own bracket bits, so deleting a bracketed member
// cannot shift a stale true onto a neighbour that was never bracketed.
func TestMemberDeleteKeepsBracketLockstep_9881(t *testing.T) {
	nodes := []*Node{{
		Keys: []string{"members", "a", "b"}, IsLeaf: true,
		KeysBracketed: []bool{false, true, true},
	}}
	if err := removeMultiLeafMembers(&nodes, "members", []string{"a"}, false); err != nil {
		t.Fatalf("delete member: %v", err)
	}
	if len(nodes) != 1 || len(nodes[0].Keys) != 2 || nodes[0].Keys[1] != "b" {
		t.Fatalf("keys after delete = %v, want [members b]", nodes[0].Keys)
	}
	if !nodes[0].KeyBracketed(1) {
		t.Fatal("surviving bracketed member lost its bit — the mask was not rebuilt in lockstep")
	}
	bare := []*Node{{
		Keys: []string{"members", "a", "b"}, IsLeaf: true,
		KeysBracketed: []bool{false, true, false},
	}}
	if err := removeMultiLeafMembers(&bare, "members", []string{"a"}, false); err != nil {
		t.Fatalf("delete member: %v", err)
	}
	if bare[0].KeyBracketed(1) {
		t.Fatal("a stale bracket bit shifted onto a neighbour that was never bracketed")
	}
}

// TestBracketGroupWholeDelete_9881 pins the delete side of the grouped
// upgrade: a path naming an ENTIRE authored bracket group is the one
// statement the brackets delimit, not a packed run, so it deletes exactly
// the named node. A MEMBER path keeps the refusal — deleting one member
// must not take the group with it (#9799 doctrine).
func TestBracketGroupWholeDelete_9881(t *testing.T) {
	build := func() *ConfigTree {
		return buildFlat9881(t, `set security zones security-zone [ trust dmz ] `+
			`host-inbound-traffic system-services ssh`)
	}
	del := func(tree *ConfigTree, line string) error {
		t.Helper()
		_, path, _, grouped, err := ParseSetVerbGrouped(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		return tree.DeletePathGrouped(path, grouped)
	}
	t.Run("whole group deletes", func(t *testing.T) {
		tree := build()
		if err := del(tree, `delete security zones security-zone [ trust dmz ]`); err != nil {
			t.Fatalf("whole-group delete refused: %v", err)
		}
		if got := tree.FormatSet(); strings.Contains(got, "security-zone") {
			t.Fatalf("bracketed container survived its delete:\n%s", got)
		}
	})
	t.Run("first member still refused", func(t *testing.T) {
		if err := del(build(), `delete security zones security-zone trust`); err == nil {
			t.Fatal("deleting one member of a group succeeded — it must be refused")
		}
	})
	t.Run("later member still refused", func(t *testing.T) {
		if err := del(build(), `delete security zones security-zone dmz`); err == nil {
			t.Fatal("deleting one member of a group succeeded — it must be refused (#9799)")
		}
	})
}

// TestWideContainerCopyPreservesGrouping_9881 pins the structural/authorship
// split: a copied WIDE container keeps its bracket grouping (it describes
// shape, which the clone shares), so it renders with brackets, replays wide,
// and deletes whole. Clearing it — correct for LEAF authorship provenance —
// would render the copy bare and let replay split a surplus member into the
// body (the #6668 defect).
func TestWideContainerCopyPreservesGrouping_9881(t *testing.T) {
	tree := buildFlat9881(t, `set security zones security-zone [ trust dmz ] `+
		`host-inbound-traffic system-services ssh`)
	src := []string{"security", "zones", "security-zone", "trust", "dmz"}
	dst := []string{"security", "zones", "security-zone", "za", "zb"}
	if err := tree.CopyPath(src, dst); err != nil {
		t.Fatalf("copy: %v", err)
	}
	zones := tree.FindChild("security").FindChild("zones")
	var copied *Node
	for _, z := range zones.FindChildren("security-zone") {
		if keysEqual(z.Keys, []string{"security-zone", "za", "zb"}) {
			copied = z
		}
	}
	if copied == nil {
		t.Fatalf("copied container missing:\n%s", tree.FormatSet())
	}
	if !copied.KeyBracketed(1) || !copied.KeyBracketed(2) {
		t.Fatalf("copy dropped the structural grouping: Keys=%q bracketed=%v",
			copied.Keys, copied.KeysBracketed)
	}
	assertWideGroupRoundTrips9881(t, tree, "za", "zb")
}

// TestWideContainerRenamePreservesGrouping_9881 is the rename half: an
// in-place re-key keeps the grouping for the same reason — same shape,
// same key count, still one authored group.
func TestWideContainerRenamePreservesGrouping_9881(t *testing.T) {
	tree := buildFlat9881(t, `set security zones security-zone [ trust dmz ] `+
		`host-inbound-traffic system-services ssh`)
	if err := tree.RenamePath(
		[]string{"security", "zones", "security-zone", "trust", "dmz"},
		[]string{"security", "zones", "security-zone", "ra", "rb"}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	zones := tree.FindChild("security").FindChild("zones")
	if got := zones.FindChildren("security-zone"); len(got) != 1 {
		t.Fatalf("expected the one renamed container, got %d", len(got))
	} else if !got[0].KeyBracketed(1) || !got[0].KeyBracketed(2) {
		t.Fatalf("rename dropped the structural grouping: Keys=%q bracketed=%v",
			got[0].Keys, got[0].KeysBracketed)
	}
	assertWideGroupRoundTrips9881(t, tree, "ra", "rb")
}

// assertWideGroupRoundTrips9881 proves a wide group survives rendering
// (brackets re-emitted), replay (rebuilds wide, the #6668 fixed point), and
// whole-group deletion — and that both members compile.
func assertWideGroupRoundTrips9881(t *testing.T, tree *ConfigTree, za, zb string) {
	t.Helper()
	setText := tree.FormatSet()
	if !strings.Contains(setText, "[ "+za+" "+zb+" ]") {
		t.Fatalf("render lost the brackets — replay would split the group:\n%s", setText)
	}
	replay := replayDisplaySet6668(t, setText)
	if d := bracketedContainerStructureDiff(tree.Children, replay.Children, nil); d != "" {
		t.Fatalf("replay split the group: %s", d)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("grouped container does not compile: %v", err)
	}
	for _, z := range []string{za, zb} {
		if _, ok := cfg.Security.Zones[z]; !ok {
			t.Errorf("zone %q missing after copy/rename — the list split", z)
		}
	}
	_, path, _, grouped, err := ParseSetVerbGrouped(
		`delete security zones security-zone [ ` + za + ` ` + zb + ` ]`)
	if err != nil {
		t.Fatalf("parse delete: %v", err)
	}
	if err := tree.DeletePathGrouped(path, grouped); err != nil {
		t.Fatalf("whole-group delete refused: %v", err)
	}
	if got := tree.FormatSet(); strings.Contains(got, za+" "+zb) || strings.Contains(got, za+zb) {
		t.Fatalf("group survived its delete:\n%s", got)
	}
}

// TestSamePathRenamePreservesBracketProvenance_9881: renaming a node to its
// own identity is a no-op and must not launder the bracket bit — otherwise
// `rename` becomes a strict-gate bypass (rename AP1 to AP1, commit clean).
func TestSamePathRenamePreservesBracketProvenance_9881(t *testing.T) {
	tree := buildFlat9881(t, `set policy-options as-path AP1 [0-9]+`)
	p := []string{"policy-options", "as-path", "AP1", "0-9", "+"}
	if err := tree.RenamePath(p, p); err != nil {
		t.Fatalf("same-path rename: %v", err)
	}
	strictRejects9881(t, "same-path-rename", "AP1", tree)
}

// lexBracketed9881 tokenizes in through the production lexer, returning each
// identifier/string value with its InBracket bit.
func lexBracketed9881(t *testing.T, in string) []struct {
	v string
	b bool
} {
	t.Helper()
	var res []struct {
		v string
		b bool
	}
	l := NewLexer(in)
	for {
		tok := l.Next()
		if tok.Type == TokenEOF {
			return res
		}
		if tok.Type == TokenError {
			t.Fatalf("lex %q: %s", in, tok.Value)
		}
		if tok.Type != TokenIdentifier && tok.Type != TokenString {
			continue
		}
		res = append(res, struct {
			v string
			b bool
		}{tok.Value, l.InBracket()})
	}
}

// TestLexerTokenlessBracketsMarkTheAdjacentToken_9881 pins the gap-loss rule
// at the layer where the information is destroyed: brackets stripped with no
// token between them (`[]`, `[ ]`, a stray `]`) mark the FOLLOWING token,
// while a balanced close of a non-empty list marks nothing.
func TestLexerTokenlessBracketsMarkTheAdjacentToken_9881(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want [][2]any
	}{
		// The headline: a POSIX `[]...]` char-class head. The pair leaves
		// no inside token; the #8453 mid-token rule then folds the rest
		// into ONE token at depth zero — which must carry the loss.
		{`[]0-9]+`, [][2]any{{"0-9]+", true}}},
		{`x [] y`, [][2]any{{"x", false}, {"y", true}}},
		{`x [ ] y`, [][2]any{{"x", false}, {"y", true}}},
		{`]a`, [][2]any{{"a", true}}},
		// Balanced, non-empty lists: no loss, bits exactly as before.
		{`[ a ] b`, [][2]any{{"a", true}, {"b", false}}},
		{`[a] b`, [][2]any{{"a", true}, {"b", false}}},
		{`[0-9]+`, [][2]any{{"0-9", true}, {"+", false}}},
		// Mid-token brackets and endpoint literals are emitted, not
		// stripped: no gap loss, bits untouched (#8453, #5182).
		{`a[b`, [][2]any{{"a[b", false}}},
		{`x]y`, [][2]any{{"x]y", false}}},
		{`[2001:db8::1]:51820`, [][2]any{{"[2001:db8::1]:51820", false}}},
	} {
		got := lexBracketed9881(t, tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("lex %q -> %v, want %v", tc.in, got, tc.want)
		}
		for i, w := range tc.want {
			if got[i].v != w[0] || got[i].b != w[1] {
				t.Errorf("lex %q token %d = (%q,%v), want (%q,%v)",
					tc.in, i, got[i].v, got[i].b, w[0], w[1])
			}
		}
	}
}

// TestLexerLastGapLossReportsTrailingStrippedBrackets_9881 pins the trailing
// accessor: a tokenless pair or stray after the last value token has no
// follower, so the gap itself must answer at span end.
func TestLexerLastGapLossReportsTrailingStrippedBrackets_9881(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{`a []`, true},
		{`a [ ]`, true},
		{`a ]`, true},
		{`a b`, false},
		{`[ a ]`, false}, // balanced close of a non-empty list: no loss
		{`a`, false},
	} {
		l := NewLexer(tc.in)
		for {
			if tok := l.Next(); tok.Type == TokenEOF {
				break
			}
		}
		if got := l.LastGapLoss(); got != tc.want {
			t.Errorf("lex %q: LastGapLoss=%v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestTokenlessBracketsRejectAtCommit_9881 drives the span verdicts: every
// tokenless-loss spelling — leading `[]`, trailing pair, stray closer —
// must be REFUSED on both authoring paths, since the stripped delimiters
// leave the joined pattern ambiguous.
func TestTokenlessBracketsRejectAtCommit_9881(t *testing.T) {
	for _, tc := range []struct {
		name string
		flat string
		hier string
	}{
		{"leading char-class head", `set policy-options as-path AP1 []0-9]+`,
			`policy-options { as-path AP1 []0-9]+; }`},
		{"trailing pair", `set policy-options as-path AP1 .* []`,
			`policy-options { as-path AP1 .* []; }`},
		{"stray closer", `set policy-options as-path AP1 ]foo`,
			`policy-options { as-path AP1 ]foo; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strictRejects9881(t, tc.name+" flat", "AP1", buildFlat9881(t, tc.flat))
			strictRejects9881(t, tc.name+" hier", "AP1", buildHier9881(t, tc.hier))
		})
	}
}

// TestQuotedValueWithTrailingDebrisAccepted_9881 pins the deliberate edge:
// a QUOTED value stays faithful no matter what tokenless debris trails it —
// the quotes delimit complete text and the empty brackets carry none — so
// the quoted-defeats-bracketed carve-out extends to the trailing taint.
func TestQuotedValueWithTrailingDebrisAccepted_9881(t *testing.T) {
	tree := buildHier9881(t, `policy-options { as-path AP1 "x" []; }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a QUOTED value with trailing debris was refused: %v", err)
	}
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "x" {
		t.Fatalf("compiled %+v, want Regex=%q", ap, "x")
	}
}
