package config

import (
	"reflect"
	"testing"
)

// #8453. A '[' or ']' met MID-TOKEN outside any bracket list is a literal
// character of the value, not list sugar.
//
// The defect it closes was silent in the worst way: the mangled value was still
// a VALID regex / a valid set of community members, so every gate downstream
// reported success and the policy matched a different set than the operator
// wrote.
//
// These cells run the production spellings through the tokenizer directly,
// because that is the layer where the information was destroyed — by the time
// the compiler or a commit gate runs, the bracket characters no longer exist.

func lexAll(t *testing.T, in string) []string {
	t.Helper()
	l := NewLexer(in)
	var out []string
	for {
		tok := l.Next()
		if tok.Type == TokenEOF {
			return out
		}
		if tok.Type == TokenError {
			t.Fatalf("lex %q: %s", in, tok.Value)
		}
		out = append(out, tok.Value)
	}
}

// The fix, stated as the AGREEMENT between the two spellings rather than as a
// literal on either side. A literal would encode which spelling is trusted, and
// here the unquoted one was the broken one.
func TestMidTokenBracketsAgreeWithTheQuotedSpelling_8453(t *testing.T) {
	for _, tc := range []struct{ unquoted, quoted string }{
		{`.*65000[0-9]*`, `".*65000[0-9]*"`},
		{`a[b]c`, `"a[b]c"`},
		{`65000:[100`, `"65000:[100"`}, // unbalanced: still one value
		{`x]y`, `"x]y"`},               // stray closer mid-token
	} {
		gotU := lexAll(t, tc.unquoted)
		gotQ := lexAll(t, tc.quoted)
		if !reflect.DeepEqual(gotU, gotQ) {
			t.Errorf("spellings disagree:\n  unquoted %s -> %q\n  quoted   %s -> %q\n"+
				"An unquoted value whose domain contains brackets must tokenize to the "+
				"same single value as its quoted twin; otherwise it is silently rewritten "+
				"into a different, still-valid value.",
				tc.unquoted, gotU, tc.quoted, gotQ)
		}
		if len(gotU) != 1 {
			t.Errorf("%s tokenized to %q — expected ONE value; splitting it is the defect "+
				"(one community member becoming several is a policy widening)", tc.unquoted, gotU)
		}
	}
}

// THE ACCEPT-SIDE CONTROLS. A rule that swallowed brackets everywhere would
// satisfy every cell above while destroying Junos list syntax, so each form the
// #5182 comment enumerates as "must remain list sugar" is pinned here.
//
// RED on over-reach: drop the `l.bracketDepth == 0` guard from readIdentifier
// and `[ a b c ]` collapses to a single token — every bracketed list in the tree
// becomes one value.
func TestGenuineBracketListsAreUnchanged_8453(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"canonical list", `[ a b c ]`, []string{"a", "b", "c"}},
		{"spaceless list", `[a b]`, []string{"a", "b"}},
		{"single element", `[tcp]`, []string{"tcp"}},
		{"empty list", `[ ]`, nil},
		{"list of two communities", `[ 65000:100 65000:200 ]`, []string{"65000:100", "65000:200"}},
		{"leading bracket is still a list", `[0-9]+`, []string{"0-9", "+"}},
		{"value after a closed list", `[ a ] b[c]`, []string{"a", "b[c]"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lexAll(t, tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("lex(%q) = %q, want %q — this form is list syntax and must be "+
					"byte-identical to its pre-#8453 tokenization", tc.in, got, tc.want)
			}
		})
	}
}

// The #5182 bracketed endpoint literal runs BEFORE readIdentifier and must be
// untouched: it is the existing precedent for "a bracket adjacent to content is
// not list sugar", and a regression here would re-open the WireGuard
// port-dropping defect rather than this one.
func TestBracketedEndpointLiteralStillWhole_8453(t *testing.T) {
	got := lexAll(t, `endpoint [2001:db8::1]:51820`)
	want := []string{"endpoint", "[2001:db8::1]:51820"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lex = %q, want %q (#5182)", got, want)
	}
}

// End to end through the production commit path, since the tokenizer cells above
// would still pass if something downstream re-split the value.
func TestASPathRegexSurvivesToTheCompiledConfig_8453(t *testing.T) {
	for _, in := range []string{
		`policy-options as-path ap1 .*65000[0-9]*`,
		`policy-options as-path ap1 ".*65000[0-9]*"`,
	} {
		path, quoted, err := ParseSetCommandQuoted("set " + in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		tree := &ConfigTree{}
		if err := tree.SetPathQuoted(path, quoted); err != nil {
			t.Fatalf("SetPathQuoted %q: %v", in, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", in, err)
		}
		if len(cfg.PolicyOptions.ASPaths) != 1 {
			t.Fatalf("%q: got %d as-paths, want 1", in, len(cfg.PolicyOptions.ASPaths))
		}
		for _, ap := range cfg.PolicyOptions.ASPaths {
			if got := ap.Regex; got != `.*65000[0-9]*` {
				t.Errorf("%q compiled to regex %q, want %q — a regex that still COMPILES "+
					"but matches a different set is the failure mode this closes",
					in, got, `.*65000[0-9]*`)
			}
		}
	}
}

// The community half: one authored member must stay one member.
func TestCommunityMemberIsNotSplitByBrackets_8453(t *testing.T) {
	path, quoted, err := ParseSetCommandQuoted(`set policy-options community c1 members a[b]c`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tree := &ConfigTree{}
	if err := tree.SetPathQuoted(path, quoted); err != nil {
		t.Fatalf("SetPathQuoted: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, c := range cfg.PolicyOptions.Communities {
		if want := []string{"a[b]c"}; !reflect.DeepEqual(c.Members, want) {
			t.Errorf("Members = %q, want %q — splitting one member into three widens the "+
				"route-map to match a OR b OR c", c.Members, want)
		}
		return
	}
	t.Fatal("community c1 not compiled")
}

// END-TO-END accept-side control. The lex-level cells above prove the token
// stream is unchanged for a genuine list; this proves the COMPILED result is
// too. Without it, a downstream change that re-split a list would satisfy every
// tokenizer cell in this file.
func TestBracketedMembersListStillCompilesToTwoMembers_8453(t *testing.T) {
	path, quoted, err := ParseSetCommandQuoted(
		`set policy-options community c1 members [ 65000:100 65000:200 ]`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tree := &ConfigTree{}
	if err := tree.SetPathQuoted(path, quoted); err != nil {
		t.Fatalf("SetPathQuoted: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, c := range cfg.PolicyOptions.Communities {
		if want := []string{"65000:100", "65000:200"}; !reflect.DeepEqual(c.Members, want) {
			t.Errorf("Members = %q, want %q — a bracketed list is Junos syntax and must "+
				"still yield its members; a rule that made brackets literal everywhere "+
				"would collapse this to one value and still pass every cell above",
				c.Members, want)
		}
		return
	}
	t.Fatal("community c1 not compiled")
}

// The OTHER production entry point. Operator `set` goes through
// SetPathQuotedGrouped, as does `load merge` / replay
// (configstore/store_command.go) — the two were unified on #9881, after this
// file was written against the split pair. A fix verified on only one of
// them is verified on a population that does not contain the other — which
// is how a live defect gets recorded as absent.
func TestMidTokenBracketsSurviveTheLoadMergePath_8453(t *testing.T) {
	for _, tc := range []struct{ in, wantRegex string }{
		{`policy-options as-path ap1 .*65000[0-9]*`, `.*65000[0-9]*`},
		{`policy-options as-path ap1 ".*65000[0-9]*"`, `.*65000[0-9]*`},
	} {
		path, quoted, grouped, err := ParseSetCommandGrouped("set " + tc.in)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.in, err)
		}
		tree := &ConfigTree{}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped %q: %v", tc.in, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", tc.in, err)
		}
		found := false
		for _, ap := range cfg.PolicyOptions.ASPaths {
			found = true
			if ap.Regex != tc.wantRegex {
				t.Errorf("load-merge path: %q compiled to %q, want %q",
					tc.in, ap.Regex, tc.wantRegex)
			}
		}
		if !found {
			t.Fatalf("%q: no as-path compiled", tc.in)
		}
	}
}
