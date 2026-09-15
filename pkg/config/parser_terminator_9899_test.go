package config

import (
	"strings"
	"testing"
)

// TestParserRequiresTerminator9899 pins F099: a top-level unfinished
// hierarchical leaf at EOF must be a parse error, not a silent implicit leaf.
//
// parser.go's default terminator arm treats "no semicolon or brace" as an
// implicit leaf with zero errors. That is correct before a right brace
// (`system { host-name foo }` omits the semicolon and Junos tolerates it),
// but at EOF there is no closing brace to justify the omission —
// `system host-name foo` (no `;`, no braces) parsed clean with nil errors,
// so CheckText/LoadOverride gated on len(errs)==0 accepted a truncated
// statement as if it were complete.
//
// The fix records an expected-semicolon ParseError when the default arm sees
// EOF, while still carrying the node for recovery (like the existing
// missing-brace recovery). Scope is EOF only: the before-right-brace
// tolerance is unchanged, and the flat-set grammar (ParseSetCommand) has its
// own EOF rule where no semicolon is required.
//
// FAIL-ON-REVERT (RED against unchanged source): the "unfinished at EOF
// errors" leg expects len(errs)>0, but the base parser returns nil errors
// with an implicit leaf, so it goes RED. The three control legs pass both
// before and after.
func TestParserRequiresTerminator9899(t *testing.T) {
	t.Run("unfinished top-level leaf at EOF errors", func(t *testing.T) {
		tree, errs := NewParser(`system host-name foo`).Parse()
		if len(errs) == 0 {
			t.Fatal("expected a ParseError for a top-level hierarchical leaf " +
				"missing its terminator at EOF, got nil errors (silent implicit leaf)")
		}
		joined := ""
		for _, e := range errs {
			joined += e.Error() + "\n"
		}
		if !strings.Contains(joined, ";") && !strings.Contains(strings.ToLower(joined), "semicolon") {
			t.Errorf("EOF-terminator error should name the missing ';'/semicolon, got: %v", errs)
		}
		// Recovery still carries the node, like the missing-brace path.
		if tree == nil || len(tree.Children) == 0 {
			t.Fatalf("recovery tree dropped the unfinished leaf entirely; "+
				"want the node carried with an error, errs=%v", errs)
		}
	})

	t.Run("terminated leaf parses clean", func(t *testing.T) {
		tree, errs := NewParser(`system host-name foo;`).Parse()
		if len(errs) != 0 {
			t.Fatalf("terminated leaf produced parse errors: %v", errs)
		}
		if tree == nil || len(tree.Children) != 1 {
			t.Fatalf("terminated leaf lost its node: %+v", tree)
		}
	})

	t.Run("flat-set EOF needs no semicolon", func(t *testing.T) {
		// Independent grammar: flat-set lines terminate at EOF by design.
		path, err := ParseSetCommand(`set system host-name foo`)
		if err != nil {
			t.Fatalf("flat-set without trailing ';' must parse (independent grammar): %v", err)
		}
		if strings.Join(path, " ") != "system host-name foo" {
			t.Fatalf("flat-set path=%v, want [system host-name foo]", path)
		}
	})

	t.Run("missing semicolon before right brace still tolerated", func(t *testing.T) {
		// Scope guard: the fix touches EOF only. A leaf whose terminator is
		// omitted immediately before '}' keeps parsing clean.
		tree, errs := NewParser(`system { host-name foo }`).Parse()
		if len(errs) != 0 {
			t.Fatalf("before-right-brace tolerance regressed (want clean): %v", errs)
		}
		if tree == nil || len(tree.Children) != 1 {
			t.Fatalf("tolerated leaf lost its block: %+v", tree)
		}
		sys := tree.Children[0]
		if len(sys.Children) != 1 || strings.Join(sys.Children[0].Keys, " ") != "host-name foo" {
			t.Fatalf("tolerated leaf has wrong children: %+v", sys.Children)
		}
	})
}
