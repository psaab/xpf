package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// compiledJSON9635 returns the strict verdict and the WHOLE compiled config as
// JSON, so a row compares everything rather than the one field the author
// thought to look at. Three of this issue's earlier probes reported a clean
// result from a field that was simply absent from the window they printed.
func compiledJSON9635(t *testing.T, text string) (string, string) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	strict := "OK"
	if _, err := CompileConfig(tree); err != nil {
		strict = "REFUSED: " + err.Error()
	}
	lt, _ := NewParser(text).Parse()
	cfg, err := CompileConfigLenient(lt)
	if err != nil {
		t.Fatalf("lenient compile %q: %v", text, err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return strict, buf.String()
}

// #9635: `proposals [ P "proposal-set" ]` references a proposal that merely
// happens to be NAMED like the sibling `proposal-set` statement. The packed
// splitter ended the multi-value statement at that token and SchemaValidate
// then refused the config with "proposal-set: missing value".
//
// Measured at origin/master 773146dd4: REFUSED in both the braced and the
// brace-elided spelling; both commit here with BOTH references.
func TestAuthoredValueStaysAValue9635(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want []string
	}{
		{
			name: "braced container, value spells a sibling keyword",
			text: `security { ike { policy P1 { proposals [ P "proposal-set" ]; } } }`,
			want: []string{"P", "proposal-set"},
		},
		{
			name: "brace-elided container, same value",
			text: `security { ike policy P1 proposals [ P "proposal-set" ]; }`,
			want: []string{"P", "proposal-set"},
		},
		{
			// CONTROL, and it passed at master too: a lone quoted value fits
			// inside the leaf's declared arg span, so no token is left over and
			// nothing ever tried to split. It pins that the single-value
			// spelling of the same reference was never the broken one -- the
			// defect needed a SECOND value to split at.
			name: "control, quoted value inside the arg span",
			text: `security { ike { policy P1 { proposals "proposal-set"; } } }`,
			want: []string{"proposal-set"},
		},
		{
			// Control: nothing here spells a sibling, so this row passed at
			// master too. It pins that the fix did not disturb the ordinary list.
			name: "control, no token spells a sibling",
			text: `security { ike { policy P1 { proposals [ P Q ]; } } }`,
			want: []string{"P", "Q"},
		},
		{
			name: "control, single reference",
			text: `security { ike { policy P1 { proposals P; } } }`,
			want: []string{"P"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strict, js := compiledJSON9635(t, tc.text)
			if strict != "OK" {
				t.Fatalf("must commit, got %s", strict)
			}
			var want bytes.Buffer
			enc := json.NewEncoder(&want)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(tc.want); err != nil {
				t.Fatalf("encode want: %v", err)
			}
			// Encode appends a newline; compare the list form itself.
			needle := `"Proposals":` + strings.TrimSpace(want.String())
			if !strings.Contains(js, needle) {
				t.Fatalf("compiled config does not carry %s\nfull: %s", needle, js)
			}
		})
	}
}

// statementsUnder9635 returns the normalized statement list at
// `security ike policy P1`, as space-joined keys.
func statementsUnder9635(t *testing.T, text string) []string {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	normalizeCompactStanzas(tree)
	nodes := tree.Children
	for _, want := range []string{"security", "ike", "policy"} {
		var next []*Node
		found := false
		for _, n := range nodes {
			if len(n.Keys) > 0 && n.Keys[0] == want {
				next, found = n.Children, true
				break
			}
		}
		if !found {
			t.Fatalf("no %q level in %q", want, text)
		}
		nodes = next
	}
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, strings.Join(n.Keys, " "))
	}
	return out
}

// #9635: an authored-value run ENDS where the authoring stops. The bracketed
// list keeps `proposal-set`, and the bare `mode aggressive` after the closing
// bracket is still its own statement.
//
// Without this row the bound on the run is untested: consuming to the end of
// the tail produces the same answer on every other fixture here, because in all
// of them the authored tokens run to the end.
func TestAuthoredValueRunEndsWithTheAuthoring9635(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want []string
	}{
		{
			name: "bare statement after a bracketed list",
			text: `security { ike { policy P1 { proposals [ P "proposal-set" ] mode aggressive; } } }`,
			want: []string{"proposals P proposal-set", "mode aggressive"},
		},
		{
			name: "control, all-bare list then a bare statement",
			text: `security { ike { policy P1 { proposals [ P Q ] mode aggressive; } } }`,
			want: []string{"proposals P Q", "mode aggressive"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := statementsUnder9635(t, tc.text)
			if len(got) != len(tc.want) {
				t.Fatalf("statements: got %q want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("statement %d: got %q want %q", i, got, tc.want)
				}
			}
		})
	}
}

// #9635: the rule is about the statement BEFORE the token, not the token alone.
// `pre-shared-key` is fixed-arity (args: 2), so once `ascii-text` and the key
// are consumed it cannot own another value and the quoted `"mode"` really does
// begin the next statement. An earlier attempt declined every split whose
// boundary landed on a quoted token, which regressed exactly this config.
//
// THE STRUCTURAL ASSERTION IS THE ONE THAT BITES, and that is not obvious.
// Dropping the arity rule fuses this run into a single node -- and the compiled
// config comes out IDENTICAL anyway, because the compiler here also reads the
// packed tail. A compiled-output comparison therefore passes either way:
// measured, by running the whole pkg/config suite with the arity rule removed,
// which stayed green. The issue states the acceptance as "keeps committing as
// two statements", so the statement list is asserted directly. Leaning on the
// downstream tolerance instead would leave the rule unfalsifiable, and a rule
// no cell can break is not a safety margin.
func TestFixedArityQuotedTokenIsAStatementHead9635(t *testing.T) {
	for _, tc := range []struct{ name, packed, separated string }{
		{
			name:      "braced container",
			packed:    `security { ike { policy P1 { pre-shared-key ascii-text "s" "mode" aggressive; } } }`,
			separated: `security { ike { policy P1 { pre-shared-key ascii-text "s"; mode aggressive; } } }`,
		},
		{
			name:      "brace-elided container",
			packed:    `security { ike policy P1 pre-shared-key ascii-text "s" "mode" aggressive; }`,
			separated: `security { ike { policy P1 { pre-shared-key ascii-text "s"; mode aggressive; } } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := statementsUnder9635(t, tc.packed)
			want := statementsUnder9635(t, tc.separated)
			if len(got) != len(want) {
				t.Fatalf("packed must normalize to the same statements\npacked:    %q\nseparated: %q", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("statement %d differs\npacked:    %q\nseparated: %q", i, got, want)
				}
			}

			sp, jp := compiledJSON9635(t, tc.packed)
			ss, js := compiledJSON9635(t, tc.separated)
			if sp != "OK" || ss != "OK" {
				t.Fatalf("both must commit: packed=%s separated=%s", sp, ss)
			}
			if jp != js {
				t.Fatalf("packed must compile like the separated spelling\npacked:    %s\nseparated: %s", jp, js)
			}
		})
	}
}

// #9635 must not make a genuinely fused statement acceptable. The pair below is
// the SAME TOKENS in the same order, differing only in whether the operator
// wrote the quote and the brackets -- which is the entire content of the claim
// that provenance is what decides this.
//
// The bare row is asserted as REFUSED, not as refused BY A PARTICULAR GATE.
// Writing it the other way was tried and was wrong: the splitter separates the
// bare run, and it is then `proposal-set` failing its own validation that
// refuses, not the #8437 fusion gate. Pinning the mechanism would have pinned a
// misreading; the property that protects the operator is that a missing
// semicolon does not commit.
func TestAuthoredMarkDecidesTheVerdict9635(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bare       string
		authored   string
		wantRefuse string
	}{
		{
			name:       "value spelling a sibling keyword",
			bare:       `security { ike { policy P1 { proposals P proposal-set; } } }`,
			authored:   `security { ike { policy P1 { proposals [ P "proposal-set" ]; } } }`,
			wantRefuse: "proposal-set",
		},
		{
			name:       "and with a trailing token of its own",
			bare:       `security { ike { policy P1 { proposals P proposal-set aggressive; } } }`,
			authored:   `security { ike { policy P1 { proposals [ P "proposal-set" "aggressive" ]; } } }`,
			wantRefuse: "proposal-set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bareTree, perrs := NewParser(tc.bare).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			normalizeCompactStanzas(bareTree)
			err := SchemaValidate(bareTree, nil)
			if err == nil {
				t.Fatalf("the bare spelling is a missing semicolon and must not commit")
			}
			if !strings.Contains(err.Error(), tc.wantRefuse) {
				t.Fatalf("refusal must name the offending token, got: %v", err)
			}

			authTree, perrs := NewParser(tc.authored).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			normalizeCompactStanzas(authTree)
			if err := SchemaValidate(authTree, nil); err != nil {
				t.Fatalf("the authored-value spelling must commit, got: %v", err)
			}
		})
	}
}
