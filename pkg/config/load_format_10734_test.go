package config

import (
	"strings"
	"testing"
)

// #10734: the flat-vs-hierarchical classifier (IsFlatLoadLine applied to every
// raw line) had no comment awareness, so a verb-led prose line inside a /* */
// block ("delete after <date>") routed a whole hierarchical file to flat
// replay, where line 1 was rejected. These cells pin the comment-aware body
// classifier every load path now routes through.

func TestClassifyLoadContentSkipsComments10734(t *testing.T) {
	hier := "system {\n    host-name day0-test;\n}\n"
	hierCommentVerb := hier + "/*\nday-0 config for the lab rack.\ndelete after 2026-01-01 once verified.\n*/\n"
	cases := map[string]struct {
		body     string
		flat     bool
		wantText string
		wantErr  bool
	}{
		"hierarchical":              {body: hier},
		"flat set":                  {body: "set system host-name a\n", flat: true},
		"flat delete":               {body: "delete system domain-name\n", flat: true},
		"flat deactivate":           {body: "deactivate system foo\n", flat: true},
		"verb in block comment":     {body: hierCommentVerb, wantText: "system {"},
		"verb only inside comment":  {body: "/*\nset system host-name a\n*/\n"},
		"single-line block comment": {body: "/* delete system host-name */\n" + hier},
		"hash comment verb":         {body: "# set system host-name a\n" + hier},
		"slash comment verb":        {body: "// delete system host-name\n" + hier},
		"code after block close":    {body: "/* header */\nset system host-name a\n", flat: true, wantText: "set system host-name a"},
		"multiline header then set": {body: "/* multi\nline\nheader */\nset system host-name a\n", flat: true},
		"unterminated block":        {body: "set system host-name a\n/* unterminated\ndelete system b\n", wantErr: true},
		"empty":                     {body: ""},
		"comments only":             {body: "# only\n\n// only\n/* only */\n"},
		"comment between tokens":    {body: "set /* note */ system host-name a\n", flat: true, wantText: "system host-name a"},
		"quoted URL preserved":      {body: "set system host-name \"https://router.example\"\n", flat: true, wantText: "\"https://router.example\""},
		"slash inside bare token":   {body: "set system host-name foo//bar\n", flat: true, wantText: "foo//bar"},
		"stray closer is code":      {body: "*/\n" + hier},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gotFlat, uncommented, err := ClassifyLoadContent(tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ClassifyLoadContent error = nil, want unterminated-comment error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyLoadContent error = %v", err)
			}
			if gotFlat != tc.flat {
				t.Errorf("flat = %v, want %v (#10734):\n%s", gotFlat, tc.flat, tc.body)
			}
			if tc.wantText != "" && !strings.Contains(uncommented, tc.wantText) {
				t.Errorf("comment-free content %q does not contain %q", uncommented, tc.wantText)
			}
			if strings.Contains(uncommented, "delete after") {
				t.Errorf("comment prose survived classification: %q", uncommented)
			}
		})
	}
}

// The authorization gate must adjudicate the store-routed form (#10305): comment
// prose carrying a verb must neither flip the gate to flat nor leak into the
// adjudicated lines as if the operator wrote it.
func TestLoadMutationLinesSkipsCommentVerbs10734(t *testing.T) {
	hier := "system {\n    host-name day0-test;\n}\n/*\ndelete after 2026-01-01.\n*/\n"
	lines := LoadMutationLines(hier)
	if len(lines) == 0 {
		t.Fatal("hierarchical content rendered no lines")
	}
	for _, l := range lines {
		if strings.Contains(l, "after") {
			t.Errorf("comment prose leaked into the adjudicated lines: %q (all: %q)", l, lines)
		}
		if !strings.HasPrefix(l, "set ") {
			t.Errorf("hierarchical rendering is not set-form: %q (all: %q)", l, lines)
		}
	}

	flat := LoadMutationLines("/* backup header */\nset system host-name a\n# note\ndelete system domain-name\n")
	if len(flat) != 2 || flat[0] != "set system host-name a" || flat[1] != "delete system domain-name" {
		t.Errorf("flat content with comments rendered %q, want the two verb lines verbatim", flat)
	}
}
