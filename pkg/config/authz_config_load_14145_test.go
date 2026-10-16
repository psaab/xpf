package config

import (
	"strings"
	"testing"
)

// #14145: ClassifyLoadContent reset inToken on '[' so a following '/*'
// inside what the real lexer reads as ONE identifier (readIdentifier keeps
// '[' '/' '*' as ident chars at bracketDepth 0, #8453) was misread as a
// block-comment opener. An unclosed fake comment made ClassifyLoadContent
// error, LoadMutationLines swallowed the error as nil, and
// AuthorizeConfigLoad adjudicated zero lines and ALLOWED a restricted
// load set whose raw lines the store then applied verbatim. A closed fake
// comment instead hid the denied lines from the gate while the store's
// raw-line replay still applied them.
//
// These cells are the decisive regression from the issue: they must fail
// on the pre-fix code (AuthorizeConfigLoad returns nil) and pass with the
// fix. They do NOT special-case the trigger bytes in production code; the
// fix makes the classifier agree with the real lexer and makes the gate
// fail closed on classifier errors.

// Premise: the denied path alone is refused, and the admitted first line
// alone is allowed, so a pass below cannot be a class refused everything
// nor a deny regex that never fires.
func TestLoadSetMidTokenBracketFakeCommentIsDenied14145(t *testing.T) {
	cfg := cfg9892(t)
	if err := AuthorizeConfigLoad(cfg, "limited", "set",
		"set system host-name allowed14145"); err != nil {
		t.Fatalf("premise failed: admitted host-name line refused: %v", err)
	}
	if err := AuthorizeConfigLoad(cfg, "limited", "set",
		"set system root-authentication plain-text-password hunter2"); err == nil {
		t.Fatal("premise failed: denied root-authentication line allowed")
	}

	cases := map[string]string{
		// The issue's decisive shape: unclosed fictitious comment opened
		// mid-token on an admitted free-text value line. Pre-fix the
		// classifier errored, the gate adjudicated nothing and allowed.
		"unclosed fake comment": "set system host-name a[/*\n" +
			"set system root-authentication plain-text-password hunter2\n",
		// Closed fake comment: pre-fix the classifier blanked the denied
		// line as comment prose and the gate allowed, while the store's
		// raw replay would still apply it.
		"closed fake comment": "set system host-name a[/*\n" +
			"set system root-authentication plain-text-password hunter2\n" +
			"# */\n",
		// Same mechanism via `load merge`: the store routes this body flat
		// (first line is a verb+path line) and replays the sanitized form,
		// so the gate must see the same denied line.
		"merge unclosed fake comment": "set system host-name a[/*\n" +
			"set system root-authentication plain-text-password hunter2\n",
		"merge closed fake comment": "set system host-name a[/*\n" +
			"set system root-authentication plain-text-password hunter2\n" +
			"# */\n",
	}
	for name, body := range cases {
		mode := "set"
		if strings.HasPrefix(name, "merge ") {
			mode = "merge"
		}
		if err := AuthorizeConfigLoad(cfg, "limited", mode, body); err == nil {
			t.Errorf("%s: load %s carrying a denied path hidden behind a mid-token "+
				"fake block comment was ALLOWED (#14145)\nbody: %q", name, mode, body)
		}
	}
}

// The gate must not adjudicate this body as EMPTY: the denied line has to
// reach the adjudicator as a mutation line. This pins the renderer half,
// so a fix that merely refuses every body containing '[' cannot pass by
// over-refusal alone — the allowed controls below pin that side too.
func TestLoadMutationLinesSeesPastMidTokenBracket14145(t *testing.T) {
	body := "set system host-name a[/*\n" +
		"set system root-authentication plain-text-password hunter2\n"
	lines, linesErr := LoadMutationLines(body)
	if linesErr != nil {
		t.Fatalf("LoadMutationLines error = %v; the classifier must agree with "+
			"the real lexer on a mid-token '[/*' (#14145)", linesErr)
	}

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "root-authentication") {
		t.Errorf("LoadMutationLines(%q) = %q; the denied line never reached "+
			"adjudication (#14145)", body, lines)
	}
}

// Bracket-boundary controls: a '[' that BEGINS a token is list sugar to
// the real lexer, so a comment after it is still a comment — the fix
// must not swing to "brackets never end a token".
func TestClassifyBracketBoundaryComments14145(t *testing.T) {
	flat, uncommented, err := ClassifyLoadContent(
		"set interfaces ge-0/0/0 description [ /* prose */ x\n")
	if err != nil {
		t.Fatalf("ClassifyLoadContent error = %v", err)
	}
	if !flat {
		t.Errorf("flat = false, want true")
	}
	if strings.Contains(uncommented, "prose") {
		t.Errorf("comment prose after bracket sugar survived: %q", uncommented)
	}
	cfg := cfg9892(t)
	body := "system {\n/* root-authentication { plain-text-password x; } */\nhost-name ok14145;\n}\n"
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", body); err != nil {
		t.Errorf("denied path inside a genuine hierarchical comment was adjudicated: %v", err)
	}
}

// Fail-closed on classifier error: a body the shared classifier cannot
// classify (a genuine unterminated block comment) must be REFUSED for a
// restricted class, not adjudicated as zero mutations. Before the fix
// LoadMutationLines mapped the error to nil and the gate allowed.
func TestLoadWithUnterminatedCommentIsDenied14145(t *testing.T) {
	cfg := cfg9892(t)
	body := "set system host-name allowed14145\n/* unterminated\n" +
		"set system root-authentication plain-text-password hunter2\n"
	for _, mode := range []string{"set", "merge"} {
		if err := AuthorizeConfigLoad(cfg, "limited", mode, body); err == nil {
			t.Errorf("load %s with an unterminated block comment was ALLOWED for a "+
				"restricted class; classifier errors must fail closed (#14145)", mode)
		}
	}
}

// Narrowness controls: the fix must not refuse bodies the store
// legitimately applies. A real block comment (started at a token
// boundary) still hides its prose, a mid-token bracket value without any
// comment sequence still loads, and a slash inside a token is not a
// comment.
func TestLoadMidTokenBracketAllowedBodiesStillPass14145(t *testing.T) {
	cfg := cfg9892(t)
	cases := map[string]string{
		"real block comment hides prose": "/* delete system root-authentication */\n" +
			"set system host-name allowed14145\n",
		"mid-token bracket value alone": "set system host-name a[bc\n",
		"slash inside bare token":       "set system host-name foo//bar\n",
		"comment between tokens":        "set /* note */ system host-name allowed14145\n",
	}
	for name, body := range cases {
		if err := AuthorizeConfigLoad(cfg, "limited", "set", body); err != nil {
			t.Errorf("%s: an allowed load was refused: %v (#14145)", name, err)
		}
	}
}

// The classifier itself must agree with the real lexer: `a[/*` is one
// identifier, so no block comment opens and nothing is blanked.
func TestClassifyLoadContentMidTokenBracketIsNotComment14145(t *testing.T) {
	body := "set system host-name a[/*\nset system host-name b\n"
	flat, uncommented, err := ClassifyLoadContent(body)
	if err != nil {
		t.Fatalf("ClassifyLoadContent error = %v; a mid-token '[/*' is identifier "+
			"text to the real lexer, not a comment (#14145)", err)
	}
	if !flat {
		t.Errorf("flat = false, want true for a verb-led body (#14145)")
	}
	if !strings.Contains(uncommented, "a[/*") {
		t.Errorf("classifier rewrote identifier text: %q (#14145)", uncommented)
	}
	if !strings.Contains(uncommented, "set system host-name b") {
		t.Errorf("classifier blanked the line after a mid-token '[/*': %q (#14145)", uncommented)
	}
}
