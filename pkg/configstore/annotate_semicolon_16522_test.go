package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16522: a ';' inside a quoted annotate comment (or a quoted path
// element) is annotation text — ValidateAnnotationText permits it and
// hierarchical /* primary; backup */ comments create it — so the box's
// own `show | display set` output must round-trip through load set and
// load merge. A structural (unquoted) ';' carrying an extra statement
// must still be refused (#15167 class: the lenient lexer would silently
// drop the tail and apply only the gated prefix).

func TestAnnotateSemicolonQuotedRoundTrip16522(t *testing.T) {
	// Probe cells: quoted ';' in the comment, in a quoted path element,
	// hierarchical comment prose, and a trailing structural ';'.
	accepted := []struct {
		name string
		line string
		want string // substring expected in the hierarchical candidate
	}{
		{"quoted semicolon comment", `annotate system host-name "primary; backup"`, "/* primary; backup */"},
		{"quoted semicolon comment trailing semi", `annotate system host-name "primary; backup";`, "/* primary; backup */"},
		{"multiple quoted semicolons", `annotate system host-name "a; b; c"`, "/* a; b; c */"},
		{"semicolon only comment", `annotate system host-name ";"`, "/* ; */"},
		{"quoted path semicolon", `annotate system "host;name" "note; here"`, ""}, // path probe below
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			body := "set system host-name fw1\n"
			if tc.name == "quoted path semicolon" {
				// The quoted path element must survive as ONE element,
				// matching the hierarchical node it names.
				body = "set system \"host;name\" fw1\n"
				// "host;name" as a single key is not a real schema path;
				// use a direct tree probe instead (below).
				_ = body
				tree, errs := config.NewParser("system {\n host-name fw1;\n}\n").Parse()
				if len(errs) > 0 {
					t.Fatalf("parse: %v", errs)
				}
				if err := applyEditLine(tree, `annotate system host-name "note; here"`); err != nil {
					t.Fatalf("applyEditLine quoted-; path probe: %v", err)
				}
				if got := tree.Format(); !strings.Contains(got, "/* note; here */") {
					t.Fatalf("tree missing quoted-; annotation:\n%s", got)
				}
				return
			}
			if _, err := s.LoadSet(body + tc.line + "\n"); err != nil {
				t.Fatalf("LoadSet %q: %v", tc.line, err)
			}
			if tc.want != "" && !strings.Contains(s.ShowCandidate(), tc.want) {
				t.Fatalf("LoadSet %q lost annotation, candidate:\n%s", tc.line, s.ShowCandidate())
			}
			// Same line through LoadMerge flat replay.
			s2 := newTestStore(t)
			if err := s2.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := s2.LoadMerge(body + tc.line + "\n"); err != nil {
				t.Fatalf("LoadMerge %q: %v", tc.line, err)
			}
			if tc.want != "" && !strings.Contains(s2.ShowCandidate(), tc.want) {
				t.Fatalf("LoadMerge %q lost annotation, candidate:\n%s", tc.line, s2.ShowCandidate())
			}
		})
	}
}

func TestAnnotateSemicolonDisplaySetRoundTrip16522(t *testing.T) {
	// The documented backup/restore contract (#15718): set an annotation
	// whose prose contains ';' via the hierarchical form, emit
	// `show | display set`, and replay it through load set / load merge.
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadMerge("system {\n    /* primary; backup */\n    host-name fw1;\n}\n"); err != nil {
		t.Fatalf("hierarchical LoadMerge with ';' comment: %v", err)
	}
	if !strings.Contains(s.ShowCandidate(), "/* primary; backup */") {
		t.Fatalf("hierarchical annotation lost:\n%s", s.ShowCandidate())
	}
	setOut := s.ShowCandidateSet()
	if !strings.Contains(setOut, `"primary; backup"`) {
		t.Fatalf("display set did not emit quoted ';' annotate line:\n%s", setOut)
	}
	for _, mode := range []string{"set", "merge"} {
		s2 := newTestStore(t)
		if err := s2.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if mode == "set" {
			if _, err := s2.LoadSet(setOut); err != nil {
				t.Fatalf("LoadSet(display set with ';' annotation): %v\n%s", err, setOut)
			}
		} else {
			if err := s2.LoadMerge(setOut); err != nil {
				t.Fatalf("LoadMerge(display set with ';' annotation): %v\n%s", err, setOut)
			}
		}
		if !strings.Contains(s2.ShowCandidate(), "/* primary; backup */") {
			t.Errorf("load %s round-trip lost ';' annotation:\n%s", mode, s2.ShowCandidate())
		}
	}
}

func TestAnnotateStructuralSemicolonRefused16522(t *testing.T) {
	// Structural-';' controls: an extra statement after ';', a bare
	// unquoted ';' tail, and a quoted-';' line followed by a second
	// statement must all be refused AND leave the candidate untouched
	// (atomic load). FAIL-ON-REVERT: deleting the strict check (or
	// restoring the lenient ParseAnnotateCommand) applies the annotate
	// prefix and silently drops the tail, going RED here.
	controls := []string{
		`annotate system host-name "primary"; delete system host-name`,
		`annotate system host-name "primary" ; delete system host-name`,
		`annotate system host-name "primary"; set system host-name evil`,
		`annotate system host-name "primary; backup"; delete system host-name`,
		`annotate system host-name "primary";;`,
		`annotate system host-name primary; backup`,
		`annotate system host-name "primary" | delete system host-name`,
		`annotate system host-name "unterminated;`,
	}
	for _, line := range controls {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		before := s.ShowCandidate()
		if _, err := s.LoadSet("set system host-name fw1\n" + line + "\n"); err == nil {
			t.Errorf("LoadSet accepted structural-';' control %q", line)
		}
		if got := s.ShowCandidate(); got != before {
			t.Errorf("LoadSet control %q mutated candidate on refusal:\nbefore:\n%s\nafter:\n%s", line, before, got)
		}
		s2 := newTestStore(t)
		if err := s2.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s2.LoadMerge("set system host-name fw1\n" + line + "\n"); err == nil {
			t.Errorf("LoadMerge accepted structural-';' control %q", line)
		}
	}
}

func TestParseAnnotateCommandStrict16522(t *testing.T) {
	// Unit probe for the strict split itself: quoted ';' accepted,
	// structural ';' refused, and the split identical to the lenient
	// parser on clean lines.
	path, comment, ok := config.ParseAnnotateCommandStrict16522(`annotate system host-name "primary; backup"`)
	if !ok || comment != "primary; backup" || len(path) != 2 || path[0] != "system" || path[1] != "host-name" {
		t.Fatalf("quoted-; strict parse = %v %q %v", path, comment, ok)
	}
	path, comment, ok = config.ParseAnnotateCommandStrict16522(`annotate system "a;b" "c;d"`)
	if !ok || comment != "c;d" || len(path) != 2 || path[1] != "a;b" {
		t.Fatalf("quoted path-; strict parse = %v %q %v", path, comment, ok)
	}
	for _, bad := range []string{
		`annotate system host-name "x"; delete system host-name`,
		`annotate system host-name "x" ;`,
		`annotate system host-name "x";;`,
		`annotate system host-name x; y`,
		`annotate system host-name "unterminated`,
		`annotate system host-name "x" {`,
	} {
		if _, _, ok := config.ParseAnnotateCommandStrict16522(bad); ok {
			t.Errorf("strict parse accepted %q", bad)
		}
	}
	// Clean lines: strict and lenient agree.
	for _, line := range []string{
		`annotate system host-name "primary fw"`,
		`annotate system "sys note"`,
	} {
		p1, c1, ok1 := config.ParseAnnotateCommand(line)
		p2, c2, ok2 := config.ParseAnnotateCommandStrict16522(line)
		if ok1 != ok2 || c1 != c2 || len(p1) != len(p2) {
			t.Errorf("strict/lenient disagree on %q: (%v,%q,%v) vs (%v,%q,%v)", line, p1, c1, ok1, p2, c2, ok2)
		}
	}
}
