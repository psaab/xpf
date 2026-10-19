package refactoraudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #8393: a Rust function carrying two `#[test]` attributes registers TWICE, and
// the reason it ends up with two is that it STOLE one from the function above it.
//
// The live instance this guard was written from: a new test was pasted between
// an existing test's doc comment and its `fn`, so the new function absorbed the
// old `#[test]` and the displaced function was left with none. It stopped running
// entirely — and it was the guard for the very renderer that same change rewrote.
//
// Nothing in the ordinary signal can see this:
//
//   - a test that stops existing cannot FAIL, so the suite stayed green;
//   - the total went UP, because the duplicate registration adds one, so even
//     "did the test count drop?" points the wrong way;
//   - `cargo test` prints ONE name in its failures block while reporting two
//     failures, and that discrepancy reads as noise.
//
// So the check has to be structural. Two `#[test]` on one function has no
// legitimate use — it runs the same body twice for no benefit — which is what
// makes this bannable outright rather than allowlisted. A guard that forces a
// workaround would be mis-specified; there is nothing here to work around.
//
// Deliberately NOT checked: "a fn inside `mod tests` with no `#[test]`". That
// over-approximates — test modules legitimately hold helpers, builders and
// fixtures — and a guard that fires on correct code teaches people to route
// around it. The duplicate is the sound half, and it is the half that actually
// marks the theft.
func TestNoRustFunctionCarriesTwoTestAttributes8393(t *testing.T) {
	root := repoRoot(t)

	var scanned int
	var findings []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "target", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
		scanned++
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		findings = append(findings, duplicateTestAttrs8393(rel, string(raw))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// A zero from a scanner is worth nothing if the scanner never looked at
	// anything. The tree has hundreds of .rs files; a handful means the walk
	// broke, not that the repo shrank.
	if scanned < 100 {
		t.Fatalf("only scanned %d .rs files — the walk is broken, so the "+
			"'no duplicates' result below would be vacuous", scanned)
	}

	for _, f := range findings {
		t.Errorf("%s\n\nTwo `#[test]` attributes on one function register it twice, and the "+
			"usual cause is that it took the attribute belonging to the function above it — "+
			"which then stops running silently (#8393). Delete the stray attribute AND check "+
			"that the function it belonged to still has one:\n\n"+
			"    cargo test <filter> -- --list | sort | uniq -d\n\n"+
			"Verify by the registered LIST, never by the pass count — the count goes UP when "+
			"this happens.", f)
	}
}

// testAttrLine reports whether a trimmed line is a test-registering attribute.
// Matched exactly rather than by substring so a doc comment mentioning
// `#[test]` in prose — of which this repo has several — is not a finding.
func testAttrLine(trimmed string) bool {
	switch trimmed {
	case "#[test]", "#[tokio::test]":
		return true
	}
	return strings.HasPrefix(trimmed, "#[test_case") ||
		strings.HasPrefix(trimmed, "#[tokio::test(")
}

// duplicateTestAttrs8393 returns one finding per function preceded by two or
// more test attributes. Split out from the test body so the detector can be
// exercised against known-good and known-bad input directly — a scanner whose
// only evidence is "it found nothing in the repo" is indistinguishable from one
// whose pattern never matches.
func duplicateTestAttrs8393(rel, src string) []string {
	var out []string
	var attrs []int // 1-based line numbers of pending test attributes
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case testAttrLine(trimmed):
			attrs = append(attrs, i+1)
		case isFnDecl8393(trimmed):
			if len(attrs) >= 2 {
				where := make([]string, 0, len(attrs))
				for _, a := range attrs {
					where = append(where, itoa8393(a))
				}
				out = append(out, rel+":"+itoa8393(i+1)+" — attributes at lines "+
					strings.Join(where, ", "))
			}
			attrs = nil
		case trimmed == "" ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#["):
			// doc comments, `#[ignore]`, `#[should_panic]`, `#[cfg(...)]` and
			// blank lines all legitimately sit between an attribute and its fn.
		default:
			// Any other code ends the attribute run.
			attrs = nil
		}
	}
	return out
}

func isFnDecl8393(trimmed string) bool {
	for _, p := range []string{"fn ", "pub fn ", "pub(crate) fn ", "async fn ",
		"pub async fn ", "const fn ", "unsafe fn "} {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return strings.HasPrefix(trimmed, "pub(") && strings.Contains(trimmed, ") fn ")
}

func itoa8393(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The detector needs its own table, because the repo-wide result is a ZERO and a
// zero proves nothing about a scanner that cannot match. The rows that matter are
// the near-misses: input that is CORRECT but structurally close to the defect. A
// detector that only passes the obvious-good and obvious-bad cases would fire on
// `#[ignore] #[test]` or on a doc comment quoting the attribute, and a guard that
// fires on correct code gets routed around rather than fixed.
func TestDuplicateTestAttrDetectorCanSeeAndCanAbstain8393(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			// The live #8393 shape: a test pasted between a doc comment and its fn.
			name: "attribute stolen by an inserted test",
			src: "    /// old doc\n    #[test]\n    /// new doc\n    #[test]\n" +
				"    fn inserted() {}\n",
			want: 1,
		},
		{
			name: "ordinary single test",
			src:  "    /// doc\n    #[test]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: two attributes, only one of them registering.
			name: "test plus ignore is not a duplicate",
			src:  "    #[test]\n    #[ignore]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: two attributes, only one of them registering.
			name: "test plus should_panic is not a duplicate",
			src:  "    #[test]\n    #[should_panic]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: prose mentioning the attribute must not count. This
			// repo's own comments discuss `#[test]` in several places.
			name: "doc comment quoting the attribute",
			src:  "    /// use #[test] here\n    /// and #[test] there\n    #[test]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: intervening code ends the run, so two tests separated
			// by a real function body are two separate registrations.
			name: "two separate tests are not a duplicate",
			src:  "    #[test]\n    fn a() {}\n    #[test]\n    fn b() {}\n",
			want: 0,
		},
		{
			name: "duplicate on an async test",
			src:  "    #[tokio::test]\n    #[tokio::test]\n    async fn dup() {}\n",
			want: 1,
		},
	}

	for _, tc := range cases {
		got := duplicateTestAttrs8393("x.rs", tc.src)
		if len(got) != tc.want {
			t.Errorf("%s: got %d findings, want %d\n  findings: %v\n  src:\n%s",
				tc.name, len(got), tc.want, got, tc.src)
		}
	}
}

// ---- #15255 (A84-01): the OTHER half of the #8393 class ------------------
//
// #8393 guarded a function carrying TWO #[test] attributes. The benign
// half — a zero-arg asserting fn in a test module with NO attribute
// and no caller — silently never runs: #9962's fix left
// `the_poll_paths_reverse_install_releases_a_predecessors_rows_9560`
// in exactly that state, so one #9560 steering-row ownership cell was
// lost from `make test` while the suite stayed green.
//
// The naive version of this check ("any un-attributed fn in a test
// file") over-approximates wildly: test modules legitimately hold
// helpers, builders and fixtures, almost all of which take arguments
// or are referenced. The pinned shape is the narrow conjunction that
// describes a displaced test and nothing else in this tree:
//
//   - file is a test-module file (tests_*.rs, *_tests.rs, *_test.rs,
//     or under a tests/ dir);
//   - fn takes ZERO arguments (helpers/builders take inputs);
//   - fn body contains an assert (fixtures arrange, tests assert);
//   - NO test attribute precedes it;
//   - the name occurs exactly ONCE in the file (nothing calls it).
//
// A helper that goes dead after a refactor is caught by the compiler
// (dead_code) or is a different defect; only the conjunction above
// is claimed here, and the detector table below pins its near-misses.

// isRustTestModuleFile15255 reports whether path (repo-relative,
// slash-separated) names a Rust test-module file.
func isRustTestModuleFile15255(rel string) bool {
	base := rel[strings.LastIndex(rel, "/")+1:]
	return strings.HasPrefix(base, "tests_") ||
		strings.HasSuffix(base, "_tests.rs") ||
		strings.HasSuffix(base, "_test.rs") ||
		strings.Contains(rel, "/tests/")
}

// fnNameAndArgs15255 parses a fn declaration line, returning the name
// and the raw argument list. ok=false for non-declarations. Generic
// parameter lists before the parens are skipped.
func fnNameAndArgs15255(trimmed string) (name, args string, ok bool) {
	rest := trimmed
	for _, p := range []string{"pub(crate) fn ", "pub fn ", "pub async fn ",
		"async fn ", "pub unsafe fn ", "unsafe fn ", "const fn ", "fn "} {
		if strings.HasPrefix(rest, p) {
			rest = rest[len(p):]
			goto found
		}
	}
	if strings.HasPrefix(rest, "pub(") {
		if idx := strings.Index(rest, ") fn "); idx >= 0 {
			rest = rest[idx+len(") fn "):]
			goto found
		}
	}
	return "", "", false
found:
	open := strings.Index(rest, "(")
	if open < 0 {
		return "", "", false
	}
	name = strings.TrimSpace(rest[:open])
	if lt := strings.Index(name, "<"); lt >= 0 {
		name = strings.TrimSpace(name[:lt])
	}
	if name == "" {
		return "", "", false
	}
	// Balance parens (argument types contain them: closures, tuples).
	depth := 0
	for i := open; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return name, rest[open+1 : i], true
			}
		}
	}
	return "", "", false
}

// fnBody15255 returns the body of the fn whose declaration starts at
// line start (0-based), bounded by brace balance after masking string
// literals and line comments so braces inside them cannot end the
// body early. Returns "" when no balanced body is found.
func fnBody15255(lines []string, start int) string {
	var b strings.Builder
	depth := 0
	started := false
	for i := start; i < len(lines); i++ {
		line := lines[i]
		for j := 0; j < len(line); j++ {
			c := line[j]
			if c == '"' {
				// Skip a string literal (honour \" escapes).
				j++
				for ; j < len(line); j++ {
					if line[j] == '\\' {
						j++
						continue
					}
					if line[j] == '"' {
						break
					}
				}
				continue
			}
			if c == '/' && j+1 < len(line) && line[j+1] == '/' {
				break // rest of line is a comment
			}
			if !started {
				b.WriteByte(c)
			} else {
				b.WriteByte(c)
			}
			switch c {
			case '{':
				depth++
				started = true
			case '}':
				depth--
				if started && depth == 0 {
					return b.String()
				}
			}
		}
		b.WriteByte('\n')
	}
	return ""
}

// unregisteredTestFns15255 returns one finding per zero-arg asserting
// fn with no test attribute and no other reference in the file.
func unregisteredTestFns15255(rel, src string) []string {
	lines := strings.Split(src, "\n")
	var out []string
	var pendingTest bool
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case testAttrLine(trimmed):
			pendingTest = true
		case isFnDecl8393(trimmed):
			name, args, ok := fnNameAndArgs15255(trimmed)
			if ok && !pendingTest && strings.TrimSpace(args) == "" {
				body := fnBody15255(lines, i)
				asserting := strings.Contains(body, "assert!(") ||
					strings.Contains(body, "assert_eq!(") ||
					strings.Contains(body, "assert_ne!(")
				if asserting {
					refs := strings.Count(src, name+"(")
					if refs <= 1 {
						out = append(out, rel+":"+itoa8393(i+1)+" — fn "+name+
							"() asserts but carries no #[test] and is never called")
					}
				}
			}
			pendingTest = false
		case trimmed == "" || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#["):
			// Between an attribute and its fn; keep pendingTest.
		default:
			pendingTest = false
		}
	}
	return out
}

func TestNoUnregisteredAssertingTestFn15255(t *testing.T) {
	root := repoRoot(t)
	var scanned int
	var findings []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "target", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !isRustTestModuleFile15255(rel) {
			return nil
		}
		scanned++
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, unregisteredTestFns15255(rel, string(raw))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned < 50 {
		t.Fatalf("only scanned %d Rust test-module files — the walk is broken, so "+
			"the 'no unregistered tests' result below would be vacuous", scanned)
	}
	for _, f := range findings {
		t.Errorf("%s\n\nA zero-arg asserting fn in a test module with no #[test] "+
			"and no caller never runs (#15255, the benign half of #8393): the "+
			"suite stays green while the cell is lost. Restore the attribute "+
			"— or, if this is a helper, give it an argument or call it.", f)
	}
}

// TestUnregisteredTestFnDetector15255 pins the detector against the
// live shape and its near-misses. A scanner whose only evidence is
// "found nothing in the repo" proves nothing.
func TestUnregisteredTestFnDetector15255(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "displaced test with no attribute and no caller",
			src:  "#[test]\nfn other() { assert!(true); }\n\nfn lost() {\n    assert_eq!(1, 1);\n}\n",
			want: 1,
		},
		{
			name: "ordinary registered test",
			src:  "#[test]\nfn ok() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "unregistered helper that takes an argument",
			src:  "fn fixture(x: u32) -> u32 { assert!(x > 0); x }\n#[test]\nfn uses() { assert_eq!(fixture(1), 1); }\n",
			want: 0,
		},
		{
			name: "unregistered zero-arg helper that is called",
			src:  "fn setup() { assert!(true); }\n#[test]\nfn uses() { setup(); assert!(true); }\n",
			want: 0,
		},
		{
			name: "unregistered zero-arg fn without asserts is a fixture",
			src:  "fn fixture() -> u32 { 7 }\n#[test]\nfn uses() { assert_eq!(fixture(), 7); }\n",
			want: 0,
		},
		{
			name: "test plus ignore still registers",
			src:  "#[test]\n#[ignore]\nfn ok() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "tokio test registers",
			src:  "#[tokio::test]\nasync fn ok() { assert!(true); }\n",
			want: 0,
		},
	}
	for _, tc := range cases {
		got := unregisteredTestFns15255("tests_x.rs", tc.src)
		if len(got) != tc.want {
			t.Errorf("%s: got %d findings, want %d\n  findings: %v\n  src:\n%s",
				tc.name, len(got), tc.want, got, tc.src)
		}
	}
}
