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

// ---- #15255 (A84-01) / #16442: the OTHER half of the #8393 class --------
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
//   - fn is inside a test region (see rustTestRegions15255): a file
//     the module system only builds under cfg(test) — `tests.rs`
//     included (#16442), the basename/`tests/` shapes the original
//     #15255 census used, and files loaded by a cfg(test)-gated
//     `#[path = "..."] mod` — or an inline `#[cfg(test)] mod
//     name { ... }` block in a production file;
//   - fn takes ZERO arguments (helpers/builders take inputs);
//   - fn body contains an assert (fixtures arrange, tests assert);
//   - NO test attribute precedes it;
//   - the name occurs exactly ONCE in the file (nothing calls it).
//
// A helper that goes dead after a refactor is caught by the compiler
// (dead_code) or is a different defect; only the conjunction above
// is claimed here, and the detector table below pins its near-misses.
//
// #16442: the original census keyed test-module-ness on basename alone
// (`tests_*`, `*_tests.rs`, `*_test.rs`, `/tests/`), so the 13
// `tests.rs` files and every inline `#[cfg(test)] mod` fell outside
// it — roughly a third of the crate's cells, including the largest
// test files, were never opened.
//
// Region model (brace depth, line oriented). A `#[cfg(test)]` line
// arms the NEXT item: if that item is an inline `mod name {`, the
// region runs to its matching `}`; if it is `mod name;` or a
// `#[path = "..."] mod name;`, the file that declaration loads is a
// whole-file test region (recorded for the census walk); anything
// else (a fn, a const, a use) is a single-item test helper, not a
// test module, and is NOT a region — scanning it would flag the
// zero-arg asserting seams production files expose for tests. A
// bare production `mod name {` is never a region, and a cfg(test)
// later in the file does not retroactively claim earlier fns. Braces
// inside string literals and line comments are masked with the same
// discipline as fnBody15255; block comments, raw strings and char
// literals are NOT understood — the walk below runs this over the
// whole tree, so any misread there surfaces as a loud finding to
// adjudicate rather than a silent skip.
//
// Whole-file rule: a .rs file is a test-module file when its basename
// matches the historical shapes or `tests.rs`, when it sits under a
// `tests/` directory, or when a cfg(test)-gated `#[path]` declaration
// loads it. Cargo integration tests under `userspace-dp/tests/` are
// covered by the `tests/` directory shape. A file opening with a
// `#[cfg(test)]` gate on a non-mod item is NOT thereby a test module:
// that shape is a production file whose first item is a test seam.
// Files no whole-file rule claims are scanned for inline regions only.

// rustCfgTestGate15255 reports whether a trimmed line gates the item
// that follows it on the test configuration:
// `#[cfg(test)]`, `#[cfg(all(test, ...))]`, `#[cfg(any(test, ...))]`,
// or `#[cfg_attr(test, ...)]`.
func rustCfgTestGate15255(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "#[cfg") {
		return false
	}
	rest := strings.TrimPrefix(trimmed, "#[cfg")
	rest = strings.TrimPrefix(rest, "_attr")
	if !strings.HasPrefix(rest, "(") {
		return false
	}
	inner := rest[1:]
	return inner == "test" || strings.HasPrefix(inner, "test)") ||
		strings.HasPrefix(inner, "test,") ||
		strings.HasPrefix(inner, "all(test") ||
		strings.HasPrefix(inner, "any(test")
}

// rustTestRegions15255 returns the [start, end) line ranges (0-based)
// of src that form test modules, for a file already known to live at
// rel. whole=true means every line is a test region (the caller need
// not consult ranges). gatedPaths collects the targets of
// cfg(test)-gated `#[path = "..."] mod name;` declarations, resolved
// against the directory of the declaring file by the caller.
func rustTestRegions15255(rel, src string) (ranges [][2]int, whole bool, gatedPaths []string) {
	lines := strings.Split(src, "\n")
	if isRustTestModuleFile15255(rel) {
		return nil, true, nil
	}
	ranges, gatedPaths = scanRustTestRegions15255(lines)
	return ranges, false, gatedPaths
}

// isRustTestModuleFile15255 reports whether path (repo-relative,
// slash-separated) names a Rust test-module file by basename or by
// sitting under a `tests/` directory. `tests.rs` is included
// (#16442): it is loaded only via `#[cfg(test)] mod tests;` or a
// cfg(test)-gated `#[path = "tests.rs"]`.
func isRustTestModuleFile15255(rel string) bool {
	base := rel[strings.LastIndex(rel, "/")+1:]
	return base == "tests.rs" ||
		strings.HasPrefix(base, "tests_") ||
		strings.HasSuffix(base, "_tests.rs") ||
		strings.HasSuffix(base, "_test.rs") ||
		strings.Contains(rel, "/tests/") ||
		strings.HasPrefix(rel, "tests/")
}

// scanRustTestRegions15255 finds the inline `#[cfg(test)] mod name {`
// regions in one file and the targets of cfg(test)-gated
// `#[path = "..."] mod name;` declarations. Only a `mod` item may
// follow the gate (possibly after one `#[path = "..."]` line): a
// gated fn/const/use is a test-only helper, not a test module.
func scanRustTestRegions15255(lines []string) (ranges [][2]int, gatedPaths []string) {
	depth := 0
	regionStart := -1
	regionBase := 0 // brace depth just outside the region's mod block
	pendingGate := false
	pendingPath := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if regionStart >= 0 {
			depth = scanBraceDepth15255(line, depth)
			if depth <= regionBase {
				ranges = append(ranges, [2]int{regionStart, i + 1})
				regionStart = -1
			}
			continue
		}
		switch {
		case rustCfgTestGate15255(trimmed):
			pendingGate = true
			pendingPath = ""
		case pendingGate && strings.HasPrefix(trimmed, `#[path = "`):
			pendingPath = rustPathAttrTarget15255(trimmed)
		case pendingGate && isModDecl15255(trimmed):
			if strings.HasSuffix(trimmed, "{") {
				regionStart = i
				regionBase = depth
				depth = scanBraceDepth15255(line, depth)
				if depth <= regionBase { // `mod tests {}` on one line
					ranges = append(ranges, [2]int{regionStart, i + 1})
					regionStart = -1
				}
			} else if pendingPath != "" {
				gatedPaths = append(gatedPaths, pendingPath)
			}
			pendingGate = false
			pendingPath = ""
		case trimmed == "" || strings.HasPrefix(trimmed, "//"):
			// Comment/blank between the gate and its item.
		case pendingGate && strings.HasPrefix(trimmed, "#["):
			// Another attribute (#[allow], ...) on the gated mod;
			// the gate still arms the mod.
		default:
			pendingGate = false
			pendingPath = ""
			depth = scanBraceDepth15255(line, depth)
		}
	}
	if regionStart >= 0 {
		ranges = append(ranges, [2]int{regionStart, len(lines)})
	}
	return ranges, gatedPaths
}

// isModDecl15255 reports whether a trimmed line declares a module:
// `mod name;`, `mod name {`, `pub mod name ...`, or `pub(...) mod`.
func isModDecl15255(trimmed string) bool {
	rest := trimmed
	if strings.HasPrefix(rest, "pub ") {
		rest = rest[len("pub "):]
	} else if strings.HasPrefix(rest, "pub(") {
		idx := strings.Index(rest, ") ")
		if idx < 0 {
			return false
		}
		rest = rest[idx+2:]
	}
	return strings.HasPrefix(rest, "mod ")
}

// rustPathAttrTarget15255 extracts the target of `#[path = "..."]`.
func rustPathAttrTarget15255(trimmed string) string {
	const pfx = `#[path = "`
	if !strings.HasPrefix(trimmed, pfx) {
		return ""
	}
	rest := trimmed[len(pfx):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// scanBraceDepth15255 returns the brace depth after one line, masking
// string literals and `//` comments with fnBody15255's discipline.
func scanBraceDepth15255(line string, depth int) int {
	for j := 0; j < len(line); j++ {
		switch line[j] {
		case '"':
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
		case '/':
			if j+1 < len(line) && line[j+1] == '/' {
				return depth
			}
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}

// resolveRustPath15255 resolves a `#[path]` target against the
// repo-relative directory of the declaring file. Targets escaping the
// declaring directory (`../bpf_map_tests.rs`) are normalised; results
// that would escape the repo are dropped by the caller.
func resolveRustPath15255(declaringRel, target string) string {
	dir := declaringRel
	if idx := strings.LastIndex(dir, "/"); idx >= 0 {
		dir = dir[:idx]
	} else {
		dir = ""
	}
	joined := target
	if dir != "" {
		joined = dir + "/" + target
	}
	var parts []string
	for _, p := range strings.Split(joined, "/") {
		switch p {
		case "", ".":
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "/")
}

// lineInRanges15255 reports whether line i (0-based) is inside any
// of the [start, end) ranges.
func lineInRanges15255(ranges [][2]int, i int) bool {
	for _, r := range ranges {
		if i >= r[0] && i < r[1] {
			return true
		}
	}
	return false
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

// wholeFileUnregisteredTestFns15255 is unregisteredTestFns15255 for a
// file whose every line is a test region, without region checks.
func wholeFileUnregisteredTestFns15255(rel, src string) []string {
	return unregisteredInRanges15255(rel, src, nil, true)
}

// unregisteredTestFns15255 returns one finding per zero-arg asserting
// fn with no test attribute and no other reference in the file, for
// fns inside a test region of the file at rel (see
// rustTestRegions15255). Files with no test region yield no findings.
func unregisteredTestFns15255(rel, src string) []string {
	ranges, whole, _ := rustTestRegions15255(rel, src)
	if !whole && len(ranges) == 0 {
		return nil
	}
	return unregisteredInRanges15255(rel, src, ranges, whole)
}

// unregisteredInRanges15255 is the detector core: pendingTest tracks a
// test attribute on the preceding item; only fns inside a region (or
// every fn, when whole) are candidates. Name references are counted
// over the whole file, as before.
func unregisteredInRanges15255(rel, src string, ranges [][2]int, whole bool) []string {
	lines := strings.Split(src, "\n")
	var out []string
	var pendingTest bool
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case testAttrLine(trimmed):
			pendingTest = true
		case isFnDecl8393(trimmed):
			inRegion := whole || lineInRanges15255(ranges, i)
			name, args, ok := fnNameAndArgs15255(trimmed)
			if inRegion && ok && !pendingTest && strings.TrimSpace(args) == "" {
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
	// First pass: read every .rs file once, classify it, and collect
	// the files a cfg(test)-gated #[path] declaration loads.
	srcs := map[string]string{}
	gated := map[string]bool{}
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
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		src := string(raw)
		srcs[rel] = src
		_, _, paths := rustTestRegions15255(rel, src)
		for _, p := range paths {
			if resolved := resolveRustPath15255(rel, p); resolved != "" &&
				!strings.HasPrefix(resolved, "../") {
				gated[resolved] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	var scanned, wholeFiles, regionFiles int
	var findings []string
	for rel, src := range srcs {
		ranges, whole, _ := rustTestRegions15255(rel, src)
		whole = whole || gated[rel]
		if !whole && len(ranges) == 0 {
			continue
		}
		scanned++
		if whole {
			wholeFiles++
			findings = append(findings, wholeFileUnregisteredTestFns15255(rel, src)...)
		} else {
			regionFiles++
			findings = append(findings, unregisteredInRanges15255(rel, src, ranges, false)...)
		}
	}
	// Floors sit well below the measured tree (492 scanned: 389
	// whole-file, 103 inline-region at #16442) but far above the old
	// basename-only census, so a region-scan regression that quietly
	// drops tests.rs or inline modules reds here instead of passing
	// vacuously.
	if scanned < 400 || wholeFiles < 300 || regionFiles < 80 {
		t.Fatalf("scanned %d Rust test-region files (%d whole-file, %d inline-region) — the walk "+
			"or region scan is broken, so the 'no unregistered tests' result below would be vacuous",
			scanned, wholeFiles, regionFiles)
	}
	for _, f := range findings {
		t.Errorf("%s\n\nA zero-arg asserting fn in a test module with no #[test] "+
			"and no caller never runs (#15255/#16442, the benign half of #8393): the "+
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
		rel  string
		src  string
		want int
	}{
		{
			name: "displaced test with no attribute and no caller",
			rel:  "tests_x.rs",
			src:  "#[test]\nfn other() { assert!(true); }\n\nfn lost() {\n    assert_eq!(1, 1);\n}\n",
			want: 1,
		},
		{
			name: "ordinary registered test",
			rel:  "tests_x.rs",
			src:  "#[test]\nfn ok() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "unregistered helper that takes an argument",
			rel:  "tests_x.rs",
			src:  "fn fixture(x: u32) -> u32 { assert!(x > 0); x }\n#[test]\nfn uses() { assert_eq!(fixture(1), 1); }\n",
			want: 0,
		},
		{
			name: "unregistered zero-arg helper that is called",
			rel:  "tests_x.rs",
			src:  "fn setup() { assert!(true); }\n#[test]\nfn uses() { setup(); assert!(true); }\n",
			want: 0,
		},
		{
			name: "unregistered zero-arg fn without asserts is a fixture",
			rel:  "tests_x.rs",
			src:  "fn fixture() -> u32 { 7 }\n#[test]\nfn uses() { assert_eq!(fixture(), 7); }\n",
			want: 0,
		},
		{
			name: "test plus ignore still registers",
			rel:  "tests_x.rs",
			src:  "#[test]\n#[ignore]\nfn ok() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "tokio test registers",
			rel:  "tests_x.rs",
			src:  "#[tokio::test]\nasync fn ok() { assert!(true); }\n",
			want: 0,
		},
		// #16442 rows: the shapes the basename-only census never opened.
		{
			name: "tests.rs path: displaced test reds",
			rel:  "userspace-dp/src/session/tests.rs",
			src:  "fn lost() {\n    assert_eq!(1, 1);\n}\n",
			want: 1,
		},
		{
			name: "tests.rs path: registered test stays green",
			rel:  "userspace-dp/src/session/tests.rs",
			src:  "#[test]\nfn ok() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "inline cfg(test) mod: displaced test reds",
			rel:  "userspace-dp/src/screen/scan.rs",
			src: "pub fn prod() {}\n\n#[cfg(test)]\nmod tests {\n" +
				"    use super::*;\n\n" +
				"    fn lost() {\n        assert_eq!(1, 1);\n    }\n}\n",
			want: 1,
		},
		{
			name: "inline cfg(test) mod: registered test stays green",
			rel:  "userspace-dp/src/screen/scan.rs",
			src:  "#[cfg(test)]\nmod tests {\n    #[test]\n    fn ok() { assert!(true); }\n}\n",
			want: 0,
		},
		{
			name: "inline cfg(test) mod: production fn before the module is not scanned",
			rel:  "userspace-dp/src/screen/scan.rs",
			src: "fn prod_helper() { assert!(true); }\n\n#[cfg(test)]\nmod tests {\n" +
				"    #[test]\n    fn ok() { assert!(true); }\n}\n",
			want: 0,
		},
		{
			name: "ungated inline mod: not a test region",
			rel:  "userspace-dp/src/screen/scan.rs",
			src:  "mod inner {\n    pub fn lost() { assert_eq!(1, 1); }\n}\n",
			want: 0,
		},
		{
			name: "cfg(test) fn seam is not a test module",
			rel:  "userspace-dp/src/screen/scan.rs",
			src:  "#[cfg(test)]\npub(crate) fn seam() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "cfg(all(test, not(miri))) inline mod reds",
			rel:  "userspace-dp/src/screen/scan.rs",
			src: "#[cfg(all(test, not(miri)))]\nmod tests {\n" +
				"    fn lost() { assert!(true); }\n}\n",
			want: 1,
		},
		{
			name: "cfg_attr(test) inline mod reds",
			rel:  "userspace-dp/src/screen/scan.rs",
			src: "#[cfg_attr(test, allow(dead_code))]\nmod tests {\n" +
				"    fn lost() { assert!(true); }\n}\n",
			want: 1,
		},
		{
			name: "cfg(not(test)) inline mod is not a test region",
			rel:  "userspace-dp/src/screen/scan.rs",
			src:  "#[cfg(not(test))]\nmod prod {\n    pub fn lost() { assert!(true); }\n}\n",
			want: 0,
		},
		{
			name: "cfg(test) first-item gate alone does not make the file a test module",
			rel:  "userspace-dp/src/afxdp/some_seam.rs",
			src:  "#[cfg(test)]\nfn lost() { assert!(true); }\n",
			want: 0,
		},
		{
			name: "production file with no test region stays green",
			rel:  "userspace-dp/src/screen/scan.rs",
			src:  "pub fn prod() { assert!(true); }\nfn helper() { assert!(true); }\n",
			want: 0,
		},
	}
	for _, tc := range cases {
		rel := tc.rel
		if rel == "" {
			rel = "tests_x.rs"
		}
		got := unregisteredTestFns15255(rel, tc.src)
		if len(got) != tc.want {
			t.Errorf("%s: got %d findings, want %d\n  findings: %v\n  src:\n%s",
				tc.name, len(got), tc.want, got, tc.src)
		}
	}
	// The gated-#[path] half of the region model: the declaring file
	// yields no finding itself; the loaded file is a whole-file region.
	decl := "#[cfg(test)]\n#[path = \"tests.rs\"]\nmod tests;\n"
	if got := unregisteredTestFns15255("userspace-dp/src/session/mod.rs", decl); len(got) != 0 {
		t.Errorf("gated #[path] declaring file: got %d findings, want 0: %v", len(got), got)
	}
	_, _, gatedPaths := rustTestRegions15255("userspace-dp/src/session/mod.rs", decl)
	if len(gatedPaths) != 1 || gatedPaths[0] != "tests.rs" {
		t.Errorf("gated #[path] targets: got %v, want [tests.rs]", gatedPaths)
	} else if got := resolveRustPath15255("userspace-dp/src/session/mod.rs", gatedPaths[0]); got != "userspace-dp/src/session/tests.rs" {
		t.Errorf("resolved gated path: got %q, want userspace-dp/src/session/tests.rs", got)
	}
	// Detector must abstain on known-good inline shapes.
	good := "#[cfg(test)]\nmod tests {\n    fn fixture(x: u32) { assert!(x > 0); }\n    #[test]\n    fn ok() { assert!(true); }\n}\n"
	if got := unregisteredTestFns15255("userspace-dp/src/screen/scan.rs", good); len(got) != 0 {
		t.Errorf("inline helper with arg: got %d findings, want 0: %v", len(got), got)
	}
}
