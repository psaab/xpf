package docsref

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// baselineFile is the grandfathered census of citations that do not resolve on
// master. See doc.go for why it exists and why it is a ratchet.
const baselineFile = "testdata/known_dangling.txt"

// citationRe matches a docs/research/... or docs/pr/... markdown citation.
// Deliberately narrow: only the two plan trees, only .md targets. Widening it
// to every docs/ path would sweep in prose mentions of directories.
//
// The alternation is a CAPTURING group on purpose. This pattern is handed to
// `git grep -E`, which is POSIX ERE and rejects a non-capturing `(?:...)` with
// "Invalid preceding regular expression" — and git grep exits 0 on that fatal,
// so the sweep would silently return nothing and the gate would pass while
// checking exactly zero citations. Keep this POSIX-compatible.
var citationRe = regexp.MustCompile(`docs/(research|pr)/[A-Za-z0-9._@/+-]+\.md`)

// repoRoot is pkg/docsref -> ../..
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Fatalf("repo root %s does not look like a checkout: %v", root, err)
	}
	return root
}

// citations returns cited-path -> sorted citing files, over TRACKED files only.
//
// Tracked is the right population: an untracked scratch file or another lane's
// worktree under .claude/ is not part of the codebase's explanation of itself,
// and including them would make the gate depend on the developer's disk.
func citations(t *testing.T, root string) map[string][]string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "grep", "-I", "--no-color", "-o", "-E", citationRe.String())
	out, err := cmd.Output()
	if err != nil {
		// git grep exits 1 when nothing matches. That is not a healthy state
		// for this repo and would make the gate vacuous, so treat it as a
		// failure rather than an empty result.
		t.Fatalf("git grep for doc citations failed (or matched nothing, which "+
			"would make this gate vacuous): %v", err)
	}
	found := map[string]map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// Format: <file>:<match>
		i := strings.LastIndex(line, ":docs/")
		if i < 0 {
			continue
		}
		file, cited := line[:i], line[i+1:]
		if isHistoricalArchive(file) {
			// A path inside a generated history or an append-only action log is
			// a HISTORICAL RECORD of what some PR body or log entry once said,
			// not a live pointer a reader would follow for rationale. Including
			// them would also make the gate depend on GitHub history:
			// docs/issues/*-history.md are regenerated wholesale by the
			// sync-history skill, so any repair made here would be reverted on
			// the next regeneration and the gate would red for no author.
			continue
		}
		// The baseline is a list OF dangling paths; it must not count as a
		// citation of them or every entry would self-justify.
		if filepath.ToSlash(file) == "pkg/docsref/"+baselineFile {
			continue
		}
		if found[cited] == nil {
			found[cited] = map[string]bool{}
		}
		found[cited][file] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan git grep output: %v", err)
	}
	out2 := map[string][]string{}
	for cited, files := range found {
		var fs []string
		for f := range files {
			fs = append(fs, f)
		}
		sort.Strings(fs)
		out2[cited] = fs
	}
	return out2
}

// historicalPathsFile is the single source for the historical-archive path
// set: pkg/docsref and scripts/ci_affected_go_tests.sh (never_read) both
// load it instead of hand-keeping diverging copies (#17115).
const historicalPathsFile = "scripts/historical-paths.txt"

// parseHistoricalPatterns17115 parses the shared data-file body.
func parseHistoricalPatterns17115(body string) []string {
	var pats []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pats = append(pats, line)
	}
	return pats
}

// loadHistoricalPatterns17115 reads the shared pattern file.
func loadHistoricalPatterns17115(t *testing.T, root string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, historicalPathsFile))
	if err != nil {
		t.Fatalf("read %s: %v", historicalPathsFile, err)
	}
	pats := parseHistoricalPatterns17115(string(b))
	if len(pats) == 0 {
		t.Fatalf("%s parsed to ZERO patterns — the loader or the file has rotted", historicalPathsFile)
	}
	return pats
}

// matchHistoricalPattern reports whether pattern matches slash path f, where
// "*" matches any (possibly empty) run of characters.
func matchHistoricalPattern(pattern, f string) bool {
	pre, suf, found := strings.Cut(pattern, "*")
	if !found {
		return pattern == f
	}
	return len(f) >= len(pre)+len(suf) && strings.HasPrefix(f, pre) && strings.HasSuffix(f, suf)
}

// isHistoricalArchive reports whether a file is a generated history or an
// append-only log (docs/log/ included: CLAUDE.md makes it the successor of
// _Log.md), whose contents quote what was written at some past time rather
// than pointing at rationale a reader should follow now. The set itself
// lives in scripts/historical-paths.txt, shared with the CI selector.
func isHistoricalArchive(file string) bool {
	f := filepath.ToSlash(file)
	for _, pat := range historicalPatterns17115 {
		if matchHistoricalPattern(pat, f) {
			return true
		}
	}
	return false
}

// historicalPatterns17115 is the shared set loaded once at test init.
// Panic (not an empty set) on failure so a missing file can never silently
// make the sweep scan archives.
var historicalPatterns17115 = loadHistoricalPatternsFS17115()

func loadHistoricalPatternsFS17115() []string {
	root, err := filepath.Abs(filepath.Join(".", "..", ".."))
	if err != nil {
		panic(err)
	}
	b, err := os.ReadFile(filepath.Join(root, historicalPathsFile))
	if err != nil {
		panic(fmt.Sprintf("read %s: %v", historicalPathsFile, err))
	}
	pats := parseHistoricalPatterns17115(string(b))
	if len(pats) == 0 {
		panic(historicalPathsFile + " parsed to ZERO patterns")
	}
	return pats
}

func loadBaseline(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(baselineFile)
	if err != nil {
		t.Fatalf("read %s: %v", baselineFile, err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = true
	}
	if len(set) == 0 {
		t.Fatalf("%s parsed to ZERO entries — the parser or the file has rotted, "+
			"and an empty baseline would make every dangling citation look new", baselineFile)
	}
	return set
}

// TestNoNewDanglingDocCitations is the ratchet.
//
// FAIL-ON-REVERT: add a citation to a docs/research/... or docs/pr/... plan
// that does not exist on master, without adding it to the baseline.
func TestNoNewDanglingDocCitations(t *testing.T) {
	root := repoRoot(t)
	baseline := loadBaseline(t)
	cited := citations(t, root)

	if len(cited) == 0 {
		t.Fatal("no doc citations found at all — the sweep has rotted and this gate is vacuous")
	}

	var newDangles []string
	for path, files := range cited {
		if _, err := os.Stat(filepath.Join(root, path)); err == nil {
			continue // resolves; fine
		}
		if baseline[path] {
			continue // grandfathered
		}
		newDangles = append(newDangles, fmt.Sprintf("%s\n      cited by: %s",
			path, strings.Join(files, ", ")))
	}
	sort.Strings(newDangles)
	if len(newDangles) > 0 {
		t.Errorf("#6615: %d NEW dangling documentation citation(s) — the cited path does not "+
			"exist on master, so the rationale it points at is unreachable and the next "+
			"engineer either re-derives it or changes the code believing none exists.\n"+
			"Fix the citation, merge the document, or (only if the plan genuinely will not "+
			"land) add the path to %s with a reason.\n\n  %s",
			len(newDangles), baselineFile, strings.Join(newDangles, "\n  "))
	}
}

// TestBaselineHasNoResolvedOrUncitedEntries keeps the census honest in the
// other direction: the baseline must not over-permit.
//
// An entry that now RESOLVES (the plan merged, or the citation was corrected)
// must be removed, or it silently grandfathers a path that could otherwise be
// enforced. An entry nothing cites any more is dead grandfathering.
//
// FAIL-ON-REVERT: add a path to the baseline that already exists on master, or
// one that nothing cites.
func TestBaselineHasNoResolvedOrUncitedEntries(t *testing.T) {
	root := repoRoot(t)
	baseline := loadBaseline(t)
	cited := citations(t, root)

	var resolved, uncited []string
	for path := range baseline {
		if _, err := os.Stat(filepath.Join(root, path)); err == nil {
			resolved = append(resolved, path)
			continue
		}
		if len(cited[path]) == 0 {
			uncited = append(uncited, path)
		}
	}
	sort.Strings(resolved)
	sort.Strings(uncited)

	if len(resolved) > 0 {
		t.Errorf("#6615: %d baseline entr(ies) now RESOLVE on master and must be removed from "+
			"%s — leaving them grandfathers a path the gate could otherwise enforce:\n  %s",
			len(resolved), baselineFile, strings.Join(resolved, "\n  "))
	}
	if len(uncited) > 0 {
		t.Errorf("#6615: %d baseline entr(ies) are no longer cited anywhere and must be removed "+
			"from %s — dead grandfathering hides how much rot is actually left:\n  %s",
			len(uncited), baselineFile, strings.Join(uncited, "\n  "))
	}
}
