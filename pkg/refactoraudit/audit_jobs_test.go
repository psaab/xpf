package refactoraudit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file exercises the two #7253 halves through their REAL scripts, in
// a throwaway git repo, so the changed-set mechanism and the refresh job
// are pinned end to end rather than only at their pure-function seams.
//
// The fixture reproduces the exact situation that used to red an innocent
// author: a committed heatmap that is stale on a file the branch never
// touched, because a sibling PR grew it in between.

// fixtureRepo is a throwaway git repo carrying a copy of the audit
// scripts and a synthetic source tree.
type fixtureRepo struct {
	t   *testing.T
	dir string
	env []string
}

// newFixtureRepo builds an empty repo with the committed audit scripts
// copied in. Git runs fully hermetically: no global or system config (so
// a developer's commit.gpgsign or hooksPath cannot reach in) and identity
// supplied by environment rather than by config.
func newFixtureRepo(t *testing.T) *fixtureRepo {
	t.Helper()
	dir := t.TempDir()
	r := &fixtureRepo{
		t:   t,
		dir: dir,
		env: append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=audit fixture",
			"GIT_AUTHOR_EMAIL=audit@fixture.invalid",
			"GIT_COMMITTER_NAME=audit fixture",
			"GIT_COMMITTER_EMAIL=audit@fixture.invalid",
			"HOME="+dir,
		),
	}

	src := repoRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir scripts: %v", err)
	}
	for _, name := range []string{
		"refactoring-audit.sh",
		"refactoring-audit-lib.sh",
		"refactoring-audit-classify.sh",
		"refactoring-audit-touched.sh",
		"refactoring-audit-refresh.sh",
	} {
		b, err := os.ReadFile(filepath.Join(src, "scripts", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "scripts", name), b, 0o755); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	r.git("init", "-q", "-b", "master")
	return r
}

// git runs a git command in the fixture and fails the test on error.
func (r *fixtureRepo) git(args ...string) string {
	r.t.Helper()
	out, err := r.gitErr(args...)
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (r *fixtureRepo) gitErr(args ...string) (string, error) {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// script runs one of the copied audit scripts in the fixture and returns
// stdout, stderr and the error separately — the loud-failure tests need
// all three.
func (r *fixtureRepo) script(env []string, args ...string) (string, string, error) {
	r.t.Helper()
	cmd := exec.Command("bash", args...)
	cmd.Dir = r.dir
	cmd.Env = append(append([]string{}, r.env...), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// writeFile writes a file of exactly n lines (n newlines), which is what
// audit_loc counts.
func (r *fixtureRepo) writeFile(rel string, n int) {
	r.t.Helper()
	path := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.t.Fatalf("mkdir for %s: %v", rel, err)
	}
	var b strings.Builder
	b.WriteString("package fixture\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "// line %d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		r.t.Fatalf("write %s: %v", rel, err)
	}
}

func (r *fixtureRepo) commit(msg string) {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
}

// regenerate writes the fixture's heatmap artifact from its own tree, the
// way an author would.
func (r *fixtureRepo) regenerate() {
	r.t.Helper()
	out, stderr, err := r.script(nil, "scripts/refactoring-audit.sh")
	if err != nil {
		r.t.Fatalf("regenerate: %v\n%s", err, stderr)
	}
	if err := os.MkdirAll(filepath.Join(r.dir, "docs"), 0o755); err != nil {
		r.t.Fatalf("mkdir docs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "docs", "refactoring-audit-current.txt"), []byte(out), 0o644); err != nil {
		r.t.Fatalf("write artifact: %v", err)
	}
}

// touched runs the changed-set probe and returns its parsed rows.
func (r *fixtureRepo) touched(baseRef string) []touchedFile {
	r.t.Helper()
	stdout, stderr, err := r.script([]string{"XPF_AUDIT_BASE_REF=" + baseRef},
		"scripts/refactoring-audit-touched.sh")
	if err != nil {
		r.t.Fatalf("refactoring-audit-touched.sh: %v\n%s", err, stderr)
	}
	return parseTouched(r.t, "fixture refactoring-audit-touched.sh", stdout)
}

func (r *fixtureRepo) touchedWithEnv(baseRef string, env []string) []touchedFile {
	r.t.Helper()
	runEnv := append([]string{"XPF_AUDIT_BASE_REF=" + baseRef}, env...)
	stdout, stderr, err := r.script(runEnv, "scripts/refactoring-audit-touched.sh")
	if err != nil {
		r.t.Fatalf("refactoring-audit-touched.sh: %v\n%s", err, stderr)
	}
	return parseTouched(r.t, "fixture refactoring-audit-touched.sh", stdout)
}

func (r *fixtureRepo) writeText(rel, text string) {
	r.t.Helper()
	path := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		r.t.Fatalf("write %s: %v", rel, err)
	}
}

// writePattern makes line identity deliberate so Git's similarity threshold
// is a property of the fixture, not an accidental property of comments.
func (r *fixtureRepo) writePattern(rel string, lines, shared int, variant string) {
	r.t.Helper()
	if lines < 1 || shared < 0 || shared >= lines {
		r.t.Fatalf("invalid pattern dimensions: lines=%d shared=%d", lines, shared)
	}
	var b strings.Builder
	b.WriteString("package fixture\n")
	for i := 1; i < lines; i++ {
		if i <= shared {
			fmt.Fprintf(&b, "// shared line %04d\n", i)
		} else {
			fmt.Fprintf(&b, "// %s line %04d\n", variant, i)
		}
	}
	r.writeText(rel, b.String())
}

func renameBase(t *testing.T, rel string, lines int) *fixtureRepo {
	t.Helper()
	r := newFixtureRepo(t)
	r.writeFile(rel, lines)
	r.commit("rename fixture base")
	r.git("checkout", "-q", "-b", "feature")
	return r
}

func requireRename(t *testing.T, r *fixtureRepo, base, source, dest string) {
	t.Helper()
	status := r.git("diff", "--name-status", "-M90%", base, "--")
	if !strings.Contains(status, "\t"+source+"\t"+dest) ||
		!strings.Contains(status, "R") {
		t.Fatalf("fixture is not a rename (want R %s -> %s); got:\n%s", source, dest, status)
	}
}

func requireTouchedPath(t *testing.T, rows []touchedFile, path string) touchedFile {
	t.Helper()
	for _, row := range rows {
		if row.path == path {
			return row
		}
	}
	t.Fatalf("missing touched row for %s; got %+v", path, rows)
	return touchedFile{}
}

func requireNoTouchedPath(t *testing.T, rows []touchedFile, path string) {
	t.Helper()
	for _, row := range rows {
		if row.path == path {
			t.Fatalf("unexpected touched row for %s: %+v", path, row)
		}
	}
}

func (r *fixtureRepo) appendLines(rel string, n int, prefix string) {
	r.t.Helper()
	path := filepath.Join(r.dir, rel)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		r.t.Fatalf("open %s for append: %v", rel, err)
	}
	defer f.Close()
	for i := range n {
		if _, err := fmt.Fprintf(f, "// %s line %04d\n", prefix, i); err != nil {
			r.t.Fatalf("append %s: %v", rel, err)
		}
	}
}

func (r *fixtureRepo) symlink(rel, target string) {
	r.t.Helper()
	path := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.Symlink(target, path); err != nil {
		r.t.Fatalf("symlink %s -> %s: %v", rel, target, err)
	}
}

func installFakeGit(t *testing.T, r *fixtureRepo, body string) string {
	t.Helper()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("locate git: %v", err)
	}
	bin := filepath.Join(r.dir, "fake-bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("mkdir fake git bin: %v", err)
	}
	script := fmt.Sprintf("#!/bin/sh\n%s\nexec %s \"$@\"\n", body, realGit)
	path := filepath.Join(bin, "git")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	return bin
}

func prependPath(dir string) string {
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// staleFixture builds the #7253 situation. Four commits, and every one of
// them is load-bearing:
//
//	B0  anchor.go 2100, split.go 1600, mine.go 1400, sibling.go 1400;
//	    heatmap regenerated and committed here and NEVER again
//	M1  a sibling PR grows sibling.go 1400 -> 1600 on master. The heatmap
//	    is not regenerated — that is the whole complaint in #7253
//	F   a feature branch forks at M1 and grows mine.go 1400 -> 1600
//	M2  master moves on AFTER the fork: someone splits split.go 1600 -> 1400
//
// At F the committed heatmap is stale on two files and only one of them is
// this branch's doing (sibling.go is in F's tree but not in F's diff), and
// master has moved underneath in both directions. M2 is what makes the
// merge-base choice observable: diffing against the master TIP would
// measure split.go as 1400 -> 1600 and red this branch for a file it never
// touched — the exact false accusation the old gate made.
func staleFixture(t *testing.T) *fixtureRepo {
	t.Helper()
	r := newFixtureRepo(t)
	r.writeFile("pkg/anchor/anchor.go", 2100)
	r.writeFile("pkg/split/split.go", 1600)
	r.writeFile("pkg/mine/mine.go", 1400)
	r.writeFile("pkg/sibling/sibling.go", 1400)
	r.writeFile("README.md", 3)
	r.regenerate()
	r.commit("base tree + heatmap")

	r.writeFile("pkg/sibling/sibling.go", 1600)
	r.commit("sibling PR grows a file this branch never touches")

	r.git("checkout", "-q", "-b", "feature")
	r.writeFile("pkg/mine/mine.go", 1600)
	r.commit("this branch grows its own file")

	r.git("checkout", "-q", "master")
	r.writeFile("pkg/split/split.go", 1400)
	r.commit("master moves on after the fork: a file is split")
	r.git("checkout", "-q", "feature")
	return r
}

// TestTouchedSetIsLocalToTheBranch is the end-to-end fail-on-revert for
// the hard half's CHANGED SET, run through the real script.
//
// It asserts the two #7253 acceptance criteria on the same tree:
//
//   - the branch's own crossing reds, named, derived from its own diff;
//   - the sibling's crossing — same tree, same stale artifact, a file the
//     branch never touched — does not.
//
// It also checks the rival mechanism on the SAME fixture: the global
// snapshot compare is red on both files here, so this is not a case where
// the two happen to agree.
func TestTouchedSetIsLocalToTheBranch(t *testing.T) {
	r := staleFixture(t)

	// The rival: a repo-global snapshot compare at this tree.
	committedBytes, err := os.ReadFile(filepath.Join(r.dir, "docs", "refactoring-audit-current.txt"))
	if err != nil {
		t.Fatalf("read fixture heatmap: %v", err)
	}
	generatedOut, stderr, err := r.script(nil, "scripts/refactoring-audit.sh")
	if err != nil {
		t.Fatalf("regenerate: %v\n%s", err, stderr)
	}
	drift := heatmapDrift(
		tierByPath(parseHeatmap(t, "fixture committed heatmap", string(committedBytes))),
		tierByPath(parseHeatmap(t, "fixture generated heatmap", generatedOut)),
	)
	if len(drift.entered) != 2 {
		t.Fatalf("fixture is wrong: the snapshot compare must be red on BOTH files "+
			"(the branch's and the sibling's); got entered=%v left=%v retiered=%v",
			drift.entered, drift.left, drift.retiered)
	}

	// The gate.
	crossings := thresholdCrossings(r.touched("master"))
	if len(crossings) != 1 {
		t.Fatalf("want exactly 1 crossing (this branch's own file); got %+v", crossings)
	}
	got := crossings[0]
	if got.path != "pkg/mine/mine.go" {
		t.Fatalf("wrong file blamed: got %s, want pkg/mine/mine.go — the sibling's "+
			"crossing is in the same tree and the same stale artifact, and must not "+
			"reach this branch's author", got.path)
	}
	if got.baseLOC != 1400 || got.headLOC != 1600 || got.tier != tierWatch {
		t.Fatalf("wrong measurement: got %d -> %d %s, want 1400 -> 1600 %s",
			got.baseLOC, got.headLOC, got.tier, tierWatch)
	}
	for _, f := range r.touched("master") {
		switch f.path {
		case "pkg/sibling/sibling.go", "pkg/split/split.go":
			t.Fatalf("%s is in the changed set; the diff must be taken against the "+
				"MERGE BASE, not against the base ref tip, or a branch inherits every "+
				"file master moved while it was open — in either direction", f.path)
		}
	}
}

// TestBranchTouchingNothingAuditedIsSilent is #7253 acceptance criterion
// 2, literally: a PR touching none of the crossing files does not red,
// however stale the global artifact is.
func TestBranchTouchingNothingAuditedIsSilent(t *testing.T) {
	r := staleFixture(t)
	r.git("checkout", "-q", "master")
	r.git("checkout", "-q", "-b", "docs-only")
	if err := os.WriteFile(filepath.Join(r.dir, "README.md"), []byte("a\nb\nc\nd\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	r.commit("docs only")

	touched := r.touched("master")
	if len(touched) != 0 {
		t.Fatalf("a docs-only branch must have an empty audited changed set; got %+v", touched)
	}
	if c := thresholdCrossings(touched); len(c) != 0 {
		t.Fatalf("a docs-only branch must not red; got %+v", c)
	}
}

// TestTouchedSetSeesUncommittedAndUntrackedGrowth pins that the probe
// measures the WORKING TREE, which is what the generator measures. An
// author running `make test` before committing must get the same answer
// they will get after, and a brand-new 1600-line file that has never been
// `git add`ed is still a file entering the audit.
func TestTouchedSetSeesUncommittedAndUntrackedGrowth(t *testing.T) {
	r := staleFixture(t)
	r.writeFile("pkg/mine/uncommitted.go", 1700) // untracked, never added

	var found bool
	for _, f := range r.touched("master") {
		if f.path == "pkg/mine/uncommitted.go" {
			found = true
			if !f.isNew {
				t.Errorf("an untracked file must report no base LOC, got %d", f.baseLOC)
			}
			if f.headLOC != 1700 {
				t.Errorf("want 1700 head LOC, got %d", f.headLOC)
			}
		}
	}
	if !found {
		t.Fatal("untracked audited files must be in the changed set; the generator " +
			"already measures them, so leaving them out lets a new 1600-line module " +
			"land without the gate ever seeing it")
	}
	crossings := thresholdCrossings(r.touched("master"))
	if len(crossings) != 2 {
		t.Fatalf("want crossings for both the grown file and the new one, got %+v", crossings)
	}
}

// TestUndeterminableBaseFailsLoudly pins the fail-closed posture. A probe
// that cannot compute a changed set must not print an empty one: empty
// reads as "nothing crossed", which is the single most dangerous wrong
// answer it can give. The existing fixtures in this package t.Fatal when
// their source is unreadable rather than passing empty, and this matches.
func TestUndeterminableBaseFailsLoudly(t *testing.T) {
	r := staleFixture(t)

	t.Run("base ref does not exist", func(t *testing.T) {
		stdout, stderr, err := r.script([]string{"XPF_AUDIT_BASE_REF=no/such/ref"},
			"scripts/refactoring-audit-touched.sh")
		if err == nil {
			t.Fatalf("want a non-zero exit for an unresolvable base ref, got success with stdout %q", stdout)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("a failing probe must print no rows, got %q", stdout)
		}
		if !strings.Contains(stderr, "no/such/ref") {
			t.Errorf("the error must name the ref it could not resolve; got %q", stderr)
		}
	})

	t.Run("no common ancestor", func(t *testing.T) {
		// An orphan branch shares no history with master, the shape a
		// shallow or grafted clone presents.
		r.git("checkout", "-q", "--orphan", "orphan")
		r.git("commit", "-q", "-m", "orphan root", "--allow-empty")
		stdout, stderr, err := r.script([]string{"XPF_AUDIT_BASE_REF=master"},
			"scripts/refactoring-audit-touched.sh")
		if err == nil {
			t.Fatalf("want a non-zero exit when there is no merge base, got success with stdout %q", stdout)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("a failing probe must print no rows, got %q", stdout)
		}
		if !strings.Contains(stderr, "common ancestor") {
			t.Errorf("the error must say what it could not compute; got %q", stderr)
		}
	})
}

// TestTouchedRename10488 is the producer-side fail-on-revert for #10488.
// Every rename assertion requires the destination row and its measured base:
// a test that merely sees a crossing (or merely sees no crossing) can pass
// while still losing the predecessor identity.
func TestTouchedRename10488(t *testing.T) {
	t.Run("committed pure rename", func(t *testing.T) {
		r := renameBase(t, "pkg/rename_old.go", 1701)
		r.git("mv", "pkg/rename_old.go", "pkg/rename_new.go")
		r.commit("commit pure rename")
		requireRename(t, r, "master", "pkg/rename_old.go", "pkg/rename_new.go")

		rows := r.touched("master")
		row := requireTouchedPath(t, rows, "pkg/rename_new.go")
		if row.isNew || row.baseLOC != 1701 || row.headLOC != 1701 {
			t.Fatalf("pure rename must inherit 1701 LOC: %+v", row)
		}
		if crossings := thresholdCrossings(rows); len(crossings) != 0 {
			t.Fatalf("pure rename must not cross: %+v", crossings)
		}
	})

	t.Run("staged rename ignores diff renames false", func(t *testing.T) {
		r := renameBase(t, "pkg/staged_old.go", 2100)
		r.git("mv", "pkg/staged_old.go", "pkg/staged_new.go")
		requireRename(t, r, "master", "pkg/staged_old.go", "pkg/staged_new.go")

		rows := r.touchedWithEnv("master", []string{
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=diff.renames",
			"GIT_CONFIG_VALUE_0=false",
		})
		row := requireTouchedPath(t, rows, "pkg/staged_new.go")
		if row.isNew || row.baseLOC != 2100 || row.headLOC != 2100 {
			t.Fatalf("explicit rename detection must beat user config: %+v", row)
		}
		if crossings := thresholdCrossings(rows); len(crossings) != 0 {
			t.Fatalf("pure staged rename must not cross: %+v", crossings)
		}
	})

	t.Run("source destination order", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.writeFile("pkg/swap_a.go", 1700)
		r.writeFile("pkg/swap_b.go", 900)
		r.commit("source destination fixture base")
		r.git("checkout", "-q", "-b", "feature")
		r.git("mv", "pkg/swap_a.go", "pkg/swap_c.go")
		r.commit("rename with destination decoy")
		requireRename(t, r, "master", "pkg/swap_a.go", "pkg/swap_c.go")

		row := requireTouchedPath(t, r.touched("master"), "pkg/swap_c.go")
		if row.isNew || row.baseLOC != 1700 || row.headLOC != 1700 {
			t.Fatalf("rename baseline must come from source, not destination: %+v", row)
		}
	})

	t.Run("fake R byte order with both blobs", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.writeFile("pkg/order_src.go", 1700)
		r.writeFile("pkg/order_dst.go", 900)
		r.commit("fake R byte-order base")
		r.git("checkout", "-q", "-b", "feature")
		r.writeFile("pkg/order_dst.go", 1700)
		fakeBin := installFakeGit(t, r, `
case " $* " in
  *" diff --name-status -z "*)
    printf 'R100\000pkg/order_src.go\000pkg/order_dst.go\000'
    exit 0
    ;;
esac`)
		stdout, stderr, err := r.script([]string{
			"XPF_AUDIT_BASE_REF=master",
			"PATH=" + prependPath(fakeBin),
		}, "scripts/refactoring-audit-touched.sh")
		if err != nil {
			t.Fatalf("fake R producer: %v\n%s", err, stderr)
		}
		row := requireTouchedPath(t, parseTouched(t, "fake R producer", stdout),
			"pkg/order_dst.go")
		if row.isNew || row.baseLOC != 1700 || row.headLOC != 1700 {
			t.Fatalf("R source must precede destination even when destination has a base blob: %+v", row)
		}
	})

	t.Run("defensive unmerged coalescing", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			stream string
		}{
			{name: "U then M", stream: `U\000pkg/coalesce.go\000M\000pkg/coalesce.go\000`},
			{name: "M then U", stream: `M\000pkg/coalesce.go\000U\000pkg/coalesce.go\000`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := newFixtureRepo(t)
				r.writeFile("pkg/coalesce.go", 2)
				r.commit("coalesce base")
				r.git("checkout", "-q", "-b", "feature")
				r.writeFile("pkg/coalesce.go", 6)
				fakeBin := installFakeGit(t, r, fmt.Sprintf(`
case " $* " in
  *" diff --name-status -z "*)
    printf '%%b' '%s'
    exit 0
    ;;
esac`, tc.stream))
				stdout, stderr, err := r.script([]string{
					"XPF_AUDIT_BASE_REF=master",
					"PATH=" + prependPath(fakeBin),
				}, "scripts/refactoring-audit-touched.sh")
				if err != nil {
					t.Fatalf("fake U+M producer: %v\n%s", err, stderr)
				}
				rows := parseTouched(t, "fake U+M producer", stdout)
				if len(rows) != 1 {
					t.Fatalf("U+M must produce one row, got %+v", rows)
				}
				row := rows[0]
				if row.path != "pkg/coalesce.go" || row.isNew || row.baseLOC != 2 || row.headLOC != 6 {
					t.Fatalf("U+M must measure one same-path row: %+v", row)
				}
			})
		}
	})

	t.Run("lone unmerged status fails", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.commit("lone U base")
		r.git("checkout", "-q", "-b", "feature")
		fakeBin := installFakeGit(t, r, `
case " $* " in
  *" diff --name-status -z "*)
    printf 'U\000pkg/lone.go\000'
    exit 0
    ;;
esac`)
		stdout, _, err := r.script([]string{
			"XPF_AUDIT_BASE_REF=master",
			"PATH=" + prependPath(fakeBin),
		}, "scripts/refactoring-audit-touched.sh")
		if err == nil || strings.TrimSpace(stdout) != "" {
			t.Fatalf("lone U must fail with no rows: err=%v stdout=%q", err, stdout)
		}
	})

	t.Run("unknown and broken statuses warn", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.writeFile("pkg/unknown.go", 10)
		r.writeFile("pkg/broken.go", 10)
		r.commit("X B base")
		r.git("checkout", "-q", "-b", "feature")
		r.writeFile("pkg/unknown.go", 11)
		r.writeFile("pkg/broken.go", 11)
		fakeBin := installFakeGit(t, r, `
case " $* " in
  *" diff --name-status -z "*)
    printf 'X\000pkg/unknown.go\000B\000pkg/broken.go\000'
    exit 0
    ;;
esac`)
		stdout, stderr, err := r.script([]string{
			"XPF_AUDIT_BASE_REF=master",
			"PATH=" + prependPath(fakeBin),
		}, "scripts/refactoring-audit-touched.sh")
		if err != nil {
			t.Fatalf("X/B producer: %v\n%s", err, stderr)
		}
		rows := parseTouched(t, "X/B producer", stdout)
		if len(rows) != 2 {
			t.Fatalf("X/B must preserve both rows: %+v", rows)
		}
		for _, path := range []string{"pkg/unknown.go", "pkg/broken.go"} {
			row := requireTouchedPath(t, rows, path)
			if row.isNew || row.baseLOC != 10 || row.headLOC != 11 {
				t.Fatalf("X/B same-path row changed baseline: %+v", row)
			}
			if !strings.Contains(stderr, path) {
				t.Fatalf("X/B warning must name %s: %q", path, stderr)
			}
		}
		if !strings.Contains(stderr, "reported X") || !strings.Contains(stderr, "reported B") {
			t.Fatalf("X/B warning must identify status: %q", stderr)
		}
	})

	t.Run("defensive deletion status is ignored", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.commit("D base")
		r.git("checkout", "-q", "-b", "feature")
		fakeBin := installFakeGit(t, r, `
case " $* " in
  *" diff --name-status -z "*)
    printf 'D\000pkg/deleted.go\000'
    exit 0
    ;;
esac`)
		stdout, stderr, err := r.script([]string{
			"XPF_AUDIT_BASE_REF=master",
			"PATH=" + prependPath(fakeBin),
		}, "scripts/refactoring-audit-touched.sh")
		if err != nil {
			t.Fatalf("defensive D producer: %v\n%s", err, stderr)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Fatalf("defensive D must not emit rows: %q", stdout)
		}
	})

	t.Run("staged rename with unstaged watch growth", func(t *testing.T) {
		r := renameBase(t, "pkg/watch_old.go", 1499)
		r.git("mv", "pkg/watch_old.go", "pkg/watch_new.go")
		r.writeFile("pkg/watch_new.go", 1500)
		requireRename(t, r, "master", "pkg/watch_old.go", "pkg/watch_new.go")

		rows := r.touched("master")
		row := requireTouchedPath(t, rows, "pkg/watch_new.go")
		if row.isNew || row.baseLOC != 1499 || row.headLOC != 1500 {
			t.Fatalf("unstaged rename growth must retain source baseline: %+v", row)
		}
		crossings := thresholdCrossings(rows)
		if len(crossings) != 1 || crossings[0].tier != tierWatch {
			t.Fatalf("1499 -> 1500 rename must be one WATCH crossing: %+v", crossings)
		}
	})

	t.Run("staged rename with unstaged refactor growth", func(t *testing.T) {
		r := renameBase(t, "pkg/refactor_old.go", 1999)
		r.git("mv", "pkg/refactor_old.go", "pkg/refactor_new.go")
		r.writeFile("pkg/refactor_new.go", 2000)
		requireRename(t, r, "master", "pkg/refactor_old.go", "pkg/refactor_new.go")

		rows := r.touched("master")
		row := requireTouchedPath(t, rows, "pkg/refactor_new.go")
		if row.isNew || row.baseLOC != 1999 || row.headLOC != 2000 {
			t.Fatalf("unstaged refactor growth must retain source baseline: %+v", row)
		}
		crossings := thresholdCrossings(rows)
		if len(crossings) != 1 || crossings[0].tier != tierRefactor {
			t.Fatalf("1999 -> 2000 rename must be one REFACTOR crossing: %+v", crossings)
		}
	})

	t.Run("committed rename growth", func(t *testing.T) {
		r := renameBase(t, "pkg/committed_old.go", 1499)
		r.git("mv", "pkg/committed_old.go", "pkg/committed_new.go")
		r.writeFile("pkg/committed_new.go", 1500)
		r.commit("commit rename growth")
		requireRename(t, r, "master", "pkg/committed_old.go", "pkg/committed_new.go")

		rows := r.touched("master")
		row := requireTouchedPath(t, rows, "pkg/committed_new.go")
		if row.isNew || row.baseLOC != 1499 || row.headLOC != 1500 {
			t.Fatalf("committed rename growth must retain source baseline: %+v", row)
		}
		if crossings := thresholdCrossings(rows); len(crossings) != 1 ||
			crossings[0].tier != tierWatch {
			t.Fatalf("committed 1499 -> 1500 must be one WATCH crossing: %+v", crossings)
		}
	})

	t.Run("below threshold similarity stays new", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.writePattern("pkg/boiler_old.go", 1600, 1599, "old")
		r.commit("boilerplate base")
		r.git("checkout", "-q", "-b", "feature")
		r.git("rm", "-q", "pkg/boiler_old.go")
		r.writePattern("pkg/boiler_new.go", 1600, 960, "new")
		r.commit("dissimilar add")

		status := r.git("diff", "--name-status", "-M90%", "master", "--")
		if strings.Contains(status, "\tboiler_old.go\tboiler_new.go") {
			t.Fatalf("60%% similarity must not pair as a rename: %s", status)
		}
		row := requireTouchedPath(t, r.touched("master"), "pkg/boiler_new.go")
		if !row.isNew || row.headLOC != 1600 {
			t.Fatalf("below-threshold add must remain new: %+v", row)
		}
		requireNoTouchedPath(t, r.touched("master"), "pkg/boiler_old.go")
		crossings := thresholdCrossings([]touchedFile{row})
		if len(crossings) != 1 || crossings[0].tier != tierWatch {
			t.Fatalf("new 1600-line destination must be one WATCH crossing: %+v", crossings)
		}
	})
	t.Run("ambiguous pair keeps true source", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.writePattern("pkg/ambiguous_big.go", 2100, 840, "big")
		r.writePattern("pkg/ambiguous_small.go", 1400, 1399, "small")
		r.commit("ambiguous pair base")
		r.git("checkout", "-q", "-b", "feature")
		r.git("mv", "pkg/ambiguous_small.go", "pkg/ambiguous_mid.go")
		r.appendLines("pkg/ambiguous_mid.go", 100, "growth")
		requireRename(t, r, "master", "pkg/ambiguous_small.go", "pkg/ambiguous_mid.go")

		row := requireTouchedPath(t, r.touched("master"), "pkg/ambiguous_mid.go")
		if row.isNew || row.baseLOC != 1400 || row.headLOC != 1500 {
			t.Fatalf("ambiguous pairing must use the 1400-line source: %+v", row)
		}
		if crossings := thresholdCrossings([]touchedFile{row}); len(crossings) != 1 ||
			crossings[0].tier != tierWatch {
			t.Fatalf("ambiguous 1400 -> 1500 must remain WATCH: %+v", crossings)
		}
	})

	t.Run("heavy rewrite remains new", func(t *testing.T) {
		r := renameBase(t, "pkg/rewrite_old.go", 1600)
		r.git("mv", "pkg/rewrite_old.go", "pkg/rewrite_new.go")
		r.writePattern("pkg/rewrite_new.go", 1700, 0, "rewritten")
		r.commit("heavy rewrite")

		status := r.git("diff", "--name-status", "-M90%", "master", "--")
		if strings.Contains(status, "\trewrite_old.go\trewrite_new.go") {
			t.Fatalf("heavy rewrite must not pair at -M90%%: %s", status)
		}
		row := requireTouchedPath(t, r.touched("master"), "pkg/rewrite_new.go")
		if !row.isNew || row.headLOC != 1700 {
			t.Fatalf("heavy rewrite must degrade to a new file: %+v", row)
		}
	})

	t.Run("copy config cannot lend baseline", func(t *testing.T) {
		r := renameBase(t, "pkg/copy_source.go", 1701)
		r.writeFile("pkg/copy_new.go", 1701)
		r.git("add", "pkg/copy_new.go")
		status := r.git("diff", "--name-status", "-M90%", "master", "--")
		if strings.Contains(status, "\tcopy_source.go\tcopy_new.go") {
			t.Fatalf("without -C the fixture must not be a copy record: %s", status)
		}

		rows := r.touchedWithEnv("master", []string{
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=diff.renames",
			"GIT_CONFIG_VALUE_0=copies",
		})
		row := requireTouchedPath(t, rows, "pkg/copy_new.go")
		if !row.isNew || row.headLOC != 1701 {
			t.Fatalf("copy must remain a new file even under copies config: %+v", row)
		}
		requireNoTouchedPath(t, rows, "pkg/copy_source.go")
		marker := filepath.Join(r.dir, "copy-config-marker")
		fakeBin := installFakeGit(t, r, fmt.Sprintf(`
case " $* " in
  *" -c diff.renames=true diff --name-status -z "*)
    printf 'A\000pkg/copy_new.go\000'
    printf pinned > %q
    exit 0
    ;;
  *" diff --name-status -z "*)
    printf 'C\000pkg/copy_source.go\000pkg/copy_new.go\000'
    printf leaked > %q
    exit 0
    ;;
esac`, marker, marker))
		stdout, stderr, err := r.script([]string{
			"XPF_AUDIT_BASE_REF=master",
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=diff.renames",
			"GIT_CONFIG_VALUE_0=copies",
			"PATH=" + prependPath(fakeBin),
		}, "scripts/refactoring-audit-touched.sh")
		if err != nil {
			t.Fatalf("copy-config producer: %v\n%s", err, stderr)
		}
		if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "pinned" {
			t.Fatalf("producer must pin diff.renames=true before copies config: marker=%q err=%v", got, readErr)
		}
		fakeRows := parseTouched(t, "copy-config producer", stdout)
		fakeRow := requireTouchedPath(t, fakeRows, "pkg/copy_new.go")
		if !fakeRow.isNew || fakeRow.headLOC != 1701 {
			t.Fatalf("pinned copy-config producer must keep destination new: %+v", fakeRow)
		}
		requireNoTouchedPath(t, fakeRows, "pkg/copy_source.go")
	})

	t.Run("consumed source recreation is new", func(t *testing.T) {
		r := renameBase(t, "pkg/consumed_old.go", 1701)
		r.git("mv", "pkg/consumed_old.go", "pkg/consumed_new.go")
		r.writeFile("pkg/consumed_old.go", 1701)
		requireRename(t, r, "master", "pkg/consumed_old.go", "pkg/consumed_new.go")

		rows := r.touched("master")
		newRow := requireTouchedPath(t, rows, "pkg/consumed_new.go")
		if newRow.isNew || newRow.baseLOC != 1701 {
			t.Fatalf("rename destination must inherit its source: %+v", newRow)
		}
		oldRow := requireTouchedPath(t, rows, "pkg/consumed_old.go")
		if !oldRow.isNew || oldRow.headLOC != 1701 {
			t.Fatalf("recreated consumed source must be new: %+v", oldRow)
		}
		crossings := thresholdCrossings(rows)
		if len(crossings) != 1 || crossings[0].path != "pkg/consumed_old.go" {
			t.Fatalf("only recreated source should cross: %+v", crossings)
		}
	})

	t.Run("same path untracked restoration keeps baseline", func(t *testing.T) {
		r := renameBase(t, "pkg/restored.go", 1701)
		r.git("rm", "-q", "pkg/restored.go")
		r.writeFile("pkg/restored.go", 1701)

		rows := r.touched("master")
		row := requireTouchedPath(t, rows, "pkg/restored.go")
		if row.isNew || row.baseLOC != 1701 || row.headLOC != 1701 {
			t.Fatalf("same-path untracked restoration must probe its base blob: %+v", row)
		}
	})

	t.Run("excluded source enters audit population", func(t *testing.T) {
		r := renameBase(t, "pkg/excluded_old_test.go", 1701)
		r.git("mv", "pkg/excluded_old_test.go", "pkg/excluded_new.go")
		requireRename(t, r, "master", "pkg/excluded_old_test.go", "pkg/excluded_new.go")

		row := requireTouchedPath(t, r.touched("master"), "pkg/excluded_new.go")
		if !row.isNew || row.headLOC != 1701 {
			t.Fatalf("excluded source to audited destination must start at zero: %+v", row)
		}
	})

	t.Run("audited source exits population", func(t *testing.T) {
		r := renameBase(t, "pkg/included_old.go", 1701)
		r.git("mv", "pkg/included_old.go", "pkg/included_new_test.go")
		r.writeFile("pkg/included_old.go", 1701)
		requireRename(t, r, "master", "pkg/included_old.go", "pkg/included_new_test.go")
		rows := r.touched("master")
		requireNoTouchedPath(t, rows, "pkg/included_new_test.go")
		old := requireTouchedPath(t, rows, "pkg/included_old.go")
		if !old.isNew || old.headLOC != 1701 {
			t.Fatalf("recreated source must be new even when rename destination is excluded: %+v", old)
		}
	})

	t.Run("two committed renames use original base", func(t *testing.T) {
		r := renameBase(t, "pkg/chain_orig.go", 1701)
		r.git("mv", "pkg/chain_orig.go", "pkg/chain_mid.go")
		r.commit("first chain rename")
		r.git("mv", "pkg/chain_mid.go", "pkg/chain_final.go")
		r.commit("second chain rename")
		requireRename(t, r, "master", "pkg/chain_orig.go", "pkg/chain_final.go")

		row := requireTouchedPath(t, r.touched("master"), "pkg/chain_final.go")
		if row.isNew || row.baseLOC != 1701 || row.headLOC != 1701 {
			t.Fatalf("final destination must use merge-base original: %+v", row)
		}
	})

	t.Run("directory rename and recreated source", func(t *testing.T) {
		r := newFixtureRepo(t)
		for _, name := range []string{"a.go", "b.go", "c.go"} {
			r.writeFile(filepath.Join("pkg/olddir", name), 100)
		}
		r.commit("directory base")
		r.git("checkout", "-q", "-b", "feature")
		r.git("mv", "pkg/olddir", "pkg/newdir")
		r.writeFile("pkg/olddir/a.go", 1701)

		rows := r.touched("master")
		for _, name := range []string{"a.go", "b.go", "c.go"} {
			row := requireTouchedPath(t, rows, filepath.Join("pkg/newdir", name))
			if row.isNew || row.baseLOC != 100 || row.headLOC != 100 {
				t.Fatalf("directory rename row must retain its own source: %+v", row)
			}
		}
		old := requireTouchedPath(t, rows, "pkg/olddir/a.go")
		if !old.isNew || old.headLOC != 1701 {
			t.Fatalf("recreated directory source must be new: %+v", old)
		}
		wantOrder := []string{
			"pkg/newdir/a.go", "pkg/newdir/b.go", "pkg/newdir/c.go", "pkg/olddir/a.go",
		}
		if len(rows) != len(wantOrder) {
			t.Fatalf("want four directory rows, got %+v", rows)
		}
		for i, want := range wantOrder {
			if rows[i].path != want {
				t.Fatalf("rows must be C-locale destination sorted: got %+v", rows)
			}
		}
	})

	t.Run("symlink source typechange uses raw blob LOC", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.symlink("pkg/type_src.go", "target.go")
		r.commit("symlink base")
		r.git("checkout", "-q", "-b", "feature")
		if err := os.Remove(filepath.Join(r.dir, "pkg/type_src.go")); err != nil {
			t.Fatalf("remove source symlink: %v", err)
		}
		r.writeFile("pkg/type_src.go", 1700)
		status := r.git("diff", "--name-status", "-z", "master", "--")
		if status != "T\x00pkg/type_src.go\x00" {
			t.Fatalf("want exact T NUL record, got %q", status)
		}

		row := requireTouchedPath(t, r.touched("master"), "pkg/type_src.go")
		if row.isNew || row.baseLOC != 0 || row.headLOC != 1700 {
			t.Fatalf("symlink blob has zero newline LOC and regular head has 1700: %+v", row)
		}
	})

	t.Run("regular to dangling symlink is dropped", func(t *testing.T) {
		r := renameBase(t, "pkg/type_dest.go", 1700)
		if err := os.Remove(filepath.Join(r.dir, "pkg/type_dest.go")); err != nil {
			t.Fatalf("remove regular source: %v", err)
		}
		r.symlink("pkg/type_dest.go", "missing.go")
		status := r.git("diff", "--name-status", "-z", "master", "--")
		if status != "T\x00pkg/type_dest.go\x00" {
			t.Fatalf("want exact T NUL record, got %q", status)
		}
		requireNoTouchedPath(t, r.touched("master"), "pkg/type_dest.go")
	})

	t.Run("rename plus typechange remains add and drop", func(t *testing.T) {
		r := renameBase(t, "pkg/cross_old.go", 1700)
		r.git("mv", "pkg/cross_old.go", "pkg/cross_new.go")
		if err := os.Remove(filepath.Join(r.dir, "pkg/cross_new.go")); err != nil {
			t.Fatalf("remove renamed regular: %v", err)
		}
		r.symlink("pkg/cross_new.go", "missing.go")
		status := r.git("diff", "--name-status", "-M", "master", "--")
		if strings.Contains(status, "\tcross_old.go\tcross_new.go") ||
			!strings.Contains(status, "A\tpkg/cross_new.go") ||
			!strings.Contains(status, "D\tpkg/cross_old.go") {
			t.Fatalf("want A+D with no cross-type rename, got:\n%s", status)
		}
		requireNoTouchedPath(t, r.touched("master"), "pkg/cross_new.go")
	})

	t.Run("content conflict stays one M row", func(t *testing.T) {
		r := newFixtureRepo(t)
		r.writeFile("pkg/conflict.go", 2)
		r.commit("conflict base")
		r.git("checkout", "-q", "-b", "ours")
		r.writeText("pkg/conflict.go", "package fixture\n// ours\n")
		r.commit("ours")
		r.git("checkout", "-q", "master")
		r.writeText("pkg/conflict.go", "package fixture\n// theirs\n")
		r.commit("theirs")
		r.git("checkout", "-q", "ours")
		if output, err := r.gitErr("merge", "master", "--no-edit"); err == nil {
			t.Fatalf("merge must leave a content conflict, output=%s", output)
		}

		treeDiff := r.git("diff", "--name-status", "-z", "master", "--")
		if treeDiff != "M\x00pkg/conflict.go\x00" {
			t.Fatalf("tree-vs-commit conflict must be one M record, got %q", treeDiff)
		}
		indexDiff := r.git("diff", "--name-status", "-z", "--")
		if indexDiff != "U\x00pkg/conflict.go\x00M\x00pkg/conflict.go\x00" {
			t.Fatalf("index-form conflict diagnostic changed, got %q", indexDiff)
		}
		rows := r.touched("master")
		row := requireTouchedPath(t, rows, "pkg/conflict.go")
		if row.isNew || row.baseLOC != 2 || row.headLOC <= row.baseLOC {
			t.Fatalf("conflict must preserve M baseline and measure markers: %+v", row)
		}
	})

	t.Run("source-only whitespace is safe", func(t *testing.T) {
		r := renameBase(t, "pkg/old dir/source.go", 1700)
		r.git("mv", "pkg/old dir/source.go", "pkg/whitespace_new.go")
		r.commit("whitespace source rename")
		requireRename(t, r, "master", "pkg/old dir/source.go", "pkg/whitespace_new.go")

		row := requireTouchedPath(t, r.touched("master"), "pkg/whitespace_new.go")
		if row.isNew || row.baseLOC != 1700 || row.headLOC != 1700 {
			t.Fatalf("quoted source-only whitespace must preserve baseline: %+v", row)
		}
	})

	t.Run("whitespace destination and malformed streams fail closed", func(t *testing.T) {
		t.Run("audited destination", func(t *testing.T) {
			r := newFixtureRepo(t)
			r.commit("empty base")
			r.git("checkout", "-q", "-b", "feature")
			r.writeFile("pkg/bad name.go", 1700)
			stdout, _, err := r.script([]string{"XPF_AUDIT_BASE_REF=master"},
				"scripts/refactoring-audit-touched.sh")
			if err == nil || strings.TrimSpace(stdout) != "" {
				t.Fatalf("whitespace destination must fail with no rows: err=%v stdout=%q", err, stdout)
			}
		})

		t.Run("truncated NUL tail", func(t *testing.T) {
			r := renameBase(t, "pkg/truncated_old.go", 10)
			fakeBin := installFakeGit(t, r, `
case " $* " in
  *" diff --name-status -z "*)
    printf 'M\000pkg/truncated.go'
    exit 0
    ;;
esac`)
			stdout, _, err := r.script([]string{
				"XPF_AUDIT_BASE_REF=master",
				"PATH=" + prependPath(fakeBin),
			}, "scripts/refactoring-audit-touched.sh")
			if err == nil || strings.TrimSpace(stdout) != "" {
				t.Fatalf("truncated NUL stream must fail with no rows: err=%v stdout=%q", err, stdout)
			}
		})

		t.Run("git diff failure", func(t *testing.T) {
			r := renameBase(t, "pkg/failure_old.go", 10)
			fakeBin := installFakeGit(t, r, `
case " $* " in
  *" diff --name-status -z "*)
    echo fake diff failure >&2
    exit 1
    ;;
esac`)
			stdout, _, err := r.script([]string{
				"XPF_AUDIT_BASE_REF=master",
				"PATH=" + prependPath(fakeBin),
			}, "scripts/refactoring-audit-touched.sh")
			if err == nil || strings.TrimSpace(stdout) != "" {
				t.Fatalf("git producer failure must fail with no rows: err=%v stdout=%q", err, stdout)
			}
		})
	})

	t.Run("missing source blob falls back with warning", func(t *testing.T) {
		r := renameBase(t, "pkg/missing_old.go", 1701)
		r.git("mv", "pkg/missing_old.go", "pkg/missing_new.go")
		requireRename(t, r, "master", "pkg/missing_old.go", "pkg/missing_new.go")
		fakeBin := installFakeGit(t, r, `
if [ "${1:-}" = cat-file ] && [ "${2:-}" = -e ]; then
  case "${3:-}" in
    *:pkg/missing_old.go)
      echo missing source blob >&2
      exit 1
      ;;
  esac
fi`)
		stdout, stderr, err := r.script([]string{
			"XPF_AUDIT_BASE_REF=master",
			"PATH=" + prependPath(fakeBin),
		}, "scripts/refactoring-audit-touched.sh")
		if err != nil {
			t.Fatalf("missing source blob must be availability-safe: %v\n%s", err, stderr)
		}
		row := requireTouchedPath(t, parseTouched(t, "missing-blob producer", stdout),
			"pkg/missing_new.go")
		if !row.isNew || row.headLOC != 1701 {
			t.Fatalf("missing source blob must emit a new row: %+v", row)
		}
		if !strings.Contains(stderr, "pkg/missing_old.go") {
			t.Fatalf("missing source warning must name source path: %q", stderr)
		}
	})
}

// TestRefreshJobConvergesTheGlobalArtifact is the fail-on-revert for the
// DEMOTED half. Global freshness still has to converge — it just converges
// through a job instead of through a human. The job must:
//
//	regenerate with the committed generator (not hand-edit),
//	commit the result,
//	commit ONLY the artifact even on a dirty tree, and
//	do nothing at all when the artifact is already current.
//
// Reverting any one of those reds exactly one assertion below.
func TestRefreshJobConvergesTheGlobalArtifact(t *testing.T) {
	r := staleFixture(t)
	r.git("checkout", "-q", "master")

	before := strings.TrimSpace(r.git("rev-parse", "HEAD"))

	// An unrelated dirty edit that must NOT be swept into the job's commit.
	if err := os.WriteFile(filepath.Join(r.dir, "README.md"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatalf("dirty README: %v", err)
	}

	// --check must report the staleness and change nothing.
	stdout, stderr, err := r.script(nil, "scripts/refactoring-audit-refresh.sh", "--check")
	if err == nil {
		t.Fatalf("--check must exit non-zero on a stale artifact; stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "sibling") {
		t.Errorf("--check must show what drifted; got %q %q", stdout, stderr)
	}
	if head := strings.TrimSpace(r.git("rev-parse", "HEAD")); head != before {
		t.Fatalf("--check committed something: %s -> %s", before, head)
	}

	// The job itself.
	stdout, stderr, err = r.script(nil, "scripts/refactoring-audit-refresh.sh")
	if err != nil {
		t.Fatalf("refresh: %v\nstdout=%q\nstderr=%q", err, stdout, stderr)
	}
	after := strings.TrimSpace(r.git("rev-parse", "HEAD"))
	if after == before {
		t.Fatal("the refresh job made no commit; global freshness converges through " +
			"this job now, so a job that does not commit means it converges through " +
			"nobody (#7253)")
	}

	// The artifact now matches the tree, and the commit carries nothing else.
	body := r.git("show", "--pretty=format:", "--name-only", "HEAD")
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if strings.TrimSpace(line) != "" {
			files = append(files, strings.TrimSpace(line))
		}
	}
	if len(files) != 1 || files[0] != "docs/refactoring-audit-current.txt" {
		t.Fatalf("the refresh commit must contain the artifact and nothing else; got %v", files)
	}
	artifact, err := os.ReadFile(filepath.Join(r.dir, "docs", "refactoring-audit-current.txt"))
	if err != nil {
		t.Fatalf("read refreshed artifact: %v", err)
	}
	if !strings.Contains(string(artifact), "pkg/sibling/sibling.go") {
		t.Fatalf("the refreshed artifact does not record the sibling's crossing:\n%s", artifact)
	}
	generated, stderr, err := r.script(nil, "scripts/refactoring-audit.sh")
	if err != nil {
		t.Fatalf("regenerate: %v\n%s", err, stderr)
	}
	if string(artifact) != generated {
		t.Fatalf("the committed artifact is not what the generator emits:\n--- committed ---\n%s\n--- generated ---\n%s",
			artifact, generated)
	}

	// Idempotent: a second run on a current artifact must not commit.
	stdout, stderr, err = r.script(nil, "scripts/refactoring-audit-refresh.sh")
	if err != nil {
		t.Fatalf("second refresh: %v\nstdout=%q\nstderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "up to date") {
		t.Errorf("a second run must report the artifact current; got %q", stdout)
	}
	if head := strings.TrimSpace(r.git("rev-parse", "HEAD")); head != after {
		t.Fatalf("the refresh job committed twice for one drift: %s -> %s", after, head)
	}
}

// TestRefreshJobRefusesAnEmptyHeatmap pins the fail-closed half of the
// job. A generator that produces nothing — a deleted root, a broken find,
// a bad regex — would otherwise be committed as "every audited file left
// the audit", quietly retiring the whole heatmap. The canary that would
// have caught that (TestProductionSentinelVisible) reads the COMMITTED
// artifact, so a job that commits an empty one takes the canary down with
// it.
func TestRefreshJobRefusesAnEmptyHeatmap(t *testing.T) {
	r := newFixtureRepo(t)
	r.writeFile("pkg/small/small.go", 10) // nothing reaches the audit floor
	r.writeFile("docs/refactoring-audit-current.txt", 1)
	r.commit("tree with no audited files")
	before := strings.TrimSpace(r.git("rev-parse", "HEAD"))

	stdout, stderr, err := r.script(nil, "scripts/refactoring-audit-refresh.sh")
	if err == nil {
		t.Fatalf("the job must refuse to commit an empty heatmap; stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "no rows") {
		t.Errorf("the refusal must say why; got %q", stderr)
	}
	if head := strings.TrimSpace(r.git("rev-parse", "HEAD")); head != before {
		t.Fatalf("the job committed an empty heatmap: %s -> %s", before, head)
	}
}
