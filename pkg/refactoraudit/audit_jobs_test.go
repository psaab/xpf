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

// TestTouchedRenamePreservesBaseLOC10488 is the regression for #10488:
// a pure rename must be measured from its source path at the merge base,
// not as a new file. The rename is staged but uncommitted so the probe's
// working-tree view is covered as well as the committed path it will
// see in a real pull request.
func TestTouchedRenamePreservesBaseLOC10488(t *testing.T) {
	r := newFixtureRepo(t)
	r.writeFile("pkg/rename_control/old.go", 1701)
	r.commit("base file")

	r.git("checkout", "-q", "-b", "feature")
	r.git("mv", "pkg/rename_control/old.go", "pkg/rename_control/new.go")

	touched := r.touched("master")
	if len(touched) != 1 {
		t.Fatalf("want one touched file, got %+v", touched)
	}
	got := touched[0]
	if got.path != "pkg/rename_control/new.go" {
		t.Fatalf("wrong touched path: got %q, want destination path", got.path)
	}
	if got.isNew || got.baseLOC != 1701 || got.headLOC != 1701 {
		t.Fatalf("pure rename must preserve source measurement: got %+v, want base=1701 head=1701 isNew=false", got)
	}
	if crossings := thresholdCrossings(touched); len(crossings) != 0 {
		t.Fatalf("pure rename must not cross a modularity floor: got %+v", crossings)
	}
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
