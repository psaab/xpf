package testguard

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// RequireGitEnv names the variable that turns a missing git checkout from a
// SKIP into a FAIL. `make test-git-leg` sets it, so the one leg that exists to
// run the git-needing tests can never pass by skipping them (#19080).
const RequireGitEnv = "XPF_REQUIRE_GIT"

// GitLegReason is the named reason a git-needing test skips with: the runner
// lanes sync the tree WITHOUT .git (scripts/vm-test-run.sh), so these tests
// run only in the dedicated leg, which syncs a shallow repo (#19080).
const GitLegReason = "needs a git checkout (HEAD plus the merge-base with origin/master); " +
	"it runs in `make test-git-leg`: scripts/vm-test-run.sh --with-git -- make test-git-leg (#19080)"

// RequireGitCheckout skips t, naming the leg that runs it, when dir is not
// inside a git work tree with a commit at HEAD. Under XPF_REQUIRE_GIT=1 it
// fails instead. A work tree that exists is never skipped, whatever state it
// is in: only the absence of one is the environment this skip is for.
func RequireGitCheckout(t testing.TB, dir string) {
	t.Helper()
	why := gitCheckoutMissing(dir)
	if why == "" {
		return
	}
	if os.Getenv(RequireGitEnv) == "1" {
		t.Fatalf("%s=1 but %s: %s", RequireGitEnv, why, GitLegReason)
	}
	t.Skipf("%s: %s", why, GitLegReason)
}

// gitCheckoutMissing reports why dir has no usable git checkout, or "".
func gitCheckoutMissing(dir string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return "no git binary"
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Output()
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		return "not inside a git work tree"
	}
	if err := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", "HEAD^{commit}").Run(); err != nil {
		return "no commit at HEAD"
	}
	return ""
}
