package refactoraudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #17112 (R4-Q47-02): pkg/zonecounters justified its existence with a
// linkage boundary that never held — "the remote cli speaks gRPC and must
// not link the dataplane", repeated in docs/log/6895.md.
//
// The claim was false when written and is false now. Measured with
// `go list -deps ./cmd/cli` on this tree, the remote CLI links
// pkg/dataplane, pkg/dataplane/userspace, pkg/nftables, pkg/routing,
// pkg/ipsec, pkg/logging, pkg/networkd and pkg/configstore transitively
// (via pkg/dataplane/userspace, pkg/monitoriface and pkg/policymatch).
// The #1451 retirement-boundary canary
// (TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports) checks only
// per-file DIRECT imports of root pkg/dataplane and skips the whole
// pkg/dataplane tree, so it never guarded transitive linkage.
//
// This guard pins the corrected record: the false sentence must not
// reappear in the package doc that carried it or in the #6895 log that
// repeated it. It deliberately does NOT assert the transitive closure is
// empty — achieving that (moving the argv parsers to a dependency-free
// leaf, splitting ProcessStatus, cutting policymatch's edges) is the
// larger Option A in #17112 and needs its own scoped change; asserting
// it here would red every tree until that lands. What this cell forbids
// is re-stating the unguarded coupling as if it were a designed boundary.
//
// Like the #6899 doc guard, this catches a literal reintroduction (a
// revert or copy-paste from history), not a paraphrase; the positive
// assertions below ensure the fix was a correction, not a deletion.
func TestCliDataplaneLinkClaimRemoved17112(t *testing.T) {
	root := repoRoot(t)

	// Built by concatenation so this guard does not itself satisfy a
	// repo-wide grep for the retired phrase (#17112 Option B acceptance).
	retired := "must not link the " + "dataplane"

	for _, rel := range []string{
		filepath.Join("pkg", "zonecounters", "zonecounters.go"),
		filepath.Join("docs", "log", "6895.md"),
	} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		// Wrap-insensitive: the retired claim spanned two lines in both
		// files, so compare against whitespace-flattened text.
		flat := strings.Join(strings.Fields(string(raw)), " ")
		if strings.Contains(flat, retired) {
			t.Errorf("%s has reacquired the false #17112 claim %q.\n\n"+
				"cmd/cli links pkg/dataplane and the daemon stack transitively "+
				"(go list -deps ./cmd/cli); the #1451 canary guards only direct "+
				"imports. Do not restate a link-time boundary that does not exist.",
				rel, retired)
		}
	}

	// The replacement must actually carry the correction. Without this the
	// guard is satisfied by deleting the rationale entirely, which would
	// remove a wrong answer by removing the answer.
	raw, err := os.ReadFile(filepath.Join(root, "pkg", "zonecounters", "zonecounters.go"))
	if err != nil {
		t.Fatalf("read pkg/zonecounters/zonecounters.go: %v", err)
	}
	flat := strings.Join(strings.Fields(string(raw)), " ")
	for _, want := range []string{
		"not a linkage boundary",
		"already links pkg/dataplane",
		"#17112",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("pkg/zonecounters/zonecounters.go is missing %q — the false "+
				"#17112 rationale was corrected, not deleted; the replacement must "+
				"state that cmd/cli already links the dataplane transitively.", want)
		}
	}
}
