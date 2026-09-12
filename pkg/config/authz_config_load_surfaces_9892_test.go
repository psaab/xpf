package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #9892: ALL THREE SURFACES MUST CALL THE SAME EVALUATOR, AND THERE MUST BE
// ONLY ONE.
//
// This is a census, not a runtime comparison, and the distinction is the point.
// A cell that fed identical content to three surfaces and asserted identical
// verdicts would PASS while a surface carried its own private copy that happens
// to agree today — which is exactly the state that produced this issue: gRPC
// had a correct implementation and the other two had none, and nothing reported
// the asymmetry.
//
// What actually prevents the drift is that there is ONE renderer and each
// surface calls it. Two renderings of "hierarchical content as set lines" drift
// invisibly, because each looks right on its own.
//
// Hermetic: a source scan. No network, no build, no cluster.

func repoRoot9892(t *testing.T) string {
	t.Helper()
	// This package sits at <root>/pkg/config.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %q has no go.mod — if this file moved, fix the `..` hops. "+
			"This is a harness path bug, not a finding.", root)
	}
	return root
}

func readGo9892(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("reading %s: %v — a surface named by this census does not exist at this "+
			"path, which is a census bug or a move nobody updated", rel, err)
	}
	return string(b)
}

// Every surface that can apply a `load` must call the shared evaluator.
func TestEveryLoadSurfaceCallsTheSharedEvaluator9892(t *testing.T) {
	root := repoRoot9892(t)
	for rel, what := range map[string]string{
		"pkg/api/authz_config_regex_9154.go":   "REST",
		"pkg/cli/cli_config.go":                "CLI (inside handleLoad, where the content is finally in hand)",
		"pkg/grpcapi/authz_config_rpc_9633.go": "gRPC",
	} {
		src := readGo9892(t, root, rel)
		if !strings.Contains(src, "AuthorizeConfigLoad(") {
			t.Errorf("%s (%s) does not call config.AuthorizeConfigLoad. `load` is the verb that "+
				"can carry EVERY denied path at once, so a surface that does not adjudicate it "+
				"reopens #9892 on that surface alone — which is the state gRPC was already out "+
				"of and REST and the CLI were still in.", rel, what)
		}
	}
}

// Rollback is the same shape and was ungated on the same two surfaces.
func TestEveryRollbackSurfaceCallsTheSharedEvaluator9892(t *testing.T) {
	root := repoRoot9892(t)
	for rel, what := range map[string]string{
		"pkg/api/authz_config_regex_9154.go":   "REST",
		"pkg/cli/cli_dispatch.go":              "CLI",
		"pkg/grpcapi/authz_config_rpc_9633.go": "gRPC",
	} {
		if !strings.Contains(readGo9892(t, root, rel), "AuthorizeConfigRollback(") {
			t.Errorf("%s (%s) does not call config.AuthorizeConfigRollback; `rollback n` replaces "+
				"the candidate with an unadjudicated older configuration — the same class as "+
				"load override (#9892)", rel, what)
		}
	}
}

// EXACTLY ONE renderer. This is the row that stops the drift, and it is the one
// a future "just copy it into my package" change trips.
func TestThereIsExactlyOneLoadContentRenderer9892(t *testing.T) {
	root := repoRoot9892(t)
	// A renderer is a function that turns load content into mutation lines.
	decl := regexp.MustCompile(`func (?:\([^)]*\) )?[Ll]oadMutationLines\w*\(`)
	var found []string
	err := filepath.Walk(filepath.Join(root, "pkg"), func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		// COUNT DECLARATIONS, NOT FILES. `decl.Match` is true once per file, so
		// a second renderer added BESIDE the first — the cheapest possible
		// drift — counted as one and escaped. Found by mutating this census,
		// not by reading it.
		for _, m := range decl.FindAll(b, -1) {
			rp, _ := filepath.Rel(root, p)
			found = append(found, rp+": "+strings.TrimSuffix(strings.TrimPrefix(string(m), "func "), "("))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking pkg/: %v", err)
	}
	// EMPTY-SWEEP GUARD. Zero means the matcher broke, not that the renderer is
	// gone — and a census that sweeps nothing reports a clean board.
	if len(found) == 0 {
		t.Fatal("the census found NO load-content renderer anywhere in pkg/. The matcher is " +
			"broken, not the tree; every verdict in this file is then vacuous.")
	}
	if len(found) != 1 {
		t.Errorf("found %d load-content renderers, want exactly 1: %v\n"+
			"Two renderings of hierarchical content as set lines DRIFT, and the drift is "+
			"invisible because each copy looks right on its own. That is why #9633's gRPC "+
			"implementation was MOVED into pkg/config rather than copied beside it.", len(found), found)
	}
	if len(found) == 1 && !strings.HasPrefix(found[0], "pkg/config/") {
		t.Errorf("the single renderer is at %s, not in pkg/config — it must live beside "+
			"AuthorizeConfigMutation, which it calls per line", found[0])
	}
}
