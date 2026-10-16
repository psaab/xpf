package dataplane

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFreshnessGateRejectsHandRegeneratedManifest13963 archives the committed
// tree, mutates only a copied shim input, hand-runs cmd/shim-manifest, then
// invokes the production freshness test in that isolated copy. The wrapper
// succeeds only when that production gate rejects the stale-object manifest.
func TestFreshnessGateRejectsHandRegeneratedManifest13963(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	fixture := t.TempDir()
	archive := filepath.Join(fixture, "repo.tar")
	cmd := exec.Command("git", "-C", strings.TrimSpace(string(root)), "archive", "--format=tar", "--output", archive, "HEAD")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("archive committed repository: %v\n%s", err, output)
	}
	if output, err := exec.Command("tar", "-xf", archive, "-C", fixture).CombinedOutput(); err != nil {
		t.Fatalf("extract repository fixture: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(fixture, "go.mod")); err != nil {
		t.Fatalf("fixture missing go.mod at %s: %v", fixture, err)
	}

	source := filepath.Join(fixture, "userspace-xdp/src/ipv6_ext_walk.rs")
	f, err := os.OpenFile(source, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open copied shim source: %v", err)
	}
	if _, err := f.WriteString("\n// #13963 stale-object regression probe\n"); err != nil {
		f.Close()
		t.Fatalf("mutate copied shim source: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close copied shim source: %v", err)
	}

	cmd = exec.Command("go", "run", "./cmd/shim-manifest", "-repo-root", fixture)
	cmd.Dir = fixture
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hand-run cmd/shim-manifest: %v\n%s", err, output)
	}

	cmd = exec.Command("go", "test", "./pkg/dataplane", "-run", "^TestUserspaceXDPShimObjectMatchesSourceManifest$", "-count=1")
	cmd.Dir = fixture
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err == nil {
		t.Fatalf("freshness gate accepted a hand-regenerated manifest for the stale object:\n%s", output.String())
	}
}
