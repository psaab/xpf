package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeferredPublishMarkIsWiredEndToEnd9637 is the F1-B source pin: the
// publication-acknowledged freshness gate is only exact if the XSK-startup
// deferred-publish branch MARKS its success (so the daemon gate reads it as
// not-running) and the daemon actually consults the mark. A revert that
// drops the mark (or stops reading it) silently reopens the deferral window
// while every behavioral test stays green — the mark has no other reader.
func TestDeferredPublishMarkIsWiredEndToEnd9637(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}

	// 1. The deferred branch marks its success. It must sit in the
	// pendingXSKStartup region (the one success-without-publish site), not
	// on the normal tail (which publishes synchronously).
	mc := read("pkg/dataplane/userspace/manager_compile.go")
	mark := "result.SnapshotPublishDeferred = true"
	deferIdx := strings.Index(mc, mark)
	branchIdx := strings.Index(mc, "pendingXSKStartup")
	if branchIdx < 0 || deferIdx < branchIdx {
		t.Error("the deferred mark must sit after the pendingXSKStartup branch opens (the success-without-publish site)")
	}
	tailIdx := strings.Index(mc, "publishSnapshotFailClosedLocked(&publishSnap")
	if tailIdx < 0 || deferIdx > tailIdx {
		t.Error("the deferred mark must precede the normal-tail publish (it belongs to the deferred branch only)")
	}

	// 2. The daemon consults the mark at BOTH writers (primary call site and
	// worker-arm re-apply): a site that sets fresh unconditionally reopens
	// the window for its path.
	tail := read("pkg/daemon/daemon_apply_dataplane.go")
	if n := strings.Count(tail, "!applyResult.SnapshotPublishDeferred"); n != 1 {
		t.Errorf("daemon_apply_dataplane.go primary site must gate on !SnapshotPublishDeferred, found %d", n)
	}
	if n := strings.Count(tail, "!res.SnapshotPublishDeferred"); n != 1 {
		t.Errorf("daemon_apply_dataplane.go re-apply site must gate on !SnapshotPublishDeferred, found %d", n)
	}

	// 3. The copy carries the mark across the process boundary types.
	if !strings.Contains(read("pkg/dataplane/apply.go"),
		"SnapshotPublishDeferred: result.SnapshotPublishDeferred,") {
		t.Error("ApplyResultFromCompileResult must copy SnapshotPublishDeferred")
	}

	// POSITIVE CONTROL: prove the reader reaches real source.
	if !strings.Contains(mc, "deferring snapshot publish during XSK startup") {
		t.Fatal("the census read manager_compile.go but did not find the deferred branch — it " +
			"is not reading the file it thinks it is")
	}
}
