package vrrp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #17165 (R4-Q36-06): the pkg/vrrp README and lock-discipline comments
// named production-unreachable seams (updateConfig, advertInterval,
// recordMasterAdvert, warnUnknownMasterAdvert, garpSendAllowed,
// resignIsPending and arrivalIfindexDetector.count) as the live path,
// and the File layout omitted the files the #8090 split and later work
// created (instance_preempt/resign/rx/timing/transition/vipupdate.go
// and resign_barrier.go). The seams now live in _test.go helpers; the
// prose is re-pointed at advertiseIntervalMS-carrying armAdvertTimer,
// updateConfigHeld and admitAndRecord.
//
// FAIL-ON-REVERT: restoring any stale string below, dropping a
// production file from the File layout, or resurrecting a seam in a
// non-test file fails this test. The seam-absence check scans non-test
// source so deadcode's verdict is pinned without the tool in CI.
func TestReadmeLayout17165(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	readme := read("pkg/vrrp/README.md")

	// Stale pointers that sent a #6230-class census to dead callers.
	stale := []string{
		"sole caller, recordMasterAdvert",
		"reached from `recordMasterAdvert`",
		"`recordMasterAdvert` → `masterAdverFloor`",
		"recordMasterAdvert under",
		"re-arms `advertTimer` at the new `vi.advertInterval()`",
		"mirroring warnUnknownMasterAdvert",
		"retains the #10719 detection entry point for",
		"advertTimer.Reset(vi.advertInterval())",
		"at both config entry points —\n`newInstance` and `updateConfig`",
		"`recordMasterAdvert` writes",
		"Recorded by recordMasterAdvert",
		"recorded by recordMasterAdvert",
		"via `recordMasterAdvert`",
		"keep refreshing `lastMasterSeen` via `recordMasterAdvert`",
		"`recordMasterAdvert` clamps",
		"`recordMasterAdvert` overwrites",
		"`recordMasterAdvert` stores",
	}
	for _, bad := range stale {
		if strings.Contains(readme, bad) {
			t.Errorf("#17165: README still contains stale claim %q", bad)
		}
	}

	// Corrected pointers must be present.
	for _, want := range []string{
		"`updateConfigHeld` writes",
		"`admitAndRecord`",
		"armAdvertTimer",
		"`advertiseIntervalMS()`",
		"`newInstance`-adjacent install clamp in `manager.go`, and `updateConfigHeld`",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("#17165: README missing corrected pointer %q", want)
		}
	}

	// Every non-test .go file must be named in the File layout section.
	const startMarker = "## File layout"
	start := strings.Index(readme, startMarker)
	if start < 0 {
		t.Fatalf("vrrp README missing %q section", startMarker)
	}
	rest := readme[start+len(startMarker):]
	end := strings.Index(rest, "\n## ")
	if end < 0 {
		t.Fatalf("vrrp README File layout section has no following section")
	}
	layout := rest[:end]
	entries, err := os.ReadDir(filepath.Join(root, "pkg", "vrrp"))
	if err != nil {
		t.Fatalf("list pkg/vrrp: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !strings.Contains(layout, "`"+name+"`") {
			t.Errorf("#17165: vrrp README File layout does not name %s", name)
		}
		// Seams must not live in production files.
		src := read(filepath.Join("pkg", "vrrp", name))
		for _, def := range []string{
			"func (vi *vrrpInstance) updateConfig(",
			"func (vi *vrrpInstance) advertInterval()",
			"func (vi *vrrpInstance) garpSendAllowed(",
			"func (vi *vrrpInstance) recordMasterAdvert(",
			"func (vi *vrrpInstance) warnUnknownMasterAdvert(",
			"func (vi *vrrpInstance) resignIsPending()",
			"func (d *arrivalIfindexDetector) count()",
		} {
			if strings.Contains(src, def) {
				t.Errorf("#17165: production seam %q still defined in %s", def, name)
			}
		}
		if strings.Contains(src, "sole caller, recordMasterAdvert") {
			t.Errorf("#17165: %s still claims recordMasterAdvert is sole caller", name)
		}
		if strings.Contains(src, "mirroring warnUnknownMasterAdvert") {
			t.Errorf("#17165: %s still mirrors warnUnknownMasterAdvert", name)
		}
	}
}
