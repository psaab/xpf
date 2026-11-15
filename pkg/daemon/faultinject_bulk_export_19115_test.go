//go:build xpf_faultinject

package daemon

// #19115: the lab fault's behaviour. This file is built and run only with
// -tags xpf_faultinject (`make test-faultinject`); the go-buildtag census
// compiles it on every `make test-go`. The release build's exclusion of the
// fault is pinned by TestReleaseBuildExcludesTheBulkExportFault19115, which
// carries no tag.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func faultDir19115(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := faultinjectBulkExportDir19115
	faultinjectBulkExportDir19115 = dir
	t.Cleanup(func() { faultinjectBulkExportDir19115 = orig })
	return dir
}

func armFault19115(t *testing.T, dir, mode string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, faultinjectBulkExportArm19115), []byte(mode+"\n"), 0o644); err != nil {
		t.Fatalf("arm the fault: %v", err)
	}
}

func faultFirings19115(t *testing.T, dir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, faultinjectBulkExportRecord19115))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read the firing record: %v", err)
	}
	return len(strings.Split(strings.TrimSpace(string(raw)), "\n"))
}

// TestBulkExportFaultModes19115: absent and unknown modes never fire; "once"
// fires exactly once and disarms itself; "persistent" fires until disarmed.
// Every firing is one record line.
func TestBulkExportFaultModes19115(t *testing.T) {
	dir := faultDir19115(t)
	armPath := filepath.Join(dir, faultinjectBulkExportArm19115)
	if err := faultinjectBulkExport19115(); err != nil {
		t.Fatalf("an unarmed fault fired: %v", err)
	}

	armFault19115(t, dir, "once")
	if err := faultinjectBulkExport19115(); !errors.Is(err, errFaultinjectBulkExport19115) {
		t.Fatalf("an armed once fault returned %v, want the injected failure", err)
	}
	if _, err := os.Stat(armPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a once fault did not disarm itself (stat: %v)", err)
	}
	if err := faultinjectBulkExport19115(); err != nil {
		t.Fatalf("a once fault fired twice: %v", err)
	}
	if got := faultFirings19115(t, dir); got != 1 {
		t.Fatalf("after one once firing the record has %d lines, want 1", got)
	}

	armFault19115(t, dir, "persistent")
	for i := range 2 {
		if err := faultinjectBulkExport19115(); !errors.Is(err, errFaultinjectBulkExport19115) {
			t.Fatalf("persistent firing %d returned %v, want the injected failure", i+1, err)
		}
	}
	if _, err := os.Stat(armPath); err != nil {
		t.Fatalf("a persistent fault disarmed itself: %v", err)
	}
	if got := faultFirings19115(t, dir); got != 3 {
		t.Fatalf("after 1 once and 2 persistent firings the record has %d lines, want 3", got)
	}

	armFault19115(t, dir, "bogus")
	if err := faultinjectBulkExport19115(); err != nil {
		t.Fatalf("an unknown mode fired: %v", err)
	}
	if got := faultFirings19115(t, dir); got != 3 {
		t.Fatalf("an unknown mode was recorded as a firing (%d lines, want 3)", got)
	}
}

// TestBulkExportFaultFailsTheBulkSnapshot19115: an armed fault fails the
// authoritative bulk's snapshot export from its first page and frames
// nothing; the next export, the once fault consumed, frames the row. The
// pager's handling of a page-1 sink error (the #18752 abandon of an open
// window) is TestSinkErrorAbandonsTheOpenWindow18752.
func TestBulkExportFaultFailsTheBulkSnapshot19115(t *testing.T) {
	dir := faultDir19115(t)
	armFault19115(t, dir, "once")
	d, ss, cfg := snapshot6031Daemon()
	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{transitDelta6031(39906)}}
	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if !errors.Is(err, errFaultinjectBulkExport19115) {
		t.Fatalf("the armed fault did not fail the bulk snapshot: err=%v", err)
	}
	if len(snap.V4) != 0 || len(snap.V6) != 0 {
		t.Fatalf("a failed bulk snapshot framed %d/%d rows, want none", len(snap.V4), len(snap.V6))
	}
	snap, err = d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err != nil || len(snap.V4) != 1 {
		t.Fatalf("after the once fault, the next bulk snapshot = (%d rows, %v), want (1, nil)", len(snap.V4), err)
	}
	if got := faultFirings19115(t, dir); got != 1 {
		t.Fatalf("the record has %d firings, want 1", got)
	}
}
