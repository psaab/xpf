//go:build xpf_faultinject

package daemon

// #19115 lab fault: fail the authoritative bulk's owner-RG export on demand.
//
// This file exists ONLY in a build made with `-tags xpf_faultinject` (`make
// build-faultinject`). A release build compiles faultinject_bulk_export_19115_release.go
// instead, whose hook returns nil and holds no state, and
// TestReleaseBuildExcludesTheBulkExportFault19115 pins that exclusion.
//
// Arming is explicit and at run time, so a node can be armed without a
// restart: write a mode to the arm file.
//
//	once        fail the NEXT bulk-snapshot export, then disarm (the file is
//	            removed before the failure is returned)
//	persistent  fail EVERY bulk-snapshot export until the file is removed
//
// The fault fires on the first page of a bulk-snapshot export, from the page
// sink, so it returns through the pager's normal error path: when the helper
// reported more pages the window is open, and the #18752 abandon runs exactly
// as for a real mid-export failure. Only the authoritative bulk's snapshot
// export is affected; the FullResync install export is not.
//
// Every firing is recorded: a Warn, and one line appended to the record file
// ("<unix-nanos> <mode> <count>"), so the lab can count firings exactly.

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// faultinjectBulkExportDir19115 is a var so the cell can point it at a temp dir.
var faultinjectBulkExportDir19115 = "/run/xpf/faultinject"

const (
	faultinjectBulkExportArm19115    = "bulk-export-19115"
	faultinjectBulkExportRecord19115 = "bulk-export-19115.fired"
)

// errFaultinjectBulkExport19115 is the injected failure.
var errFaultinjectBulkExport19115 = errors.New("faultinject #19115: injected owner-RG bulk-snapshot export failure")

var faultinjectBulkExportFired19115 atomic.Int64

// faultinjectBulkExport19115 returns the injected error when the arm file is
// present with a valid mode, nil otherwise.
func faultinjectBulkExport19115() error {
	arm := filepath.Join(faultinjectBulkExportDir19115, faultinjectBulkExportArm19115)
	raw, err := os.ReadFile(arm)
	if err != nil {
		return nil
	}
	mode := strings.TrimSpace(string(raw))
	switch mode {
	case "once":
		// Consume BEFORE failing: a once fault fires exactly once even if
		// the record write below fails.
		if err := os.Remove(arm); err != nil {
			slog.Warn("faultinject #19115: cannot consume the once arm file; not firing", "path", arm, "err", err)
			return nil
		}
	case "persistent":
	default:
		slog.Warn("faultinject #19115: unknown mode in the arm file; not firing", "path", arm, "mode", mode)
		return nil
	}
	n := faultinjectBulkExportFired19115.Add(1)
	slog.Warn("faultinject #19115: failing the bulk-snapshot owner-RG export", "mode", mode, "count", n)
	rec := filepath.Join(faultinjectBulkExportDir19115, faultinjectBulkExportRecord19115)
	if f, err := os.OpenFile(rec, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%d %s %d\n", time.Now().UnixNano(), mode, n)
		_ = f.Close()
	} else {
		slog.Warn("faultinject #19115: cannot write the firing record", "path", rec, "err", err)
	}
	return errFaultinjectBulkExport19115
}
