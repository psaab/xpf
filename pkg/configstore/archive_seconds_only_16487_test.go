package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIsXPFConfigArchiveSnapshotSecondsOnly16487 pins the #16487 recognizer
// gap: builds from 2026-02-14..06-28 wrote archives as
// config-YYYYMMDD-HHMMSS.conf (seconds only, no nanosecond fraction, no
// seq). The pre-fix recognizer accepted only the nanosecond legacy shape
// and the sequenced shape, so the api-auth purge skipped these files and
// rotateArchives never pruned them.
//
// FAIL-ON-REVERT: drop the seconds-only parse and the seconds-only cells
// go RED while every pre-existing shape stays GREEN.
func TestIsXPFConfigArchiveSnapshotSecondsOnly16487(t *testing.T) {
	recognized := []string{
		// Seconds-only legacy (2026-02-14..06-28 builds).
		"config-20260501-101500.conf",
		"config-20240214-000000.conf",
		"config-20260628-235959.conf",
		// Legacy nanosecond pre-sequence.
		"config-20240101-000000.000000000.conf",
		// Current sequenced.
		"config-20240101-000002.000000002.00000000000000000003.conf",
	}
	for _, name := range recognized {
		if !isXPFConfigArchiveSnapshot(name) {
			t.Errorf("isXPFConfigArchiveSnapshot(%q) = false, want true", name)
		}
	}
	foreign := []string{
		"config-compliance-report.conf",
		"config-20260501.conf",            // date only, no time
		"config-20260501-1015.conf",       // truncated time
		"config-20260501-1015000.conf",    // seven-digit time field
		"config-20261301-101500.conf",     // month 13: not a real date
		"config-20260501-246000.conf",     // hour 24 / minute 60
		"config-20260501-101500.txt",      // wrong suffix
		"other-20260501-101500.conf",      // wrong prefix
		"config-20260501-101500.1.conf",   // one-digit tail is neither a stamp nor a 20-digit seq
		"config-20260501-101500.conf.bak", // suffix past .conf
		"config-.conf",                    // empty stamp
	}
	for _, name := range foreign {
		if isXPFConfigArchiveSnapshot(name) {
			t.Errorf("isXPFConfigArchiveSnapshot(%q) = true, want false (foreign name must stay untouched)", name)
		}
	}
}

// TestRotateArchivesPrunesSecondsOnly16487 pins the retention half of
// #16487: seconds-only snapshots have no parseable seq, so they must count
// toward maxArchives and sort oldest (lexical-by-ts among legacy peers),
// pruned before nanosecond-legacy and sequenced snapshots.
//
// FAIL-ON-REVERT: with the seconds-only shape unrecognized, rotation
// leaves all five files in place and the count/prune assertions go RED.
func TestRotateArchivesPrunesSecondsOnly16487(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Three seconds-only snapshots (oldest, lexical order = chronological).
	write("config-20260501-101500.conf", "seconds-1\n")
	write("config-20260502-101500.conf", "seconds-2\n")
	write("config-20260503-101500.conf", "seconds-3\n")
	// One nanosecond legacy and one current sequenced snapshot.
	write("config-20260601-000000.000000000.conf", "nano-legacy\n")
	ts := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	write(fmt.Sprintf("config-%s.%020d.conf", ts.Format("20060102-150405.000000000"), uint64(7)), "current\n")

	if err := rotateArchives(dir, 2); err != nil {
		t.Fatalf("rotateArchives: %v", err)
	}

	remain := archiveContents(t, dir)
	if len(remain) != 2 {
		t.Fatalf("rotation must retain max=2 recognized snapshots, got %v", remain)
	}
	for _, want := range []string{"nano-legacy", "current"} {
		if !remain[want] {
			t.Errorf("newer snapshot %q must survive rotation; remain=%v", want, remain)
		}
	}
	for _, pruned := range []string{"seconds-1", "seconds-2", "seconds-3"} {
		if remain[pruned] {
			t.Errorf("seconds-only snapshot %q must be pruned as oldest; remain=%v", pruned, remain)
		}
	}
}

// TestRotateArchivesKeepsNewestSecondsOnly16487 pins that among
// seconds-only peers the lexical (chronological) tiebreak keeps the
// newest stamps when they are the only snapshots present.
//
// FAIL-ON-REVERT: unrecognized seconds-only names are never counted, so
// all three survive and the prune assertions go RED.
func TestRotateArchivesKeepsNewestSecondsOnly16487(t *testing.T) {
	dir := t.TempDir()
	for i, name := range []string{
		"config-20260501-101500.conf",
		"config-20260502-101500.conf",
		"config-20260503-101500.conf",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fmt.Sprintf("seconds-%d\n", i+1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := rotateArchives(dir, 2); err != nil {
		t.Fatalf("rotateArchives: %v", err)
	}
	remain := archiveContents(t, dir)
	if len(remain) != 2 || !remain["seconds-2"] || !remain["seconds-3"] || remain["seconds-1"] {
		t.Fatalf("want newest two seconds-only snapshots retained, got %v", remain)
	}
}
