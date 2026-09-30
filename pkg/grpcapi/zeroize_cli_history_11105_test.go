package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
)

// #11105: pre-existing CLI history files (cleartext PSKs) must not survive
// zeroize. Seed both filenames with a PSK line, run the leg against a
// throwaway home, assert absence. Missing files are fine (idempotent wipe).
func TestZeroizeCLIHistoryFilesRemoved11105(t *testing.T) {
	home := t.TempDir()
	for _, f := range zeroizeCLIHistoryFilenames {
		if err := os.WriteFile(filepath.Join(home, f), []byte("set system login user x authentication plain-text-password hunter2\n"), 0600); err != nil {
			t.Fatalf("seed %s: %v", f, err)
		}
	}
	if err := zeroizeCLIHistoryFiles(home); err != nil {
		t.Fatalf("zeroizeCLIHistoryFiles: %v", err)
	}
	for _, f := range zeroizeCLIHistoryFilenames {
		if _, err := os.Lstat(filepath.Join(home, f)); !os.IsNotExist(err) {
			t.Errorf("%s survived the wipe (err=%v)", f, err)
		}
	}
	// Idempotent: second run on absent files is clean.
	if err := zeroizeCLIHistoryFiles(home); err != nil {
		t.Errorf("second wipe must be clean, got: %v", err)
	}
}
