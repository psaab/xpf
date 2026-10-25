package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #16683: the local console handler for
// `request system configuration rescue delete` had an empty
// `if err != nil {}` block left by #15897. It printed
// "Rescue configuration deleted" and returned nil when rescue.conf was
// absent, could not be unlinked, or its directory fsync failed, while the
// gRPC twin returns codes.Internal for the same errors. rescue.conf is a
// full copy of the active config (#4056 secret class), so a false success
// receipt leaves cleartext secrets on disk the operator believes are gone.
//
// FAIL-ON-REVERT: restore the empty error block and the absent and
// undeletable rows below go green on the defect — both report success and
// print the success line.

func newRescueDeleteCLI(t *testing.T) (*CLI, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, path)
	rescuePath := filepath.Join(filepath.Dir(path), configstore.RescueConfigBase)
	return New(store, nil, nil, nil, nil, nil, nil, nil, nil, nil), rescuePath
}

func TestConsoleRescueDeleteError16683(t *testing.T) {
	t.Run("absent_returns_error_and_no_success_line", func(t *testing.T) {
		c, _ := newRescueDeleteCLI(t)
		var err error
		out := captureStdout(t, func() {
			err = c.handleRequestSystemConfiguration([]string{"rescue", "delete"})
		})
		if err == nil {
			t.Fatal("rescue delete with no rescue.conf reported success; the absent-file error must be returned (#16683)")
		}
		if !strings.Contains(err.Error(), "delete rescue configuration") {
			t.Fatalf("error = %q, want it wrapped as %q (matching the gRPC twin wording)", err, "delete rescue configuration")
		}
		if !strings.Contains(err.Error(), "no rescue configuration exists") {
			t.Fatalf("error = %q, want the store's absence reason preserved", err)
		}
		if strings.Contains(out, "Rescue configuration deleted") {
			t.Fatalf("success line printed for a failed delete; output = %q", out)
		}
	})

	t.Run("undeletable_returns_error_and_no_success_line", func(t *testing.T) {
		c, rescuePath := newRescueDeleteCLI(t)
		// A non-empty directory at the rescue path cannot be unlinked by
		// os.Remove, so DeleteRescueConfig fails even for a privileged
		// operator.
		if err := os.Mkdir(rescuePath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rescuePath, "occupant"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		out := captureStdout(t, func() {
			err = c.handleRequestSystemConfiguration([]string{"rescue", "delete"})
		})
		if err == nil {
			t.Fatal("rescue delete of an undeletable rescue.conf reported success; the unlink error must be returned (#16683)")
		}
		if !strings.Contains(err.Error(), "delete rescue configuration") {
			t.Fatalf("error = %q, want it wrapped as %q (matching the gRPC twin wording)", err, "delete rescue configuration")
		}
		if strings.Contains(out, "Rescue configuration deleted") {
			t.Fatalf("success line printed for a failed delete; output = %q", out)
		}
		if _, statErr := os.Stat(rescuePath); statErr != nil {
			t.Fatalf("rescue path vanished despite the failed delete: %v", statErr)
		}
	})

	// Positive control: the regular-file row still deletes and prints the
	// success line.
	t.Run("regular_file_still_deletes", func(t *testing.T) {
		c, rescuePath := newRescueDeleteCLI(t)
		if err := os.WriteFile(rescuePath, []byte("system { host-name rescue-16683; }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		out := captureStdout(t, func() {
			err = c.handleRequestSystemConfiguration([]string{"rescue", "delete"})
		})
		if err != nil {
			t.Fatalf("rescue delete of a regular file refused: %v", err)
		}
		if !strings.Contains(out, "Rescue configuration deleted") {
			t.Fatalf("success line missing for a successful delete; output = %q", out)
		}
		if _, statErr := os.Stat(rescuePath); !os.IsNotExist(statErr) {
			t.Fatalf("rescue.conf still present after successful delete: stat err=%v", statErr)
		}
	})
}
