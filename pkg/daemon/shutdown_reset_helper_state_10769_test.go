package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// resetHelperStateDP simulates the userspace helper's shutdown behavior: its
// final state write lands on Close/Teardown, after the wipe already erased
// the file. The interface is nil-embedded like shutdownModeDP; only the
// lifecycle arms run here.
type resetHelperStateDP struct {
	dataplane.RuntimeDataPlane

	stateFile string
}

func (d *resetHelperStateDP) Start(context.Context) error { return nil }
func (d *resetHelperStateDP) Close() error                { return d.writeFinal() }
func (d *resetHelperStateDP) Teardown() error             { return d.writeFinal() }

func (d *resetHelperStateDP) writeFinal() error {
	if err := os.MkdirAll(filepath.Dir(d.stateFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(d.stateFile, []byte("helper final snapshot"), 0o600)
}

// TestRunShutdownSequenceRemovesHelperStateAfterReset pins the S-RUN fix:
// the helper's final state write lands after the wipe erased it, so a
// reset shutdown must sweep the configured state file once the helper is
// gone. Without the sweep the shutdown recreates tenant state behind a
// reported-success reset. The non-reset control keeps the file.
func TestRunShutdownSequenceRemovesHelperStateAfterReset(t *testing.T) {
	for _, resetting := range []bool{true, false} {
		name := "reset sweeps helper state"
		if !resetting {
			name = "plain shutdown keeps helper state"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			stateFile := filepath.Join(root, "run", "xpf", "userspace-dp.json")
			store, err := configstore.New(filepath.Join(root, "xpf.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			set := "set system dataplane-type userspace\n" +
				"set system dataplane control-socket " + filepath.Join(root, "run", "xpf", "control.sock") + "\n" +
				"set system dataplane state-file " + stateFile + "\n"
			if _, err := store.LoadSet(set); err != nil {
				t.Fatalf("LoadSet: %v", err)
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
			d.setDataplane(&resetHelperStateDP{stateFile: stateFile})
			if resetting {
				d.enterResetGeneration()
			}
			var wg sync.WaitGroup
			sentinel := context.Canceled
			done := make(chan error, 1)
			go func() { done <- d.runShutdownSequence(&wg, func() {}, sentinel) }()
			select {
			case got := <-done:
				if got != sentinel {
					t.Fatalf("runShutdownSequence returned %v, want passthrough", got)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("runShutdownSequence did not return within 30s")
			}
			_, statErr := os.Lstat(stateFile)
			if resetting && !os.IsNotExist(statErr) {
				t.Fatalf("helper state %s survived a reset shutdown: %v", stateFile, statErr)
			}
			if !resetting && statErr != nil {
				t.Fatalf("plain shutdown must not sweep helper state: %v", statErr)
			}
		})
	}
}
