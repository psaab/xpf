package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

// TestBootExpiredFirstRollbackRetiresHostAuth12621 proves Store.Load's
// downtime-expiry rollback is followed by the #12155 boot teardown's host-auth
// closeout. This path has no live rollback callback and consequently no
// #12169 host-auth closeout record to replay.
func TestBootExpiredFirstRollbackRetiresHostAuth12621(t *testing.T) {
	_ = firstCommit12155FilesAndCommands(t)
	originalSSHDReload := sshdReloadCmd
	reloadAttempts := 0
	sshdReloadCmd = func() ([]byte, error) {
		reloadAttempts++
		if reloadAttempts == 1 {
			return []byte("injected reload failure"), errors.New("sshd unavailable")
		}
		return nil, nil
	}
	t.Cleanup(func() { sshdReloadCmd = originalSSHDReload })

	root := t.TempDir()
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	chpasswd := "#!/bin/sh\ncat > " + filepath.Join(root, "chpasswd.stdin") + "\n" +
		"while IFS=: read -r u h _; do [ -n \"$u\" ] && [ -n \"$h\" ] && " +
		"sed -i \"s/^$u:[^:]*/$u:$h/\" " + shadowPath + "; done < " +
		filepath.Join(root, "chpasswd.stdin") + "\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(chpasswd), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	path := filepath.Join(root, "xpf.conf")
	armed := newConfigStore(t, path)
	if err := armed.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := armed.SetFromInput("system host-name abandoned"); err != nil {
		t.Fatal(err)
	}
	if _, err := armed.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	armed.ExitConfigure()
	armed.CancelConfirmTimerForTesting()
	if err := expireConfirmWindow12155(t, path); err != nil {
		t.Fatal(err)
	}

	// Loading a fresh store expires FIRST inside Load, before any daemon
	// rollback callback can create the separate #12169 replay record.
	store := newConfigStore(t, path)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("Store.Load did not retain expired FIRST teardown debt")
	}
	if record, err := store.PendingFirstCommitHostAuthCloseout(); err != nil || record != nil {
		t.Fatalf("Load unexpectedly produced a live-rollback closeout record: record=%v err=%v", record, err)
	}

	// Model host-auth state left behind by the abandoned commit apply.
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:$6$salt$activehash:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: path, NoDataplane: true}}
	// Keep this probe focused on the #12155 boot consumer; bootstrap networkd,
	// FRR and dataplane effects are exercised by their existing teardown cells.
	d.applyBodyForTest = func(*config.Config) {}
	if d.teardownRecoveredFirstCommitBeforeDataplane() {
		t.Fatal("teardown reported success despite failed sshd reload")
	}
	markerPath := filepath.Join(root, ".configdb", "first-commit-teardown.json")
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("failed sshd reload cleared durable teardown intent: %v", err)
	}
	if !d.teardownRecoveredFirstCommitBeforeDataplane() {
		t.Fatal("boot teardown did not converge after sshd reload retry")
	}
	if reloadAttempts < 3 {
		t.Fatalf("sshd reload attempts=%d, want owner reload plus forced reload on each closeout attempt", reloadAttempts)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("durable teardown intent disappeared before post-dataplane closeout: %v", err)
	}

	shadow, err := os.ReadFile(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(shadow), "\n") {
		if strings.HasPrefix(line, "alice:") && !strings.HasPrefix(line, "alice:!") {
			t.Fatalf("abandoned FIRST login password remained usable after boot teardown: %q", line)
		}
	}
	for _, marker := range []string{
		filepath.Join(provisionedUsersDir, "alice"),
		filepath.Join(provisionedPasswordsDir(), "alice"),
	} {
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Errorf("boot teardown left host-auth ownership marker %s (stat err=%v)", marker, err)
		}
	}
}
