package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

// TestFirstCommitRollbackCrashMidCloseoutReplaysOnRestart12169 kills a child
// daemon after the sudoers owner but at the sshd reload boundary. The durable
// store has already promoted to bootstrap, while root-auth retirement has not
// run. A fresh Store/Daemon startup must replay the pending closeout without
// invoking the ordinary config apply and remove the remaining owned residue.
func TestFirstCommitRollbackCrashMidCloseoutReplaysOnRestart12169(t *testing.T) {
	if root := os.Getenv("XPF_12169_CLOSEOUT_CRASH_ROOT"); root != "" {
		isolateFirstCommitRollbackHostAuth12169(t)
		setFirstCommitCloseoutCrashPaths12169(root)
		s, err := configstore.New(filepath.Join(root, "xpf.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Load(); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: s, applySem: semaphore.NewWeighted(1)}
		d.applyBodyForTest = func(*config.Config) {}
		s.SetRollbackExecutor(d.executeConfirmedRollback)
		sshdReloadCmd = func() ([]byte, error) { os.Exit(73); return nil, nil }
		s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
		t.Fatal("did not reach injected mid-closeout crash boundary")
	}

	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	setFirstCommitCloseoutCrashPaths12169(root)
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir(), rootSSHDir, sudoersDir, filepath.Dir(sshdConfPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	s, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name abandoned; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootAuthorizedKeysPath(), []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI12169 root@xpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sudoersDir, "xpf-alice"), []byte("alice ALL=(ALL) NOPASSWD: ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshdConfPath, []byte("# Managed by xpf\nPermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFirstCommitRollbackCrashMidCloseoutReplaysOnRestart12169$", "-test.v")
	cmd.Env = append(os.Environ(), "XPF_12169_CLOSEOUT_CRASH_ROOT="+root)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("child did not crash at sshd reload boundary: %v\n%s", err, output)
	}
	t.Logf("child exited mid-closeout after durable rollback promotion:\n%s", output)
	if _, err := os.Stat(filepath.Join(sudoersDir, "xpf-alice")); !os.IsNotExist(err) {
		t.Fatalf("crash did not occur after sudoers retirement: %v", err)
	}
	if _, err := os.Stat(rootAuthorizedKeysPath()); err != nil {
		t.Fatalf("root key unexpectedly retired before injected crash: %v", err)
	}

	restarted, err := configstore.New(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: restarted, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: s.ConfigPath(), NoDataplane: true}}
	oldNodeID := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return false }
	t.Cleanup(func() { hasNodeIDFileFn = oldNodeID })
	restarted.SetRollbackExecutor(d.executeConfirmedRollback)
	if failClosed, err := d.loadAndBootstrapConfig(); err != nil || failClosed {
		t.Fatalf("restart load: failClosed=%v err=%v", failClosed, err)
	}
	d.ensureEarlyInputBootstrapGuard()
	applies := 0
	d.applyBodyForTest = func(*config.Config) { applies++ }
	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatal(err)
	}
	if applies != 0 {
		t.Fatalf("bootstrap retirement replay unexpectedly invoked ordinary config apply %d times", applies)
	}
	if _, err := os.Stat(rootAuthorizedKeysPath()); !os.IsNotExist(err) {
		t.Fatalf("restart did not retire abandoned root key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sudoersDir, "xpf-alice")); !os.IsNotExist(err) {
		t.Fatalf("restart left abandoned sudoers grant: %v", err)
	}
	if _, err := os.Stat(sshdConfPath); !os.IsNotExist(err) {
		t.Fatalf("restart left abandoned sshd drop-in: %v", err)
	}
	if record, err := restarted.PendingFirstCommitHostAuthCloseout(); err != nil || record != nil {
		t.Fatalf("completed replay obligation remains: record=%v err=%v", record, err)
	}
	t.Log("fresh-store bootstrap replay retired the remaining root key, sudoers and sshd state with zero ordinary applies")
}

func setFirstCommitCloseoutCrashPaths12169(root string) {
	shadowPath = filepath.Join(root, "shadow")
	passwdPath = filepath.Join(root, "passwd")
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	homeBaseDir = filepath.Join(root, "home")
	rootSSHDir = filepath.Join(root, "root-ssh")
	sudoersDir = filepath.Join(root, "sudoers.d")
	sshdConfPath = filepath.Join(root, "sshd_config.d", "00-xpf.conf")
	EarlyInputHandoffMarkerPath = filepath.Join(root, "early-input-handoff.done")
	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, nil }
}
