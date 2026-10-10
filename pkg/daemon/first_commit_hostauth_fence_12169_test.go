package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
	"testing"
)

const lateFenceHash12169 = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"

// TestFirstCommitRollbackLateRevocationReconcilesLiveCommit12169 reproduces
// the bounded-runner case: rollback returns while an old chpasswd invocation
// is blocked, a real commitConfirmedAndApply promotes the same three accounts,
// then the old invocation resumes. Its lock must be repaired to the live
// password before it can complete or drop the accounts' provenance markers.
func TestFirstCommitRollbackLateRevocationReconcilesLiveCommit12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	shadowPath = filepath.Join(root, "shadow")
	passwdPath = filepath.Join(root, "passwd")
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	homeBaseDir = filepath.Join(root, "home")
	rootSSHDir = filepath.Join(root, "root-ssh")
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir(), homeBaseDir, rootSSHDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"alice", "bob", "carol"}
	oldHash := "$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var passwd, shadow strings.Builder
	passwd.WriteString("root:x:0:0::/root:/bin/bash\n")
	shadow.WriteString("root:!:19000:0:99999:7:::\n")
	for i, name := range names {
		fmt.Fprintf(&passwd, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, 1001+i, 1001+i, name)
		fmt.Fprintf(&shadow, "%s:%s:19000:0:99999:7:::\n", name, oldHash)
	}
	if err := os.WriteFile(passwdPath, []byte(passwd.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte(shadow.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: s.ConfigPath()}}
	d.applyBodyForTest = func(*config.Config) {}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	var oldConfig strings.Builder
	oldConfig.WriteString("system { host-name abandoned; login {")
	for _, name := range names {
		fmt.Fprintf(&oldConfig, " user %s { class super-user; authentication { encrypted-password \"%s\"; } }", name, lateFenceHash12169)
	}
	oldConfig.WriteString("} }")
	if err := s.LoadOverride(oldConfig.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfirmGenForTesting()
	for i, name := range names {
		if err := markProvisioned(name, 1001+i); err != nil {
			t.Fatal(err)
		}
		if err := markPasswordProvisioned(name, 1001+i); err != nil {
			t.Fatal(err)
		}
	}

	started := filepath.Join(root, "lock-started")
	repaired := filepath.Join(root, "repaired")
	staleWrite := filepath.Join(root, "stale-write")
	events := filepath.Join(root, "password-events")
	failLock := filepath.Join(root, "fail-lock")
	gate := filepath.Join(root, "release-lock")
	if err := unix.Mkfifo(gate, 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then printf 'lock-start:%s\\n' \"$user\" >> '" + events + "'; printf '%s\\n' \"$user\" > '" + started + "'; read -r release < '" + gate + "'; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"if [ \"$hash\" = '!' ]; then printf 'stale-write:%s\\n' \"$user\" >> '" + events + "'; touch '" + staleWrite + "'; [ ! -f '" + failLock + "' ] || exit 1; else printf 'password-write:%s\\n' \"$user\" >> '" + events + "'; touch '" + repaired + "'; fi\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
	oldBudget := hostAuthCloseoutBudget
	hostAuthCloseoutBudget = 80 * time.Millisecond
	t.Cleanup(func() { hostAuthCloseoutBudget = oldBudget })

	rollbackDone := make(chan struct{})
	go func() {
		s.InvokeRollbackTimerForTesting(gen)
		close(rollbackDone)
	}()
	waitFile12169(t, started)
	select {
	case <-rollbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded rollback did not return with old owner blocked")
	}

	var candidate strings.Builder
	candidate.WriteString("system { host-name legitimate; login {")
	for _, name := range names {
		fmt.Fprintf(&candidate, " user %s { class super-user; authentication { encrypted-password \"%s\"; } }", name, lateFenceHash12169)
	}
	candidate.WriteString("} }")
	if err := s.LoadOverride(candidate.String()); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) { d.applyErrForTest = d.applySystemLogin(cfg) }
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if got, ok := currentShadowHash(name); !ok || got != lateFenceHash12169 {
			t.Fatalf("real commit did not apply the live password for %s before the old owner resumed: %q %v", name, got, ok)
		}
	}
	for _, path := range []string{repaired, events} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(failLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, staleWrite)
	waitFile12169(t, repaired)
	victimData, err := os.ReadFile(started)
	if err != nil {
		t.Fatal(err)
	}
	victim := strings.TrimSpace(string(victimData))
	// Give the old inventory owner time to visit every remaining name. A
	// second lock-start would prove a post-promotion cascade, even if a later
	// repair happened to restore its hash.
	time.Sleep(100 * time.Millisecond)
	wantEvents := "stale-write:" + victim + "\npassword-write:" + victim + "\n"
	if got, err := os.ReadFile(events); err != nil || string(got) != wantEvents {
		t.Fatalf("stale owner started post-promotion revocations or repaired out of order: events=%q err=%v want=%q", got, err, wantEvents)
	}
	for _, name := range names {
		if got, ok := currentShadowHash(name); !ok || got != lateFenceHash12169 {
			t.Errorf("stale rollback owner left live password for %s revoked: %q %v", name, got, ok)
		}
		if _, err := os.Stat(markerPath(name)); err != nil {
			t.Errorf("live account %s provenance marker was dropped by stale owner: %v", name, err)
		}
		if _, err := os.Stat(markerPathIn(provisionedPasswordsDir(), name)); err != nil {
			t.Errorf("live account %s password provenance marker was dropped by stale owner: %v", name, err)
		}
	}
	if !s.IsConfirmPending() {
		t.Fatal("new commit-confirmed window was lost")
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	t.Log("accelerated 80ms closeout: real runner returned with one chpasswd blocked; real confirmed commit promoted three accounts; stale write was synchronously repaired before owner completion, other accounts were not revoked, and every live marker remained")
}

func waitFile12169(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
