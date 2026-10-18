package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stageDeprovisionShellEnv points passwd/shadow/markers/home at a temp tree.
// chpasswd and usermod are injected via runCommandTimeout (below), so no fake
// binaries are needed for those; deprovision uses runCommandStdinTimeout for
// chpasswd which shells out, so install a fake chpasswd on PATH.
func stageDeprovisionShellEnv(t *testing.T, passwdContent, shadowContent string) (passwdFile string) {
	t.Helper()
	dir := t.TempDir()
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o600); err != nil {
		t.Fatal(err)
	}
	oldShadow, oldPasswd, oldDir, oldHome := shadowPath, passwdPath, provisionedUsersDir, homeBaseDir
	shadowPath, passwdPath = shadow, passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = oldShadow, oldPasswd, oldDir, oldHome
	})
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte("#!/bin/sh\ncat >/dev/null\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	return passwd
}

// deprovisionFixture stages alice (UID 1001, /bin/bash) with account+password+
// key markers, records usermod via the runCommandTimeout seam, and funnels both
// the production (ownsAccount) and elevated-preexisting (shell-only) scenarios.
func deprovisionFixture(t *testing.T, withAccountMarker bool) (passwdFile string, usermodCalls *[][]string) {
	t.Helper()
	passwdFile = stageDeprovisionShellEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:,,,:/home/alice:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\nalice:$6$salt$activehash:19000:0:99999:7:::\n")
	if withAccountMarker {
		if err := markProvisioned("alice", 1001); err != nil {
			t.Fatal(err)
		}
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	keysFile := managedAuthorizedKeysPath("alice")
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAAC3 alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := [][]string{}
	pf := passwdFile
	orig := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "usermod" {
			cpy := append([]string{name}, args...)
			calls = append(calls, cpy)
			if len(args) == 4 && args[0] == "-s" {
				data, err := os.ReadFile(pf)
				if err != nil {
					return nil, err
				}
				updated := strings.Replace(string(data), "/home/alice:/bin/bash\n", "/home/alice:"+args[1]+"\n", 1)
				if err := os.WriteFile(pf, []byte(updated), 0o600); err != nil {
					return nil, err
				}
			}
			return nil, nil
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = orig })
	return passwdFile, &calls
}

// TestDeprovisionLoginUserResetsInteractiveShellToNologin is the #14695
// decisive regression: an xpf-created super-user (useradd -m -s /bin/bash,
// account marker) removed from config must have its interactive shell reset
// to /usr/sbin/nologin via `usermod -s /usr/sbin/nologin -- alice` BEFORE
// provenance markers are dropped, and a failed usermod must retain markers.
func TestDeprovisionLoginUserResetsInteractiveShellToNologin(t *testing.T) {
	passwdFile, usermodCalls := deprovisionFixture(t, true)

	d := &Daemon{}
	if err := d.deprovisionLoginUser("alice"); err != nil {
		t.Fatalf("deprovisionLoginUser: %v", err)
	}
	want := []string{"usermod", "-s", loginShellNologin, "--", "alice"}
	if len(*usermodCalls) != 1 || strings.Join((*usermodCalls)[0], "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("usermod calls = %v, want exactly [%v] (interactive /bin/bash must be reset to nologin)", *usermodCalls, want)
	}
	shell, found, err := loginUserShell("alice")
	if err != nil || !found {
		t.Fatalf("loginUserShell(alice) = %q,%v,%v", shell, found, err)
	}
	if shell != loginShellNologin {
		t.Fatalf("passwd shell after deprovision = %q, want %q", shell, loginShellNologin)
	}
	if _, err := os.Stat(markerPath("alice")); !os.IsNotExist(err) {
		t.Fatalf("account marker survived after successful shell reset (err=%v)", err)
	}
	_ = passwdFile
}

// TestDeprovisionLoginUserShellResetFailureRetainsProvenance: a failing
// usermod must fail the deprovision and keep markers so the next apply retries
// (mirrors the password-lock / key-removal fail-closed discipline).
func TestDeprovisionLoginUserShellResetFailureRetainsProvenance(t *testing.T) {
	stageDeprovisionShellEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:,,,:/home/alice:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\nalice:$6$salt$activehash:19000:0:99999:7:::\n")
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	orig := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "usermod" {
			return []byte("usermod: simulated failure"), fmt.Errorf("exit status 1")
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = orig })

	d := &Daemon{}
	if err := d.deprovisionLoginUser("alice"); err == nil {
		t.Fatal("deprovision reported success while usermod failed; shell stays /bin/bash")
	}
	if _, err := os.Stat(markerPath("alice")); err != nil {
		t.Fatalf("account marker dropped despite failed shell reset: %v (next apply cannot retry)", err)
	}
}

// TestDeprovisionLoginUserAlreadyNologinIsNoop: already-nologin shell must not
// invoke usermod (idempotent, no spurious exec).
func TestDeprovisionLoginUserAlreadyNologinIsNoop(t *testing.T) {
	stageDeprovisionShellEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:,,,:/home/alice:"+loginShellNologin+"\n",
		"root:$6$r$h:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n")
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	var usermodCount int
	origRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "usermod" {
			usermodCount++
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })
	d := &Daemon{}
	if err := d.deprovisionLoginUser("alice"); err != nil {
		t.Fatalf("deprovisionLoginUser: %v", err)
	}
	if usermodCount != 0 {
		t.Fatalf("usermod ran %d times for an already-nologin shell, want 0", usermodCount)
	}
	if _, err := os.Stat(markerPath("alice")); !os.IsNotExist(err) {
		t.Fatalf("account marker survived nologin deprovision (err=%v)", err)
	}
}

// TestDeprovisionShellOnlyElevationIsRevoked covers the second arm: a
// pre-existing account elevated to super-user (shell mutated to /bin/bash by
// applySystemLogin, no password/key of its own) leaves a shell marker and,
// once removed from config, its shell is reset even though it has no
// password/key markers.
func TestDeprovisionShellOnlyElevationIsRevoked(t *testing.T) {
	// Simulate the apply path's shell-marker write for an existing account.
	passwdFile, usermodCalls := deprovisionFixtureShellOnly(t)
	_ = passwdFile

	d := &Daemon{}
	if err := d.deprovisionLoginUser("alice"); err != nil {
		t.Fatalf("deprovisionLoginUser(shell-only): %v", err)
	}
	want := []string{"usermod", "-s", loginShellNologin, "--", "alice"}
	if len(*usermodCalls) != 1 || strings.Join((*usermodCalls)[0], "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("usermod calls = %v, want [%v] for shell-only elevated account", *usermodCalls, want)
	}
	if _, err := os.Stat(markerPathIn(provisionedShellsDir(), "alice")); !os.IsNotExist(err) {
		t.Fatalf("shell marker survived deprovision (err=%v)", err)
	}
}

// deprovisionFixtureShellOnly stages alice with ONLY a shell marker.
func deprovisionFixtureShellOnly(t *testing.T) (string, *[][]string) {
	t.Helper()
	passwdFile := stageDeprovisionShellEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:,,,:/home/alice:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n")
	if err := markShellProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	calls := [][]string{}
	orig := runCommandTimeout
	pf := passwdFile
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "usermod" {
			cpy := append([]string{name}, args...)
			calls = append(calls, cpy)
			if len(args) == 4 && args[0] == "-s" {
				data, err := os.ReadFile(pf)
				if err != nil {
					return nil, err
				}
				updated := strings.Replace(string(data), "/home/alice:/bin/bash\n", "/home/alice:"+args[1]+"\n", 1)
				if err := os.WriteFile(pf, []byte(updated), 0o600); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = orig })
	return passwdFile, &calls
}

// TestDeprovisionNonXpfAccountShellUntouched: an account with NO markers at
// all must never be shell-reset (never touch a non-xpf account).
func TestDeprovisionNonXpfAccountShellUntouched(t *testing.T) {
	stageDeprovisionShellEnv(t,
		"root:x:0:0:root:/root:/bin/bash\neve:x:1001:1001:,,,:/home/eve:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\neve:$6$salt$hash:19000:0:99999:7:::\n")
	var usermodCount int
	orig := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "usermod" {
			usermodCount++
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = orig })
	d := &Daemon{}
	if err := d.deprovisionLoginUser("eve"); err != nil {
		t.Fatalf("deprovisionLoginUser(eve): %v", err)
	}
	if usermodCount != 0 {
		t.Fatalf("usermod ran on a non-xpf account (overclaim)")
	}
	// reconcile must not even enumerate eve.
	names, err := provisionedNames()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := names["eve"]; ok {
		t.Fatal("non-xpf account enumerated by provisionedNames")
	}
	_ = config.Config{}
}
