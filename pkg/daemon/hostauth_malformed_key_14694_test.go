package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14694: an early continue/return on a malformed SSH key or a negative UID
// in applySystemLogin / applyRootAuth skipped the login-shell demotion and
// reconcileUserPassword for an EXISTING account. On the tolerant /
// peer-sync / rollback apply path (config already live) and on the silent
// negative-UID arm, a demoted account therefore kept its old bash shell,
// its old shadow hash and its old authorized_keys while the demoting /
// revoking config was live — a config<->host credential desync.
//
// These tests stage an EXISTING account (passwd shell /bin/bash, usable
// shadow hash, xpf password+key markers) and apply a config that demotes
// it (class read-only, no password -> D2 lock, no keys -> key revoke)
// while ALSO carrying the defect trigger (one malformed key, or UID<0).
// The demotion/lock must still run; the malformed key must never be
// written; the error must surface (including for UID<0, previously
// silent). For root, applyRootAuth must still reconcile the password
// (lock here) despite the malformed root key, and must not write it.

const malformedKey14694 = `command="true" ssh-ed25519 AAAA forged`

// stage14694Existing stages passwd/shadow for an existing user `name`
// (uid 1001, shell /bin/bash, usable hash), an xpf password marker, and a
// fake chpasswd that records stdin AND mutates the fixture shadow like
// the real tool (so the lock is observable in the DB, not only in argv).
// runCommandTimeout is stubbed: `id` succeeds (user exists), `usermod`
// rewrites the passwd shell, and any other command is an error.
func stage14694Existing(t *testing.T, name string) (passwdPathF, shadowPathF, sentinel string, sawUsermod *bool) {
	t.Helper()
	dir := t.TempDir()
	passwdPathF = filepath.Join(dir, "passwd")
	shadowPathF = filepath.Join(dir, "shadow")
	passwdContent := fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\n%s:x:1001:1001:,,,:/home/%s:/bin/bash\n", name, name)
	shadowContent := fmt.Sprintf("root:!:19000:0:99999:7:::\n%s:$6$old$activehash:19000:0:99999:7:::\n", name)
	if err := os.WriteFile(passwdPathF, []byte(passwdContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPathF, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}
	origShadow, origPasswd, origDir, origHome := shadowPath, passwdPath, provisionedUsersDir, homeBaseDir
	origCandidates, origRun := loginCLIShellCandidates, runCommandTimeout
	origChown := chownSSHDir
	shadowPath, passwdPath = shadowPathF, passwdPathF
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	const cliShell = "/test/xpf/cli"
	loginCLIShellCandidates = []string{cliShell}
	chownSSHDir = func(string, int, int) error { return nil }
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = origShadow, origPasswd, origDir, origHome
		loginCLIShellCandidates, runCommandTimeout = origCandidates, origRun
		chownSSHDir = origChown
	})

	sentinel = filepath.Join(dir, "chpasswd-stdin")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	// Fake chpasswd: append stdin to sentinel, and apply user:hash to shadow.
	script := "#!/bin/sh\n" +
		"line=$(cat)\n" +
		"printf '%s\\n' \"$line\" >> " + sentinel + "\n" +
		"user=${line%%:*}\n" +
		"hash=${line#*:}\n" +
		"awk -F: -v u=\"$user\" -v h=\"$hash\" 'BEGIN{OFS=\":\"} $1==u{$2=h} {print}' " + shadowPathF + " > " + shadowPathF + ".tmp && mv " + shadowPathF + ".tmp " + shadowPathF + "\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	saw := false
	sawUsermod = &saw
	runCommandTimeout = func(cmd string, args ...string) ([]byte, error) {
		switch cmd {
		case "id":
			return nil, nil // user exists
		case "usermod":
			if len(args) != 4 || args[0] != "-s" || args[2] != "--" || args[3] != name {
				return nil, fmt.Errorf("unexpected usermod argv %v", args)
			}
			*sawUsermod = true
			data, err := os.ReadFile(passwdPathF)
			if err != nil {
				return nil, err
			}
			// Only the target user's line: root also ends in /bin/bash.
			updated := strings.Replace(string(data), "/home/"+name+":/bin/bash\n", "/home/"+name+":"+args[1]+"\n", 1)
			return nil, os.WriteFile(passwdPathF, []byte(updated), 0o600)
		default:
			return nil, fmt.Errorf("unexpected command %q %v", cmd, args)
		}
	}
	// xpf provisioned this account's password (D2 lock gate).
	if err := markProvisioned(name, 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned(name, 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned(name, 1001); err != nil {
		t.Fatal(err)
	}
	return passwdPathF, shadowPathF, sentinel, sawUsermod
}

func assertDemoted14694(t *testing.T, name, passwdF, sentinel string, sawUsermod *bool) {
	t.Helper()
	if !*sawUsermod {
		t.Fatalf("%s kept /bin/bash: usermod demotion was skipped (#14694)", name)
	}
	data, err := os.ReadFile(passwdF)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == name {
			if f[6] == "/bin/bash" {
				t.Fatalf("%s passwd shell still /bin/bash, want demoted CLI shell", name)
			}
		}
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("chpasswd was not invoked to lock %s: %v", name, err)
	}
	if !strings.Contains(string(got), name+":!") {
		t.Fatalf("chpasswd stdin = %q, want %q lock for %s", string(got), name+":!", name)
	}
	if h, ok := currentShadowHash(name); !ok || !isLockedShadow(h) {
		t.Fatalf("%s shadow = (%q,%v), want locked after demotion", name, h, ok)
	}
}

func TestApplySystemLoginMalformedKeyStillDemotesAndLocks14694(t *testing.T) {
	const name = "alice"
	passwdF, _, sentinel, sawUsermod := stage14694Existing(t, name)
	// Pre-existing xpf-managed keys that the emptied... (keys present but
	// malformed in new config) — file must not be overwritten with bad key.
	keysFile := managedAuthorizedKeysPath(name)
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAAOLD alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "read-only", // demotion: bash -> CLI shell
		SSHKeys: []string{malformedKey14694},
		// no EncryptedPassword: D2 lock
	})
	err := (&Daemon{}).applySystemLogin(cfg)
	if err == nil {
		t.Fatal("applySystemLogin accepted malformed SSH key without error (#14694)")
	}
	assertDemoted14694(t, name, passwdF, sentinel, sawUsermod)
	data, err := os.ReadFile(keysFile)
	if err != nil {
		t.Fatalf("pre-existing authorized_keys removed/changed unexpectedly: %v", err)
	}
	if strings.Contains(string(data), "forged") || strings.Contains(string(data), "command=") {
		t.Fatalf("malformed key was written to authorized_keys: %q", string(data))
	}
	if string(data) != "ssh-ed25519 AAAAOLD alice@host\n" {
		t.Fatalf("authorized_keys = %q, want untouched old key (malformed key must not be installed)", string(data))
	}
}

func TestApplySystemLoginNegativeUIDStillDemotesAndLocks14694(t *testing.T) {
	const name = "alice"
	passwdF, _, sentinel, sawUsermod := stage14694Existing(t, name)
	keysFile := managedAuthorizedKeysPath(name)
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAAOLD alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := loginCfg(&config.LoginUser{
		Name:  name,
		Class: "read-only",
		UID:   -1, // tolerant-path invalid sentinel (#11826)
		// valid key present so only UID triggers; keys must NOT be installed
		// for a refused-creation user, but shell/password of EXISTING
		// account must converge.
		SSHKeys: []string{"ssh-ed25519 AAAAC3Nz alice@host"},
	})
	err := (&Daemon{}).applySystemLogin(cfg)
	if err == nil {
		t.Fatal("applySystemLogin silently accepted negative UID (want error surfaced, #14694)")
	}
	assertDemoted14694(t, name, passwdF, sentinel, sawUsermod)
	// No useradd must have run (stub errors on it) — existing account only.
	data, err := os.ReadFile(keysFile)
	if err != nil {
		t.Fatalf("pre-existing authorized_keys removed unexpectedly: %v", err)
	}
	if string(data) != "ssh-ed25519 AAAAOLD alice@host\n" {
		t.Fatalf("authorized_keys = %q, want untouched (negative-UID user must not get new keys installed)", string(data))
	}
}

func TestApplyRootAuthMalformedKeyStillLocksPassword14694(t *testing.T) {
	sentinel, rootKeys := stageRootAuthEnv(t, "$6$rootsalt$roothash")
	if err := markProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	writeRootKeys(t, rootKeys, rootKeyContent)

	// Demoting/revoking root config: no password (D2 lock) + malformed key.
	cfg := rootAuthCfg("", malformedKey14694)
	err := (&Daemon{}).applyRootAuth(cfg)
	if err == nil {
		t.Fatal("applyRootAuth accepted malformed root SSH key without error (#14694)")
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("chpasswd was not invoked to lock root despite malformed key: %v", err)
	}
	if strings.TrimSpace(string(got)) != "root:!" {
		t.Fatalf("chpasswd stdin = %q, want %q (root lock must run despite malformed key)", strings.TrimSpace(string(got)), "root:!")
	}
	data, err := os.ReadFile(rootKeys)
	if err != nil {
		t.Fatalf("root authorized_keys removed/changed unexpectedly: %v", err)
	}
	if string(data) != rootKeyContent {
		t.Fatalf("root authorized_keys = %q, want untouched %q (malformed key must not be installed)", string(data), rootKeyContent)
	}
}

// Control: a brand-new user with a malformed key or negative UID must
// still NOT be created (no useradd), preserving #5005/#11826 fail-closed
// creation semantics.
func TestApplySystemLoginMalformedKeyNewUserNotCreated14694(t *testing.T) {
	withHermeticAccountDB(t)
	calls := captureRunCommand(t)
	d := &Daemon{}
	_ = d.applySystemLogin(loginCfg(
		&config.LoginUser{Name: "newbad", Class: "operator", SSHKeys: []string{malformedKey14694}},
		&config.LoginUser{Name: "newneg", Class: "operator", UID: -5},
	))
	for _, c := range *calls {
		if c.name == "useradd" {
			t.Fatalf("useradd ran for refused user: %v", c)
		}
	}
}
