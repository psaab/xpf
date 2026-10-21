package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5841: login credential ownership was neither atomic nor resource-specific.
// A single per-account provenance marker was (a) written best-effort AFTER a
// successful credential mutation — a marker-write failure was logged and the
// apply continued, leaving a mutated-but-unmarked credential xpf could no
// longer lock/clean (underclaim) — and (b) treated as proof of BOTH password
// and SSH-key ownership, so provisioning only a password could cause the
// emptied-key / deprovision reconcilers to clobber an operator-installed
// authorized_keys xpf never wrote (overclaim). The fix tracks password and
// SSH-key ownership in separate resource markers, written marker-first before
// the mutation (fail-visible). These are the fail-on-revert guards.

// TestApplySystemLoginPasswordOnlyDoesNotClaimSSHKey is the #5841 OVERCLAIM
// guard: xpf provisioning ONLY a user's PASSWORD must NOT mark the SSH key as
// xpf-owned, so emptying that user's key list can never remove an
// operator-installed authorized_keys xpf never wrote. bob has the password +
// account markers (a real password apply writes both) but NO key marker, and
// an operator-installed key file. Reverting the emptied-key gate from
// keyProvisioned back to the coarse xpfProvisioned (account marker present)
// removes bob's operator key — RED.
func TestApplySystemLoginPasswordOnlyDoesNotClaimSSHKey(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "bob", 1002)

	// xpf set bob's password + created/manages the account (both markers a
	// password apply writes) but NEVER wrote his SSH keys (no key marker).
	if err := markProvisioned("bob", 1002); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("bob", 1002); err != nil {
		t.Fatal(err)
	}
	// Prove the key marker is genuinely absent for the setup.
	if ownedKey(t, "bob", 1002) {
		t.Fatal("test setup wrote a key marker for bob; the overclaim guard needs it absent")
	}

	// bob has an operator-installed authorized_keys that xpf did not write.
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA bob-operator-installed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// bob is configured with NO SSH keys (his password is set elsewhere).
	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{Name: "bob", Class: "operator"}))

	// The operator key MUST survive — password ownership is not key ownership.
	if _, err := os.Stat(keysFile); err != nil {
		t.Fatalf("operator authorized_keys removed on a password-only provision (err=%v) — password ownership overclaimed SSH-key ownership (#5841)", err)
	}
}

// TestReconcileUserPasswordMarkerFailureSkipsChpasswd is the #5841 ATOMICITY
// guard: a durable password-ownership marker-write failure must be SURFACED,
// not silently swallowed — the credential mutation (chpasswd) is SKIPPED so xpf
// never leaves a mutated-but-unmarked password it can no longer lock (the
// underclaim). The sibling password-marker directory is pre-created as a
// regular FILE so the marker-first MkdirAllDurable fails (ENOTDIR). Reverting
// to the best-effort marker-AFTER-mutation ordering (or dropping the skip on a
// marker failure) runs chpasswd and swallows the failure — /etc/shadow changes
// — so the "shadow unchanged + chpasswd not run" assertion goes RED.
func TestReconcileUserPasswordMarkerFailureSkipsChpasswd(t *testing.T) {
	dir := t.TempDir()

	// op present with a DIFFERENT hash → passwordAction returns pwApply; passwd
	// resolves so uidOK is true (the marker-first branch is exercised).
	const oldHash = "$6$old$existinghash"
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow, []byte("op:"+oldHash+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("op:x:1001:1001:,,,:/home/op:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldShadow, oldPasswd, oldDir := shadowPath, passwdPath, provisionedUsersDir
	shadowPath, passwdPath = shadow, passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { shadowPath, passwdPath, provisionedUsersDir = oldShadow, oldPasswd, oldDir })

	// Make the durable PASSWORD-marker write fail: pre-create the sibling
	// password-marker directory path as a regular FILE, so MkdirAllDurable on it
	// returns ENOTDIR. (The account-marker directory stays a writable dir.)
	if err := os.WriteFile(provisionedPasswordsDir(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Fake chpasswd on PATH that records that it was invoked.
	sentinel := filepath.Join(dir, "chpasswd-ran")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ntouch " + sentinel + "\ncat >/dev/null\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	d := &Daemon{}
	d.reconcileUserPassword(&config.LoginUser{Name: "op", EncryptedPassword: config.NewSecret("$6$newsalt$newhash")})

	// chpasswd must NOT have run: the marker-first write failed, so the mutation
	// is skipped (fail-visible), never a mutated-but-unmarked credential.
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("chpasswd ran despite a failed password-ownership marker write — marker failure was swallowed (#5841 underclaim)")
	}
	// /etc/shadow is untouched (op still has the old hash).
	if cur, ok := currentShadowHash("op"); !ok || cur != oldHash {
		t.Fatalf("shadow field changed despite a marker-write failure: %q,%v", cur, ok)
	}
}
