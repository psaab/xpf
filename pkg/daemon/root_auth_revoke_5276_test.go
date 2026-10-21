package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5276: applyRootAuth was WRITE-ONLY — it returned immediately when the
// root-authentication stanza was nil and had only positive branches for a
// nonempty password or key list, so removing the stanza (or emptying a leaf)
// left the prior /etc/shadow root hash and /root/.ssh/authorized_keys LIVE.
// These tests are the fail-on-revert guards: they go RED if applyRootAuth is
// reverted to the early-return / positive-only form (no lock on password
// removal, no key removal on key-list emptying). They reuse the same throwaway
// shadow/passwd/marker/home fixtures the #1944/#5106/#5128 tests use.

// stageRootAuthEnv points the account DBs + marker dir + root .ssh dir at a
// throwaway tree, seeds /etc/shadow's root field to shadowRootField, and
// installs a fake `chpasswd` on PATH that records the stdin it receives (the
// `root:<hash>` apply or `root:!` lock). It returns the sentinel path holding
// that captured stdin and the xpf-managed root authorized_keys path.
func stageRootAuthEnv(t *testing.T, shadowRootField string) (sentinel, rootKeys string) {
	t.Helper()
	dir := t.TempDir()

	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow, []byte("root:"+shadowRootField+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origShadow, origPasswd, origDir, origRoot := shadowPath, passwdPath, provisionedUsersDir, rootSSHDir
	shadowPath, passwdPath = shadow, passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	rootSSHDir = filepath.Join(dir, "root-ssh")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, rootSSHDir = origShadow, origPasswd, origDir, origRoot
	})

	sentinel = filepath.Join(dir, "chpasswd-stdin")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat > " + sentinel + "\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	return sentinel, rootAuthorizedKeysPath()
}

// writeRootKeys stages an authorized_keys file at path with content.
func writeRootKeys(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rootAuthCfg builds a config whose root-authentication stanza carries pw and
// keys. An empty pw / nil keys models an emptied leaf; pass &config.Config{}
// directly (nil stanza) for a full stanza removal.
func rootAuthCfg(pw string, keys ...string) *config.Config {
	cfg := &config.Config{}
	cfg.System.RootAuthentication = &config.RootAuthConfig{
		EncryptedPassword: config.NewSecret(pw),
		SSHKeys:           keys,
	}
	return cfg
}

const rootKeyContent = "ssh-ed25519 AAAAROOT root@host\n"

// TestApplyRootAuthRevokesOnStanzaRemoval is the primary #5276 fail-on-revert
// guard: a previously xpf-provisioned root password + key, once the whole
// root-authentication stanza is removed, must have the password LOCKED and the
// xpf-managed authorized_keys REMOVED. Reverting applyRootAuth to its
// early-return-on-nil form makes this RED (no lock, key retained).
func TestApplyRootAuthRevokesOnStanzaRemoval(t *testing.T) {
	sentinel, rootKeys := stageRootAuthEnv(t, "$6$rootsalt$roothash") // active (unlocked) hash

	// xpf provisioned root's credentials — password AND keys — so both resource
	// markers are present (#5841: the lock is gated on the password marker, the
	// key removal on the key marker).
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

	// root-authentication removed entirely.
	d := &Daemon{}
	d.applyRootAuth(&config.Config{})

	// (a) chpasswd LOCKED root.
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("chpasswd was not invoked to lock root after stanza removal: %v", err)
	}
	if strings.TrimSpace(string(got)) != "root:!" {
		t.Fatalf("chpasswd stdin = %q, want %q (root password lock)", strings.TrimSpace(string(got)), "root:!")
	}
	// (b) the xpf-managed root authorized_keys is gone (key login revoked).
	if _, err := os.Stat(rootKeys); !os.IsNotExist(err) {
		t.Fatalf("root authorized_keys still present after stanza removal (err=%v) — #5276 revocation missing", err)
	}
}

// TestApplyRootAuthPasswordLeafRemovedKeepsKey: emptying ONLY the
// encrypted-password leaf (a key still configured) must LOCK the password while
// RETAINING the configured key. Reverting the password-lock branch makes the
// lock assertion RED.
func TestApplyRootAuthPasswordLeafRemovedKeepsKey(t *testing.T) {
	sentinel, rootKeys := stageRootAuthEnv(t, "$6$rootsalt$roothash")

	// xpf set root's password (marker present → the password-leaf removal
	// locks it, #5841). The key marker is (re)written by the positive key
	// branch below since a key is still configured.
	if err := markProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	// The staged key file already equals the configured key content, so the
	// positive key branch takes its no-op (content-unchanged) path — no chown.
	writeRootKeys(t, rootKeys, rootKeyContent)

	d := &Daemon{}
	d.applyRootAuth(rootAuthCfg("", "ssh-ed25519 AAAAROOT root@host"))

	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("chpasswd was not invoked to lock root after password leaf removed: %v", err)
	}
	if strings.TrimSpace(string(got)) != "root:!" {
		t.Fatalf("chpasswd stdin = %q, want %q (root password lock)", strings.TrimSpace(string(got)), "root:!")
	}
	// The key is still configured → retained.
	if b, err := os.ReadFile(rootKeys); err != nil || string(b) != rootKeyContent {
		t.Fatalf("configured root key not retained: content=%q err=%v", string(b), err)
	}
}

// TestApplyRootAuthKeyLeafRemovedKeepsPassword is the vice-versa: emptying ONLY
// the key list (the password still configured) must REMOVE the xpf-managed key
// while leaving the password UNTOUCHED (not locked). Reverting the key-removal
// branch makes the removal assertion RED.
func TestApplyRootAuthKeyLeafRemovedKeepsPassword(t *testing.T) {
	// Stage the shadow root field EQUAL to the configured hash so the password
	// reconcile takes pwNoop (no chpasswd at all) — proving the password is left
	// exactly as configured, neither re-applied nor locked.
	const hash = "$6$rootsalt$roothash"
	sentinel, rootKeys := stageRootAuthEnv(t, hash)

	// xpf wrote root's keys (key marker present → the emptied key list revokes
	// them, #5841). No password marker: the password is left exactly as
	// configured (pwNoop), proving key removal does not touch the password.
	if err := markProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	writeRootKeys(t, rootKeys, rootKeyContent)

	d := &Daemon{}
	d.applyRootAuth(rootAuthCfg(hash)) // password kept, key list empty

	// Password left untouched: no chpasswd (neither apply nor lock).
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran while the password was unchanged (err=%v) — password must be retained, not locked/re-applied", err)
	}
	// The emptied key list revoked the managed key.
	if _, err := os.Stat(rootKeys); !os.IsNotExist(err) {
		t.Fatalf("root authorized_keys still present after key list emptied (err=%v) — #5276 revocation missing", err)
	}
}

// TestApplyRootAuthKeepsNonProvenanceKey proves the revocation is
// provenance-scoped: with NO marker (xpf never provisioned root), a stanza
// removal must NOT lock root nor delete an operator-installed
// /root/.ssh/authorized_keys. This is the security-critical "never revoke a
// credential xpf did not place" invariant (and the fresh-boot safety bar).
func TestApplyRootAuthKeepsNonProvenanceKey(t *testing.T) {
	sentinel, rootKeys := stageRootAuthEnv(t, "$6$rootsalt$roothash")

	// No markProvisioned("root", 0) — xpf does not own root's credentials.
	writeRootKeys(t, rootKeys, "ssh-ed25519 AAAAOPERATOR operator@host\n")

	d := &Daemon{}
	d.applyRootAuth(&config.Config{}) // stanza absent

	// chpasswd must NEVER have run (root not locked).
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran without a provenance marker (err=%v) — an unmanaged root password was locked", err)
	}
	// The operator-installed key file must survive.
	if _, err := os.Stat(rootKeys); err != nil {
		t.Fatalf("operator-installed root authorized_keys was removed (err=%v) — removal must be provenance-scoped", err)
	}
}

// TestApplyRootAuthIdempotentStanzaAbsent proves re-applying with the stanza
// still absent is a clean no-op: the already-locked root field takes pwNoop (no
// chpasswd churn) and the already-removed key file stays absent without error.
func TestApplyRootAuthIdempotentStanzaAbsent(t *testing.T) {
	sentinel, rootKeys := stageRootAuthEnv(t, "!") // already locked

	if err := markProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	// Deliberately do NOT create rootKeys — already revoked.

	d := &Daemon{}
	d.applyRootAuth(&config.Config{})
	d.applyRootAuth(&config.Config{}) // second pass must not churn

	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran on an already-locked root (err=%v) — lock is not idempotent", err)
	}
	if _, err := os.Stat(rootKeys); !os.IsNotExist(err) {
		t.Fatalf("root authorized_keys unexpectedly present after an already-revoked reconcile (err=%v)", err)
	}
}
