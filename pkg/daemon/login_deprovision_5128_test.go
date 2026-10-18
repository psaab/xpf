package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stageDeprovisionEnv points the login-credential databases + marker dir + home
// base at a throwaway tree and installs a fake `chpasswd` on PATH that records
// the stdin it receives (the `<user>:!` lock command). It returns the sentinel
// path holding that captured stdin.
func stageDeprovisionEnv(t *testing.T, passwdContent, shadowContent string) string {
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
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = oldShadow, oldPasswd, oldDir, oldHome
	})

	sentinel := filepath.Join(dir, "chpasswd-stdin")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	// Record stdin; the trailing newline in `<user>:!\n` is trimmed by the
	// asserting test.
	script := "#!/bin/sh\ncat > " + sentinel + "\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// #14695: deprovision also resets the xpf-owned shell via the real
	// runCommandTimeout exec, so stage a no-op usermod alongside chpasswd.
	if err := os.WriteFile(filepath.Join(fakeBin, "usermod"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	return sentinel
}

// TestReconcileAbsentLoginUsersRevokesCredentials is the #5128 fail-on-revert
// guard: a login user removed from config must have its password LOCKED and its
// managed authorized_keys REMOVED (host access revoked), not merely lose its
// sudo grant. Reverting reconcileAbsentLoginUsers/deprovisionLoginUser makes
// this RED (no chpasswd lock, keys retained, marker retained).
func TestReconcileAbsentLoginUsersRevokesCredentials(t *testing.T) {
	sentinel := stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:,,,:/home/alice:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\nalice:$6$salt$activehash:19000:0:99999:7:::\n",
	)

	// alice was provisioned at UID 1001 (matches passwd): xpf set her password
	// AND wrote her managed keys, so both resource markers are present (#5841:
	// the lock is gated on the password marker, the key removal on the key
	// marker).
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
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
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAAC3... alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// alice removed from config entirely.
	d := &Daemon{}
	d.reconcileAbsentLoginUsers(&config.Config{})

	// (a) chpasswd was invoked to LOCK alice.
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("chpasswd was not invoked to lock the removed user: %v", err)
	}
	if strings.TrimSpace(string(got)) != "alice:!" {
		t.Fatalf("chpasswd stdin = %q, want %q (password lock)", strings.TrimSpace(string(got)), "alice:!")
	}
	// (b) the managed authorized_keys is gone (key login revoked).
	if _, err := os.Stat(keysFile); !os.IsNotExist(err) {
		t.Fatalf("authorized_keys for removed user still present (err=%v)", err)
	}
	// (c) the provenance marker is dropped (xpf forgets the account).
	if _, err := os.Stat(markerPath("alice")); !os.IsNotExist(err) {
		t.Fatalf("provenance marker still present after deprovision (err=%v)", err)
	}
}

// TestReconcileAbsentLoginUsersScoping proves the deprovision is scoped: a user
// STILL in config is untouched, and an out-of-band account whose UID no longer
// matches its marker (deleted+recreated) is never locked or de-keyed — only the
// stale marker is cleaned. This is the security-critical "never revoke a
// non-xpf / still-active account" invariant.
func TestReconcileAbsentLoginUsersScoping(t *testing.T) {
	sentinel := stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\n"+
			"carol:x:1001:1001:,,,:/home/carol:/bin/bash\n"+ // still in config
			"eve:x:2002:2002:,,,:/home/eve:/bin/bash\n", // recreated out of band
		"root:$6$r$h:19000:0:99999:7:::\n"+
			"carol:$6$c$h:19000:0:99999:7:::\n"+
			"eve:$6$e$h:19000:0:99999:7:::\n",
	)

	// carol: provisioned, still configured → must be kept.
	if err := markProvisioned("carol", 1001); err != nil {
		t.Fatal(err)
	}
	carolKeys := managedAuthorizedKeysPath("carol")
	if err := os.MkdirAll(filepath.Dir(carolKeys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(carolKeys, []byte("ssh-ed25519 AAAA carol\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// eve: marker records UID 1234, but the live account is UID 2002 (out-of-band
	// recreate) → xpfProvisioned mismatch → must NOT be touched.
	if err := markProvisioned("eve", 1234); err != nil {
		t.Fatal(err)
	}
	eveKeys := managedAuthorizedKeysPath("eve")
	if err := os.MkdirAll(filepath.Dir(eveKeys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eveKeys, []byte("ssh-ed25519 AAAA eve\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Only carol is in config.
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{{Name: "carol"}}}
	d := &Daemon{}
	d.reconcileAbsentLoginUsers(cfg)

	// chpasswd must NEVER have run — neither carol (kept) nor eve (not ours).
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran during a scoping-only reconcile (err=%v) — a kept/out-of-band account was locked", err)
	}
	// carol keeps her marker + keys.
	if _, err := os.Stat(carolKeys); err != nil {
		t.Fatalf("still-configured user's authorized_keys removed: %v", err)
	}
	if _, err := os.Stat(markerPath("carol")); err != nil {
		t.Fatalf("still-configured user's marker removed: %v", err)
	}
	// eve keeps her keys (never our account); the mismatched marker is cleaned
	// by xpfProvisioned's inline stale-marker removal.
	if _, err := os.Stat(eveKeys); err != nil {
		t.Fatalf("out-of-band account's authorized_keys removed — hijack: %v", err)
	}
}
