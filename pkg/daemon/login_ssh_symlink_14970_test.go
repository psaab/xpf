package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14970 (D31-02): /home/<user>/.ssh is user-writable. Before the fix,
// applySystemLogin and the key-revocation arms followed a planted symlink
// there as root:
//
//   - chownSSHDir(sshDir, uid, gid) chowned the symlink TARGET directory
//     (os.Chown follows links), handing an arbitrary directory's ownership
//     to the login user.
//   - fsatomic.WriteFileDurable(authorized_keys) created its temp file
//     inside the TARGET directory and renamed it over the target's
//     authorized_keys (root overwrite of an arbitrary file path).
//   - os.Remove(managedAuthorizedKeysPath) in the emptied-key branch (and in
//     deprovisionLoginUser) deleted the TARGET file when the .ssh path
//     resolved through a symlink (os.Remove on a path whose intermediate
//     component is a link unlinks the resolved file, not the link).
//
// Each test below plants a .ssh symlink (or an authorized_keys symlink) and
// asserts the operation is refused/fails closed AND the victim outside the
// .ssh tree is untouched. On pre-fix code the victim IS chowned / written /
// deleted, so every test goes RED.

// stageSymlinkLoginEnv stages the 5026-style login env for name, then plants
// a symlink at the exact path the SSH-key branch will act on.
//
//	plant == "sshdir": <home>/<name>/.ssh is a symlink to targetDir.
//	plant == "keysfile": .ssh is a real dir, but authorized_keys inside it
//	                     is a symlink to targetDir/authorized_keys.
func stageSymlinkLoginEnv(t *testing.T, name, plant string) (victimDir, sshDir string) {
	t.Helper()
	_, sshDir = stageChownEnv(t, name)

	victimDir = t.TempDir()
	// Pin mode 0755 (t.TempDir makes 0777-ish roots): if the vulnerable
	// code chowns it we can observe the mode change; content sentinel for
	// writes/deletes.
	if err := os.Chmod(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, "authorized_keys"), []byte("victim-original\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	switch plant {
	case "sshdir":
		if err := os.MkdirAll(filepath.Dir(sshDir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victimDir, sshDir); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	case "keysfile":
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(victimDir, "authorized_keys"), filepath.Join(sshDir, "authorized_keys")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	default:
		t.Fatalf("unknown plant %q", plant)
	}
	return victimDir, sshDir
}

func assertVictimUntouched14970(t *testing.T, victimDir string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(victimDir, "authorized_keys"))
	if err != nil {
		t.Fatalf("victim authorized_keys missing/gone (symlink traversal deleted it): %v", err)
	}
	if string(data) != "victim-original\n" {
		t.Fatalf("victim authorized_keys overwritten through symlink: %q", data)
	}
	st, err := os.Stat(victimDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("victim dir mode = %o, want 0755 (dir was chmod/chown'd through symlink)", st.Mode().Perm())
	}
}

// Write leg: a symlinked .ssh must not let root write authorized_keys into
// the symlink target, and the apply must fail (not report convergence).
func TestApplySystemLoginRefusesSymlinkedSSHDir14970(t *testing.T) {
	const name = "symlinkuser"
	victimDir, _ := stageSymlinkLoginEnv(t, name, "sshdir")

	d := &Daemon{}
	err := d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAAC3Nz symlinkuser@host"},
	}))
	if err == nil {
		t.Fatal("applySystemLogin through a symlinked .ssh returned nil — key convergence reported over a planted symlink (#14970)")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("apply error does not identify the symlink refusal: %v", err)
	}
	assertVictimUntouched14970(t, victimDir)
	// The link itself must still be a link (not replaced by a real dir).
	if fi, err := os.Lstat(filepath.Join(homeBaseDir, name, ".ssh")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf(".ssh after refused apply: mode symlink=%v err=%v (link replaced?)", err == nil && fi != nil && fi.Mode()&os.ModeSymlink != 0, err)
	}
}

// Write leg, file-level: authorized_keys itself as a symlink.
func TestApplySystemLoginRefusesSymlinkedAuthorizedKeys14970(t *testing.T) {
	const name = "filelinkuser"
	victimDir, _ := stageSymlinkLoginEnv(t, name, "keysfile")

	d := &Daemon{}
	err := d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAAC3Nz filelinkuser@host"},
	}))
	if err == nil {
		t.Fatal("applySystemLogin onto a symlinked authorized_keys returned nil (#14970)")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("apply error does not identify the symlink refusal: %v", err)
	}
	assertVictimUntouched14970(t, victimDir)
}

// Deprovision leg: removing a user (or emptying its key list) must not delete
// the file a symlinked .ssh points at. The error must surface (markers kept
// for retry) and the victim must survive.
func TestDeprovisionRefusesSymlinkedSSHDir14970(t *testing.T) {
	// alice removed from config entirely; she owns password+keys per markers.
	sentinel := stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:,,,:/home/alice:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\nalice:$6$salt$activehash:19000:0:99999:7:::\n",
	)
	_ = sentinel
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}

	// Plant: /home/alice/.ssh is a symlink to a victim dir holding a real
	// authorized_keys. A naive os.Remove(managedAuthorizedKeysPath) resolves
	// through the link and deletes the VICTIM's file.
	victimDir := t.TempDir()
	if err := os.Chmod(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, "authorized_keys"), []byte("victim-original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	homeAlice := filepath.Join(homeBaseDir, "alice")
	if err := os.MkdirAll(homeAlice, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, filepath.Join(homeAlice, ".ssh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	d := &Daemon{}
	err := d.reconcileAbsentLoginUsers(&config.Config{})
	if err == nil {
		t.Fatal("deprovision through a symlinked .ssh returned nil — revocation reported over a planted symlink (#14970)")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("deprovision error does not identify the symlink refusal: %v", err)
	}
	assertVictimUntouched14970(t, victimDir)
}

// Empty-key-list leg on a RETAINED user (applySystemLogin else-branch,
// #5106): same symlink must block the delete and surface an error.
func TestApplySystemLoginRefusesSymlinkOnEmptiedKeys14970(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "alice", 1001)
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	// Replace the real .ssh with a symlink to a victim dir.
	victimDir := t.TempDir()
	if err := os.Chmod(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, "authorized_keys"), []byte("victim-original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Dir(keysFile)
	if err := os.MkdirAll(filepath.Dir(sshDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, sshDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	d := &Daemon{}
	err := d.applySystemLogin(loginCfg(&config.LoginUser{Name: "alice", Class: "operator"}))
	if err == nil {
		t.Fatal("emptied-key revoke through a symlinked .ssh returned nil (#14970)")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("apply error does not identify the symlink refusal: %v", err)
	}
	assertVictimUntouched14970(t, victimDir)
}

// Control: a normal (non-symlink) .ssh still provisions and revokes. This
// pins that the guard does not break the legitimate path.
func TestLoginSSHDirRegularPathStillWorks14970(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "alice", 1001)
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAAC3... alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	if err := d.applySystemLogin(loginCfg(&config.LoginUser{Name: "alice", Class: "operator"})); err != nil {
		t.Fatalf("legitimate emptied-key revoke now fails: %v", err)
	}
	if _, err := os.Stat(keysFile); !os.IsNotExist(err) {
		t.Fatalf("legitimate authorized_keys not revoked: %v", err)
	}
}
