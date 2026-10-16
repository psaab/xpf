package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5026 (historical): PR #5019 (#5005) added `--` end-of-options separators
// to every root-privileged exec in applySystemLogin (id/useradd/chown).
// #14111 superseded the chown half: the .ssh directory is now owned by the
// resolved numeric (uid, gid) via os.Chown in-process, so there is no
// external chown argv left to guard — the option-injection surface the
// `--` defended (a "<name>:<name>" operand) no longer exists. The test
// below now pins the successor invariant: the SSH-key branch runs, no
// external chown is invoked at all, and the .ssh directory ends up owned
// and traversable. The id/useradd `--` guards remain pinned by
// TestApplySystemLoginUsesEndOfOptions.

// stageChownEnv points the account DBs, provisioned-user marker dir, and home
// base at a throwaway tree, seeds /etc/passwd (so lookupUIDGID resolves the
// owner and the SSH-key branch is entered) and a LOCKED /etc/shadow field (so
// reconcileUserPassword takes pwNoop and never execs chpasswd), and stubs
// runCommandTimeout to RECORD every argv while reporting the user already
// EXISTS (`id` returns nil) so the privileged useradd is skipped and the test
// runs unprivileged. The passwd entry uses the CURRENT uid/gid so the
// DurableState authorized_keys write (fsatomic.WithOwner) fchowns the temp fd
// to self and succeeds without root. It returns the recorded-command slice and
// the .ssh dir the chown must target. #5026.
func stageChownEnv(t *testing.T, name string) (*[]recordedCmd, string) {
	t.Helper()
	dir := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()

	passwd := filepath.Join(dir, "passwd")
	passwdContent := fmt.Sprintf(
		"root:x:0:0:root:/root:/bin/bash\n%s:x:%d:%d:,,,:/home/%s:/bin/bash\n",
		name, uid, gid, name)
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o600); err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(dir, "shadow")
	// Locked ("!") field + no configured password ⇒ passwordAction returns
	// pwNoop, so reconcileUserPassword never execs chpasswd.
	shadowContent := fmt.Sprintf("root:*:19000:0:99999:7:::\n%s:!:19000:0:99999:7:::\n", name)
	if err := os.WriteFile(shadow, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}

	origShadow, origPasswd, origMarker, origHome := shadowPath, passwdPath, provisionedUsersDir, homeBaseDir
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = origShadow, origPasswd, origMarker, origHome
	})

	var calls []recordedCmd
	origRun := runCommandTimeout
	runCommandTimeout = func(cmd string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCmd{name: cmd, args: append([]string(nil), args...)})
		if cmd == "id" {
			return nil, nil // user exists → useradd skipped
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })

	return &calls, filepath.Join(homeBaseDir, name, ".ssh")
}

// TestApplySystemLoginChownUsesEndOfOptions is the successor guard for the
// chown half of #5005/#5026 after #14111. It provisions a valid login user
// WITH an authorized SSH key so applySystemLogin enters the key branch,
// then asserts (a) NO external chown command is invoked — directory
// ownership is applied in-process by numeric (uid, gid), so the
// "<name>:<name>" operand an attacker-controlled name could have turned
// into an option no longer exists — and (b) the .ssh directory was
// actually created with mode 0700 and its authorized_keys written. The
// existing TestApplySystemLoginUsesEndOfOptions cannot catch a regression
// here: its user has no SSH key, so this branch never runs. RED on revert:
// restoring the external name-based chown makes (a) fire; dropping the
// in-process chown leaves a root-owned .ssh and (on a non-root test run)
// the key write itself fails.
func TestApplySystemLoginChownUsesEndOfOptions(t *testing.T) {
	const name = "keyuser"
	calls, sshDir := stageChownEnv(t, name)

	d := &Daemon{}
	if err := d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAAC3Nz keyuser@host"},
	})); err != nil {
		t.Fatalf("applySystemLogin = %v, want nil", err)
	}

	for _, c := range *calls {
		if c.name == "chown" {
			t.Fatalf("external chown invoked with argv %v — .ssh ownership must be applied by numeric (uid,gid) in-process (#14111, successor to #5026)", c.args)
		}
	}
	st, err := os.Stat(sshDir)
	if err != nil {
		t.Fatalf(".ssh dir not created — the SSH-key branch did not run: %v (captured: %v)", err, *calls)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode = %o, want 0700", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Errorf("authorized_keys not written into .ssh: %v", err)
	}
}

// TestApplySystemLoginChownSkipsUnsafeName pins the fail-closed username
// re-validation for the ownership path: an unsafe (leading-dash) login
// name that slips past the tolerant load carrying an SSH key must be
// rejected before the key branch, so it NEVER reaches the privileged
// ownership/key-writing code. A valid peer in the same config is still
// provisioned. Reverting the ValidateLoginUsername skip lets `-r` flow
// into the key branch, so the "no key material for the unsafe name"
// assertion fails (#5026; #14111 successor form).
func TestApplySystemLoginChownSkipsUnsafeName(t *testing.T) {
	const good = "keyuser"
	calls, sshDir := stageChownEnv(t, good)

	d := &Daemon{}
	d.applySystemLogin(loginCfg(
		&config.LoginUser{Name: "-r", Class: "operator", SSHKeys: []string{"ssh-ed25519 AAAA evil@host"}},
		&config.LoginUser{Name: good, Class: "operator", SSHKeys: []string{"ssh-ed25519 AAAAC3Nz keyuser@host"}},
	))

	for _, c := range *calls {
		if c.name == "chown" {
			t.Fatalf("external chown invoked with argv %v — ownership is numeric/in-process after #14111", c.args)
		}
		for _, a := range c.args {
			if a == "-r:-r" || a == "-r" {
				t.Fatalf("unsafe username reached privileged argv %v — pre-branch re-validation missing (#5026)", c.args)
			}
		}
	}
	// The valid peer was still provisioned (its .ssh + keys exist)...
	if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatalf("valid peer 'keyuser' was never provisioned — the skip must not drop good users: %v", err)
	}
	// ...and no key material was written for the unsafe name.
	if _, err := os.Stat(filepath.Join(homeBaseDir, "-r", ".ssh", "authorized_keys")); !os.IsNotExist(err) {
		t.Fatalf("unsafe username '-r' got authorized_keys written (stat err=%v) — fail-closed skip missing (#5026)", err)
	}
}
