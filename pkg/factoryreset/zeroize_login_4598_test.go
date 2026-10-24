package factoryreset

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// assertPresent is the safety-property counterpart to assertAbsent: it fails if
// a NON-xpf artifact (an operator/system account's keys or sudoers file) was
// removed by the login-account teardown.
func assertPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected %s to SURVIVE zeroize (non-xpf artifact), stat err = %v", path, err)
	}
}

// setZeroizeLoginPaths points the #4598 login-account teardown at a throwaway
// tree and records userdel invocations. It returns the recorder slice pointer.
func setZeroizeLoginPaths(t *testing.T, provDir, sudoersDir, homeBase, passwdPath string) *[]string {
	t.Helper()
	origProv, origSudoers, origHome, origPasswd, origUserdel :=
		wipeProvisionedUsersDir, wipeSudoersDir, wipeHomeBase, wipePasswdPath, wipeUserdel
	origBusy, origKill := wipeAccountHasLiveProcesses, wipeKillAccountProcesses
	t.Cleanup(func() {
		wipeProvisionedUsersDir = origProv
		wipeSudoersDir = origSudoers
		wipeHomeBase = origHome
		wipePasswdPath = origPasswd
		wipeUserdel = origUserdel
		wipeAccountHasLiveProcesses = origBusy
		wipeKillAccountProcesses = origKill
	})
	wipeProvisionedUsersDir = provDir
	wipeSudoersDir = sudoersDir
	wipeHomeBase = homeBase
	wipePasswdPath = passwdPath
	// #16443: login-teardown cells model idle accounts unless they say so.
	wipeAccountHasLiveProcesses = func(int) (bool, error) { return false, nil }
	wipeKillAccountProcesses = func(int) ([]byte, error) { return nil, nil }
	var deleted []string
	wipeUserdel = func(name string) ([]byte, error) {
		deleted = append(deleted, name)
		return nil, nil
	}
	return &deleted
}

// TestZeroizeLoginAccountsRemovesProvisionedNotOthers pins #4598: the zeroize
// wipe must tear down the OS LOGIN accounts xpf provisioned — their
// /etc/shadow hashes (via userdel), SSH authorized_keys, and
// /etc/sudoers.d/xpf-* grants — so a re-tenanted device does not grant the
// prior tenant interactive login + passwordless sudo. It must do so
// marker-aware: a non-xpf operator/system account and operator-authored sudoers
// drop-ins are left untouched. (The UID-mismatch out-of-band recreate and the
// #5496 fail-closed uncertainty paths have their own tests, below and in
// zeroize_login_failclosed_5496_test.go.)
//
// RED on revert: before this fix performWipe tore down no OS accounts
// (applySystemLogin runs only inside the boot-time apply, which a post-zeroize
// boot SKIPS), so the shadow hash / authorized_keys / xpf-<user> sudoers all
// SURVIVED — every assertAbsent below (and the userdel recorder) fails on
// revert. The assertPresent safety checks pin that the teardown never nukes a
// non-xpf account.
func TestZeroizeLoginAccountsRemovesProvisionedNotOthers(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// /etc/passwd: root + a system account + an operator's OWN account (no
	// marker) + the xpf-provisioned "alice" (UID matches its marker).
	mustWriteFile(t, passwdPath, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
			"operator:x:1000:1000:operator:/home/operator:/bin/bash\n"+
			"alice:x:1001:1001:alice:/home/alice:/bin/bash\n"))

	// Provenance markers (content = UID at provision time). "ghost" has a
	// marker but no /etc/passwd entry (already removed out of band).
	aliceMarker := filepath.Join(provDir, "alice")
	ghostMarker := filepath.Join(provDir, "ghost")
	mustWriteFile(t, aliceMarker, []byte("1001"))
	mustWriteFile(t, ghostMarker, []byte("3000"))

	// sudoers.d: two xpf-<user> grants (both removed by the namespace sweep) +
	// one operator/system drop-in without the prefix (must survive).
	xpfAliceSudo := filepath.Join(sudoersDir, "xpf-alice")
	xpfGhostSudo := filepath.Join(sudoersDir, "xpf-ghost")
	operatorSudo := filepath.Join(sudoersDir, "90-cloud-init-users")
	mustWriteFile(t, xpfAliceSudo, []byte("alice ALL=(ALL) NOPASSWD: ALL\n"))
	mustWriteFile(t, xpfGhostSudo, []byte("ghost ALL=(ALL) NOPASSWD: ALL\n"))
	mustWriteFile(t, operatorSudo, []byte("operator ALL=(ALL) ALL\n"))

	// authorized_keys: alice (xpf → removed), ghost (gone → residue removed),
	// operator (own account, no marker → MUST survive).
	aliceKeys := filepath.Join(homeBase, "alice", ".ssh", "authorized_keys")
	ghostKeys := filepath.Join(homeBase, "ghost", ".ssh", "authorized_keys")
	operatorKeys := filepath.Join(homeBase, "operator", ".ssh", "authorized_keys")
	mustWriteFile(t, aliceKeys, []byte("ssh-ed25519 AAAAxpf alice\n"))
	mustWriteFile(t, ghostKeys, []byte("ssh-ed25519 AAAAghost ghost\n"))
	mustWriteFile(t, operatorKeys, []byte("ssh-ed25519 AAAAop operator\n"))

	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err != nil {
		t.Fatalf("wipeLoginAccounts returned error: %v", err)
	}

	// userdel fired for the exact xpf-provisioned account ONLY.
	got := append([]string(nil), *deleted...)
	sort.Strings(got)
	if len(got) != 1 || got[0] != "alice" {
		t.Errorf("userdel invoked for %v, want exactly [alice] (never stale/ghost/operator/root)", got)
	}

	// The fix: xpf login vectors are gone (RED on revert).
	assertAbsent(t, aliceKeys)
	assertAbsent(t, ghostKeys)
	assertAbsent(t, xpfAliceSudo)
	assertAbsent(t, xpfGhostSudo)
	assertAbsent(t, aliceMarker)
	assertAbsent(t, ghostMarker)

	// Safety property: NON-xpf accounts + operator sudoers are untouched.
	assertPresent(t, operatorKeys) // operator's own account (no marker)
	assertPresent(t, operatorSudo) // operator/system drop-in (no xpf- prefix)

	// The empty marker directory is cleaned up.
	assertAbsent(t, provDir)
}

// TestZeroizeLoginAccountsSurfacesUserdelFailureAndKeepsMarker pins the
// error-surfacing + retry contract: a userdel that fails must (a) surface the
// FIRST error so the factory reset is not reported clean while a live login
// account remains, and (b) RETAIN the provenance marker so a retried zeroize
// re-attempts the removal. authorized_keys is still removed (best-effort
// defense so the SSH vector dies even when userdel fails).
func TestZeroizeLoginAccountsSurfacesUserdelFailureAndKeepsMarker(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	mustWriteFile(t, passwdPath, []byte("bob:x:1500:1500:bob:/home/bob:/bin/bash\n"))
	bobMarker := filepath.Join(provDir, "bob")
	mustWriteFile(t, bobMarker, []byte("1500"))
	bobKeys := filepath.Join(homeBase, "bob", ".ssh", "authorized_keys")
	mustWriteFile(t, bobKeys, []byte("ssh-ed25519 AAAAbob bob\n"))
	mustWriteFile(t, filepath.Join(sudoersDir, "xpf-bob"), []byte("bob ALL=(ALL) NOPASSWD: ALL\n"))

	setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)
	wipeUserdel = func(name string) ([]byte, error) {
		return []byte("userdel: user bob is currently used by process 1234"),
			errors.New("exit status 8")
	}

	err := wipeLoginAccounts()
	if err == nil {
		t.Fatalf("wipeLoginAccounts with a failing userdel returned nil; want the failure surfaced")
	}

	// authorized_keys removed even though userdel failed (defense in depth).
	assertAbsent(t, bobKeys)
	// sudoers grant removed by the namespace sweep regardless.
	assertAbsent(t, filepath.Join(sudoersDir, "xpf-bob"))
	// Marker RETAINED so a retried zeroize re-attempts the userdel.
	if _, statErr := os.Stat(bobMarker); statErr != nil {
		t.Errorf("expected the provenance marker %s to be RETAINED after a userdel failure, stat err = %v", bobMarker, statErr)
	}
}
