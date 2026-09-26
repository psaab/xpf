package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// setZeroizeRootPaths points the #5520 root-account revocation at a throwaway
// tree and records the root password-lock invocation. It returns a pointer to a
// counter incremented once per zeroizeLockRootPassword call. lockErr, when
// non-nil, is what the recorded seam returns (to drive the fail-closed path).
func setZeroizeRootPaths(t *testing.T, rootSSHDir string, lockErr error) *int {
	t.Helper()
	origDir, origLock := zeroizeRootSSHDir, zeroizeLockRootPassword
	t.Cleanup(func() {
		zeroizeRootSSHDir = origDir
		zeroizeLockRootPassword = origLock
	})
	zeroizeRootSSHDir = rootSSHDir
	var locks int
	zeroizeLockRootPassword = func() ([]byte, error) {
		locks++
		if lockErr != nil {
			return []byte("passwd: lock failed"), lockErr
		}
		return nil, nil
	}
	return &locks
}

// TestZeroizeRevokesManagedRootInPlace pins #5520: on a MANAGED-ROOT appliance
// the daemon writes a genuine provenance marker for root
// (markProvisioned("root", 0), applyRootAuth), so zeroizeLoginAccounts
// enumerates root — but root MUST be special-cased away from the generic
// /home/<name> + userdel teardown. Root's authorized_keys is at /root/.ssh (NOT
// /home/root/.ssh), and userdel -r root fails on UID 0. The factory reset must
// revoke root IN PLACE: remove /root/.ssh/authorized_keys, lock the root
// password, and NEVER userdel root.
//
// RED on revert: remove the `name == "root"` special-case and root falls into
// the generic path — keysFile becomes /home/root/.ssh/authorized_keys (the real
// key at /root/.ssh SURVIVES), the password is never locked (no lock recorded),
// and userdel is invoked for "root" (which on a real box fails on UID 0 and can
// abort the reset). Every root assertion below then fails. The alice
// assertions pin that the non-root generic path is unchanged.
func TestZeroizeRevokesManagedRootInPlace(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")
	rootSSHDir := filepath.Join(root, "rootssh") // stand-in for /root/.ssh

	// /etc/passwd: root (UID 0) + an xpf-provisioned non-root account (alice).
	mustWriteFile(t, passwdPath, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"alice:x:1001:1001:alice:/home/alice:/bin/bash\n"))

	// Provenance markers: root (managed-root, UID 0 — #5276) + alice (UID 1001).
	rootMarker := filepath.Join(provDir, "root")
	aliceMarker := filepath.Join(provDir, "alice")
	mustWriteFile(t, rootMarker, []byte("0"))
	mustWriteFile(t, filepath.Join(filepath.Dir(provDir), "provisioned-passwords", "root"), []byte("0"))
	mustWriteFile(t, aliceMarker, []byte("1001"))

	// Root's REAL authorized_keys at /root/.ssh (the prior tenant's key). This
	// is the artifact the generic /home/root path misses.
	rootKeys := filepath.Join(rootSSHDir, "authorized_keys")
	mustWriteFile(t, rootKeys, []byte("ssh-ed25519 AAAAprior prior-operator\n"))

	// A DECOY at /home/root/.ssh — nothing should have written here, and root's
	// revocation must not depend on it. It must survive (root path never touches
	// /home/root).
	decoyHomeRootKeys := filepath.Join(homeBase, "root", ".ssh", "authorized_keys")
	mustWriteFile(t, decoyHomeRootKeys, []byte("ssh-ed25519 AAAAdecoy decoy\n"))

	// alice's xpf-managed key + sudoers grant (the unchanged generic path).
	aliceKeys := filepath.Join(homeBase, "alice", ".ssh", "authorized_keys")
	mustWriteFile(t, aliceKeys, []byte("ssh-ed25519 AAAAalice alice\n"))
	mustWriteFile(t, filepath.Join(sudoersDir, "xpf-alice"), []byte("alice ALL=(ALL) NOPASSWD: ALL\n"))

	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)
	locks := setZeroizeRootPaths(t, rootSSHDir, nil)

	if err := zeroizeLoginAccounts(); err != nil {
		t.Fatalf("zeroizeLoginAccounts returned error: %v", err)
	}

	// (1) Root's REAL SSH key at /root/.ssh is removed (the core #5520 leak).
	assertAbsent(t, rootKeys)
	// (2) Root password lock invoked exactly once.
	if *locks != 1 {
		t.Errorf("root password lock invoked %d times, want exactly 1", *locks)
	}
	// (3) Root is NEVER userdel'd (UID 0). alice IS.
	got := append([]string(nil), *deleted...)
	sort.Strings(got)
	if len(got) != 1 || got[0] != "alice" {
		t.Errorf("userdel invoked for %v, want exactly [alice] (never root/UID 0)", got)
	}
	// (4) Root marker dropped (revocation fully succeeded).
	assertAbsent(t, rootMarker)

	// Non-root generic path unchanged (bit-for-bit): alice torn down.
	assertAbsent(t, aliceKeys)
	assertAbsent(t, filepath.Join(sudoersDir, "xpf-alice"))
	assertAbsent(t, aliceMarker)
}

// TestZeroizeKeysOnlyRootPreservesPassword pins #10741: the account-registry
// marker is written for a keys-only root-authentication, but only a separate
// provisioned-passwords marker proves xpf owns the console password. Zeroize
// must remove the xpf root key without locking the factory/operator password.
//
// RED on revert: restoring the unconditional zeroizeLockRootPassword call makes
// this record one lock (want zero), despite the missing password marker.
func TestZeroizeKeysOnlyRootPreservesPassword(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")
	rootSSHDir := filepath.Join(root, "rootssh")

	mustWriteFile(t, passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"))
	rootMarker := filepath.Join(provDir, "root")
	rootKeyMarker := filepath.Join(filepath.Dir(provDir), "provisioned-keys", "root")
	rootKeys := filepath.Join(rootSSHDir, "authorized_keys")
	mustWriteFile(t, rootMarker, []byte("0"))
	mustWriteFile(t, rootKeyMarker, []byte("0"))
	mustWriteFile(t, rootKeys, []byte("ssh-ed25519 AAAAprior prior-operator\n"))

	setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)
	locks := setZeroizeRootPaths(t, rootSSHDir, nil)
	if err := zeroizeLoginAccounts(); err != nil {
		t.Fatalf("zeroizeLoginAccounts returned error: %v", err)
	}

	if *locks != 0 {
		t.Errorf("root password lock invoked %d times for keys-only root, want zero", *locks)
	}
	assertAbsent(t, rootKeys)
	assertAbsent(t, rootMarker)
	assertAbsent(t, rootKeyMarker)
}

// TestZeroizeRootRevocationFailsClosed pins the fail-closed contract for root
// (mirrors the #5496 non-root userdel-failure retention): if locking the root
// password fails, zeroizeLoginAccounts must (a) surface the error so the
// factory reset is not reported clean while root login may still be usable, and
// (b) RETAIN the root marker so a retried zeroize re-attempts. The
// authorized_keys is still removed first (best-effort defense so the SSH-key
// vector dies even when the lock fails).
func TestZeroizeRootRevocationFailsClosed(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")
	rootSSHDir := filepath.Join(root, "rootssh")

	mustWriteFile(t, passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"))
	rootMarker := filepath.Join(provDir, "root")
	mustWriteFile(t, rootMarker, []byte("0"))
	mustWriteFile(t, filepath.Join(filepath.Dir(provDir), "provisioned-passwords", "root"), []byte("0"))
	rootKeys := filepath.Join(rootSSHDir, "authorized_keys")
	mustWriteFile(t, rootKeys, []byte("ssh-ed25519 AAAAprior prior-operator\n"))

	setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)
	locks := setZeroizeRootPaths(t, rootSSHDir, errors.New("exit status 1"))

	err := zeroizeLoginAccounts()
	if err == nil {
		t.Fatalf("zeroizeLoginAccounts with a failing root password lock returned nil; want the failure surfaced")
	}

	// The lock was attempted.
	if *locks != 1 {
		t.Errorf("root password lock invoked %d times, want exactly 1", *locks)
	}
	// authorized_keys removed even though the lock failed (defense in depth).
	assertAbsent(t, rootKeys)
	// Marker RETAINED so a retried zeroize re-attempts the lock.
	if _, statErr := os.Stat(rootMarker); statErr != nil {
		t.Errorf("expected the root provenance marker %s to be RETAINED after a lock failure, stat err = %v", rootMarker, statErr)
	}
}
