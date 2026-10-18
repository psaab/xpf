package grpcapi

import (
	"path/filepath"
	"testing"
)

// #5841 split the single per-account provenance marker into THREE UID-file
// roots: the account/enumeration registry (provisioned-users, unchanged) plus
// two resource-specific roots — provisioned-passwords (gates the password lock)
// and provisioned-keys (gates authorized_keys removal). The factory-reset login
// teardown (zeroizeLoginAccounts) originally enumerated ONLY provisioned-users,
// so the two new roots SURVIVED a zeroize. That is a re-tenant leak twice over:
//
//   - Residue: prior-tenant username→UID mappings persist on a "factory-reset"
//     box (the #5869/#5871 residue class).
//   - Overclaim resurrected: UID reuse is the useradd default (first non-system
//     user = 1000). A new tenancy's account reusing a surviving marker's
//     (name, UID) is enumerated by reconcileAbsentLoginUsers — which unions all
//     three roots — and deprovisionLoginUser then finds passwordProvisioned /
//     keyProvisioned TRUE and LOCKS the new operator's password + DELETES their
//     authorized_keys despite xpf never provisioning it — the exact overclaim
//     #5841 exists to kill.
//
// TestZeroizeLoginAccountsErasesAllThreeMarkerRoots seeds a fully-provisioned
// account with a marker in ALL THREE roots and asserts every one is gone after
// the teardown.
//
// RED on revert: neutralizing the single resource-marker removal in
// zeroizeSweepResourceMarkerRoot — `fail(os.Remove(filepath.Join(dir, name)))`
// — leaves the provisioned-passwords/alice and provisioned-keys/alice markers
// (and their root dirs) behind, so the two assertAbsent checks on those markers
// go RED. The provisioned-users marker is removed by the registry loop
// regardless, and no other test seeds the resource roots (their sweep
// ReadDir returns ErrNotExist and stops before the removal line), so exactly
// this test fails — target count 1.
func TestZeroizeLoginAccountsErasesAllThreeMarkerRoots(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	pwDir := filepath.Join(root, "provisioned-passwords")
	keyDir := filepath.Join(root, "provisioned-keys")
	shellDir := filepath.Join(root, "provisioned-shells")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// alice is a fully-provisioned xpf account: a real password apply writes the
	// registry + password markers, a real key apply writes the key marker. She is
	// live in /etc/passwd at the marker UID with an xpf-written authorized_keys.
	mustWriteFile(t, passwdPath, []byte("alice:x:1001:1001:alice:/home/alice:/bin/bash\n"))

	usersMarker := filepath.Join(provDir, "alice")
	pwMarker := filepath.Join(pwDir, "alice")
	keyMarker := filepath.Join(keyDir, "alice")
	shellMarker := filepath.Join(shellDir, "alice")
	mustWriteFile(t, usersMarker, []byte("1001"))
	mustWriteFile(t, pwMarker, []byte("1001"))
	mustWriteFile(t, keyMarker, []byte("1001"))
	mustWriteFile(t, shellMarker, []byte("1001"))

	aliceKeys := filepath.Join(homeBase, "alice", ".ssh", "authorized_keys")
	mustWriteFile(t, aliceKeys, []byte("ssh-ed25519 AAAAxpf alice\n"))

	// setZeroizeLoginPaths points zeroizeProvisionedUsersDir at provDir; the two
	// resource roots are computed as its siblings (zeroizeProvisionedPasswordsDir
	// / zeroizeProvisionedKeysDir), so this single seam relocates all three roots
	// under the throwaway tree together.
	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := zeroizeLoginAccounts(); err != nil {
		t.Fatalf("zeroizeLoginAccounts returned error: %v", err)
	}

	// Sanity: the registry teardown ran (userdel fired for the live account), so
	// this is a SUCCESSFUL teardown — alice is not on the fail-closed retain path
	// that would legitimately keep her markers.
	if len(*deleted) != 1 || (*deleted)[0] != "alice" {
		t.Fatalf("userdel invoked for %v, want exactly [alice]", *deleted)
	}

	// The #5841 fix: NO per-account marker survives in ANY of the three roots.
	// The two resource-root assertions are the ones that go RED without the
	// resource-root sweep.
	assertAbsent(t, usersMarker)
	assertAbsent(t, pwMarker)  // RED on revert of the resource-root sweep
	assertAbsent(t, keyMarker) // RED on revert of the resource-root sweep
	assertAbsent(t, shellMarker)

	// The now-empty root directories are cleaned up (all roots).
	assertAbsent(t, provDir)
	assertAbsent(t, pwDir)  // RED on revert of the resource-root sweep
	assertAbsent(t, keyDir) // RED on revert of the resource-root sweep
	assertAbsent(t, shellDir)
}
