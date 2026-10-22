package factoryreset

import (
	"path/filepath"
	"testing"
)

// #6190: a KEY-ONLY account's xpf-written authorized_keys survived a factory
// reset. The factory-reset login teardown (wipeLoginAccounts) removes
// authorized_keys only for accounts in the provisioned-users REGISTRY. But a
// pre-existing (operator / prior-tenant) account configured with `system login
// user <name> authentication ssh-*` and NO encrypted-password gets a
// provisioned-keys marker and NO registry marker (applySystemLogin writes
// markProvisioned only in the useradd branch; reconcileUserPassword only on a
// password apply). Such a KEY-ONLY account is never iterated by the registry
// loop, so before #6190 the #6183 fix correctly swept its keys MARKER but the
// actual xpf-written authorized_keys FILE was never removed — the prior tenant
// retained SSH login on that account after a "factory reset" (the #4598
// credential-leak class). This is ASYMMETRIC with the day-2 path
// (reconcileAbsentLoginUsers enumerates the UNION provisionedNames() and
// deprovisionLoginUser DOES remove that key file).
//
// The fix (wipeSweepProvisionedKeys) removes the xpf-written key FILE for
// every account with a provisioned-keys marker (union enumeration), UID-gated
// and fail-closed, while preserving the retained-set (#6183) semantics and never
// touching an operator's own (unmarked) key file.

// TestZeroizeRemovesKeyOnlyAccountAuthorizedKeys pins the #6190 fix: a live
// key-only account (provisioned-keys marker + xpf-written authorized_keys, NO
// registry/password marker) has BOTH its marker AND its authorized_keys removed
// by the factory-reset teardown, while a NON-provisioned operator account's own
// key file (no marker) is left untouched. No userdel fires — xpf only added a
// key, it did not create the account.
//
// RED on revert of the #6190 key-file-removal binding (clean assertion failures,
// no compile break). The key removal now lives in the shared
// wipeRemoveKeyFileThenMarker helper (#6201):
//
//   - Surgical: make the helper's `os.Remove(keysFile)` a no-op (e.g. replace it
//     with `keyErr := error(nil)`). It still compiles; the keyonly marker is
//     still swept, but the xpf-written authorized_keys FILE SURVIVES, so
//     `assertAbsent(keyonlyKeys)` here goes RED (the canonical #6190 pin). The
//     #6201 retain tests also trip, since a no-op removal leaves keyErr nil and
//     the marker is dropped on the failing-key accounts they seed.
//   - Broad: revert the phase-(C) keys-root sweep call in wipeLoginAccounts
//     from `wipeSweepProvisionedKeys(...)` back to
//     `wipeSweepResourceMarkerRoot(wipeProvisionedKeysDir(), retained,
//     fail)` (the marker-only sweep). The key file is never touched (survives)
//     AND the UID-gated fail-closed retention is dropped, so this test,
//     TestZeroizeKeyOnlyRetainedAndMismatchPreserveKeys, and the #6201 retain
//     tests all go RED.
//
// The #6201 retain-on-error binding (the marker is RETAINED on a real key-removal
// error) has its own tests below — TestZeroizeKeyOnlyRetainsMarkerOnKeyRemovalError
// and TestZeroizeKeyOnlyOrphanRetainsMarkerOnKeyRemovalError — whose neutralization
// (revert the helper's marker gate to an unconditional `fail(os.Remove(markerFile))`)
// leaves this happy-path test unaffected.
func TestZeroizeRemovesKeyOnlyAccountAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	keyDir := filepath.Join(root, "provisioned-keys")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// /etc/passwd: the key-only account (live at UID 1500) + an operator's OWN
	// account (no marker of any kind).
	mustWriteFile(t, passwdPath, []byte(
		"keyonly:x:1500:1500:keyonly:/home/keyonly:/bin/bash\n"+
			"operator:x:1000:1000:operator:/home/operator:/bin/bash\n"))

	// KEY-ONLY provenance: a provisioned-keys marker ONLY (no provisioned-users
	// registry marker, no provisioned-passwords marker) — exactly what a
	// `ssh-*`-only `system login user` produces on a pre-existing account.
	keyonlyMarker := filepath.Join(keyDir, "keyonly")
	mustWriteFile(t, keyonlyMarker, []byte("1500"))

	// The xpf-written authorized_keys for the key-only account — the artifact the
	// registry-only teardown misses (the leak).
	keyonlyKeys := filepath.Join(homeBase, "keyonly", ".ssh", "authorized_keys")
	mustWriteFile(t, keyonlyKeys, []byte("ssh-ed25519 AAAAxpf keyonly\n"))

	// An operator's OWN authorized_keys with NO marker in any root — xpf never
	// wrote it, so it MUST survive (the core "only what xpf wrote" invariant).
	operatorKeys := filepath.Join(homeBase, "operator", ".ssh", "authorized_keys")
	mustWriteFile(t, operatorKeys, []byte("ssh-ed25519 AAAAop operator\n"))

	// setZeroizeLoginPaths points wipeProvisionedUsersDir at provDir; the two
	// resource roots are computed as its siblings, so this single seam relocates
	// all three roots (incl. keyDir) under the throwaway tree together.
	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err != nil {
		t.Fatalf("wipeLoginAccounts returned error: %v", err)
	}

	// No userdel: xpf did not create the account, it only added a key. (Mirrors
	// deprovisionLoginUser where ownsAccount=false → no userdel.)
	if len(*deleted) != 0 {
		t.Errorf("userdel invoked %v for a key-only account; want none (xpf only added a key)", *deleted)
	}

	// The #6190 fix: the xpf-written key file AND its marker are gone.
	assertAbsent(t, keyonlyKeys)   // RED on revert of the key-file removal
	assertAbsent(t, keyonlyMarker) // marker swept (already worked pre-#6190)
	assertAbsent(t, keyDir)        // now-empty keys root dropped

	// Safety: the operator's own (unmarked) key file is untouched.
	assertPresent(t, operatorKeys)
}

// TestZeroizeKeyOnlyRetainedAndMismatchPreserveKeys pins the two non-destructive
// paths of the #6190 sweep, so a key file is only ever removed for the exact
// account xpf wrote it for:
//
//   - Retained-set preservation (#6183): an account whose REGISTRY teardown is
//     RETAINED for a fail-closed retry keeps ALL its state consistent — its keys
//     marker AND its key file are left untouched by the keys sweep. Here `retain`
//     has a registry marker whose recorded UID (3000) mismatches its live UID
//     (3001), so the registry teardown reports the anomaly and retains its
//     markers; the keys sweep must then skip it entirely.
//   - UID-mismatch operator-key protection: `stalekey` is a KEY-ONLY account
//     whose keys marker (2000) mismatches its live UID (2001) — an out-of-band
//     userdel+recreate. Its current authorized_keys belongs to SOMEONE ELSE, so
//     the sweep must leave the file AND retain the marker rather than delete an
//     operator's keys.
//
// wipeLoginAccounts returns a non-nil error (both are surfaced fail-closed
// conditions), which is the expected outcome — the point of this test is the
// non-destructive preservation, not a clean reset.
func TestZeroizeKeyOnlyRetainedAndMismatchPreserveKeys(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	keyDir := filepath.Join(root, "provisioned-keys")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// retain: registry marker UID 3000 but live UID 3001 (out-of-band recreate) →
	// registry teardown retains. It also carries a keys marker + a key file.
	// stalekey: KEY-ONLY, keys marker UID 2000 but live UID 2001 (recreate).
	mustWriteFile(t, passwdPath, []byte(
		"retain:x:3001:3001:retain:/home/retain:/bin/bash\n"+
			"stalekey:x:2001:2001:stalekey:/home/stalekey:/bin/bash\n"))

	retainUsersMarker := filepath.Join(provDir, "retain")
	retainKeyMarker := filepath.Join(keyDir, "retain")
	mustWriteFile(t, retainUsersMarker, []byte("3000")) // != live 3001 → retained
	mustWriteFile(t, retainKeyMarker, []byte("3000"))
	retainKeys := filepath.Join(homeBase, "retain", ".ssh", "authorized_keys")
	mustWriteFile(t, retainKeys, []byte("ssh-ed25519 AAAAnew retain-newowner\n"))

	stalekeyMarker := filepath.Join(keyDir, "stalekey")
	mustWriteFile(t, stalekeyMarker, []byte("2000")) // != live 2001 → mismatch
	stalekeyKeys := filepath.Join(homeBase, "stalekey", ".ssh", "authorized_keys")
	mustWriteFile(t, stalekeyKeys, []byte("ssh-ed25519 AAAAnew stalekey-newowner\n"))

	_ = setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts with retained + UID-mismatch key markers returned nil; want the unresolved conditions surfaced")
	}

	// Retained account (registry teardown kept): key marker AND key file preserved
	// so the account's markers stay together for a retry.
	assertPresent(t, retainUsersMarker)
	assertPresent(t, retainKeyMarker) // keys sweep skipped it (retained)
	assertPresent(t, retainKeys)      // someone else's recreated home — untouched

	// UID-mismatch key-only account: the recreated owner's keys and the marker are
	// left intact (never delete an operator's keys).
	assertPresent(t, stalekeyKeys)
	assertPresent(t, stalekeyMarker)
}

// TestZeroizeKeyOnlyRetainsMarkerOnKeyRemovalError pins the #6201 retain-on-error
// gap in the proven-owned (default) branch of wipeSweepProvisionedKeys. A
// key-only account is PROVEN-OWNED (live /etc/passwd UID == keys-marker UID), so
// the sweep tries to remove its xpf-written authorized_keys and then drop the
// keys marker. If the key removal hits a REAL error (an immutable file, an
// ENOTDIR/ENOTEMPTY path shape, an I/O error) the key SURVIVES. The marker must
// then be RETAINED — mirroring the day-2 deprovisionLoginUser contract, which
// KEEPS the provenance markers and retries on a real authorized_keys removal
// error — so a retried factory reset re-enumerates the account (the keys marker
// is what makes a key-only account discoverable) and re-attempts the removal.
// Dropping the marker while the key file survives would strand the prior tenant's
// SSH key with no retry evidence, and unlike the account-registry teardown there
// is no `userdel -r` backstop that would delete the whole home tree.
//
// The removal error is constructed WITHOUT root by making the authorized_keys
// PATH a non-empty DIRECTORY: os.Remove on a non-empty directory returns
// ENOTEMPTY, a real (non-ErrNotExist) error, so the retain-on-error gate fires.
//
// RED on revert: change wipeRemoveKeyFileThenMarker's gated marker removal
// back to the unconditional `fail(os.Remove(markerFile))`. The key removal still
// fails (surfaced), but the marker is then dropped anyway, so
// `assertPresent(keyonlyMarker)` here goes RED. The #6190 happy-path test
// (successful key removal, keyErr == nil) is UNAFFECTED — the gate only diverges
// on the key-removal failure path.
func TestZeroizeKeyOnlyRetainsMarkerOnKeyRemovalError(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	keyDir := filepath.Join(root, "provisioned-keys")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// Proven-owned key-only account: live at UID 1500, keys marker records 1500,
	// NO registry / password marker → the default (UID-match) branch of the sweep.
	mustWriteFile(t, passwdPath, []byte(
		"keyonly:x:1500:1500:keyonly:/home/keyonly:/bin/bash\n"))
	keyonlyMarker := filepath.Join(keyDir, "keyonly")
	mustWriteFile(t, keyonlyMarker, []byte("1500"))

	// Make authorized_keys a NON-EMPTY DIRECTORY so os.Remove(keysFile) fails with
	// ENOTEMPTY — a real, non-ErrNotExist key-removal error, no root required.
	keyonlyKeys := filepath.Join(homeBase, "keyonly", ".ssh", "authorized_keys")
	mustWriteFile(t, filepath.Join(keyonlyKeys, "sentinel"), []byte("blocks os.Remove\n"))

	_ = setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	// The reset is reported INCOMPLETE: the key-removal error is surfaced.
	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts returned nil despite an unremovable key file; want the key-removal error surfaced")
	}

	// The #6201 fix: the key marker is RETAINED (still present) so a retried reset
	// re-enumerates this account. Before the fix the marker was dropped even though
	// the key file survived, losing the retry evidence.
	assertPresent(t, keyonlyMarker) // RED on revert of the retain-on-error gate
	assertPresent(t, keyonlyKeys)   // the surviving (unremovable) key dir
}

// TestZeroizeKeyOnlyOrphanRetainsMarkerOnKeyRemovalError pins the SAME
// retain-on-error contract in the genuinely-absent (!curFound) branch of
// wipeSweepProvisionedKeys. Here the account is gone from /etc/passwd (an
// out-of-band userdel) but an xpf-written authorized_keys residue and its keys
// marker remain. The sweep removes the orphaned residue and drops the stale
// marker — but ONLY when the residue removal succeeded. On a real removal error
// the residue SURVIVES (a prior-tenant key still on disk), so the marker is
// RETAINED so a retried reset re-attempts, exactly as in the proven-owned branch.
//
// RED on revert: same neutralization as the proven-owned test — revert
// wipeRemoveKeyFileThenMarker's gated marker removal to unconditional. The
// orphan residue removal fails (surfaced), the marker is dropped anyway, and
// `assertPresent(orphanMarker)` goes RED.
func TestZeroizeKeyOnlyOrphanRetainsMarkerOnKeyRemovalError(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	keyDir := filepath.Join(root, "provisioned-keys")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// /etc/passwd is READABLE but does NOT contain "orphan": the account is
	// genuinely absent (curFound=false, lookupErr=nil) → the !curFound branch.
	mustWriteFile(t, passwdPath, []byte(
		"someoneelse:x:1000:1000:someoneelse:/home/someoneelse:/bin/bash\n"))

	// Orphaned keys marker + xpf-written key residue for the absent account.
	orphanMarker := filepath.Join(keyDir, "orphan")
	mustWriteFile(t, orphanMarker, []byte("1600"))

	// Residue authorized_keys as a NON-EMPTY DIRECTORY → os.Remove fails ENOTEMPTY.
	orphanKeys := filepath.Join(homeBase, "orphan", ".ssh", "authorized_keys")
	mustWriteFile(t, filepath.Join(orphanKeys, "sentinel"), []byte("blocks os.Remove\n"))

	_ = setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts returned nil despite an unremovable orphan key residue; want the removal error surfaced")
	}

	// The marker is RETAINED so the surviving orphan residue is re-attempted.
	assertPresent(t, orphanMarker) // RED on revert of the retain-on-error gate
	assertPresent(t, orphanKeys)   // the surviving (unremovable) residue dir
}
