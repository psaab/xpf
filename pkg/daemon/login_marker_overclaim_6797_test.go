package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6797: ownership markers are written marker-first (#5841) and were never
// withdrawn when the credential mutation they claimed then FAILED.
//
// The severity lives in the CONSUMER, not in the write. These markers do not
// gate a write — they gate a REVOCATION: the key marker gates
// `os.Remove(authorized_keys)` and the password marker gates the declarative D2
// lock. So a marker that outlives a failed mutation does not lose something xpf
// owns; it makes xpf later DELETE an operator's pre-existing key file, or LOCK
// an account whose password xpf never set.
//
// The fix is not to reverse the ordering — that reinstates #5841's underclaim
// (a mutated-but-unmarked credential xpf can no longer revoke). It is to make
// the claim undoable: withdraw a claim THIS pass created, preserve one an
// earlier apply legitimately made.

// breakSSHDir makes name's home a regular FILE, so MkdirAllDurable on
// <home>/.ssh fails with ENOTDIR — a real, deterministic key-write failure that
// needs no seam.
func breakSSHDir(t *testing.T, name string) {
	t.Helper()
	home := filepath.Dir(filepath.Dir(managedAuthorizedKeysPath(name)))
	if err := os.MkdirAll(filepath.Dir(home), 0o755); err != nil {
		t.Fatal(err)
	}
	// Replace whatever is there (an existing home directory from a prior
	// phase) with a regular file.
	if err := os.RemoveAll(home); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFailedKeyWriteDoesNotClaimOperatorKeys is the fail-on-revert gate, run as
// the full consequence chain rather than a marker assertion alone: a failed key
// write must not leave a claim, AND the operator's pre-existing key file must
// survive the later revocation that claim would have authorised.
//
// FAIL-ON-REVERT: remove the keyClaim.rollback() calls in applySystemLogin and
// phase 1 goes RED (a marker is left over a key file xpf never wrote); phase 2
// then shows what that costs — carol's operator-installed authorized_keys is
// deleted.
func TestFailedKeyWriteDoesNotClaimOperatorKeys_6797(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "carol", 1003)

	// Phase 1: carol is configured WITH an SSH key, but the key write cannot
	// succeed. xpf must not end up claiming her key file.
	breakSSHDir(t, "carol")

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    "carol",
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAA carol-from-config"},
	}))

	if ownedKey(t, "carol", 1003) {
		t.Fatalf("a FAILED authorized_keys write left a key-ownership marker "+
			"(%s). xpf now claims a key file it never wrote, and the emptied-key "+
			"reconcile will delete the operator's own (#6797)",
			markerPathIn(provisionedKeysDir(), "carol"))
	}

	// Phase 2: the consequence. Repair the home dir, install the operator's own
	// authorized_keys, and remove the key directive from config. The emptied-key
	// reconcile must leave the operator's file alone, because xpf never
	// successfully wrote one.
	home := filepath.Dir(filepath.Dir(keysFile))
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	const operatorKey = "ssh-ed25519 AAAA carol-operator-installed\n"
	if err := os.WriteFile(keysFile, []byte(operatorKey), 0o600); err != nil {
		t.Fatal(err)
	}

	d.applySystemLogin(loginCfg(&config.LoginUser{Name: "carol", Class: "operator"}))

	got, err := os.ReadFile(keysFile)
	if err != nil {
		t.Fatalf("operator authorized_keys was REMOVED after a key write that "+
			"never succeeded (err=%v) — xpf revoked a credential it does not "+
			"own (#6797)", err)
	}
	if string(got) != operatorKey {
		t.Errorf("operator authorized_keys content changed: %q", string(got))
	}
}

// TestPreExistingKeyClaimSurvivesAFailedRewrite is the TIGHTENING control, and
// the reason the fix withdraws only claims THIS pass created.
//
// xpf legitimately wrote carol's keys on an earlier apply, so the key marker is
// real and the key file is xpf-owned. A later apply whose rewrite FAILS must
// NOT withdraw that claim: doing so would orphan a key file xpf really does own
// — #5841's underclaim, reintroduced by an over-eager rollback. A rollback that
// fired unconditionally would pass the test above and fail this one.
func TestPreExistingKeyClaimSurvivesAFailedRewrite_6797(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "dave", 1004)

	// An earlier apply wrote dave's keys: real marker, xpf-owned key file.
	if err := markKeyProvisioned("dave", 1004); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA dave-from-xpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ownedKey(t, "dave", 1004) {
		t.Fatal("test setup: dave should start with a genuine key claim")
	}

	// Now a rewrite that cannot succeed.
	breakSSHDir(t, "dave")

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    "dave",
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAA dave-rotated"},
	}))

	if !ownedKey(t, "dave", 1004) {
		t.Fatal("a failed REWRITE withdrew a key claim an earlier apply " +
			"legitimately made; xpf can no longer revoke a key file it owns — " +
			"the #5841 underclaim, reintroduced (#6797)")
	}
}

// TestOwnershipClaimRollbackSemantics pins the helper directly: a claim this
// pass created is withdrawable, a pre-existing one is not. Unit-level so the
// two branches are exercised in isolation from the apply path.
func TestOwnershipClaimRollbackSemantics_6797(t *testing.T) {
	dir := t.TempDir()

	// New claim → rollback removes it.
	fresh, err := claimOwnership(dir, "erin", 1005)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedMarker(t, dir, "erin", 1005) {
		t.Fatal("claimOwnership did not write the marker")
	}
	if fresh.preExisting {
		t.Error("a first-time claim must not report preExisting")
	}
	fresh.rollback()
	if ownedMarker(t, dir, "erin", 1005) {
		t.Error("rollback did not withdraw a claim created by this pass")
	}

	// Pre-existing claim → rollback is a no-op.
	if err := writeProvenanceMarker(dir, "frank", 1006); err != nil {
		t.Fatal(err)
	}
	again, err := claimOwnership(dir, "frank", 1006)
	if err != nil {
		t.Fatal(err)
	}
	if !again.preExisting {
		t.Error("a re-claim of an already-owned credential must report preExisting")
	}
	again.rollback()
	if !ownedMarker(t, dir, "frank", 1006) {
		t.Error("rollback withdrew a pre-existing claim; that orphans a " +
			"credential xpf really owns (#5841 underclaim)")
	}

	// A marker recorded for a DIFFERENT uid is not this account's prior
	// ownership, so the claim counts as new and is withdrawable.
	if err := writeProvenanceMarker(dir, "gina", 999); err != nil {
		t.Fatal(err)
	}
	stale, err := claimOwnership(dir, "gina", 1007)
	if err != nil {
		t.Fatal(err)
	}
	if stale.preExisting {
		t.Error("a marker for a different UID must not count as prior ownership")
	}
	stale.rollback()
	if ownedMarker(t, dir, "gina", 1007) {
		t.Error("rollback did not withdraw a claim over a UID-mismatched marker")
	}
}

// breakKeyFileWrite lets the .ssh DIRECTORY be created normally but makes the
// authorized_keys write itself fail: the target path is a DIRECTORY, so
// WriteFileDurable's rename over it fails.
//
// This is a distinct branch from breakSSHDir. applySystemLogin rolls the claim
// back at BOTH the mkdir failure and the write failure, and a fixture that only
// ever fails at mkdir leaves the write-failure rollback mutation-invisible —
// measured: deleting it left the suite green.
func breakKeyFileWrite(t *testing.T, keysFile string) {
	t.Helper()
	if err := os.MkdirAll(keysFile, 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestFailedKeyFileWriteDoesNotClaim covers the WRITE-failure branch of the
// user key path (breakSSHDir above covers the mkdir branch).
//
// FAIL-ON-REVERT: remove the keyClaim.rollback() at the WriteFileDurable
// failure and this reds.
func TestFailedKeyFileWriteDoesNotClaim_6797(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "helen", 1008)
	breakKeyFileWrite(t, keysFile)

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    "helen",
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAA helen-from-config"},
	}))

	if ownedKey(t, "helen", 1008) {
		t.Fatalf("a FAILED authorized_keys WRITE left a key-ownership marker; " +
			"the mkdir-failure rollback is not enough on its own (#6797)")
	}
}

// TestFailedRootKeyWriteDoesNotClaim covers the ROOT key path, which has its
// own marker-first block and its own rollback.
//
// Root is the highest-consequence case: a stale root key claim authorises
// removing /root/.ssh/authorized_keys, and if that file is the operator's own
// out-of-band root key, revoking it can lock them out of the box entirely.
//
// FAIL-ON-REVERT: remove the rootKeyClaim.rollback() at the root
// WriteFileDurable failure and this reds.
func TestFailedRootKeyWriteDoesNotClaim_6797(t *testing.T) {
	_, rootKeys := stageRootAuthEnv(t, "*")

	// The .ssh dir creates fine; the key file path is a DIRECTORY so the write
	// fails at the rename.
	if err := os.MkdirAll(rootKeys, 0o700); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	_ = d.applyRootAuth(rootAuthCfg("", "ssh-ed25519 AAAAROOT root@host"))

	if ownedKey(t, "root", 0) {
		t.Fatalf("a FAILED root authorized_keys write left a key-ownership " +
			"marker; a later empty key list would then remove root's key file " +
			"— including an operator-installed one (#6797)")
	}
}

// installFailingChpasswd puts a chpasswd on PATH that always exits non-zero,
// so the user-password apply reaches its failure branch. The user key/password
// fixtures stub runCommandTimeout, but chpasswd goes through
// runCommandStdinTimeout, which execs the real binary from PATH.
func installFailingChpasswd(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	script := "#!/bin/sh\ncat >/dev/null\necho 'chpasswd: refused' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
}

// TestFailedChpasswdDoesNotClaimPassword covers the PASSWORD path, whose
// consumer is the declarative D2 lock rather than a file removal.
//
// The chain: an operator already has their own password on the account, the
// config adds an encrypted-password directive, chpasswd FAILS, and the marker
// persists. When the directive is later removed, the D2 branch reads that
// marker as proof xpf set the password and LOCKS the account — an operator
// locked out of a password xpf never set.
//
// FAIL-ON-REVERT: remove the pwClaim/acctClaim rollbacks at the chpasswd
// failure and this reds.
func TestFailedChpasswdDoesNotClaimPassword_6797(t *testing.T) {
	stageEmptiedKeysEnv(t, "ivan", 1009)
	installFailingChpasswd(t)

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:              "ivan",
		Class:             "operator",
		EncryptedPassword: config.NewSecret("$6$salt$xpfhash"),
	}))

	if ownedPassword(t, "ivan", 1009) {
		t.Errorf("a FAILED chpasswd left a password-ownership marker; removing " +
			"the directive later would LOCK an account whose password xpf " +
			"never set (#6797)")
	}
	if ownedAccount(t, "ivan", 1009) {
		t.Errorf("a FAILED chpasswd left an account-registry marker; xpf claims " +
			"to manage an account it never provisioned (#6797)")
	}
}

// TestPreExistingPasswordClaimSurvivesAFailedChpasswd is the password-side
// TIGHTENING control, mirroring the key-side one: a claim an EARLIER apply
// legitimately made must survive a later failed chpasswd, or xpf loses the
// ability to D2-lock a password it really did set.
func TestPreExistingPasswordClaimSurvivesAFailedChpasswd_6797(t *testing.T) {
	stageEmptiedKeysEnv(t, "judy", 1010)
	installFailingChpasswd(t)

	// An earlier apply set judy's password.
	if err := markPasswordProvisioned("judy", 1010); err != nil {
		t.Fatal(err)
	}
	if err := markProvisioned("judy", 1010); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:              "judy",
		Class:             "operator",
		EncryptedPassword: config.NewSecret("$6$salt$rotated"),
	}))

	if !ownedPassword(t, "judy", 1010) {
		t.Error("a failed password ROTATION withdrew a claim an earlier apply " +
			"legitimately made; xpf can no longer lock a password it set — the " +
			"#5841 underclaim, reintroduced (#6797)")
	}
}

// TestFailedRootSSHDirDoesNotClaim covers the root MKDIR-failure branch, which
// is a separate rollback site from the root write-failure branch above.
//
// FAIL-ON-REVERT: remove the rootKeyClaim/rootAcctClaim rollbacks at the
// MkdirAllDurable failure and this reds.
func TestFailedRootSSHDirDoesNotClaim_6797(t *testing.T) {
	stageRootAuthEnv(t, "*")

	// rootSSHDir itself is a regular FILE, so MkdirAllDurable fails.
	if err := os.WriteFile(rootSSHDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	_ = d.applyRootAuth(rootAuthCfg("", "ssh-ed25519 AAAAROOT root@host"))

	if ownedKey(t, "root", 0) {
		t.Errorf("a FAILED /root/.ssh creation left a root key-ownership " +
			"marker (#6797)")
	}
	if ownedAccount(t, "root", 0) {
		t.Errorf("a FAILED /root/.ssh creation left a root account-registry " +
			"marker (#6797)")
	}
}

// TestAccountMarkerFailureWithdrawsThePasswordClaim covers the rollback that
// fires when the SECOND claim of a pair cannot be recorded.
//
// The password claim succeeds, the account-registry claim then fails, and the
// apply gives up before chpasswd. The password claim must be withdrawn: no
// mutation happened, so nothing may be left asserting xpf set this password.
//
// FAIL-ON-REVERT: remove the pwClaim.rollback() in the account-marker failure
// branch and this reds.
func TestAccountMarkerFailureWithdrawsThePasswordClaim_6797(t *testing.T) {
	stageEmptiedKeysEnv(t, "karl", 1011)

	// The password marker root works; the ACCOUNT registry root is a regular
	// FILE, so its MkdirAllDurable fails.
	if err := os.WriteFile(provisionedUsersDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:              "karl",
		Class:             "operator",
		EncryptedPassword: config.NewSecret("$6$salt$xpfhash"),
	}))

	if ownedPassword(t, "karl", 1011) {
		t.Errorf("the password claim survived an aborted apply: the account " +
			"marker could not be written, so chpasswd never ran, yet xpf still " +
			"claims to own this password (#6797)")
	}
}
