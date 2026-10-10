// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// login_password.go implements the `system login user <name> authentication
// encrypted-password` apply + declarative-reconciliation lifecycle (#1944).
//
// The OS-account password for a configured non-root user must reach
// /etc/shadow so the operator can log in on the serial console (SSH has the
// authorized_keys path; the console has nothing without a password). This
// mirrors applyRootAuth's `chpasswd -e` idiom, adds idempotency by reading
// /etc/shadow directly, and — when the directive is REMOVED from config —
// locks the account (Path D2) instead of orphaning a live credential, but
// ONLY for accounts xpf actually provisioned, identified by a UID-keyed
// provenance marker.

// pwAction is the decision a pure helper makes about whether to (re)apply,
// lock, or leave a user's password alone on a config apply.
type pwAction int

const (
	pwNoop  pwAction = iota // leave /etc/shadow as-is
	pwApply                 // write `desired` via chpasswd -e
	pwLock                  // lock the account via chpasswd -e (<user>:!)
)

// provisionedUsersDir holds one marker file per xpf-provisioned account — the
// account/enumeration REGISTRY: which OS accounts xpf manages at all. The
// marker's CONTENT is the numeric UID of the account at the time xpf created
// it or set its password. Keying provenance by UID (not name alone) lets
// removing a directive act on the SAME account (leave-then-rejoin: UID
// unchanged → fires) while leaving an out-of-band userdel+recreate alone (new
// UID → marker mismatch → skip), with no separate garbage-collection pass.
// /var/lib/xpf is persistent (it holds the config DB + archive). #1944 §5.4.
//
// #5841 — resource-specific ownership. A single account marker conflated
// password ownership with SSH-key ownership, so setting only a user's password
// could cause the emptied-key / deprovision reconcilers to clobber an
// operator-installed authorized_keys xpf never wrote (overclaim), while a
// best-effort marker write that failed AFTER a successful credential mutation
// left a credential xpf could no longer lock/clean (underclaim). Ownership is
// now tracked per RESOURCE in sibling directories, each holding a UID marker
// with the SAME format as the account registry:
//
//   - provisionedPasswordsDir()  "xpf set this account's /etc/shadow password"
//   - provisionedKeysDir()       "xpf wrote this account's authorized_keys"
//
// The resource markers are written BEFORE their credential mutation
// (marker-first atomicity, fail-visible) and gate the corresponding REVOCATION;
// the account registry is unchanged in format and location so the factory-reset
// teardown (pkg/grpcapi zeroize) that enumerates it is untouched.
//
// #6797 — marker-first alone OVERCLAIMS. Because the markers gate a REVOCATION
// rather than a write, a marker that outlives a FAILED mutation does not lose
// something of ours, it deletes an operator's pre-existing authorized_keys or
// locks an account whose password xpf never set. The apply path therefore
// claims ownership through claimOwnership/rollback, which withdraws a claim
// THIS pass created when the mutation fails while preserving one an earlier
// apply legitimately made.
var provisionedUsersDir = "/var/lib/xpf/provisioned-users"

// provisionedPasswordsDir and provisionedKeysDir are the resource-specific
// ownership marker roots, kept as SIBLINGS of provisionedUsersDir so overriding
// provisionedUsersDir in a test relocates all three marker roots together
// (there is exactly one seam to point at a throwaway tree). In production they
// are /var/lib/xpf/provisioned-passwords and /var/lib/xpf/provisioned-keys.
// #5841.
func provisionedPasswordsDir() string {
	return filepath.Join(filepath.Dir(provisionedUsersDir), "provisioned-passwords")
}

func provisionedKeysDir() string {
	return filepath.Join(filepath.Dir(provisionedUsersDir), "provisioned-keys")
}

// shadowPath and passwdPath are the OS account databases the password
// reconciler reads directly. They are package vars only so tests can
// inject sample files; production never overrides them.
var (
	shadowPath = "/etc/shadow"
	passwdPath = "/etc/passwd"
)

// passwordAction is PURE and table-tested. It is the central safety
// invariant of #1944:
//   - Fail-OPEN toward applying a real password: on any shadow read error /
//     missing entry / mismatch, (re)apply, so a first commit never silently
//     skips the password.
//   - Fail-CLOSED (noop) in the lock branch on a read error, so a transient
//     /etc/shadow read failure can NEVER lock out an operator.
//
// cur is the current shadow password field; ok is whether it was read
// successfully; desired is the configured encrypted-password ("" when the
// directive is absent).
func passwordAction(cur string, ok bool, desired string) pwAction {
	if desired != "" {
		if !ok || cur != desired {
			return pwApply // apply on read-fail / miss / mismatch (fail-open)
		}
		return pwNoop
	}
	// desired == "": Path D2 declarative lock.
	if !ok {
		return pwNoop // never lock on a read error
	}
	if isLockedShadow(cur) {
		return pwNoop // already locked
	}
	return pwLock // empty (passwordless) OR a usable hash → lock
}

// isLockedShadow reports whether a /etc/shadow password field is in a
// locked state. A bare "*" or any field beginning with "!" ("!", "!!",
// "!$6$...") is locked. An EMPTY field is passwordless (`passwd -d`) — the
// MOST permissive state, NOT locked — so D2 must lock it. #1944 §5.4.
func isLockedShadow(s string) bool {
	return s == "*" || strings.HasPrefix(s, "!")
}

// currentShadowHash reads /etc/shadow DIRECTLY (the daemon runs as root) and
// returns the password field (field 2) for name, plus ok. It returns
// ("", false) on any read/parse error or if the user is absent. A direct
// read is used in preference to `getent shadow`, which shells out and is
// subject to nscd/NSS caching → stale reads. #1944 §5.4.
func currentShadowHash(name string) (string, bool) {
	data, err := os.ReadFile(shadowPath)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == name {
			return fields[1], true
		}
	}
	return "", false
}

// lookupUIDGIDErr parses /etc/passwd for name, distinguishing the THREE
// outcomes a fail-closed caller must tell apart. /etc/passwd field 2 is the
// UID, field 3 is the primary GID. It is cgo-free (consistent with
// currentShadowHash — the codebase deliberately avoids os/user to stay free
// of cgo/nsswitch):
//
//   - (uid, gid, true,  nil): name found.
//   - (0,   0,   false, nil): passwd READ OK, name genuinely ABSENT — a real
//     out-of-band userdel. This is the only outcome that proves the account
//     is gone.
//   - (0,   0,   false, err): passwd could NOT be read/parsed — a transient
//     mount/permission/I/O error, or a malformed entry FOR name. The identity
//     database is UNKNOWN, NOT proven absent.
//
// The err return is what lets a fail-CLOSED caller (deprovisionLoginUser,
// #5493) tell a genuine account deletion from a transient /etc/passwd read
// failure. lookupUID/lookupUIDGID collapse both negatives into ok=false,
// which is safe for callers that merely skip-and-retry on the next apply, but
// is a fail-OPEN hazard for deprovisionLoginUser: there a read error would be
// indistinguishable from deletion, so the caller would drop the provenance
// marker and abandon revocation of a removed user's still-live credentials
// once passwd became readable again. A malformed entry for the EXACT name is
// reported as an error (unknown), never as genuine absence — never abandon
// revocation on a corrupt identity DB.
func lookupUIDGIDErr(name string) (uid, gid int, found bool, err error) {
	data, rerr := os.ReadFile(passwdPath)
	if rerr != nil {
		return 0, 0, false, rerr
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] == name {
			u, uerr := strconv.Atoi(fields[2])
			g, gerr := strconv.Atoi(fields[3])
			if uerr != nil || gerr != nil {
				return 0, 0, false, fmt.Errorf("passwd: unparseable uid/gid for %q", name)
			}
			return u, g, true, nil
		}
	}
	return 0, 0, false, nil
}

// lookupUIDGID returns the numeric UID and GID for name by parsing
// /etc/passwd directly. It returns (uid, gid, true) on success, (0, 0, false)
// if absent OR unreadable OR unparseable — the two-state convenience contract
// kept for callers that skip-and-retry on any negative (a transient read
// error simply defers their work to the next apply, retaining state). Callers
// that must NOT treat "unreadable" as "absent" use lookupUIDGIDErr /
// lookupUIDErr instead.
//
// fsatomic.WithOwner uses this so a DurableState authorized_keys write
// installs the file already owned by the target user/group at rename
// time — no post-rename chown race that could leave root-owned keys.
func lookupUIDGID(name string) (uid, gid int, ok bool) {
	u, g, found, err := lookupUIDGIDErr(name)
	return u, g, found && err == nil
}

// lookupUID returns the numeric UID for name (the GID-less convenience
// wrapper over lookupUIDGID, kept for existing callers).
func lookupUID(name string) (int, bool) {
	uid, _, ok := lookupUIDGID(name)
	return uid, ok
}

// lookupUIDErr is the 3-state, error-returning counterpart of lookupUID for
// fail-CLOSED callers that must distinguish a transient /etc/passwd read
// failure (unknown → retain state, retry) from a genuine account absence
// (proven gone → safe to forget). See lookupUIDGIDErr. #5493.
func lookupUIDErr(name string) (uid int, found bool, err error) {
	u, _, found, err := lookupUIDGIDErr(name)
	return u, found, err
}

// markerPathIn returns the provenance marker file path for name inside dir.
// names are validated OS usernames here (created via useradd), but the name is
// reduced defensively so a marker can never escape the directory.
//
// Clean+Base alone did NOT deliver that (#7171). Base(Clean(x)) keeps a bare
// traversal element -- Base(Clean("..")) is ".." -- so Join(dir, "..") yielded
// dir's PARENT, and Base(Clean(".")) / Base(Clean("/")) yielded dir ITSELF.
// The latter matters as much as the escape: the deprovision path calls
// os.Remove on this result, so a name of "." aimed a remove at the whole
// provenance registry directory rather than at one marker inside it.
//
// The old containment test could not see any of this: every input it sampled
// ("../../etc/shadow", "/etc/passwd", "a/b/c") ends in a real component, so
// Base returns "shadow"/"passwd"/"c" and containment holds under any
// implementation. Those inputs cannot distinguish a correct reduction from a
// broken one; only a name that cleans to a bare traversal element can.
func markerPathIn(dir, name string) string {
	base := filepath.Base(filepath.Clean(name))
	switch base {
	case ".", "..", string(filepath.Separator):
		// A name that reduces to a traversal element is not a username and
		// must not address dir or anything above it. Map it to a single
		// reserved, contained filename: two such names colliding is
		// irrelevant (neither is a legal account), whereas either escaping
		// is not. Containment is now true by construction rather than by
		// the caller happening to pass a well-formed name.
		base = "_invalid-name"
	}
	return filepath.Join(dir, base)
}

// markerPath is markerPathIn for the account/enumeration registry. Kept as the
// name existing callers (and the zeroize-parity doc) reference.
func markerPath(name string) string {
	return markerPathIn(provisionedUsersDir, name)
}

// writeProvenanceMarker is the atomic primitive behind every ownership marker:
// it records name's current UID in dir durably. Callers write the marker
// BEFORE mutating the corresponding credential (marker-first) so a marker-write
// failure can never leave a mutated-but-unmarked credential — the #5841
// underclaim. A failure is RETURNED (fail-visible), never swallowed.
func writeProvenanceMarker(dir, name string, uid int) error {
	// DurableState: the marker must survive a power cut so a post-reboot
	// declarative lock/revoke can still identify what xpf provisioned
	// (#1944 §5.4). MkdirAllDurable persists the directory entry itself, not
	// just the file's entry within it.
	if err := fsatomic.MkdirAllDurable(dir, 0o700); err != nil {
		return err
	}
	return fsatomic.WriteFileDurable(markerPathIn(dir, name), []byte(strconv.Itoa(uid)), 0o600)
}

// readProvenanceMarker reports whether dir records name as xpf-owned for the
// account that currently has UID curUID. It reports true ONLY if the marker
// exists AND its recorded UID equals curUID. A marker whose UID no longer
// matches (account deleted/recreated out of band with a different UID) or is
// corrupt is opportunistically removed — no separate GC pass — and reports
// false, so a revoke decision never touches an out-of-band account. #1944 §5.4.
//
// #6798: it carries the ABSENT/UNREADABLE distinction a bare bool cannot. It
// replaced a bool-only hasProvenanceMarker that collapsed EVERY os.ReadFile
// error — ENOENT, EACCES, EIO, ENOTDIR — into the same `false`. A genuinely
// ABSENT marker proves the resource is not xpf's (owned false, err nil); an
// UNREADABLE one proves NOTHING, yet produced the identical `false`, and every
// revocation gate read that false as "not ours, skip". The credential then
// survived a deprovision that reported success.
//
// The returned ownership stays FALSE on a read error, deliberately: the caller
// must not revoke a credential it cannot prove it owns — that is #6797's
// overclaim from the other direction. What changes is that the caller can now
// tell "proven not ours" from "could not tell" and report the latter instead of
// converging on it. There is deliberately NO bool-only wrapper: one would
// reintroduce the exact collapse this closes.
func readProvenanceMarker(dir, name string, curUID int) (bool, error) {
	path := markerPathIn(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // genuinely not ours
		}
		return false, fmt.Errorf("read ownership marker %s: %w", path, err)
	}
	recorded, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		// Corrupt marker — treat as not-ours and clean it up. This IS a
		// determination (the bytes were read; they are not a UID), so it is not
		// an unreadable-inventory error.
		_ = os.Remove(path)
		return false, nil
	}
	if recorded != curUID {
		// Stale marker for a different (recreated) account: clean inline.
		_ = os.Remove(path)
		return false, nil
	}
	return true, nil
}

// ownershipClaim records a marker-first ownership claim so a FAILED credential
// mutation can undo it (#6797).
//
// #5841 writes the resource marker BEFORE the mutation it claims, deliberately:
// a marker written afterwards can fail after the credential has already
// changed, leaving a live credential xpf can no longer lock or clean (the
// UNDERCLAIM). But marker-first has the mirror hazard — if the mutation then
// fails, the marker outlives it and asserts ownership of a credential xpf never
// wrote (the OVERCLAIM). That is worse than it sounds, because the markers do
// not gate a WRITE, they gate a REVOCATION: the key marker gates
// `os.Remove(authorized_keys)` and the password marker gates the declarative
// D2 lock. A stale claim therefore does not lose something of ours — it DELETES
// an operator's pre-existing key file, or locks an account whose password xpf
// never set.
//
// Reversing the order would just trade one for the other. The fix is to make
// the claim undoable: remember whether the marker ALREADY recorded this exact
// account, and on mutation failure remove it only if THIS pass created it. A
// pre-existing genuine claim is preserved (no new underclaim); a claim invented
// moments ago by a mutation that then failed is withdrawn.
type ownershipClaim struct {
	dir, name string
	// preExisting is true when the marker already recorded this UID before the
	// claim, i.e. an earlier apply legitimately owned the credential. Its
	// rollback is a no-op — withdrawing it would orphan a credential xpf really
	// does own.
	preExisting bool
}

// claimOwnership records name's UID in dir and returns a claim that can be
// rolled back. The write error is returned unchanged so every existing
// fail-visible caller keeps its behaviour.
func claimOwnership(dir, name string, uid int) (ownershipClaim, error) {
	// readProvenanceMarker's inline cleanup of a mismatched/corrupt marker is
	// harmless here: such a marker is not this account's prior ownership, so
	// preExisting=false is the correct reading and the write below replaces it.
	//
	// #6798: an UNREADABLE marker is treated as PRE-EXISTING, not absent. The
	// only thing preExisting gates is rollback(), which REMOVES the marker —
	// i.e. it releases ownership. "Only proven absence may release ownership
	// work": if we cannot read the marker we cannot prove xpf did not already
	// own this credential, and withdrawing a real marker orphans a live
	// credential xpf can then never lock or revoke (the #5841 underclaim).
	// Erring toward preExisting=true costs at most a stale marker, which the
	// next apply re-reads and reconciles.
	owned, readErr := readProvenanceMarker(dir, name, uid)
	if readErr != nil {
		slog.Warn("cannot read ownership marker before claiming it; treating "+
			"as pre-existing so a failed mutation does not withdraw a claim "+
			"xpf may already hold", "dir", dir, "name", name, "err", readErr)
		owned = true
	}
	c := ownershipClaim{dir: dir, name: name, preExisting: owned}
	return c, writeProvenanceMarker(dir, name, uid)
}

// rollback withdraws a claim this pass created, after the credential mutation
// it was claiming has FAILED. It is a no-op for a claim that already existed.
//
// Best-effort by construction: the alternative to a failed removal is leaving
// the overclaim in place, which is what this exists to prevent, and the caller
// is already reporting the mutation failure that triggered it.
func (c ownershipClaim) rollback() {
	if c.preExisting || c.dir == "" {
		return
	}
	if err := removeProvenanceMarker(c.dir, c.name); err != nil {
		slog.Warn("could not withdraw ownership marker after a failed credential "+
			"mutation; xpf may later revoke a credential it does not own",
			"dir", c.dir, "name", c.name, "err", err)
	}
}

// removeProvenanceMarker drops name's marker in dir (ENOENT is not an error).
func removeProvenanceMarker(dir, name string) error {
	if err := os.Remove(markerPathIn(dir, name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// forgetProvenance drops name's markers across ALL three ownership roots — the
// account registry and both resource roots — once every xpf-owned resource for
// the account has been revoked (deprovision) or the account is proven gone.
// It joins any per-root removal error (ENOENT excluded by removeProvenanceMarker)
// so a caller that must know whether the reconcile fully converged (the #5874
// cancel closeout) can observe a marker that could not be cleaned. #5841.
func forgetProvenance(name string) error {
	return errors.Join(
		removeProvenanceMarker(provisionedUsersDir, name),
		removeProvenanceMarker(provisionedPasswordsDir(), name),
		removeProvenanceMarker(provisionedKeysDir(), name),
	)
}

// --- account/enumeration registry (which accounts xpf manages) -------------

// markProvisioned records that xpf manages this account by writing the
// account's current UID into the per-user registry marker. Called on a
// successful useradd AND on a successful pwApply / root key apply, so the
// account is enumerated by reconcileAbsentLoginUsers and the factory-reset
// teardown. #1944 §5.4.
func markProvisioned(name string, uid int) error {
	return writeProvenanceMarker(provisionedUsersDir, name, uid)
}

// xpfProvisioned reports whether the account registry records name for UID
// curUID (marker present AND UID matches; a mismatch/corrupt marker is cleaned
// inline). #1944 §5.4.
func xpfProvisioned(name string, curUID int) (bool, error) {
	return readProvenanceMarker(provisionedUsersDir, name, curUID)
}

// --- password-ownership marker (xpf set the /etc/shadow password) ----------

// markPasswordProvisioned records that xpf set name's /etc/shadow password,
// gating the declarative D2 password lock (#5841).
//
// The PRODUCTION apply path does not call this directly — it goes through
// claimOwnership(provisionedPasswordsDir(), ...) so a chpasswd that then fails
// can withdraw the claim (#6797). This remains the plain write primitive, used
// by tests to seed "xpf already owns this" fixtures.
func markPasswordProvisioned(name string, uid int) error {
	return writeProvenanceMarker(provisionedPasswordsDir(), name, uid)
}

// passwordProvisioned reports whether xpf set name's password for UID curUID.
// #5841.
func passwordProvisioned(name string, curUID int) (bool, error) {
	return readProvenanceMarker(provisionedPasswordsDir(), name, curUID)
}

// --- SSH-key-ownership marker (xpf wrote authorized_keys) ------------------

// markKeyProvisioned records that xpf wrote name's authorized_keys, gating the
// key-file removal on directive/user removal so an operator-installed key file
// xpf never wrote is left untouched (#5841).
//
// The PRODUCTION apply path does not call this directly — it goes through
// claimOwnership(provisionedKeysDir(), ...) so a key write that then fails can
// withdraw the claim (#6797). This remains the plain write primitive, used by
// tests to seed "xpf already owns this" fixtures.
func markKeyProvisioned(name string, uid int) error {
	return writeProvenanceMarker(provisionedKeysDir(), name, uid)
}

// keyProvisioned reports whether xpf wrote name's authorized_keys for UID
// curUID. #5841.
func keyProvisioned(name string, curUID int) (bool, error) {
	return readProvenanceMarker(provisionedKeysDir(), name, curUID)
}

// provisionedNames returns the UNION of account names that appear in any of the
// three ownership roots — the set of accounts xpf provisioned some resource
// for. reconcileAbsentLoginUsers deprovisions each name in this set that is no
// longer in config, so a pre-existing account xpf only added an SSH key to
// (key marker, no account registry entry) is still revoked when removed. #5841.
func provisionedNames() (map[string]struct{}, error) {
	var readErr error
	out := make(map[string]struct{})
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// #6798: an ABSENT root is legitimately empty — a fresh install has
			// provisioned nothing, so it contributes no names and that is a
			// determination. An UNREADABLE root contributes no names either,
			// but that is not the same fact: the inventory is INCOMPLETE, and
			// silently truncating it makes the revocation sweep skip accounts
			// whose only marker lived there. Report it; keep sweeping the roots
			// that DO read, because revoking what we can see is strictly better
			// than revoking nothing.
			if !os.IsNotExist(err) {
				readErr = errors.Join(readErr, fmt.Errorf(
					"read ownership inventory %s: %w", dir, err))
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			out[e.Name()] = struct{}{}
		}
	}
	return out, readErr
}

// homeBaseDir is the parent directory of per-user home directories. It is a
// package var only so tests can point the authorized_keys reconcile at a
// throwaway tree; production never overrides it. #5128.
var homeBaseDir = "/home"

// rootSSHDir is the root account's .ssh directory. It is a package var only so
// tests can point the root authorized_keys reconcile at a throwaway tree;
// production never overrides it. It is the root-account analogue of homeBaseDir
// for the #5276 root-credential revocation lifecycle.
var rootSSHDir = "/root/.ssh"

// rootAuthorizedKeysPath returns the xpf-managed root authorized_keys file.
// applyRootAuth writes /root/.ssh/authorized_keys wholesale from the configured
// root-authentication SSHKeys, so the whole file is xpf-owned. Revocation
// removes it to disable key-based root login, gated on the UID-keyed provenance
// marker (name "root", UID 0) so an operator-installed key file xpf never wrote
// is left untouched — the same provenance scoping the non-root
// managedAuthorizedKeysPath removal uses. #5276.
func rootAuthorizedKeysPath() string {
	return filepath.Join(rootSSHDir, "authorized_keys")
}

// managedAuthorizedKeysPath returns the xpf-managed authorized_keys file for
// name. applySystemLogin writes /home/<name>/.ssh/authorized_keys wholesale
// from the configured SSHKeys, so the whole file is xpf-owned. Two reconciles
// remove it to revoke key-based login: the absent-user reconcile when the user
// is deleted from config (#5128), and applySystemLogin's own empty-key-list
// branch when a RETAINED user's last key is removed from config (#5106).
// filepath.Base(Clean(...)) keeps the join inside homeBaseDir defensively
// (names reaching here are validated OS usernames, but never trust a name for
// a root-privileged removal). #5128.
func managedAuthorizedKeysPath(name string) string {
	return filepath.Join(homeBaseDir, filepath.Base(filepath.Clean(name)), ".ssh", "authorized_keys")
}

// reconcileAbsentLoginUsers revokes the host credentials of every
// xpf-provisioned login account that is NO LONGER present in
// cfg.System.Login.Users (#5128). Declarative removal of a `system login user`
// must revoke that user's host access — Junos semantics — not merely drop the
// sudo grant (reconcileSudoers) while leaving the account, password, and
// authorized_keys live.
//
// It is the removal half of the #1944 UID-keyed provenance lifecycle and the
// mirror of reconcileSudoers: it MUST run unconditionally on every apply
// (independent of applySystemLogin's early return) so the "all users removed"
// case still revokes. It enumerates the UNION of the three ownership roots
// (provisionedNames) — every account xpf provisioned any resource for — and
// deprovisions each name that no longer appears in the config. An out-of-band
// account (no marker in any root) is never enumerated and never touched. #5841.
//
// It stays best-effort per account but ACCUMULATES each deprovision failure
// into the returned error so the #5874 cancel closeout can see that a removed
// user's credentials were NOT actually revoked (a monotonic-revocation gap).
// #6790: the NORMAL apply path joins this return into the commit result as
// well. `delete system login user bob` acknowledged as SUCCESS while bob's
// password and authorized_keys are still live is the exact failure this
// reconciler exists to prevent, and nothing retries before the next boot.
func (d *Daemon) reconcileAbsentLoginUsers(cfg *config.Config) (retErr error) {
	// #6798: an unreadable inventory root is NOT "nothing provisioned". The
	// previous form collapsed both into len(names)==0 and returned nil —
	// SUCCESS — so a removed operator kept their password and authorized_keys
	// while the reconcile reported convergence, and the #5874 closeout (which
	// exists to catch exactly this class) saw nothing to report. Surface the
	// read failure and still revoke every account the readable roots DID name.
	names, invErr := provisionedNames()
	if invErr != nil {
		slog.Error("ownership inventory could not be fully read; a removed "+
			"account's credentials may NOT have been revoked",
			"err", invErr)
		retErr = errors.Join(retErr, invErr)
	}

	// The set of usernames still declared in config; these are kept.
	desired := make(map[string]struct{})
	if cfg.System.Login != nil {
		for _, u := range cfg.System.Login.Users {
			if u.Name == "" {
				continue
			}
			desired[u.Name] = struct{}{}
		}
	}

	for name := range names {
		if name == "root" {
			continue // root is never provisioned/deprovisioned via config
		}
		if _, keep := desired[name]; keep {
			continue // still configured — leave it alone
		}
		retErr = errors.Join(retErr, d.deprovisionLoginUser(name))
	}
	return retErr
}

// deprovisionLoginUser revokes one removed account's xpf-owned credentials,
// each gated on its OWN resource marker so xpf only ever locks a password it
// set and only ever removes an authorized_keys it wrote — never an
// operator-managed credential it did not provision (#5841). Once every owned
// resource is revoked it drops all provenance markers so xpf forgets the
// account. It is fail-closed toward retry: any step that cannot be completed
// safely leaves the markers in place so the next apply retries. #5128.
//
// It stays best-effort but ACCUMULATES each failure into the returned error so
// the #5874 cancel closeout can observe that a removed account's credentials
// were NOT actually revoked; a naked return yields the accumulated retErr, not
// a block-local err. Since #6790 the normal apply path joins it into the
// commit result too, so a failed revocation fails the commit.
func (d *Daemon) deprovisionLoginUser(name string) (retErr error) {
	fail := func(e error) { retErr = errors.Join(retErr, e) }
	curUID, found, err := lookupUIDErr(name)
	if err != nil {
		// /etc/passwd could not be READ (transient mount/permission/I/O
		// error) — the identity database is UNKNOWN, NOT proof the account is
		// gone. Fail CLOSED: keep the provenance markers and revocation intent,
		// retry next apply. Dropping a marker here — as the old lookupUID
		// bool contract silently did on any read error — would PERMANENTLY
		// abandon revocation: once passwd is readable again the account is no
		// longer enumerated (marker gone), so the removed user's password and
		// keys would stay live forever (#5493). This mirrors the
		// currentShadowHash fail-closed discipline below: identity-database
		// uncertainty is "unknown → retry", never "absent → abandon".
		slog.Warn("skipping removed-user deprovision: cannot read passwd",
			"user", name, "err", err)
		// Fail-visible: an unread identity DB means the removed account's
		// credential may still be live and was NOT revoked. The naked return
		// yields the accumulated retErr, not the block-local err above.
		fail(fmt.Errorf("read passwd for removed user %s: %w", name, err))
		return // keep markers; retry next apply
	}
	if !found {
		// passwd READ OK and name genuinely ABSENT — there is nothing to
		// revoke. A concurrent commit may be creating this same live account,
		// so fence marker cleanup too and converge the re-presented account.
		if _, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired {
			if live := d.liveConfig12169(); live != nil {
				fail(d.applySystemLogin(live))
			}
			return retErr
		}
		_ = forgetProvenance(name)
		if _, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired {
			staleRevocationSuperseded12169("restore-user-after-marker-cleanup", name)
			if live := d.liveConfig12169(); live != nil {
				fail(d.applySystemLogin(live))
			}
		}
		return retErr
	}

	// Resolve per-resource ownership for the account CURRENTLY at curUID. Each
	// check cleans a UID-mismatched/corrupt marker inline (out-of-band
	// recreate), so a false here also means "not ours".
	ownsPassword, pwErr := passwordProvisioned(name, curUID)
	ownsKey, keyErr := keyProvisioned(name, curUID)
	ownsAccount, acctErr := xpfProvisioned(name, curUID)
	if ownErr := errors.Join(pwErr, keyErr, acctErr); ownErr != nil {
		// #6798: a marker that could not be READ proves nothing. Before this,
		// all three reads failing produced three falses, matched the
		// "nothing owned" branch below, and returned nil — SUCCESS — leaving
		// the removed account's password and authorized_keys live. Keep the
		// markers (so the next apply retries) and report, WITHOUT revoking:
		// acting on unproven ownership is #6797's overclaim from the other
		// side.
		slog.Error("cannot determine credential ownership for a removed login "+
			"user; NOT revoking, and NOT reporting convergence",
			"user", name, "err", ownErr)
		fail(fmt.Errorf("determine ownership for removed user %s: %w", name, ownErr))
		return retErr
	}
	if !ownsPassword && !ownsKey && !ownsAccount {
		// Nothing xpf-owned for the current account (markers absent, or a UID
		// mismatch already cleaned inline). NEVER touch a non-xpf / out-of-band
		// account.
		return nil
	}

	// The timed-out first-commit closeout owner can resume after a later
	// commit has promoted the same account. Re-read the live intent before
	// revoking and after the blocking chpasswd operation: if the live config
	// owns this account, keep/re-apply its password and retain its markers.
	liveUser, liveDesired := d.liveDesiredLoginUser12169(name)
	if ownsPassword {
		cur, ok := currentShadowHash(name)
		if !ok {
			slog.Warn("skipping removed-user deprovision: cannot read shadow",
				"user", name)
			fail(fmt.Errorf("read shadow for removed user %s", name))
			return // keep markers; retry next apply
		}
		if liveDesired && liveUser.EncryptedPassword.Reveal() != "" {
			staleRevocationSuperseded12169("lock-password", name)
			if err := d.reconcileUserPassword(&liveUser); err != nil {
				fail(err)
				return // keep every marker until live password converges
			}
		} else if !isLockedShadow(cur) {
			// Re-read directly at the mutation boundary: promotion may have
			// happened while ownership and shadow state were being checked.
			if current, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired &&
				current.EncryptedPassword.Reveal() != "" {
				staleRevocationSuperseded12169("lock-password", name)
				if err := d.reconcileUserPassword(&current); err != nil {
					fail(err)
					return
				}
				liveUser, liveDesired = current, true
			} else {
				stdin := strings.NewReader(name + ":!\n")
				out, lockErr := runCommandStdinTimeout(stdin, "chpasswd", "-e")
				if lockErr != nil {
					slog.Warn("failed to lock password for removed login user",
						"user", name, "err", lockErr, "output", strings.TrimSpace(string(out)))
					fail(fmt.Errorf("lock password for removed user %s: %w", name, lockErr))
				} else {
					slog.Info("locked password for removed login user", "user", name)
				}

				// chpasswd may have changed shadow before returning an error,
				// or may have been blocked across a later promotion. Repair the
				// live password on every exit before marker cleanup or return.
				if current, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired &&
					current.EncryptedPassword.Reveal() != "" {
					staleRevocationSuperseded12169("repair-password", name)
					if err := d.reconcileUserPassword(&current); err != nil {
						fail(err)
						return
					}
					liveUser, liveDesired = current, true
				}
				if lockErr != nil {
					return // retain markers; the attempted revocation failed
				}
			}
		}
	}

	// Remove the xpf-managed authorized_keys ONLY if xpf wrote it. A later
	// commit may have re-presented the user and its keys while this owner was
	// blocked in chpasswd; skip those keys, or restore them before completion
	// if the promotion raced the unlink.
	if ownsKey {
		keysFile := managedAuthorizedKeysPath(name)
		// Refresh immediately before unlinking; a password operation above
		// may have blocked while a commit re-presented this account.
		liveUser, liveDesired = d.liveDesiredLoginUser12169(name)
		if liveDesired && len(liveUser.SSHKeys) > 0 {
			staleRevocationSuperseded12169("remove-user-keys", name)
		} else if err := os.Remove(keysFile); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove authorized_keys for removed login user",
				"user", name, "file", keysFile, "err", err)
			fail(fmt.Errorf("remove authorized_keys for removed user %s: %w", name, err))
			return // keep markers; retry
		} else {
			// The promotion can land between the intent check and unlink.
			// Re-run the live login reconciler on that rare stale path before
			// allowing this owner to complete.
			if current, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired &&
				len(current.SSHKeys) > 0 {
				staleRevocationSuperseded12169("repair-user-keys", name)
				if live := d.liveConfig12169(); live != nil {
					if err := d.applySystemLogin(live); err != nil {
						fail(err)
						return
					}
				}
				liveUser, liveDesired = current, true
			} else if err := removeProvenanceMarker(provisionedKeysDir(), name); err != nil {
				fail(err)
				return
			}
		}
	}

	// A re-presented login remains xpf-owned. Keep account/password markers
	// so later removals still have the provenance needed to revoke it; only a
	// now-empty key list drops the independent key marker.
	if _, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired {
		// A promotion can race marker cleanup after the credential checks.
		// Re-apply the whole live login state so a credential and its
		// provenance are restored together before this owner returns.
		if live := d.liveConfig12169(); live != nil {
			fail(d.applySystemLogin(live))
		}
		return retErr
	}

	// Fully revoked — drop every provenance marker so xpf no longer manages
	// this account. If the same user is later re-added, applySystemLogin
	// recreates it and re-records the markers.
	fail(forgetProvenance(name))
	if _, stillDesired := d.liveDesiredLoginUser12169(name); stillDesired {
		staleRevocationSuperseded12169("restore-user-after-marker-cleanup", name)
		if live := d.liveConfig12169(); live != nil {
			fail(d.applySystemLogin(live))
		}
		return retErr
	}
	slog.Info("deprovisioned removed login user",
		"user", name, "password_locked", ownsPassword, "keys_removed", ownsKey)
	return retErr
}
