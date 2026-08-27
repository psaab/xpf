package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// HOST-AUTHORIZATION reconcilers, split out of daemon_system.go (#6880).
//
// The seam is an ERROR CONTRACT, not a line count. daemon_system.go held two
// categories of `system { }` handler with opposite contracts:
//
//   - BEST-EFFORT host settings — hostname, timezone, NTP, kernel tuning,
//     syslog, the aggregator. These return NOTHING. A failure is logged and the
//     apply continues, deliberately: a bad timezone must not fail a commit.
//   - HOST-AUTHORIZATION reconcilers — login accounts, sudoers, sshd, root
//     auth. Every one returns an error, and those errors are load-bearing.
//     `hostAuthCloseoutOwners` (daemon_apply_hostauth.go) runs them as a named,
//     ordered owner set under a wall-clock budget, and #5874 exists precisely
//     because five of these had their failures DISCARDED — a cancel closeout
//     that reported clean while credentials had not converged.
//
// Mixing the two in one 2597-line file made the contract invisible at the point
// where it matters most: when adding a handler, or converting an existing one,
// nothing in the surrounding code says which category it joins. That is the
// same shape as the #5874 defect rather than a stylistic preference, which is
// why this split is worth making beyond the audit tier.
//
// The cluster was already named by the codebase — `hostAuthOwner`,
// `hostAuthCloseoutOwners` — and already had its own orchestration file. Only
// the implementations were left behind. This completes a seam the codebase had
// drawn, rather than inventing one to reach a line target.
//
// What stays in daemon_system.go: every handler whose failure is intentionally
// swallowed, plus `applySSHKnownHosts` — SSH-named, but not a
// `hostAuthCloseoutOwners` member and returning nothing, so it belongs with the
// best-effort set by the cluster's own definition.
//
// Pure code motion: no signature, body or behaviour changed.

// applySystemLogin creates OS user accounts and SSH authorized_keys from
// system { login { user ... } } configuration.
// applySystemLogin reconciles OS login accounts (create/password/SSH keys)
// from config. It stays best-effort — a per-user failure is logged and the
// loop continues to the next user — but it now also ACCUMULATES those
// failures into the returned error so a caller that needs to know whether the
// reconcile actually converged (the #5874 cancel closeout) can see them.
// #6790: the NORMAL apply path now joins this return into the commit result
// too — a commit that could not create the account or install its
// authorized_keys must not report success. Pure defensive skips (an invalid
// username refused before any mutation) are NOT accumulated — they are the
// safe outcome, not an incomplete reconcile.
func (d *Daemon) applySystemLogin(cfg *config.Config) (err error) {
	fail := func(e error) { err = errors.Join(err, e) }
	if cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		return nil
	}

	for _, user := range cfg.System.Login.Users {
		if user.Name == "" || user.Name == "root" {
			continue // never create/modify root via config
		}

		// #5005 defense in depth: never format an unvalidated username into a
		// root-privileged id/useradd/chown invocation. The strict commit-check
		// rejects a crafted name (schema keyValidator, ValidateLoginUsername),
		// but the tolerant load / peer-sync path downgrades that to a warning
		// (#1960), so a leading-dash or otherwise unsafe name can still reach
		// here. Skip it entirely — the same doctrine the sudoers writer already
		// applies (reconcileSudoers/writeSudoersGrant, #4895). Combined with the
		// `--` end-of-options separators below, this fails closed against option
		// injection into the account/SSH-key writer.
		if err := config.ValidateLoginUsername(user.Name, nil); err != nil {
			slog.Warn("refusing to provision invalid login user name",
				"user", user.Name, "err", err)
			continue
		}

		// Check if user already exists. A non-zero exit means "user
		// doesn't exist"; a timeout also lands here, in which case the
		// useradd below fails with "already exists" and is logged. The `--`
		// stops id treating a name as an option (#5005).
		_, err := runCommandTimeout("id", "--", user.Name)
		if err != nil {
			// User doesn't exist — create it
			args := []string{"-m", "-s", "/bin/bash"}
			if user.UID > 0 {
				args = append(args, "-u", fmt.Sprintf("%d", user.UID))
			}
			// `--` before the operand so a name is never parsed as a useradd
			// option (#5005 option-injection defense).
			args = append(args, "--", user.Name)
			if out, err := runCommandTimeout("useradd", args...); err != nil {
				slog.Warn("failed to create user",
					"user", user.Name, "err", err, "output", string(out))
				fail(fmt.Errorf("create user %s: %w", user.Name, err))
				continue
			}
			slog.Info("created system user", "user", user.Name, "uid", user.UID)
			// Record provenance keyed by the account's actual UID so a
			// later directive removal can lock THIS exact account (D2),
			// while an out-of-band userdel+recreate with a different UID
			// is left untouched (#1944 §5.4).
			if uid, ok := lookupUID(user.Name); ok {
				if err := markProvisioned(user.Name, uid); err != nil {
					slog.Warn("failed to write provisioned-user marker",
						"user", user.Name, "err", err)
					fail(fmt.Errorf("mark provisioned %s: %w", user.Name, err))
				}
			}
		}

		// Apply / lock the login password (#1944). Mirrors applyRootAuth's
		// `chpasswd -e` idiom; idempotent via a direct /etc/shadow read;
		// D2-locks the account when the directive is removed but ONLY for
		// the exact xpf-provisioned account (UID-keyed marker).
		fail(d.reconcileUserPassword(user))

		// Super-user sudo grants are reconciled separately by
		// reconcileSudoers so that a class DOWNGRADE or full user removal
		// REVOKES the stale NOPASSWD grant. reconcileSudoers must run even
		// when this per-user loop is skipped (Login nil / no users), which
		// is exactly the "user removed from config" case (#3889).

		// Set SSH authorized keys. An EMPTY configured key list takes the else
		// branch below and REVOKES any xpf-managed authorized_keys (#5106).
		if len(user.SSHKeys) > 0 {
			// Derive the .ssh dir from the SAME homeBaseDir seam the emptied-key
			// removal branch below uses (managedAuthorizedKeysPath), so the key
			// WRITE and the key REMOVE resolve the same path by construction
			// instead of via two independent expressions. In production
			// homeBaseDir is "/home", so this is byte-identical to the previous
			// fmt.Sprintf("/home/%s", user.Name); the seam only lets a test point
			// the home base at a throwaway tree to exercise this branch — and its
			// chown `--` guard below — hermetically (#5026).
			sshDir := filepath.Dir(managedAuthorizedKeysPath(user.Name))

			// Resolve the owner FIRST (cgo-free /etc/passwd parse). The user
			// was created above, so it resolves. If it does not, abort the
			// whole keys block (retried next apply) rather than installing
			// anything root-owned that sshd would refuse (#1916 D7).
			uid, gid, ok := lookupUIDGID(user.Name)
			if !ok {
				slog.Warn("could not resolve uid/gid for authorized_keys owner; skipping to avoid a root-owned-keys lockout window",
					"user", user.Name)
				fail(fmt.Errorf("resolve uid/gid for authorized_keys owner %s", user.Name))
				continue
			}

			// #5841 marker-first: record SSH-KEY ownership BEFORE writing
			// authorized_keys. This is a DISTINCT marker from the
			// password/account markers, so setting only a password never claims
			// the key file — the emptied-key / deprovision reconcilers only
			// remove a key file this marker proves xpf wrote. Written
			// unconditionally (idempotent) so an upgrade that already has
			// xpf-written keys but no key marker gains one on the next apply.
			// Fail VISIBLE: if the durable marker cannot be written, skip the
			// key write and retry next apply rather than leave a
			// written-but-unmarked key grant (the underclaim).
			// #6797: hold the claim so a FAILED key write can withdraw it. The
			// key marker gates os.Remove(authorized_keys) below, so a marker
			// left behind by a write that never happened makes a later
			// directive removal delete an operator's pre-existing key file.
			keyClaim, err := claimOwnership(provisionedKeysDir(), user.Name, uid)
			if err != nil {
				slog.Warn("skipping authorized_keys apply: cannot record key ownership marker",
					"user", user.Name, "err", err)
				// Fail-visible for the #5874 closeout: the key write was skipped,
				// so this user's SSH keys did NOT converge to the desired state.
				fail(fmt.Errorf("mark key provisioned %s: %w", user.Name, err))
				continue
			}

			// MkdirAllDurable (not plain MkdirAll): authorized_keys is a
			// DurableState file written into this dir; WriteFileDurable
			// persists the file's entry in .ssh, not .ssh's own entry in
			// its parent, so a power cut could otherwise drop the
			// just-created .ssh directory (Codex r1, fsatomic README).
			if err := fsatomic.MkdirAllDurable(sshDir, 0700); err != nil {
				slog.Warn("failed to create .ssh dir", "user", user.Name, "dir", sshDir, "err", err)
				keyClaim.rollback() // #6797: no key file was written
				fail(fmt.Errorf("create .ssh dir for %s: %w", user.Name, err))
				continue
			}
			// Chown the .ssh DIR to the user UNCONDITIONALLY (idempotent),
			// not only when the key content changes. MkdirAllDurable creates
			// it root-owned; if this chown ran only inside the content-changed
			// branch, a crash between the durable key write and the chown
			// would leave a durable root-owned .ssh that, since the key
			// content then matches on reboot, the whole block (and the chown)
			// would skip forever — never repairing the dir owner (Codex r2
			// HIGH). Running it every apply closes that window.
			// `--` stops chown parsing "-name:-name" as options (#5005).
			if out, err := runCommandTimeout("chown", "-R", "--", user.Name+":"+user.Name, sshDir); err != nil {
				slog.Warn("failed to chown ssh dir",
					"user", user.Name, "dir", sshDir,
					"err", err, "output", strings.TrimSpace(string(out)))
				fail(fmt.Errorf("chown .ssh dir for %s: %w", user.Name, err))
			}

			keysContent := strings.Join(user.SSHKeys, "\n") + "\n"
			keysFile := sshDir + "/authorized_keys"
			current, _ := os.ReadFile(keysFile)
			if string(current) != keysContent {
				// DurableState authorized_keys: SSH access must survive a
				// power cut. WriteFileDurable replaces the inode with a
				// root-owned temp; WithOwner chowns the temp fd BEFORE the
				// rename so the file is correctly-owned at install time —
				// closing the crash window that would otherwise leave
				// root-owned 0600 keys sshd refuses (EACCES → lockout).
				if err := fsatomic.WriteFileDurable(keysFile, []byte(keysContent), 0600, fsatomic.WithOwner(uid, gid)); err != nil {
					slog.Warn("failed to write authorized_keys",
						"user", user.Name, "err", err)
					keyClaim.rollback() // #6797: the key file was not written
					fail(fmt.Errorf("write authorized_keys for %s: %w", user.Name, err))
					continue
				}
				slog.Info("SSH keys updated", "user", user.Name, "keys", len(user.SSHKeys))
			}
		} else {
			// Empty key list on a RETAINED user: reconcile the xpf-managed
			// authorized_keys to ABSENT so removing the last key from config
			// actually revokes key-based login. Without this the stale key file
			// a prior apply wrote keeps granting access — reconcileAbsentLogin-
			// Users only covers a fully REMOVED user, not a retained user whose
			// key list was emptied (#5106). Gate on the UID-keyed provenance
			// marker (as deprovisionLoginUser does) so we only ever remove an
			// authorized_keys file xpf itself wrote — never a pre-existing /
			// out-of-band user's operator-installed keys. The whole file is
			// xpf-owned when the marker matches (applySystemLogin writes it
			// wholesale), so removing it is safe. Gated on the KEY marker
			// (#5841): a user whose PASSWORD xpf set but whose keys it never
			// wrote has no key marker, so an operator-installed authorized_keys
			// is left untouched (the overclaim this closes).
			uid, uidOK := lookupUID(user.Name)
			ownsKeys, ownErr := false, error(nil)
			if uidOK {
				ownsKeys, ownErr = keyProvisioned(user.Name, uid)
			}
			if ownErr != nil {
				// #6798: an unreadable key marker proves nothing. Do NOT remove
				// the file (that would revoke on unproven ownership), but do not
				// report convergence either — the emptied key list has NOT been
				// honoured, and the next apply retries.
				slog.Error("cannot determine SSH-key ownership; NOT revoking keys "+
					"and NOT reporting convergence", "user", user.Name, "err", ownErr)
				fail(fmt.Errorf("determine key ownership for %s: %w", user.Name, ownErr))
			}
			if uidOK && ownsKeys {
				keysFile := managedAuthorizedKeysPath(user.Name)
				switch err := os.Remove(keysFile); {
				case err == nil:
					slog.Info("revoked SSH keys (last key removed from config)",
						"user", user.Name)
					// Key file gone → drop the key marker; xpf no longer owns a
					// key file for this user.
					_ = removeProvenanceMarker(provisionedKeysDir(), user.Name)
				case os.IsNotExist(err):
					// Already absent (idempotent) — drop the stale key marker.
					_ = removeProvenanceMarker(provisionedKeysDir(), user.Name)
				default:
					slog.Warn("failed to remove authorized_keys after key list emptied",
						"user", user.Name, "file", keysFile, "err", err)
					fail(fmt.Errorf("revoke authorized_keys for %s: %w", user.Name, err))
				}
			}
		}
	}
	return err
}

// sudoersDir is the directory that holds xpf-managed NOPASSWD sudo grants
// for super-user login accounts. Overridable in tests so the reconcile can
// run against a throwaway directory instead of the real /etc/sudoers.d.
var sudoersDir = "/etc/sudoers.d"

// sudoersPrefix namespaces every xpf-managed sudoers drop-in. Only files
// with this prefix are ever written, kept, or removed by reconcileSudoers —
// operator-authored files in the same directory are left untouched.
const sudoersPrefix = "xpf-"

// validateSudoersFile checks a generated sudoers drop-in with `visudo -cf`
// so a malformed grant can never lock out sudo (a single broken drop-in
// makes sudo refuse to run at all). It is a package var so tests can stub
// it. The default is best-effort: it only validates when the process is
// root (the daemon is; unit tests are not) and when visudo is installed —
// otherwise it returns nil and the atomic durable write is relied on as
// the write safety (the file content is a fixed, config-validated template).
var validateSudoersFile = defaultValidateSudoersFile

func defaultValidateSudoersFile(path string) error {
	// visudo enforces root-ownership + 0440 on drop-ins, so the check is
	// only meaningful when we actually run as root. Skip otherwise to keep
	// non-root unit tests deterministic and hermetic.
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := exec.LookPath("visudo"); err != nil {
		return nil // best-effort: visudo not present
	}
	if out, err := runCommandTimeout("visudo", "-cf", path); err != nil {
		return fmt.Errorf("visudo -cf %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// reconcileSudoers makes /etc/sudoers.d match the CURRENT config's
// super-user set on every apply. It (a) writes a NOPASSWD grant
// xpf-<user> for each current super-user login account and (b) REVOKES
// any xpf-<user> drop-in whose user is no longer a super-user (class
// DOWNGRADE) or no longer present in the config (user REMOVAL). Without
// this sweep a demoted or deleted admin kept passwordless root sudo
// forever (#3889) — the original write-only path had no revocation branch.
//
// It mirrors the networkd/rsyslog stale-file reconcilers: build the desired
// set, sweep the managed namespace, remove what is not desired. Only
// sudoersPrefix files are touched. It MUST be called on every apply,
// independent of applySystemLogin's early return, so the "all users
// removed" case still revokes stale grants.
func (d *Daemon) reconcileSudoers(cfg *config.Config) (err error) {
	fail := func(e error) { err = errors.Join(err, e) }
	// Desired: an xpf-<user> drop-in for each current super-user account.
	desired := make(map[string]struct{})
	if cfg.System.Login != nil {
		for _, user := range cfg.System.Login.Users {
			if user.Name == "" || user.Name == "root" {
				continue // never grant/modify root via config
			}
			if user.Class != "super-user" {
				continue
			}
			// #4895 defense in depth: never format an unvalidated username into
			// an /etc/sudoers.d grant. Strict commit-check rejects a crafted
			// name (schema keyValidator), but the tolerant load / peer-sync path
			// downgrades that to a warning (#1960), so a bad name can still reach
			// here. Skip it entirely: neither desire nor write it, so any stale
			// grant is also revoked by the sweep below.
			if err := config.ValidateLoginUsername(user.Name, nil); err != nil {
				slog.Warn("refusing sudoers grant for invalid login user name",
					"user", user.Name, "err", err)
				continue
			}
			desired[sudoersPrefix+user.Name] = struct{}{}
			if err := writeSudoersGrant(user.Name); err != nil {
				slog.Warn("failed to write sudoers file",
					"user", user.Name, "err", err)
				fail(fmt.Errorf("write sudoers grant for %s: %w", user.Name, err))
			}
		}
	}

	// Revoke: remove any xpf-managed drop-in that is no longer desired.
	//
	// #6798: the ReadDir error used to be discarded. An ABSENT sudoers.d is a
	// determination — no drop-in can exist in a directory that does not, so
	// there is nothing to revoke and nil is correct. An UNREADABLE one
	// (EACCES/EIO/ENOTDIR) is NOT: it yields the same empty slice, the sweep
	// below iterates nothing, and reconcileSudoers returns nil — SUCCESS —
	// while a demoted or deleted admin's xpf-<user> NOPASSWD grant is still
	// live on disk. Report it so the #5874 closeout sees the revocation debt.
	//
	// NOTE: readErr, not err — `err` is this function's NAMED RETURN, and a
	// function-scope `entries, err :=` would ASSIGN ENOENT to it (no shadowing
	// at this block level), making a host with no /etc/sudoers.d report a
	// bogus reconcile failure forever.
	entries, readErr := os.ReadDir(sudoersDir)
	if readErr != nil && !os.IsNotExist(readErr) {
		slog.Error("cannot read sudoers directory; a demoted or removed "+
			"super-user's passwordless sudo grant may NOT have been revoked",
			"dir", sudoersDir, "err", readErr)
		fail(fmt.Errorf("read sudoers inventory %s: %w", sudoersDir, readErr))
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, sudoersPrefix) {
			continue // leave non-xpf sudoers.d files (and subdirs) alone
		}
		if _, keep := desired[name]; keep {
			continue
		}
		path := filepath.Join(sudoersDir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to revoke stale sudoers grant",
				"file", name, "err", err)
			fail(fmt.Errorf("revoke stale sudoers grant %s: %w", name, err))
		} else if err == nil {
			slog.Info("revoked stale super-user sudo grant", "file", name)
		}
	}
	return err
}

// writeSudoersGrant writes (idempotently) the NOPASSWD grant for one
// super-user. The write is durable because a torn or lost sudoers file is
// a management-access (sudo) hazard that must survive a power cut. The
// generated file is validated with visudo; if validation fails the file is
// removed rather than left as a lockout landmine (a broken drop-in breaks
// ALL sudo invocations).
//
// #4895: the username is formatted verbatim into both the drop-in filename
// and the grant line, and the config lexer decodes `\n` in a quoted string
// into a literal newline. A name with a newline/whitespace/sudoers
// metacharacter would inject additional directives that pass visudo's syntax
// check. Re-validate defensively here — never format an unvalidated name into
// sudoers, even if a caller bypassed reconcileSudoers' skip or the strict
// commit-check gate was downgraded on a tolerant load (#1960).
func writeSudoersGrant(user string) error {
	if err := config.ValidateLoginUsername(user, nil); err != nil {
		return fmt.Errorf("refusing sudoers grant for invalid login user name %q: %w", user, err)
	}
	path := filepath.Join(sudoersDir, sudoersPrefix+user)
	line := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", user)
	if current, _ := os.ReadFile(path); string(current) == line {
		return nil // idempotent: already correct
	}
	// DurableState: a torn or lost sudoers file is a management-access
	// (sudo) hazard, so it must survive a power cut.
	if err := fsatomic.WriteFileDurable(path, []byte(line), 0440); err != nil {
		return err
	}
	if err := validateSudoersFile(path); err != nil {
		// Fail closed toward availability of sudo itself: never leave an
		// invalid drop-in that would break every sudo invocation.
		os.Remove(path)
		return fmt.Errorf("generated sudoers grant rejected: %w", err)
	}
	return nil
}

// reconcileUserPassword applies, leaves, or locks a login user's OS
// password per the declarative #1944 lifecycle. It runs under the apply lock
// (so there is no marker/shadow race). It is keyed entirely on user.Name /
// the account's current UID, so it is name-agnostic: applySystemLogin drives
// it for each non-root login user, and applyRootAuth drives it for the root
// account (name "root", UID 0) so root gets the SAME apply-boundary
// revalidation, UID-keyed provenance, and lock-on-removal semantics (#5276).
//
//   - encrypted-password set → write it via `chpasswd -e` unless the
//     on-disk shadow hash already equals it (idempotent); a successful
//     apply (re)records the UID-keyed provenance marker.
//   - encrypted-password absent → LOCK the account (Path D2) so removing
//     the directive disables password login instead of orphaning a live
//     credential — but only for the exact xpf-provisioned account (marker
//     UID matches the current UID) and never on a shadow read error.
func (d *Daemon) reconcileUserPassword(user *config.LoginUser) (err error) {
	fail := func(e error) { err = errors.Join(err, e) }
	desired := user.EncryptedPassword.Reveal()
	curUID, uidOK := lookupUID(user.Name)
	cur, ok := currentShadowHash(user.Name)

	switch passwordAction(cur, ok, desired) {
	case pwApply:
		// Defense-in-depth: re-validate the hash at the apply boundary
		// before it reaches /etc/shadow. The strict operator commit gate
		// (config.SchemaValidate → ValidateCryptHash) already rejects
		// plaintext/DES/empty-checksum/':' values, BUT the lenient
		// Load/SyncApply ingress (pkg/configstore/store.go
		// compileTreeLenient, #1319 PR 2) only DOWNGRADES that violation
		// to a warning so an older-binary persisted config or a synced
		// peer value cannot brick boot. Without this guard, such a value
		// would still be written to /etc/shadow verbatim — a plaintext
		// password or a chpasswd-stdin-corrupting ':' (Codex #1944 r1
		// High #2). Re-checking here makes "plaintext never reaches
		// /etc/shadow" hold on EVERY path, while still not bricking boot
		// (we skip+warn, leaving the existing shadow field untouched).
		if err := config.ValidateCryptHash(desired, nil); err != nil {
			slog.Warn("refusing to apply invalid login encrypted-password to /etc/shadow",
				"user", user.Name, "err", err)
			break
		}
		// #5841 marker-first atomicity: record password ownership (and the
		// account registry entry) BEFORE mutating /etc/shadow. If the durable
		// marker cannot be written we must NOT run chpasswd — a
		// mutated-but-unmarked password is the underclaim this closes (xpf
		// could no longer lock a password it set). Fail VISIBLE: log and skip,
		// and the idempotent apply retries next commit. Only when the account's
		// UID resolves (uidOK) can a UID-keyed marker be written; a pwApply for
		// an unresolved account (the fail-open missing-entry case) still runs
		// chpasswd, which fails for a nonexistent user, so no live credential is
		// ever left unmarked.
		// #6797: hold both claims so a FAILED chpasswd can withdraw whichever
		// of them THIS pass created. The password marker gates the declarative
		// D2 lock below, so a marker left behind by a chpasswd that never
		// succeeded makes a later directive removal LOCK an account whose
		// password xpf never set — the operator's own password.
		var pwClaim, acctClaim ownershipClaim
		if uidOK {
			var err error
			if pwClaim, err = claimOwnership(provisionedPasswordsDir(), user.Name, curUID); err != nil {
				slog.Warn("skipping password apply: cannot record password ownership marker",
					"user", user.Name, "err", err)
				// Fail-visible for the #5874 closeout: chpasswd was skipped, so
				// the password did NOT converge to the desired state.
				fail(fmt.Errorf("mark password provisioned %s: %w", user.Name, err))
				break
			}
			if acctClaim, err = claimOwnership(provisionedUsersDir, user.Name, curUID); err != nil {
				slog.Warn("skipping password apply: cannot record account marker",
					"user", user.Name, "err", err)
				pwClaim.rollback() // the password mutation will not run
				fail(fmt.Errorf("mark provisioned %s: %w", user.Name, err))
				break
			}
		}
		stdin := strings.NewReader(user.Name + ":" + desired + "\n")
		if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
			slog.Warn("failed to set user password",
				"user", user.Name, "err", err, "output", strings.TrimSpace(string(out)))
			// #6797: the shadow password did NOT change, so withdraw the
			// ownership this pass claimed for it. A claim an EARLIER apply
			// legitimately made is preserved — rollback is a no-op for it.
			pwClaim.rollback()
			acctClaim.rollback()
			fail(fmt.Errorf("set password for %s: %w", user.Name, err))
		} else {
			// The password + account markers were already recorded marker-first
			// above (#5841), before chpasswd ran, so nothing is written here on
			// success — only the confirmation is logged.
			slog.Info("user encrypted-password applied", "user", user.Name)
		}
	case pwLock:
		// Only lock the exact account whose PASSWORD xpf provisioned (password
		// marker) — never an account xpf touched solely for its SSH key (#5841).
		ownsPassword, ownErr := false, error(nil)
		if uidOK {
			ownsPassword, ownErr = passwordProvisioned(user.Name, curUID)
		}
		if ownErr != nil {
			// #6798: never LOCK on unproven ownership (that is the #6797
			// overclaim), but never report the declarative lock converged
			// either.
			slog.Error("cannot determine password ownership; NOT locking and "+
				"NOT reporting convergence", "user", user.Name, "err", ownErr)
			fail(fmt.Errorf("determine password ownership for %s: %w", user.Name, ownErr))
			break
		}
		if !uidOK || !ownsPassword {
			break
		}
		stdin := strings.NewReader(user.Name + ":!\n")
		if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
			slog.Warn("failed to lock user password",
				"user", user.Name, "err", err, "output", strings.TrimSpace(string(out)))
			fail(fmt.Errorf("lock password for %s: %w", user.Name, err))
		} else {
			slog.Info("user password locked (no encrypted-password in config)",
				"user", user.Name)
		}
	}
	return err
}

// sshdConfPath is the xpf-managed sshd drop-in. Overridable in tests so the
// remove/revert side effects can be exercised against a temp dir.
//
// #7609: it is the SOLE seam for the drop-in's location. applySSHConfig
// derives the directory it creates from this path (filepath.Dir) rather than
// repeating the literal, so pointing this one var at a throwaway tree relocates
// the file AND its parent together. Before that the parent was hard-coded, so a
// relocated path had no directory to be written into.
var sshdConfPath = "/etc/ssh/sshd_config.d/xpf.conf"

// FS + reload seam (#2062). applySSHConfig owns three real-world side effects
// — write the drop-in, remove the drop-in, reload sshd — and the
// config-removal and reload-failure recovery paths can only be tested if those
// effects are injectable. These package-level vars default to the production
// implementations and are overridden by a recorder in daemon_ssh_test.go.
// Mirrors the listenFn/ensureLinkLocalFn seam in pkg/ra.
var (
	sshdReadFile   = os.ReadFile
	sshdWriteFile  = fsatomic.WriteFileAtomic
	sshdRemoveFile = os.Remove
	sshdMkdirAll   = os.MkdirAll
	sshdReloadCmd  = func() ([]byte, error) {
		return runCommandTimeout("systemctl", "reload", "sshd")
	}
	// sshdValidateCmd runs `sshd -t`, which parses the full merged sshd
	// configuration (/etc/ssh/sshd_config plus the sshd_config.d drop-ins,
	// including the xpf drop-in) and fails on a bad Ciphers/MACs/
	// KexAlgorithms spelling or any other syntax error. applySSHConfig gates
	// the reload on this passing so a cipher/MAC typo never reaches a SIGHUP
	// that could drop sshd's listener (#4311 review). Overridden in
	// daemon_ssh_test.go.
	sshdValidateCmd = func() ([]byte, error) {
		return runCommandTimeout("/usr/sbin/sshd", "-t")
	}
)

// applySSHConfig configures sshd from system { services { ssh { ... } } }.
// Uses a drop-in config file to avoid modifying the main sshd_config.
//
// Drop-in lifecycle (#2062): the drop-in is created/updated when there are
// xpf-managed ssh settings, and REMOVED when there are none — including when
// the whole ssh stanza is deleted (cfg.System.Services / .SSH == nil) — so
// clearing the config reverts sshd to the base-image defaults instead of
// leaving stale PermitRootLogin/KexAlgorithms enforced — an existing drop-in
// that cannot be read (permission/IO error) is still treated as present so it
// gets removed. If the reload fails after a write, the drop-in is reverted to
// its prior content (or removed if there was none, the prior was unreadable,
// or the restore write itself fails) so a bad config never persists to break
// the next sshd restart.
func (d *Daemon) applySSHConfig(cfg *config.Config) (retErr error) {
	fail := func(e error) { retErr = errors.Join(retErr, e) }
	var ssh *config.SSHServiceConfig
	if cfg.System.Services != nil {
		ssh = cfg.System.Services.SSH
	}

	// buildSSHDConfig is nil-safe and returns "" when there is nothing to
	// manage, so an absent ssh stanza and an ssh stanza with no recognised
	// leaves collapse to the same "no managed settings" case.
	content := buildSSHDConfig(ssh)

	// Read the prior content once: needed both to skip no-op writes and to
	// restore the file if a reload fails after we change it.
	//
	// Distinguish "absent" from "exists but unreadable": a permission/IO error
	// reading an existing drop-in is NOT the same as no drop-in. Treating an
	// unreadable-but-present file as absent would skip removal and leave a
	// stale drop-in enforcing PermitRootLogin/KexAlgorithms after the config
	// was cleared. hadDropIn = the file exists (read OK, or failed with
	// something other than not-exist); priorReadable = we actually have its
	// content (only then can we restore it on a reload failure).
	prior, priorErr := sshdReadFile(sshdConfPath)
	priorReadable := priorErr == nil
	hadDropIn := priorReadable || !os.IsNotExist(priorErr)

	if content == "" {
		// No xpf-managed ssh settings. Remove any existing drop-in and reload
		// so sshd reverts to base-image defaults. No-op when absent.
		//
		// #6800: `!hadDropIn` alone erased the debt of a FAILED reload. This
		// branch has nothing to revert TO — unlike the update path below, whose
		// #2062 revert leaves the file differing from desired so the next apply
		// rewrites and reloads on its own. Here the drop-in is DELETED, so once
		// the reload fails every later apply reads `hadDropIn == false` and
		// returns above without ever reaching a reload: sshd keeps enforcing the
		// xpf policy the operator REMOVED — a PermitRootLogin/cipher/MAC setting
		// that may be MORE permissive than the base-image default — until a
		// manual restart or a reboot. The retained debt is the only record, so
		// it joins the gate here and is re-driven by
		// serviceReloadDebtReassertLoop.
		if !hadDropIn && !d.sshdReloadOwed() {
			return nil
		}
		if err := sshdRemoveFile(sshdConfPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove sshd config drop-in", "err", err)
			// naked return: yields the accumulated named result, not the
			// block-shadowed err from the `if err := ...` binding above.
			fail(fmt.Errorf("remove sshd config drop-in: %w", err))
			return
		}
		out, err := sshdReloadCmd()
		d.noteSSHDReloadResult(err)
		if err != nil {
			slog.Error("failed to reload sshd after removing drop-in; the drop-in "+
				"is gone but sshd has not re-read its configuration — will retry",
				"err", err, "output", strings.TrimSpace(string(out)))
			fail(fmt.Errorf("reload sshd after removing drop-in: %w", err))
			return
		}
		slog.Info("SSH config drop-in removed (reverted to defaults)")
		return nil
	}

	if priorReadable && string(prior) == content {
		return nil // no change
	}

	// Best-effort create the drop-in directory before writing. If this fails
	// the write below will also fail, but the mkdir error is the real cause
	// (e.g. a read-only /etc) so surface it rather than only the opaque write
	// error.
	//
	// #7609: derived from sshdConfPath rather than repeated as a literal.
	// Byte-identical in production — filepath.Dir("/etc/ssh/sshd_config.d/
	// xpf.conf") IS "/etc/ssh/sshd_config.d" — so this changes no behaviour on
	// a real box. What it fixes is the SEAM: sshdConfPath is a package var
	// precisely so a test can point the drop-in at a throwaway tree, and a
	// hard-coded parent meant relocating it created the file path without its
	// directory. The write then failed with ENOENT, and the failure surfaced
	// as whatever the test was actually asserting — a cell that only checked
	// "the tail returned an error" would pass for the wrong reason.
	//
	// That is not hypothetical: the #6790 credential cells hit it, and carried
	// an os.MkdirAll(filepath.Dir(sshdConfPath)) workaround in their fixture
	// until this landed. Deleting that workaround is this change's regression
	// signal — if the control cell stays green without it, the derivation
	// works.
	//
	// One var now relocates the whole drop-in, which is the property
	// provisionedUsersDir already has for the three #5841 marker roots.
	if err := sshdMkdirAll(filepath.Dir(sshdConfPath), 0755); err != nil {
		slog.Warn("failed to create sshd config drop-in directory", "err", err)
		fail(fmt.Errorf("create sshd config drop-in directory: %w", err))
	}
	// AtomicGeneratedConfig (D2): regenerated each apply and reloaded
	// immediately. A power-cut loss reverts PermitRootLogin to the base
	// image default (prohibit-password) until the next boot apply — that
	// FAILS SAFE (more restrictive, never more permissive), so no fsync.
	if err := sshdWriteFile(sshdConfPath, []byte(content), 0644); err != nil {
		slog.Warn("failed to write sshd config", "err", err)
		fail(fmt.Errorf("write sshd config: %w", err))
		return
	}

	// revertDropIn restores the drop-in to its prior state after a validation
	// or reload failure: restore the previously-read content, else remove the
	// file. Only restore the prior content when we actually read it
	// (priorReadable); an unreadable-but-present prior is unknown, so fail safe
	// by removing the drop-in instead of restoring garbage. No drop-in is safer
	// than the known-bad content we just wrote (which would break the next sshd
	// restart).
	revertDropIn := func(reason string) {
		if priorReadable {
			if rerr := sshdWriteFile(sshdConfPath, prior, 0644); rerr != nil {
				slog.Warn("failed to restore prior sshd config; removing drop-in",
					"reason", reason, "err", rerr)
				if rmErr := sshdRemoveFile(sshdConfPath); rmErr != nil && !os.IsNotExist(rmErr) {
					slog.Warn("failed to remove bad sshd config after failed restore", "err", rmErr)
				}
			}
		} else {
			if rerr := sshdRemoveFile(sshdConfPath); rerr != nil && !os.IsNotExist(rerr) {
				slog.Warn("failed to remove bad sshd config", "reason", reason, "err", rerr)
			}
		}
	}

	// Validate the merged sshd config BEFORE reloading (#4311 review). A bad
	// Ciphers/MACs/KexAlgorithms line reaching a reload (SIGHUP) can make sshd
	// re-exec into an invalid config and drop its listener → SSH lockout on the
	// appliance. `sshd -t` catches the typo first. On failure revert the
	// drop-in and SKIP the reload entirely: the running sshd is never disturbed
	// and the next restart reads the good prior config. This makes the
	// cipher-typo-lockout protection self-contained rather than relying on the
	// base-image ExecReload=sshd -t.
	if out, err := sshdValidateCmd(); err != nil {
		slog.Error("sshd config validation failed; SSH drop-in not applied",
			"err", err, "output", strings.TrimSpace(string(out)))
		revertDropIn("validation-failed")
		fail(fmt.Errorf("validate sshd config: %w", err))
		return
	}

	// Reload sshd to pick up changes. Validation passed, so this should
	// succeed; the reload-failure revert stays as a backstop (e.g. a runtime
	// reload error unrelated to config syntax).
	out, err := sshdReloadCmd()
	// #6800: report the outcome even though this path has its own retry owner
	// (revertDropIn leaves the file differing from desired, so the next apply
	// rewrites and reloads). A SUCCESS here must still DISCHARGE a debt an
	// earlier REMOVAL left outstanding — sshd has just re-read its
	// configuration, so nothing is owed any more.
	d.noteSSHDReloadResult(err)
	if err != nil {
		slog.Error("failed to reload sshd",
			"err", err, "output", strings.TrimSpace(string(out)))
		revertDropIn("reload-failed")
		fail(fmt.Errorf("reload sshd: %w", err))
		// Best-effort reload of the restored content so the running sshd is
		// not left referencing a drop-in we just rewrote/removed underneath
		// it. The original reload already failed; a second failure here is
		// only logged.
		if out2, err2 := sshdReloadCmd(); err2 != nil {
			slog.Warn("failed to reload sshd after reverting drop-in",
				"err", err2, "output", strings.TrimSpace(string(out2)))
		}
		return
	}
	slog.Info("SSH config applied",
		"root_login", ssh.RootLogin,
		"key_exchange", strings.Join(ssh.KeyExchange, ","))
	return nil
}

// buildSSHDConfig renders the xpf-managed sshd drop-in body from the SSH
// service config, or "" when there is nothing to manage. Each setting is an
// independent line: root-login → PermitRootLogin, key-exchange → KexAlgorithms
// (H5, #2008). sshd validates algorithm spellings at reload, so xpf does not
// enum-check the key-exchange list.
// filterSSHAlgorithms drops any token that is not a safe OpenSSH algorithm
// name (config.ValidateSSHAlgorithm), the render-side belt for #4902. Only the
// injection/breakage shape (comma/space/control char) is filtered; sshd still
// owns the actual algorithm-spelling check at reload. A dropped token is logged
// so an operator can see why a leniently-loaded value did not take effect.
func filterSSHAlgorithms(in []string) []string {
	out := in[:0:0]
	for _, tok := range in {
		if err := config.ValidateSSHAlgorithm(tok, nil); err != nil {
			slog.Warn("skipping invalid SSH algorithm token", "token", tok, "err", err)
			continue
		}
		out = append(out, tok)
	}
	return out
}

func buildSSHDConfig(ssh *config.SSHServiceConfig) string {
	if ssh == nil {
		return ""
	}
	var lines []string
	if ssh.RootLogin != "" {
		var permitRoot string
		switch ssh.RootLogin {
		case "allow":
			permitRoot = "yes"
		case "deny":
			permitRoot = "no"
		case "deny-password":
			permitRoot = "prohibit-password"
		}
		if permitRoot != "" {
			lines = append(lines, "PermitRootLogin "+permitRoot)
		}
	}
	// #4902 render belt: filter each algorithm list to safe OpenSSH tokens
	// before comma-joining into the sshd line. A leniently-loaded / peer-synced
	// token carrying a comma/space/control char (which would smuggle a second
	// sshd directive token onto the line, or fail the reload) is dropped; the
	// strict commit gate (config.ValidateSSHAlgorithm) rejects it at commit.
	if kex := filterSSHAlgorithms(ssh.KeyExchange); len(kex) > 0 {
		lines = append(lines, "KexAlgorithms "+strings.Join(kex, ","))
	}
	// #4305 S-4: sshd hardening knobs. sshd validates the algorithm
	// spellings and numeric ranges at reload; xpf gates the injection/breakage
	// shape (#4902) and lets sshd own the spelling check.
	if ciphers := filterSSHAlgorithms(ssh.Ciphers); len(ciphers) > 0 {
		lines = append(lines, "Ciphers "+strings.Join(ciphers, ","))
	}
	if macs := filterSSHAlgorithms(ssh.MACs); len(macs) > 0 {
		lines = append(lines, "MACs "+strings.Join(macs, ","))
	}
	if ssh.ConnectionLimit > 0 {
		// Junos `connection-limit` bounds concurrent sessions; sshd's
		// nearest knob is MaxStartups (concurrent unauthenticated
		// connections). Not an exact equivalent, but the standard mapping.
		lines = append(lines, fmt.Sprintf("MaxStartups %d", ssh.ConnectionLimit))
	}
	if ssh.ClientAliveIntervalSet {
		lines = append(lines, fmt.Sprintf("ClientAliveInterval %d", ssh.ClientAliveInterval))
	}
	if ssh.ClientAliveCountMaxSet {
		lines = append(lines, fmt.Sprintf("ClientAliveCountMax %d", ssh.ClientAliveCountMax))
	}
	if len(lines) == 0 {
		return ""
	}
	return "# Managed by xpf — do not edit\n" + strings.Join(lines, "\n") + "\n"
}

// applyRootAuth applies AND declaratively reconciles `system
// root-authentication` (encrypted-password + SSH keys) against root's OS
// credentials, mirroring the non-root #1944/#5106/#5128 lifecycle.
//
// Before #5276 this was WRITE-ONLY: it returned immediately when the stanza was
// absent and had only positive branches for a nonempty password or key list, so
// removing the stanza (or emptying a leaf) left the prior /etc/shadow root hash
// and /root/.ssh/authorized_keys LIVE — offboarding/rotation/compromise never
// revoked root access despite a green commit. Non-root reconciliation already
// LOCKS a removed password and REMOVES the last xpf-managed key via a UID-keyed
// provenance marker; root now gets the SAME semantics:
//
//   - Password: delegated to reconcileUserPassword keyed on name "root" / UID 0.
//     A configured encrypted-password is applied via `chpasswd -e` (with the
//     apply-boundary hash revalidation) and records the provenance marker; an
//     ABSENT password (stanza removed OR the encrypted-password leaf emptied)
//     LOCKS the root shadow field — but ONLY when xpf itself provisioned root's
//     credentials (marker present) and the field is not already locked, and
//     NEVER on a shadow read error (fail-closed). A fresh boot that never
//     configured root-authentication has no marker, so root is never locked out
//     and console/recovery access is preserved.
//   - Keys: a configured key list is written wholesale to
//     /root/.ssh/authorized_keys and records the provenance marker; an EMPTY
//     key list (stanza removed OR the ssh-* leaf emptied) REMOVES the
//     xpf-managed authorized_keys — but ONLY when the provenance marker is
//     present, so an operator-installed key file xpf never wrote is left
//     untouched (provenance-scoped removal, never a hand-placed key).
//
// The single UID-keyed marker (name "root", UID 0) gates both revocations — the
// same one-marker-per-principal scheme the non-root path uses — and is recorded
// on EITHER a password apply or a key apply so a keys-only root-authentication
// (no encrypted-password) is still revocable. Idempotent: re-applying with the
// stanza still absent re-locks nothing (the shadow field is already "!") and
// removes nothing (the key file is already gone).
func (d *Daemon) applyRootAuth(cfg *config.Config) (retErr error) {
	fail := func(e error) { retErr = errors.Join(retErr, e) }
	ra := cfg.System.RootAuthentication

	// A nil stanza means "root-authentication not configured": the desired
	// password AND key list are empty, so the reconcile REVOKES whatever xpf
	// previously provisioned (gated by the marker) instead of early-returning
	// and orphaning a live root credential (#5276).
	var password config.Secret
	var keys []string
	if ra != nil {
		password = ra.EncryptedPassword
		keys = ra.SSHKeys
	}

	// Password: reuse the non-root #1944 reconciler keyed on name "root" / UID 0.
	// It applies a configured hash (with apply-boundary revalidation + marker)
	// and, when the password is absent, D2-locks root ONLY if the marker shows
	// xpf provisioned it — never on a read error, never an already-locked field.
	fail(d.reconcileUserPassword(&config.LoginUser{Name: "root", EncryptedPassword: password}))

	// Keys: write the configured set wholesale, else revoke the xpf-managed file.
	if len(keys) > 0 {
		// #5841 marker-first: record root KEY ownership AND the account registry
		// entry BEFORE writing root's authorized_keys. The key marker gates the
		// key REMOVAL below (resource-specific — so a keys-only stanza never
		// touches root's out-of-band password); the account registry keeps root
		// enumerated by the factory-reset teardown (#5520) for a keys-only
		// root-authentication. Fail VISIBLE: skip the key write if either
		// durable marker cannot be recorded, retry next apply.
		// #6797: hold both claims so a FAILED root key write can withdraw
		// whichever THIS pass created. The key marker gates the root
		// authorized_keys removal below, so a stale claim deletes an
		// operator-installed root key file xpf never wrote.
		rootKeyClaim, err := claimOwnership(provisionedKeysDir(), "root", 0)
		if err != nil {
			slog.Warn("skipping root authorized_keys apply: cannot record key ownership marker", "err", err)
			// Fail-visible for the #5874 closeout: root's key write was skipped,
			// so root SSH keys did NOT converge. The naked return yields the
			// accumulated retErr, not a block-shadowed err.
			fail(fmt.Errorf("mark root key provisioned: %w", err))
			return
		}
		rootAcctClaim, err := claimOwnership(provisionedUsersDir, "root", 0)
		if err != nil {
			slog.Warn("skipping root authorized_keys apply: cannot record account marker", "err", err)
			rootKeyClaim.rollback() // the key write will not run
			fail(fmt.Errorf("mark root provisioned: %w", err))
			return
		}
		// MkdirAllDurable: root authorized_keys is DurableState written into
		// this dir, so the dir's own entry must survive a power cut too
		// (Codex r1).
		if err := fsatomic.MkdirAllDurable(rootSSHDir, 0700); err != nil {
			slog.Warn("failed to create /root/.ssh dir", "err", err)
			rootKeyClaim.rollback() // #6797: no key file was written
			rootAcctClaim.rollback()
			// naked return: yields the accumulated named result, not the
			// block-shadowed err from the `if err := ...` binding.
			fail(fmt.Errorf("create /root/.ssh dir: %w", err))
			return
		}
		keysContent := strings.Join(keys, "\n") + "\n"
		keysFile := rootAuthorizedKeysPath()
		current, _ := os.ReadFile(keysFile)
		if string(current) != keysContent {
			// DurableState: root SSH access must survive a power cut.
			// WithOwner(0,0) is harmless/explicit (root keys are already
			// uid 0) and keeps the install correctly-owned at rename.
			if err := fsatomic.WriteFileDurable(keysFile, []byte(keysContent), 0600, fsatomic.WithOwner(0, 0)); err != nil {
				slog.Warn("failed to write root authorized_keys", "err", err)
				rootKeyClaim.rollback() // #6797: the key file was not written
				rootAcctClaim.rollback()
				fail(fmt.Errorf("write root authorized_keys: %w", err))
				return
			}
			slog.Info("root SSH keys applied", "keys", len(keys))
		}
	} else if rootOwnsKeys, rootOwnErr := keyProvisioned("root", 0); rootOwnErr != nil {
		// #6798: an unreadable root key marker proves nothing. Do NOT remove
		// root's authorized_keys on unproven ownership — if it is the
		// operator's own out-of-band key that is a total lockout — but do not
		// report the emptied key list as converged either.
		slog.Error("cannot determine root SSH-key ownership; NOT revoking root "+
			"keys and NOT reporting convergence", "err", rootOwnErr)
		fail(fmt.Errorf("determine root key ownership: %w", rootOwnErr))
	} else if rootOwnsKeys {
		// Empty/absent key list AND xpf wrote root's keys: revoke the xpf-managed
		// root authorized_keys so removing the keys from config actually disables
		// key-based root login. The KEY marker gate leaves an operator-installed
		// key file xpf never wrote untouched — provenance-scoped removal,
		// mirroring applySystemLogin's emptied-key-list branch +
		// deprovisionLoginUser (the whole file is xpf-owned when the marker
		// matches). #5276/#5841.
		keysFile := rootAuthorizedKeysPath()
		switch err := os.Remove(keysFile); {
		case err == nil:
			slog.Info("revoked root SSH keys (root-authentication keys removed from config)")
			_ = removeProvenanceMarker(provisionedKeysDir(), "root")
		case os.IsNotExist(err):
			_ = removeProvenanceMarker(provisionedKeysDir(), "root")
		default:
			slog.Warn("failed to remove root authorized_keys after key list emptied",
				"file", keysFile, "err", err)
			fail(fmt.Errorf("revoke root authorized_keys: %w", err))
		}
	}
	return retErr
}
