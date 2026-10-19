package daemon

import (
	"context"
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
// The moved implementations remain unchanged except for the #10725
// apply-boundary validation immediately below.

// validateAuthorizedSSHKeys enforces the authorized_keys apply-boundary format
// shared by non-root login and root-authentication. OpenSSH accepts many key
// types besides the ssh-* family (ecdsa-sha2-nistp256/384/521 and the FIDO
// sk-* variants). Junos operators habitually store the full
// "<type> <base64> <comment>" string as the leaf value, so an ecdsa key filed
// under any ssh-* leaf reaches this point verbatim; requiring an ssh- prefix
// rejected such a valid key and skipped ALL provisioning for that user
// (#14111). The accepted set is therefore the OpenSSH authorized_keys key-type
// vocabulary — still a fail-closed allowlist: an option-prefixed line
// (`command="..." ssh-ed25519 ...`), a bare blob, or any unknown type is
// refused before any credential mutation. A whitespace-separated base64 blob
// must follow the type; the comment is optional.

// sshAuthorizedKeyTypes is the OpenSSH authorized_keys key-type vocabulary
// accepted at the apply boundary (#14111).
var sshAuthorizedKeyTypes = map[string]bool{
	"ssh-ed25519":                                 true,
	"ssh-rsa":                                     true,
	"ssh-dss":                                     true,
	"ecdsa-sha2-nistp256":                         true,
	"ecdsa-sha2-nistp384":                         true,
	"ecdsa-sha2-nistp521":                         true,
	"sk-ssh-ed25519@openssh.com":                  true,
	"sk-ecdsa-sha2-nistp256@openssh.com":          true,
	"ssh-ed25519-cert-v01@openssh.com":            true,
	"ssh-rsa-cert-v01@openssh.com":                true,
	"ssh-dss-cert-v01@openssh.com":                true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com":    true,
	"ecdsa-sha2-nistp384-cert-v01@openssh.com":    true,
	"ecdsa-sha2-nistp521-cert-v01@openssh.com":    true,
	"sk-ssh-ed25519-cert-v01@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
}

func validAuthorizedSSHKey(key string) bool {
	typ, blob, ok := strings.Cut(key, " ")
	if !ok || !sshAuthorizedKeyTypes[typ] {
		return false
	}
	blob = strings.TrimLeft(blob, " ")
	if blob == "" {
		return false
	}
	if i := strings.IndexByte(blob, ' '); i >= 0 {
		blob = blob[:i]
	}
	for _, r := range blob {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func validateAuthorizedSSHKeys(principal string, keys []string) error {
	for i, key := range keys {
		if strings.ContainsAny(key, "\r\n") || !validAuthorizedSSHKey(key) {
			return fmt.Errorf("SSH key %d for %s must be a single-line OpenSSH public key", i+1, principal)
		}
	}
	return nil
}

// Login-shell policy for configured local accounts (#10833). Only the literal
// super-user class keeps a general-purpose shell; all other known classes enter
// the RBAC-enforced xpf CLI, and empty/unknown classes fail closed to nologin.
const (
	loginShellBash    = "/bin/bash"
	loginShellNologin = "/usr/sbin/nologin"
)

var loginCLIShellCandidates = []string{"/usr/local/sbin/cli", "/usr/local/bin/cli"}

func resolveLoginCLIShell() string {
	for _, p := range loginCLIShellCandidates {
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	// A missing CLI denies shell login rather than falling back to bash.
	if len(loginCLIShellCandidates) > 0 {
		return loginCLIShellCandidates[0]
	}
	return loginShellNologin
}

func loginShellForClass(cfg *config.Config, class, cliShell string) string {
	switch class {
	case "super-user":
		return loginShellBash
	case "", "unauthorized":
		return loginShellNologin
	default:
		if _, ok := config.ResolveClassPermissions(cfg, class); !ok {
			return loginShellNologin
		}
		return cliShell
	}
}

func loginUserShell(name string) (string, bool, error) {
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		return "", false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 0 && fields[0] == name {
			if len(fields) < 7 {
				return "", false, fmt.Errorf("passwd: malformed entry for %q", name)
			}
			return fields[6], true, nil
		}
	}
	return "", false, nil
}

// chownSSHDir owns a user's .ssh directory by numeric (uid, gid). It is a
// package var only so tests that stage fake passwd uids (which an
// unprivileged test process cannot chown to) can observe/skip the real
// filesystem ownership change; production always calls os.Chown (#14111).
var chownSSHDir = func(dir string, uid, gid int) error { return os.Chown(dir, uid, gid) }

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
	// #14969: a superseded abandoned closeout owner abstains before its
	// first host mutation (the seams fence later mutations individually).
	if seamErr := checkHostAuthSeam14969(); seamErr != nil {
		return seamErr
	}
	fail := func(e error) { err = errors.Join(err, e) }
	var releaseApply func()
	defer func() {
		if releaseApply != nil {
			releaseApply()
		}
	}()
	acquireApply := func() error {
		if releaseApply != nil || d == nil || d.applySem == nil {
			return nil
		}
		// A normal apply holds applySem and runs cfg == live, so a keyed user
		// takes the write path and cannot reach this restore. Only a stale
		// owner blocks here; it cannot re-enter the permit.
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			return err
		}
		releaseApply = func() { d.applySem.Release(1) }
		return nil
	}
	restoreLiveLoginKeys := func(name string) error {
		if err := acquireApply(); err != nil {
			return err
		}
		live, ok := d.liveDesiredLoginUser12169(name)
		if !ok || len(live.SSHKeys) == 0 {
			return nil
		}
		liveCfg := d.liveConfig12169()
		if liveCfg == nil {
			return nil
		}
		return d.applySystemLogin(liveCfg)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		return nil
	}

	cliShell := resolveLoginCLIShell()
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
		// #14694: a malformed key or a negative UID must not skip the
		// shell demotion / password reconcile for an EXISTING account.
		// On the tolerant/peer-sync/rollback path the demoting config is
		// already live, so an early continue would leave the old bash
		// shell, shadow hash and keys in force while reporting (for
		// UID<0, silently) success. Record the failure, suppress ONLY
		// the key install / account creation below, and still converge
		// shell + password. A nonexistent account is never created.
		keysValid := true
		if err := validateAuthorizedSSHKeys(user.Name, user.SSHKeys); err != nil {
			fail(err)
			keysValid = false
		}
		// A missing UID (zero) requests the system's normal automatic
		// assignment. Invalid authored UIDs are kept negative by compilation
		// on the tolerant path and must never silently take that route.
		uidValid := true
		if user.UID < 0 {
			slog.Warn("refusing to provision login user with invalid uid",
				"user", user.Name, "uid", user.UID)
			fail(fmt.Errorf("login user %s has invalid uid %d", user.Name, user.UID))
			uidValid = false
		}
		provisionBlocked := !keysValid || !uidValid

		// Check if user already exists. A non-zero exit means "user
		// doesn't exist"; a timeout also lands here, in which case the
		// useradd below fails with "already exists" and is logged. The `--`
		// stops id treating a name as an option (#5005).
		shell := loginShellForClass(cfg, user.Class, cliShell)

		_, err := runCommandTimeout("id", "--", user.Name)
		if err != nil && provisionBlocked {
			// #14694: never create an account whose keys/UID are invalid.
			continue
		}
		if err != nil {
			// User doesn't exist — create it
			args := []string{"-m", "-s", shell}

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
			if uid, ok := lookupUID(user.Name); ok {
				slog.Info("created system user", "user", user.Name, "uid", uid)
				// Record provenance keyed by the account's actual UID so a
				// later directive removal can lock THIS exact account (D2),
				// while an out-of-band userdel+recreate with a different UID
				// is left untouched (#1944 §5.4).
				if err := markProvisioned(user.Name, uid); err != nil {
					slog.Warn("failed to write provisioned-user marker",
						"user", user.Name, "err", err)
					fail(fmt.Errorf("mark provisioned %s: %w", user.Name, err))
				}
			} else {
				slog.Info("created system user", "user", user.Name, "uid", "unknown")
			}
		} else {
			// `id` may resolve NSS accounts that are not local. Only manage
			// shells for passwd-file accounts; fail visibly if their shell
			// cannot be determined so an old bash cannot be reported as fixed.
			currentShell, found, err := loginUserShell(user.Name)
			if err != nil {
				fail(fmt.Errorf("determine login shell for %s: %w", user.Name, err))
				continue
			}
			if found && currentShell != shell {
				// #14695: claim shell ownership BEFORE mutating the shell
				// (marker-first, #5841/#6797 discipline). Without this a
				// pre-existing account elevated to super-user (shell ->
				// /bin/bash) with no password/key of its own left no
				// provenance, so deprovision early-returned and the shell
				// grant survived removal. Roll back the claim if usermod
				// fails so a non-xpf shell is never later reset.
				uidForShell, uidOK := lookupUID(user.Name)
				var shellClaim ownershipClaim
				if uidOK {
					var claimErr error
					if shellClaim, claimErr = claimOwnership(provisionedShellsDir(), user.Name, uidForShell); claimErr != nil {
						slog.Warn("skipping login shell update: cannot record shell ownership marker",
							"user", user.Name, "err", claimErr)
						fail(fmt.Errorf("mark shell provisioned %s: %w", user.Name, claimErr))
						continue
					}
				}
				if out, err := runCommandTimeout("usermod", "-s", shell, "--", user.Name); err != nil {
					shellClaim.rollback()
					slog.Warn("failed to update login shell",
						"user", user.Name, "shell", shell, "err", err, "output", strings.TrimSpace(string(out)))
					fail(fmt.Errorf("update login shell for %s: %w", user.Name, err))
					continue
				}
				slog.Info("updated login shell", "user", user.Name, "shell", shell)
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
		// #14694: when keys/UID are invalid, skip BOTH branches — never
		// install the bad key, and never treat its presence as an emptied
		// list that revokes the prior xpf-managed keys.
		if provisionBlocked {
			continue
		}
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
			// #14970: .ssh is user-writable; a planted symlink here would
			// make the Chown below re-own the link TARGET and the durable
			// write below land in the target. Refuse before any mutation.
			if err := ensureSSHDirSafeForWrite(sshDir); err != nil {
				slog.Warn("refusing authorized_keys apply: .ssh path is a symlink",
					"user", user.Name, "dir", sshDir, "err", err)
				keyClaim.rollback()
				fail(fmt.Errorf("refuse symlinked .ssh for %s: %w", user.Name, err))
				continue
			}
			if err := fsatomic.MkdirAllDurable(sshDir, 0700); err != nil {
				slog.Warn("failed to create .ssh dir", "user", user.Name, "dir", sshDir, "err", err)
				keyClaim.rollback() // #6797: no key file was written
				fail(fmt.Errorf("create .ssh dir for %s: %w", user.Name, err))
				continue
			}
			// Chown the .ssh DIR to the resolved (uid, gid) — not to the
			// textual "<name>:<name>" pair. An existing account whose
			// primary group is not eponymously named (e.g. alice:users)
			// has no group named after the user, so the name-based chown
			// failed on every apply; with a freshly created root-owned 0700
			// .ssh the user then could not traverse the directory at all
			// (#14111). (uid, gid) was already resolved above (#1916 D7);
			// numeric ids also keep this root-privileged exec free of any
			// username/group-name operand to mis-parse (the #5005 `--`
			// concern is subsumed). Run it UNCONDITIONALLY (idempotent),
			// not only when the key content changes: MkdirAllDurable
			// creates the dir root-owned, so a crash between the durable
			// key write and this chown would otherwise leave a durable
			// root-owned .ssh that later applies skip forever because the
			// key content already matches (Codex r2 HIGH). Only the dir
			// itself is chowned: authorized_keys is installed with the
			// same owner by fsatomic.WithOwner(uid, gid) below, and a
			// recursive walk would also re-own operator-placed files.
			// A chown failure ABORTS this user's key install: claiming
			// marker-first ownership and writing keys into a directory
			// whose ownership is unproven would report convergence over a
			// .ssh the user may not be able to traverse.
			if err := chownSSHDir(sshDir, uid, gid); err != nil {
				slog.Warn("failed to chown ssh dir",
					"user", user.Name, "dir", sshDir, "err", err)
				keyClaim.rollback() // #6797: no key file was written
				fail(fmt.Errorf("chown .ssh dir for %s: %w", user.Name, err))
				continue
			}

			keysContent := strings.Join(user.SSHKeys, "\n") + "\n"
			keysFile := sshDir + "/authorized_keys"
			current, _ := os.ReadFile(keysFile)
			if string(current) != keysContent {
				// #14970: re-check immediately before the write; a link
				// planted between the pre-MkdirAll check and here must still
				// be refused rather than written through.
				if err := ensureSSHDirSafeForWrite(sshDir); err != nil {
					slog.Warn("refusing authorized_keys write: .ssh path is a symlink",
						"user", user.Name, "dir", sshDir, "err", err)
					keyClaim.rollback()
					fail(fmt.Errorf("refuse symlinked .ssh for %s: %w", user.Name, err))
					continue
				}
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
				// #14112: a timed-out closeout owner can resume after a newer
				// commit re-presented this retained user WITH keys. Consult
				// the LIVE config before revoking, and repair after the
				// unlink/marker cleanup if a promotion raced them — the same
				// #12169 fence deprovisionLoginUser and applyRootAuth apply.
				if liveUser, liveDesired := d.liveDesiredLoginUser12169(user.Name); liveDesired && len(liveUser.SSHKeys) > 0 {
					staleRevocationSuperseded12169("remove-retained-user-keys", user.Name)
					fail(restoreLiveLoginKeys(user.Name))
				} else {
					keysFile := managedAuthorizedKeysPath(user.Name)
					// #14970: removeManagedAuthorizedKeys refuses a symlinked
					// .ssh/authorized_keys instead of deleting the resolved
					// victim file; the refusal lands in the default arm below
					// (fail + marker retained, retry next apply).
					switch err := removeManagedAuthorizedKeys(user.Name); {
					case err == nil:
						slog.Info("revoked SSH keys (last key removed from config)",
							"user", user.Name)
						if liveUser, liveDesired := d.liveDesiredLoginUser12169(user.Name); liveDesired && len(liveUser.SSHKeys) > 0 {
							staleRevocationSuperseded12169("repair-retained-user-keys", user.Name)
							fail(restoreLiveLoginKeys(user.Name))
						} else if err := removeProvenanceMarker(provisionedKeysDir(), user.Name); err != nil {
							fail(fmt.Errorf("remove key marker for %s: %w", user.Name, err))
						} else if liveUser, liveDesired := d.liveDesiredLoginUser12169(user.Name); liveDesired && len(liveUser.SSHKeys) > 0 {
							staleRevocationSuperseded12169("restore-retained-user-keys-after-marker-cleanup", user.Name)
							fail(restoreLiveLoginKeys(user.Name))
						}
					case os.IsNotExist(err):
						// Already absent (idempotent) — drop the stale key marker,
						// unless a promotion re-presented keys in the meantime.
						if liveUser, liveDesired := d.liveDesiredLoginUser12169(user.Name); liveDesired && len(liveUser.SSHKeys) > 0 {
							staleRevocationSuperseded12169("repair-retained-user-keys", user.Name)
							fail(restoreLiveLoginKeys(user.Name))
						} else if err := removeProvenanceMarker(provisionedKeysDir(), user.Name); err != nil {
							fail(fmt.Errorf("remove key marker for %s: %w", user.Name, err))
						} else if liveUser, liveDesired := d.liveDesiredLoginUser12169(user.Name); liveDesired && len(liveUser.SSHKeys) > 0 {
							staleRevocationSuperseded12169("restore-retained-user-keys-after-marker-cleanup", user.Name)
							fail(restoreLiveLoginKeys(user.Name))
						}
					default:
						slog.Warn("failed to remove authorized_keys after key list emptied",
							"user", user.Name, "file", keysFile, "err", err)
						fail(fmt.Errorf("revoke authorized_keys for %s: %w", user.Name, err))
					}
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
	// #14969: superseded abandoned owner abstains (see applySystemLogin).
	if seamErr := checkHostAuthSeam14969(); seamErr != nil {
		return seamErr
	}
	fail := func(e error) { err = errors.Join(err, e) }
	var releaseApply func()
	defer func() {
		if releaseApply != nil {
			releaseApply()
		}
	}()
	acquireApply := func() error {
		if releaseApply != nil || d == nil || d.applySem == nil {
			return nil
		}
		// A normal apply holds applySem and runs cfg == live, so a desired
		// grant is in this call's desired set and cannot reach this restore.
		// Only a stale owner blocks here; it cannot re-enter the permit.
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			return err
		}
		releaseApply = func() { d.applySem.Release(1) }
		return nil
	}
	restoreLiveSudoersGrant := func(user string) error {
		if err := acquireApply(); err != nil {
			return err
		}
		live := d.liveConfig12169()
		if live == nil || !d.liveDesiredSudoersGrant12169(user) {
			return nil
		}
		return d.reconcileSudoers(live)
	}
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
		user := strings.TrimPrefix(name, sudoersPrefix)
		if d.liveDesiredSudoersGrant12169(user) {
			staleRevocationSuperseded12169("remove-sudoers-grant", user)
			continue
		}
		path := filepath.Join(sudoersDir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to revoke stale sudoers grant",
				"file", name, "err", err)
			fail(fmt.Errorf("revoke stale sudoers grant %s: %w", name, err))
		} else if err == nil {
			slog.Info("revoked stale super-user sudo grant", "file", name)
			// Close the check/unlink race: a promotion that landed during
			// os.Remove must restore its grant while serialized against commits.
			if d.liveDesiredSudoersGrant12169(user) {
				staleRevocationSuperseded12169("repair-sudoers-grant", user)
				fail(restoreLiveSudoersGrant(user))
			}
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
		// Defense-in-depth: re-validate the hash at the apply boundary before
		// it reaches /etc/shadow. Lenient Load/SyncApply ingress may downgrade
		// strict validation to a warning, so reject here as well and report a
		// failure rather than claiming that a skipped password converged.
		if err := config.ValidateCryptHash(desired, nil); err != nil {
			slog.Warn("refusing to apply invalid login encrypted-password to /etc/shadow",
				"user", user.Name, "err", err)
			fail(fmt.Errorf("refuse invalid encrypted password for %s: %w", user.Name, err))
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
		} else if actual, ok := currentShadowHash(user.Name); !ok {
			slog.Error("could not verify user password after chpasswd",
				"user", user.Name)
			fail(fmt.Errorf("verify password for %s: shadow entry unavailable after chpasswd", user.Name))
		} else if actual != desired {
			slog.Error("user password differs from desired hash after chpasswd",
				"user", user.Name)
			fail(fmt.Errorf("verify password for %s: shadow hash does not match desired value", user.Name))
		} else {
			// The password + account markers were recorded marker-first above
			// (#5841); readback confirms the shadow mutation actually converged.
			slog.Info("user encrypted-password applied", "user", user.Name)
		}
	case pwLock:
		// A timed-out rollback owner may resume after a new config re-presents
		// this account. The helper repairs its live password and, for root,
		// settles under applySem. Login deprovision fences each of its own
		// live-password repairs through marker cleanup; the direct pre-lock
		// repair below retains provenance but has no post-repair settlement.
		if superseded, err := d.repairStalePasswordLock12169(user.Name); superseded {
			fail(err)
			break
		}

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
		// Re-read after the ownership lookup as well: a confirmed commit may
		// have promoted this password since the earlier fence above.
		if live, desiredNow := d.liveDesiredPasswordUser12169(user.Name); desiredNow &&
			live.EncryptedPassword.Reveal() != "" {
			staleRevocationSuperseded12169("lock-password", user.Name)
			fail(d.reconcileUserPassword(&live))
			break
		}
		stdin := strings.NewReader(user.Name + ":!\n")
		out, lockErr := runCommandStdinTimeout(stdin, "chpasswd", "-e")
		if lockErr != nil {
			slog.Warn("failed to lock user password",
				"user", user.Name, "err", lockErr, "output", strings.TrimSpace(string(out)))
			fail(fmt.Errorf("lock password for %s: %w", user.Name, lockErr))
		} else {
			slog.Info("user password locked (no encrypted-password in config)",
				"user", user.Name)
		}
		// Even an errored/timed-out child may have changed shadow before
		// returning. Repair the live password on every exit, preserving any
		// original lock error as a separate closeout failure.
		if superseded, repairErr := d.repairStalePasswordLock12169(user.Name); superseded {
			fail(repairErr)
		}
	}
	return err
}

// sshdConfPath is the xpf-managed sshd drop-in. The 00 prefix makes xpf policy
// precede the image's 10-xpf-factory.conf, since sshd uses the first value for
// most directives. Overridable in tests so filesystem effects can use a temp dir.
var sshdConfPath = "/etc/ssh/sshd_config.d/00-xpf.conf"

// sshdLegacyConfPath derives the former xpf drop-in location, which shipped
// after the factory file and therefore could not override its PermitRootLogin.
func sshdLegacyConfPath() string {
	return filepath.Join(filepath.Dir(sshdConfPath), "xpf.conf")
}

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
	// #14969: superseded abandoned owner abstains (see applySystemLogin).
	if seamErr := checkHostAuthSeam14969(); seamErr != nil {
		return seamErr
	}
	fail := func(e error) { retErr = errors.Join(retErr, e) }
	var ssh *config.SSHServiceConfig
	if cfg.System.Services != nil {
		ssh = cfg.System.Services.SSH
	}

	// PAM account lockout supplements MaxAuthTries, which is only per
	// connection. The appliance image has password authentication disabled and
	// uses its own factory posture; non-appliance hosts get the shared
	// pam_faillock state when their common-auth stack is the supported Debian
	// baseline. Unknown host PAM stacks remain administrator-owned and are
	// reported without changing them.
	//
	// #15229: EVERY faillock failure is advisory. The PAM state is host
	// state the operator owns; a locally tuned (modified) managed block,
	// an unreadable/unwritable common-auth, or any other faillock error
	// must never hard-fail the sshd drop-in policy this apply exists to
	// enforce — a PermitRootLogin revocation must land even when the
	// PAM leg cannot. The failure is logged so the missing lockout (or
	// the tuned block) stays operator-visible, faillockInstalled stays
	// false (nothing was changed, so the #14973 rollback strip is a
	// no-op), and the apply continues to the drop-in.
	faillockInstalled, err := applySSHPAMFaillockChanged()
	if err != nil {
		if errors.Is(err, errSSHPAMFaillockUnsupported) {
			slog.Warn("SSH cross-connection password lockout not applied; host PAM stack is not the supported Debian baseline",
				"err", err)
		} else {
			slog.Warn("SSH cross-connection password lockout not applied; continuing with sshd drop-in apply",
				"err", err)
		}
	}
	// #14973: if this apply changed common-auth (installed or upgraded the
	// managed faillock rules) and the apply as a whole fails, strip those
	// rules again so a failed apply leaves no lockout policy behind — the
	// same posture as revertDropIn for the sshd drop-in. Keyed on the final
	// named result so every failure site is covered without per-site
	// wiring: direct returns (content-build, legacy/remove errors) set
	// retErr before returning, and the validate/reload paths join into
	// retErr via fail(). A nested recovery apply (live-config repair) is a
	// separate invocation with its own faillockInstalled, so it never
	// strips on behalf of an outer failure, and stripping is a no-op when
	// this apply changed nothing (pre-existing admin faillock survives).
	defer func() {
		if retErr != nil {
			if serr := stripSSHPAMFaillockOnRollback(faillockInstalled); serr != nil {
				retErr = errors.Join(retErr, serr)
			}
		}
	}()
	content, contentErr := buildSSHDConfigErr(ssh)
	if contentErr != nil {
		// #14111: a nonempty algorithm restriction that filters to nothing
		// must fail the apply WITHOUT touching the drop-in. Writing the
		// mandatory-bounds-only body (or removing the drop-in) would
		// silently revert sshd to its built-in algorithm defaults; leaving
		// the previously installed drop-in in force and reporting the
		// error keeps the last known restriction until the config is fixed.
		// naked return semantics: retErr is non-nil (contentErr joined),
		// so the deferred #14973 faillock rollback fires.
		return fmt.Errorf("render sshd config: %w", errors.Join(contentErr, retErr))
	}
	if content == "" {
		if live := d.liveConfig12169(); live != nil && live.System.Services != nil &&
			buildSSHDConfig(live.System.Services.SSH) != "" {
			staleRevocationSuperseded12169("remove-sshd-dropin", "sshd")
			return d.applySSHConfig(live)
		}
	}

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
	// Remove the former, later-sorting drop-in during the cutover. A failed
	// removal must fail the apply rather than silently leave an inert policy.
	if content == "" {
		if live := d.liveConfig12169(); live != nil && live.System.Services != nil &&
			buildSSHDConfig(live.System.Services.SSH) != "" {
			staleRevocationSuperseded12169("remove-sshd-dropin", "sshd")
			return d.applySSHConfig(live)
		}
	}
	legacyPath := sshdLegacyConfPath()
	legacyPresent := false
	if legacyPath != sshdConfPath {
		if err := sshdRemoveFile(legacyPath); err == nil {
			legacyPresent = true
		} else if !os.IsNotExist(err) {
			slog.Warn("failed to remove legacy sshd config drop-in", "err", err)
			fail(fmt.Errorf("remove legacy sshd config drop-in: %w", err))
			return
		}
	}

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
		if live := d.liveConfig12169(); live != nil && live.System.Services != nil &&
			buildSSHDConfig(live.System.Services.SSH) != "" {
			staleRevocationSuperseded12169("remove-sshd-dropin", "sshd")
			return d.applySSHConfig(live)
		}
		if !hadDropIn && !legacyPresent && !d.sshdReloadOwed() {
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
			if live := d.liveConfig12169(); live != nil && live.System.Services != nil &&
				buildSSHDConfig(live.System.Services.SSH) != "" {
				staleRevocationSuperseded12169("repair-sshd-dropin-after-reload-error", "sshd")
				fail(d.applySSHConfig(live))
			}
			return
		}
		if live := d.liveConfig12169(); live != nil && live.System.Services != nil &&
			buildSSHDConfig(live.System.Services.SSH) != "" {
			staleRevocationSuperseded12169("repair-sshd-dropin", "sshd")
			return d.applySSHConfig(live)
		}
		slog.Info("SSH config drop-in removed (reverted to defaults)")
		return nil
	}

	// #14693: `!d.sshdReloadOwed()` joins this gate for the same reason
	// it joins the removal branch's early-return gate above. When the drop-in already
	// matches desired but a reload is still owed — e.g. an earlier
	// removal-path reload failed while the file stayed converged — an
	// unconditional early return strands sshd on its previous runtime
	// configuration: the file is right, the daemon never re-reads it,
	// and no later identical apply would ever reach a reload. Falling
	// through re-runs the idempotent write + validate + reload, which
	// is what pays the debt.
	if priorReadable && string(prior) == content && !legacyPresent && !d.sshdReloadOwed() {
		return nil // no change
	}

	// Best-effort create the drop-in directory before writing. If this fails
	// the write below will also fail, but the mkdir error is the real cause
	// (e.g. a read-only /etc) so surface it rather than only the opaque write
	// error.
	//
	// #7609: derived from sshdConfPath rather than repeated as a literal.
	// Byte-identical in production — filepath.Dir("/etc/ssh/sshd_config.d/
	// 00-xpf.conf") IS "/etc/ssh/sshd_config.d" — so this changes no behaviour on
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

// buildSSHDConfig renders the xpf-managed sshd drop-in body for a configured
// SSH service. A missing SSH stanza produces no daemon drop-in: the image's
// factory drop-in owns the unconditional attempt limits (#10825) and the
// unconditional forwarding denial (#14581). Configured
// stanzas repeat those limits before user-selected settings: root-login →
// PermitRootLogin, key-exchange → KexAlgorithms (H5, #2008). sshd validates
// algorithm spellings at reload. filterSSHAlgorithms drops any token that is
// not a safe OpenSSH algorithm name (config.ValidateSSHAlgorithm), the
// render-side belt for #4902.
func filterSSHAlgorithms(in []string) []string {
	out, _ := filterSSHAlgorithmsErr(in)
	return out
}

// filterSSHAlgorithmsErr is filterSSHAlgorithms plus the fail-closed signal
// for the #14111 algorithm-fallback defect: it reports an error when a
// NONEMPTY operator-specified list filters down to nothing. Omitting the
// directive line in that case silently reverted sshd to its built-in
// algorithm defaults — the operator asked for a restriction and got the
// lenient default instead. Partial filtering (some valid tokens remain)
// still renders the survivors; only the all-invalid nonempty case, where
// rendering nothing would DROP the restriction, is an error. An empty
// input list is not an error: the directive was never specified.
func filterSSHAlgorithmsErr(in []string) ([]string, error) {
	out := in[:0:0]
	for _, tok := range in {
		if err := config.ValidateSSHAlgorithm(tok, nil); err != nil {
			slog.Warn("skipping invalid SSH algorithm token", "token", tok, "err", err)
			continue
		}
		out = append(out, tok)
	}
	if len(in) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("all %d SSH algorithm token(s) %q are invalid; refusing to silently revert to sshd defaults", len(in), in)
	}
	return out, nil
}

func buildSSHDConfig(ssh *config.SSHServiceConfig) string {
	content, _ := buildSSHDConfigErr(ssh)
	return content
}

// buildSSHDConfigErr is buildSSHDConfig plus the #14111 fail-closed signal:
// when a nonempty operator-specified algorithm list (key-exchange, ciphers,
// or macs) filters to nothing, it returns an error instead of a drop-in that
// silently omits the requested restriction and reverts sshd to its defaults.
// Callers that mutate or remove the live drop-in (applySSHConfig) use this
// variant and refuse to touch sshd state on error — the previously installed
// drop-in (or factory defaults) stays in force and the apply reports the
// failure so it is retried, never a silent downgrade. Pure render/compare
// callers keep using buildSSHDConfig.
func buildSSHDConfigErr(ssh *config.SSHServiceConfig) (string, error) {
	if ssh == nil {
		return "", nil
	}
	lines := []string{
		"MaxAuthTries 3",
		"LoginGraceTime 30",
		"PermitEmptyPasswords no",
		// #14581: an SSH remote forward can squat on the loopback
		// management port (127.0.0.1:50051) and impersonate xpfd.
		// Login shells are the RBAC-enforced CLI or bash for
		// super-user (#10833); neither needs forwarding on an
		// appliance, so disable it unconditionally in every managed
		// drop-in. The factory drop-in (scripts/image/bake.py) sets
		// the same line for boxes with no ssh stanza.
		"DisableForwarding yes",
	}
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
	// #14111: a nonempty list that filters to EMPTY is an error, not a silent
	// omission — see filterSSHAlgorithmsErr.
	kex, err := filterSSHAlgorithmsErr(ssh.KeyExchange)
	if err != nil {
		return "", fmt.Errorf("key-exchange: %w", err)
	}
	if len(kex) > 0 {
		lines = append(lines, "KexAlgorithms "+strings.Join(kex, ","))
	}
	// #4305 S-4: sshd hardening knobs. sshd validates the algorithm
	// spellings and numeric ranges at reload; xpf gates the injection/breakage
	// shape (#4902) and lets sshd own the spelling check.
	ciphers, err := filterSSHAlgorithmsErr(ssh.Ciphers)
	if err != nil {
		return "", fmt.Errorf("ciphers: %w", err)
	}
	if len(ciphers) > 0 {
		lines = append(lines, "Ciphers "+strings.Join(ciphers, ","))
	}
	macs, err := filterSSHAlgorithmsErr(ssh.MACs)
	if err != nil {
		return "", fmt.Errorf("macs: %w", err)
	}
	if len(macs) > 0 {
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
	// #15282 (V31-S1, residual of #4305): the Junos password-forbidding
	// leaves. NoPasswordAuthentication forbids the password method only;
	// NoPasswords is the broader leaf and also forbids keyboard-interactive
	// (which carries passwords through PAM on Debian). Either renders
	// PasswordAuthentication no exactly once. Absent leaves render nothing:
	// existing stanzas keep host/factory posture.
	if ssh.NoPasswordAuthentication || ssh.NoPasswords {
		lines = append(lines, "PasswordAuthentication no")
	}
	if ssh.NoPasswords {
		lines = append(lines, "KbdInteractiveAuthentication no")
	}
	if len(lines) == 0 {
		return "", nil
	}
	return "# Managed by xpf — do not edit\n" + strings.Join(lines, "\n") + "\n", nil
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
	// #14969: superseded abandoned owner abstains (see applySystemLogin).
	if seamErr := checkHostAuthSeam14969(); seamErr != nil {
		return seamErr
	}
	var releaseApply func()
	defer func() {
		if releaseApply != nil {
			releaseApply()
		}
	}()
	acquireApply := func() error {
		if releaseApply != nil || d == nil || d.applySem == nil {
			return nil
		}
		// A normal apply holds applySem and runs cfg == live, so configured
		// root keys take the write path above this restore. Only a stale
		// owner reaches this branch with live keys desired.
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			return err
		}
		releaseApply = func() { d.applySem.Release(1) }
		return nil
	}
	restoreLiveRootAuth := func() error {
		if err := acquireApply(); err != nil {
			return err
		}
		live := d.liveConfig12169()
		if live == nil || live.System.RootAuthentication == nil ||
			len(live.System.RootAuthentication.SSHKeys) == 0 {
			return nil
		}
		return d.applyRootAuth(live)
	}
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

	// #14694: a malformed root key must not skip the password reconcile
	// below. Record the failure, suppress ONLY the key install, and
	// still apply/lock root's password. Prior xpf-managed keys stay
	// untouched (the bad key is never installed, and its presence is
	// not an emptied list).
	keysValid := true
	if err := validateAuthorizedSSHKeys("root", keys); err != nil {
		fail(err)
		keysValid = false
	}

	// Password: reuse the non-root #1944 reconciler keyed on name "root" / UID 0.
	// It applies a configured hash (with apply-boundary revalidation + marker)
	// and, when the password is absent, D2-locks root ONLY if the marker shows
	// xpf provisioned it — never on a read error, never an already-locked field.
	fail(d.reconcileUserPassword(&config.LoginUser{Name: "root", EncryptedPassword: password}))

	// Keys: write the configured set wholesale, else revoke the xpf-managed file.
	// #14694: invalid keys suppress both branches (see above).
	if !keysValid {
		return retErr
	}
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
		// A timed-out rollback owner may resume after root keys were
		// re-presented. Keep the live keys and ownership marker, repairing
		// them if a promotion raced the removal.
		liveRootAuth := d.liveDesiredRootAuth12169()
		if liveRootAuth != nil && len(liveRootAuth.SSHKeys) > 0 {
			staleRevocationSuperseded12169("remove-root-keys", "root")
			fail(restoreLiveRootAuth())
		} else {
			keysFile := rootAuthorizedKeysPath()
			switch err := os.Remove(keysFile); {
			case err == nil:
				slog.Info("revoked root SSH keys (root-authentication keys removed from config)")
			case os.IsNotExist(err):
			default:
				slog.Warn("failed to remove root authorized_keys after key list emptied",
					"file", keysFile, "err", err)
				fail(fmt.Errorf("revoke root authorized_keys: %w", err))
				return retErr
			}
			if current := d.liveDesiredRootAuth12169(); current != nil && len(current.SSHKeys) > 0 {
				staleRevocationSuperseded12169("repair-root-keys", "root")
				fail(restoreLiveRootAuth())
			} else {
				fail(removeProvenanceMarker(provisionedKeysDir(), "root"))
				// A promotion can race the key-marker unlink itself. Re-run
				// root auth under applySem to restore live keys and ownership.
				if current := d.liveDesiredRootAuth12169(); current != nil && len(current.SSHKeys) > 0 {
					staleRevocationSuperseded12169("restore-root-keys-after-marker-cleanup", "root")
					fail(restoreLiveRootAuth())
				}
			}
		}
	}
	return retErr
}
