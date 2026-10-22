// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"errors"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// hostauth_live_fence_12169.go — #12169 F1: completion-fenced host-auth
// revocation.
//
// The #12169 first-commit rollback reuses the bounded closeout runner on the
// LIVE rollback path. When the runner's budget expires the in-flight owner is
// abandoned but keeps running: its blocked `chpasswd` (or a not-yet-started
// removal) resumes AFTER a later commit promoted the same accounts, and
// locks/deletes credentials the new commit owns. The runner's context is
// never threaded into the owner (it cannot be — SIGKILLing the zombie is
// provably wrong: the new commit must return while the old revocation is
// still blocked, and the in-flight process holds state only it can repair),
// so the fence lives IN the revocation operations themselves:
//
//   - PRE-mutation: re-read the LIVE active config before revoking a
//     credential; if it desires the credential, abstain and retain markers.
//     A stale deprovision owner's live-login restore instead acquires
//     applySem before applying, re-reads live intent under the permit, and
//     keeps the permit through owner return.
//   - POST-mutation (blocking mutations only — `chpasswd`, sshd reload): the
//     process may have been spawned pre-promotion and resumed
//     post-promotion. Password repairs made before settlement can therefore
//     write stale state; settlement reacquires applySem, compares with live
//     intent, and repairs or relocks before provenance cleanup. It retains the
//     permit through cleanup. If a stale password write lands after removal
//     and a password-less re-add, settlement restores provenance before the
//     declarative D2 lock. Root repairs via repairStalePasswordLock12169 also
//     settle under applySem; the direct pre-lock root repair retains markers
//     for a later apply rather than providing that settlement guarantee.
//
// Under applySem the passed config IS the live config, so stale restore checks
// are no-ops on the healthy path. Login-tail restores, password settlements,
// root-key restores, and sudoers repairs acquire or retain the permit through
// their mutation, preventing promotion from changing intent during repair.
// All helpers are nil-safe: a nil Daemon or nil store (unit tests driving
// reconcilers directly) disables the fence and preserves stand-alone behavior.

// liveConfig12169 returns the current live active config, or nil when there
// is no store to read it from (nil-safe for direct reconciler tests).
func (d *Daemon) liveConfig12169() *config.Config {
	if d == nil || d.store == nil {
		return nil
	}
	return d.store.ActiveConfig()
}

// liveDesiredLoginUser12169 reports the LIVE desired login user for name, or
// false when the live config does not declare it (or is unavailable). Root
// is never a login user; root intent comes from liveDesiredRootAuth12169.
func (d *Daemon) liveDesiredLoginUser12169(name string) (config.LoginUser, bool) {
	live := d.liveConfig12169()
	if live == nil || live.System.Login == nil {
		return config.LoginUser{}, false
	}
	for _, u := range live.System.Login.Users {
		if u != nil && u.Name == name {
			return *u, true
		}
	}
	return config.LoginUser{}, false
}

// liveDesiredRootAuth12169 reports the LIVE root-authentication stanza, or
// nil when the live config carries none (or is unavailable).
func (d *Daemon) liveDesiredRootAuth12169() *config.RootAuthConfig {
	live := d.liveConfig12169()
	if live == nil {
		return nil
	}
	return live.System.RootAuthentication
}

// liveDesiredPasswordUser12169 returns the password directive from the live
// login/root-auth stanza. The boolean distinguishes an absent stanza from an
// explicitly present stanza with no password.
func (d *Daemon) liveDesiredPasswordUser12169(name string) (config.LoginUser, bool) {
	if name == "root" {
		ra := d.liveDesiredRootAuth12169()
		if ra == nil {
			return config.LoginUser{}, false
		}
		return config.LoginUser{Name: "root", EncryptedPassword: ra.EncryptedPassword}, true
	}
	return d.liveDesiredLoginUser12169(name)
}

// repairStalePasswordLock12169 re-applies a live password after a timed-out
// owner resumes from its captured `name:!` chpasswd. It reports whether the
// live config still desires an encrypted password and therefore superseded
// the stale lock operation. Only an abandoned closeout owner can observe a
// mismatch: normal apply callers hold applySem and apply the promoted config.
func (d *Daemon) repairStalePasswordLock12169(name string) (bool, error) {
	live, ok := d.liveDesiredPasswordUser12169(name)
	if !ok || live.EncryptedPassword.Reveal() == "" {
		return false, nil
	}
	staleRevocationSuperseded12169("repair-password", name)
	repairErr := d.reconcileUserPassword(&live)
	if name != "root" {
		return true, repairErr
	}
	return true, errors.Join(repairErr, d.settleStaleRootPassword12169())
}

// settleStaleRootPassword12169 revalidates root's password after a stale
// closeout repair while serialized with config commits. The caller is an
// abandoned owner, not a normal apply already holding applySem.
func (d *Daemon) settleStaleRootPassword12169() error {
	if d != nil && d.applySem != nil {
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			return err
		}
		defer d.applySem.Release(1)
	}

	live, desired := d.liveDesiredPasswordUser12169("root")
	if !desired {
		live = config.LoginUser{Name: "root"}
	}
	return d.reconcileUserPassword(&live)
}

// liveDesiredSudoersGrant12169 reports whether the LIVE config desires the
// xpf-<user> sudo grant: a declared super-user with a committable name,
// mirroring reconcileSudoers' own desire rule.
func (d *Daemon) liveDesiredSudoersGrant12169(user string) bool {
	if err := config.ValidateLoginUsername(user); err != nil {
		return false
	}
	u, ok := d.liveDesiredLoginUser12169(user)
	return ok && u.Class == "super-user"
}

// liveDesiredSSH12169 reports the LIVE ssh service stanza, or nil when the
// live config carries none (or is unavailable). Nil-safe down the chain.
func (d *Daemon) liveDesiredSSH12169() *config.SSHServiceConfig {
	live := d.liveConfig12169()
	if live == nil || live.System.Services == nil {
		return nil
	}
	return live.System.Services.SSH
}

// staleRevocationSuperseded12169 logs the fail-visible record of a stale
// owner abstaining from (or repairing) a revocation the live config now
// desires. One call site per fenced operation keeps the attribution exact.
func staleRevocationSuperseded12169(op, target string) {
	slog.Info("stale host-auth revocation superseded by a newer commit; converging to the live config instead of revoking",
		"op", op, "target", target)
}
