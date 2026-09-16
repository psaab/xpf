package daemon

// apply_credential_failclosed_6790_test.go — #6790.
//
// applyTailReconciles ran the five host-credential reconcilers as
//
//	_ = d.applySystemLogin(cfg)
//	_ = d.reconcileSudoers(cfg)
//	_ = d.reconcileAbsentLoginUsers(cfg)
//	_ = d.applySSHConfig(cfg)
//	_ = d.applyRootAuth(cfg)
//
// so EVERY failure they accumulate — an account that could not be created, a
// sudo grant that could not be revoked, a removed operator whose password and
// authorized_keys were NOT revoked, an sshd drop-in that failed validation, a
// root key file that was not written — was discarded and the commit reported
// SUCCESS. #5874 had already made all five RETURN their failures, but only the
// daemon-stop cancel closeout collected them; the ordinary commit path an
// operator actually uses to revoke access kept throwing them away.
//
// These cells drive the REAL applyTailReconciles with exactly ONE owner
// injected to fail and assert the commit result NAMES that owner's failure.
// Because each cell keys on a substring unique to its owner, dropping that
// owner's operand from the tail errors.Join (or reverting its capture to
// `_ =`) reds that cell and only that cell.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// credentialTailFixture6790 is the shared harness: a Daemon whose tail can run
// end-to-end with every NON-credential owner (nft lo0 / host-inbound, DNS,
// VRRP, networkd) stubbed clean, and every credential owner pointed at
// throwaway trees so it is clean UNLESS the cell injects a failure.
//
// The control cell below proves the harness really is clean — without it,
// "the tail returns an error" would be satisfied by a harness in which
// something unrelated fails on every run.
type credentialTailFixture6790 struct {
	d    *Daemon
	cfg  *config.Config
	root string
}

func newCredentialTailFixture6790(t *testing.T) *credentialTailFixture6790 {
	t.Helper()
	installFakeNetworkctl(t)

	origNftApply, origNftDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { nftApplyPayload, nftDeleteTable = origNftApply, origNftDelete })

	root := t.TempDir()

	origUsersDir, origSudoersDir := provisionedUsersDir, sudoersDir
	origSSHDPath, origHomeBase := sshdConfPath, homeBaseDir
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	sudoersDir = filepath.Join(root, "sudoers.d")
	sshdConfPath = filepath.Join(root, "sshd_config.d", "xpf.conf")
	homeBaseDir = filepath.Join(root, "home")
	t.Cleanup(func() {
		provisionedUsersDir, sudoersDir = origUsersDir, origSudoersDir
		sshdConfPath, homeBaseDir = origSSHDPath, origHomeBase
	})
	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		t.Fatalf("seed sudoers dir: %v", err)
	}
	// #7609 REMOVED the MkdirAll that used to sit here. applySSHConfig derives
	// its drop-in directory from sshdConfPath now, so relocating that one var
	// relocates the parent with it and the fixture no longer has to create it.
	// This deletion IS #7609's regression signal: if the parent stops being
	// derived, the write fails with ENOENT and the healthy-control cell below
	// goes red instead of the failure being absorbed into whatever a cell was
	// actually asserting.

	// A readable, valid identity pair holding only root, so no login user
	// resolves and no credential is ever mutated by a cell that did not ask.
	origPasswd, origShadow := passwdPath, shadowPath
	passwdPath = filepath.Join(root, "passwd")
	shadowPath = filepath.Join(root, "shadow")
	t.Cleanup(func() { passwdPath, shadowPath = origPasswd, origShadow })
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("seed passwd: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\n"), 0o644); err != nil {
		t.Fatalf("seed shadow: %v", err)
	}

	// No real process ever runs: id/useradd/chown succeed silently unless a
	// cell replaces this, visudo and the sshd validate/reload are stubbed at
	// their own seams.
	origRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = origRun })

	origValidateSudoers := validateSudoersFile
	validateSudoersFile = func(string) error { return nil }
	t.Cleanup(func() { validateSudoersFile = origValidateSudoers })

	origSSHDValidate, origSSHDReload := sshdValidateCmd, sshdReloadCmd
	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, nil }
	t.Cleanup(func() { sshdValidateCmd, sshdReloadCmd = origSSHDValidate, origSSHDReload })

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}
	return &credentialTailFixture6790{d: d, cfg: cfg, root: root}
}

// tail runs the REAL applyTailReconciles with every head-produced deferred
// error nil, so the only operands that can be non-nil are the ones this
// function's own steps produce.
func (f *credentialTailFixture6790) tail() error {
	return f.d.applyTailReconciles(f.cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

// breakMarkerRoots6790 makes all three ownership-marker roots unusable by
// putting a regular FILE where their parent directory must be: MkdirAll then
// fails with ENOTDIR, which no amount of privilege can bypass (so the cell
// behaves identically for a root and a non-root test runner).
func breakMarkerRoots6790(t *testing.T, root string) {
	t.Helper()
	blocked := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatalf("seed the blocking file: %v", err)
	}
	provisionedUsersDir = filepath.Join(blocked, "provisioned-users")
}

// TestApplyTailIsCleanWithHealthyCredentialReconciles6790 is the PAIRED
// control for every failure cell below. With nothing injected the tail must
// return nil — otherwise "the tail surfaces a credential failure" would be
// satisfied by a tail that fails every commit, which is the opposite defect.
func TestApplyTailIsCleanWithHealthyCredentialReconciles6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	f.cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	if err := f.tail(); err != nil {
		t.Fatalf("applyTailReconciles returned %v with every credential "+
			"reconciler healthy — every commit would now fail closed", err)
	}
}

// TestApplyTailSurfacesSystemLoginFailure6790: the account could not be
// created, so the configured operator cannot log in at all, and the commit
// said success.
func TestApplyTailSurfacesSystemLoginFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	// `id` reports the account missing and `useradd` then refuses.
	runCommandTimeout = func(string, ...string) ([]byte, error) {
		return []byte("simulated: refused"), os.ErrPermission
	}

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while applySystemLogin FAILED " +
			"to create the configured login account — the commit reports " +
			"success over an operator who cannot log in (#6790)")
	}
	if !strings.Contains(err.Error(), "create user") {
		t.Fatalf("the commit error does not carry the system-login failure "+
			"through the tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesSudoersFailure6790: the NOPASSWD grant could not be
// written, so a configured super-user has no sudo — and, on the revoke side,
// the same accumulator carries a grant that could not be REMOVED, which is a
// demoted operator keeping passwordless root.
func TestApplyTailSurfacesSudoersFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	sudoersDir = filepath.Join(f.root, "sudoers-missing") // never created → write fails

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while reconcileSudoers FAILED " +
			"to write a super-user grant — the commit reports success (#6790)")
	}
	if !strings.Contains(err.Error(), "write sudoers grant for") {
		t.Fatalf("the commit error does not carry the sudoers failure through "+
			"the tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesAbsentUserRevocationFailure6790 is the cell the issue is
// really about: an operator removed from config whose credentials were NOT
// revoked because the identity database could not be read. The deprovision
// deliberately fails CLOSED (markers kept, retry next apply) — but the commit
// that ordered the revocation still reported success, so the operator believes
// the account is gone while its password and authorized_keys are live.
func TestApplyTailSurfacesAbsentUserRevocationFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	// A provisioned account that is no longer in config.
	if err := os.MkdirAll(provisionedUsersDir, 0o700); err != nil {
		t.Fatalf("seed the account registry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(provisionedUsersDir, "ghost"), []byte("4242"), 0o600); err != nil {
		t.Fatalf("seed the ghost marker: %v", err)
	}
	// /etc/passwd unreadable (a directory) → lookupUIDErr returns an error →
	// deprovisionLoginUser keeps the markers and reports the failure.
	passwdPath = filepath.Join(f.root, "passwd-as-dir")
	if err := os.MkdirAll(passwdPath, 0o755); err != nil {
		t.Fatalf("seed an unreadable passwd: %v", err)
	}

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while a REMOVED login user's " +
			"credentials could not be revoked — the commit that ordered the " +
			"deprovision reports success while the password and " +
			"authorized_keys stay live (#6790)")
	}
	if !strings.Contains(err.Error(), "read passwd for removed user") {
		t.Fatalf("the commit error does not carry the absent-user revocation "+
			"failure through the tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesSSHConfigFailure6790: the sshd drop-in failed
// validation, so it was reverted and the committed PermitRootLogin posture is
// NOT what sshd is enforcing.
func TestApplyTailSurfacesSSHConfigFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	sshdValidateCmd = func() ([]byte, error) {
		return []byte("simulated: bad configuration option"), os.ErrInvalid
	}

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while the sshd drop-in FAILED " +
			"validation and was reverted — sshd keeps the pre-commit " +
			"root-login posture and the commit reports success (#6790)")
	}
	if !strings.Contains(err.Error(), "validate sshd config") {
		t.Fatalf("the commit error does not carry the sshd failure through the "+
			"tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesRootAuthFailure6790: root's authorized_keys were NOT
// written because the ownership marker could not be recorded, so the committed
// root key set is not the one root actually accepts.
func TestApplyTailSurfacesRootAuthFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.RootAuthentication = &config.RootAuthConfig{
		SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI6790 test@xpf"},
	}
	breakMarkerRoots6790(t, f.root)

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while applyRootAuth SKIPPED " +
			"the root authorized_keys write — the committed root key set is " +
			"not what root accepts and the commit reports success (#6790)")
	}
	if !strings.Contains(err.Error(), "mark root key provisioned") {
		t.Fatalf("the commit error does not carry the root-auth failure through "+
			"the tail errors.Join, got %v", err)
	}
}

// TestApplyTailRunsEveryCredentialOwnerDespiteAnEarlierFailure6790 binds the
// OTHER half of the contract: fail-closed must not become fail-FAST. A login
// reconcile that fails must not skip root-auth — skipping it would leave root's
// credentials at the pre-commit generation, which is the monotonic-revocation
// violation the fail-closed change exists to prevent.
//
// Both failures are injected at once and BOTH must be named in the single
// joined commit error.
func TestApplyTailRunsEveryCredentialOwnerDespiteAnEarlierFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	f.cfg.System.RootAuthentication = &config.RootAuthConfig{
		SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI6790 test@xpf"},
	}
	runCommandTimeout = func(string, ...string) ([]byte, error) {
		return []byte("simulated: refused"), os.ErrPermission
	}
	breakMarkerRoots6790(t, f.root)

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil with TWO credential " +
			"reconcilers failing (#6790)")
	}
	if !strings.Contains(err.Error(), "create user") {
		t.Fatalf("the earlier (system-login) failure is missing from the joined "+
			"commit error: %v", err)
	}
	if !strings.Contains(err.Error(), "mark root key provisioned") {
		t.Fatalf("the LATER (root-auth) owner did not run, or its failure was "+
			"dropped, after an earlier credential reconcile failed — "+
			"fail-closed must not become fail-fast: %v", err)
	}
}

// --- #1960 no-brick / peer-sync classification -----------------------------
//
// Joining five more operands into applyTailReconciles' result changes what
// applyConfigLocked RETURNS, and two callers classify that return rather than
// just reporting it:
//
//   - applyAndSyncCommitted (#4034) skips the push to the standby, and
//   - syncAndApply (#5564) DISCARDS the peer-promoted config,
//
// but ONLY for the two error classes applyErrSkipsPeerSync names: a
// required-protocol-gate error (dataplane disarmed, #2138) or a context
// cancel/deadline (#2926 daemon-stop abort). Every other error is the
// non-fatal best-effort class that must keep syncing, because the config is
// already committed + active and the dataplane armed — skipping the sync there
// is what #4034 fixed.
//
// A credential reconcile failure is a LOCAL, node-specific, transient
// condition (this node's sshd refused, this node's /etc/passwd was briefly
// unreadable). It says nothing about whether the CONFIG is good, so it must
// land in the non-fatal class or a standby would refuse a peer-synced config
// and the nodes would diverge — the #1960 no-brick contract.
//
// These cells pin that classification against the REAL errors the five
// reconcilers produce, not hand-built ones.

// TestCredentialFailuresDoNotSkipThePeerSync6790 is the #1960 no-brick pin.
func TestCredentialFailuresDoNotSkipThePeerSync6790(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *credentialTailFixture6790)
	}{
		{"system-login", func(t *testing.T, f *credentialTailFixture6790) {
			f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{{Name: "admin", Class: "super-user"}}}
			runCommandTimeout = func(string, ...string) ([]byte, error) {
				return []byte("simulated: refused"), os.ErrPermission
			}
		}},
		{"sudoers", func(t *testing.T, f *credentialTailFixture6790) {
			f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{{Name: "admin", Class: "super-user"}}}
			sudoersDir = filepath.Join(f.root, "sudoers-missing")
		}},
		{"absent-login-users", func(t *testing.T, f *credentialTailFixture6790) {
			if err := os.MkdirAll(provisionedUsersDir, 0o700); err != nil {
				t.Fatalf("seed the account registry: %v", err)
			}
			if err := os.WriteFile(filepath.Join(provisionedUsersDir, "ghost"), []byte("4242"), 0o600); err != nil {
				t.Fatalf("seed the ghost marker: %v", err)
			}
			passwdPath = filepath.Join(f.root, "passwd-as-dir")
			if err := os.MkdirAll(passwdPath, 0o755); err != nil {
				t.Fatalf("seed an unreadable passwd: %v", err)
			}
		}},
		{"ssh-config", func(t *testing.T, f *credentialTailFixture6790) {
			f.cfg.System.Services = &config.SystemServicesConfig{
				SSH: &config.SSHServiceConfig{RootLogin: "deny"},
			}
			sshdValidateCmd = func() ([]byte, error) {
				return []byte("simulated: bad configuration option"), os.ErrInvalid
			}
		}},
		{"root-auth", func(t *testing.T, f *credentialTailFixture6790) {
			f.cfg.System.RootAuthentication = &config.RootAuthConfig{
				SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI6790 test@xpf"},
			}
			breakMarkerRoots6790(t, f.root)
		}},
		{"external-command-killed-by-timeout", func(t *testing.T, f *credentialTailFixture6790) {
			// The shape externalCommandTimeout produces in practice: the process
			// STARTED and was then killed when the 15s context expired, which
			// exec reports as *exec.ExitError ("signal: killed") — NOT a context
			// error. Injected as that exact shape rather than produced by racing
			// a real `sleep` against a short deadline: which of exec's two error
			// shapes you get depends on whether fork/exec wins the race with the
			// deadline, so sampling it is a reading of the MACHINE, not of the
			// subject (#7563). The pre-expired-start shape is pinned separately
			// by TestACommandDeadlineIsMisclassified6790.
			f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{{Name: "admin", Class: "super-user"}}}
			runCommandTimeout = func(string, ...string) ([]byte, error) {
				return nil, killedByTimeoutErr6790(t)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCredentialTailFixture6790(t)
			tc.setup(t, f)

			err := f.tail()
			if err == nil {
				t.Fatalf("precondition: the %s reconcile did not fail, so this cell "+
					"cannot classify anything", tc.name)
			}
			if applyErrSkipsPeerSync(err) {
				t.Fatalf("a %s credential reconcile failure is classified FATAL by "+
					"applyErrSkipsPeerSync, so applyAndSyncCommitted would skip the "+
					"push to the standby and syncAndApply would DISCARD a "+
					"peer-promoted config. A local, node-specific credential "+
					"failure must never brick a peer sync (#1960). err=%v", tc.name, err)
			}
		})
	}
}

// TestApplyErrSkipsPeerSyncStillCatchesTheFatalClasses6790 is the PAIRED
// positive control for the cells above. Without it, "credential failures are
// not classified fatal" is satisfied by an applyErrSkipsPeerSync that returns
// false for everything — which would break the #4034/#2138 fail-closed
// suppression the classifier exists for.
func TestApplyErrSkipsPeerSyncStillCatchesTheFatalClasses6790(t *testing.T) {
	if !applyErrSkipsPeerSync(context.Canceled) {
		t.Error("context.Canceled is no longer classified fatal — a daemon-stop " +
			"abort would now push a half-applied config to the standby (#2926)")
	}
	// #7618 INVERTED this line rather than deleting it, so the control keeps
	// watching the same input. A wrapped context.DeadlineExceeded is now
	// NON-fatal: the apply context is cancel-only, so a deadline reaching the
	// classifier is always a per-command budget (nft 5s, systemctl, useradd
	// 15s), never the #2926 abort. The Canceled and protocol-gate assertions
	// above and below still carry this cell's original purpose — the
	// classifier cannot degrade to "nothing is fatal".
	if applyErrSkipsPeerSync(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)) {
		t.Error("a wrapped context.DeadlineExceeded is classified fatal again; a " +
			"local command running out of ITS OWN budget would once more skip the " +
			"push to the standby (#7618)")
	}
	gate := fmt.Errorf("apply: %w", dpuserspace.ErrPolicySchedulerProtocolIncompatible)
	if !applyErrSkipsPeerSync(gate) {
		t.Error("a required-protocol-gate error is no longer classified fatal — a " +
			"config that DISARMS the dataplane would now be pushed to the " +
			"standby too (#2138/#4034)")
	}
}

// killedByTimeoutErr6790 returns a REAL *exec.ExitError of the shape
// externalCommandTimeout produces when a started process is killed at the
// deadline. Built by running a command that is killed deterministically (not by
// racing a deadline), so the cell using it is a reading of the subject rather
// than of the scheduler.
func killedByTimeoutErr6790(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sleep", "30")
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the victim process: %v", err)
	}
	cancel() // kill AFTER a successful Start -> ExitError, never ctx.Err()
	err := cmd.Wait()
	if err == nil {
		t.Fatal("the victim process was not killed, so this fixture does not " +
			"carry the shape it claims")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an *exec.ExitError from a killed process, got %T: %v", err, err)
	}
	return fmt.Errorf("create user admin: %w", err)
}

// TestACommandDeadlineIsNotADaemonStopAbort7618 is the INVERSION of
// TestACommandDeadlineIsMisclassifiedAsADaemonStopAbort6790, performed in the
// change that fixed the gap that cell existed to pin — as its own comment
// instructed.
//
// exec.CommandContext has TWO error shapes at a deadline. If the process
// STARTED, the kill surfaces as *exec.ExitError ("signal: killed") — the cell
// above, which was always classified correctly. If the context expires BEFORE
// fork/exec completes, Start returns ctx.Err() and CombinedOutput hands back a
// BARE context.DeadlineExceeded. Which shape you get is decided by whether
// fork/exec wins the race with the deadline, i.e. by machine load, which is
// why the misclassification appeared only under a loaded full-package run.
//
// #7618 removed context.DeadlineExceeded from applyErrSkipsPeerSync's fatal
// set because it never had a true positive there: the apply context is
// cancel-only end to end (see TestApplyCancelContextIsCancelOnly7618), so a
// #2926 daemon-stop abort always arrives as context.Canceled, and every
// DeadlineExceeded reaching the classifier is a per-command budget from a
// runner rooted at context.Background().
//
// "My useradd took 15s" is not "the daemon is stopping": the standby must
// still receive the config.
func TestACommandDeadlineIsNotADaemonStopAbort7618(t *testing.T) {
	preExpired := fmt.Errorf("create user admin: %w", context.DeadlineExceeded)
	if applyErrSkipsPeerSync(preExpired) {
		t.Fatal("a bare context.DeadlineExceeded from a pre-expired command start is " +
			"still classified as the daemon-stop abort class, so applyAndSyncCommitted " +
			"skips the push to the standby and syncAndApply DISCARDS a peer-promoted " +
			"config because a local useradd/nft/systemctl ran out of ITS OWN budget")
	}
}

// TestADaemonStopAbortStillSuppressesTheSync7618 is the other half, and
// without it the change above is indistinguishable from deleting the whole
// clause.
//
// The #2926 abort must STILL suppress the sync: the local node is tearing
// down, the next boot re-applies in full, and reverse-sync-on-reconnect
// converges the peer, so a push racing the transport teardown is avoided.
func TestADaemonStopAbortStillSuppressesTheSync7618(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"bare", context.Canceled},
		{"wrapped", fmt.Errorf("apply aborted at phase boundary: %w", context.Canceled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !applyErrSkipsPeerSync(tc.err) {
				t.Fatal("a #2926 daemon-stop context abort no longer suppresses the peer " +
					"sync; the fix for #7618 was over-applied and now pushes config from a " +
					"node that is tearing down")
			}
		})
	}
}

// TestApplyCancelContextIsCancelOnly7618 binds the PREMISE the #7618 deletion
// rests on, rather than leaving it as prose in a doc comment.
//
// The argument is: DeadlineExceeded can be dropped from the fatal set because
// the apply context can never produce it. That is only true while the context
// is cancel-only — cmd/xpfd/main.go passes context.Background(), Run wraps it
// in signal.NotifyContext, and daemon_run.go derives applyCancelContext with
// context.WithCancel. If anyone ever gives that chain a deadline, a genuine
// abort could arrive as DeadlineExceeded and would no longer suppress the
// sync. This cell is what makes that a red rather than a silent regression.
func TestApplyCancelContextIsCancelOnly7618(t *testing.T) {
	d := &Daemon{}
	ctx, cancel := context.WithCancel(context.Background())
	d.applyCancelContext, d.applyCancel = ctx, cancel
	defer cancel()

	if dl, ok := d.applyCancelCtx().Deadline(); ok {
		t.Fatalf("the apply context carries a deadline (%v); a #2926 abort could now "+
			"surface as context.DeadlineExceeded, which #7618 removed from the fatal "+
			"set — restore the discrimination before adding one", dl)
	}
	// And the error it DOES produce is the one the classifier still treats as
	// fatal. Asserting the absence of a deadline alone would not catch a chain
	// that started reporting some third error.
	cancel()
	if err := d.applyCancelCtx().Err(); !applyErrSkipsPeerSync(err) {
		t.Fatalf("a cancelled apply context yields %v, which applyErrSkipsPeerSync does "+
			"NOT classify as fatal; the #2926 abort would push config from a node that "+
			"is tearing down", err)
	}
	// Non-vacuity: the nil-context fallback must not be what was measured.
	if (&Daemon{}).applyCancelCtx().Done() != nil {
		t.Fatal("the nil fallback is no longer context.Background()")
	}
}
