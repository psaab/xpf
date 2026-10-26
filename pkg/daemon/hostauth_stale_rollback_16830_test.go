package daemon

// hostauth_stale_rollback_16830_test.go — #16830 (R3-F11-01).
//
// #15539 fenced every DIRECT host-auth write, but a superseded owner's
// COMPENSATING actions were still unfenced, so its failure handling
// undid the newer authority's work:
//
//  1. applySystemLogin: keyClaim.rollback() (login_password.go) called
//     the raw removeProvenanceMarker. A stale owner parked between its
//     fenced claim (marker absent → preExisting=false) and its fenced
//     write resumed after a newer authority wrote K2 under the marker;
//     the fenced write refused stale, and the unfenced rollback then
//     unlinked the marker. The next empty-key revocation is
//     marker-gated, so K2 stayed installed while the commit succeeded.
//  2. applySSHConfig: the deferred restoreSSHPAMFaillockOnRollback
//     wrote through the raw sshdPAMWriteFile, stripping the faillock
//     the newer authority had just installed.
//  3. exec seam: a chpasswd that COMPLETED before supersession was
//     observed had its result discarded for the stale sentinel, so
//     reconcileUserPassword rolled back the password/account markers
//     for a mutation that may have landed.
//
// Fix: rollback() routes through removeProvenanceMarkerFenced14969;
// sshdPAMWriteFile is the fenced guardedWriteFileAtomic14969 and
// restoreSSHPAMFaillockOnRollback checks the seam (plus the deferred
// caller skips stale/completed-superseded triggers); the exec seam
// returns a completed child's real result marked
// errHostAuthExecCompletedSuperseded16830, never the stale sentinel.
//
// Fail-on-revert: restore the raw removeProvenanceMarker in rollback,
// the raw fsatomic PAM writer, or the discarded-result exec arm and
// the corresponding cell below goes RED.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// markerExists16830 reports whether name's marker exists in dir.
func markerExists16830(dir, name string) bool {
	_, err := os.Stat(markerPathIn(dir, name))
	return err == nil
}

// TestStaleOwnerKeyRollbackKeepsNewerMarker16830 is the key-marker
// defect cell. It drives the real applySystemLogin: the owner claims
// (marker absent), parks inside chownSSHDir (the seam immediately
// before the fenced durable write), a newer authority completes the
// same apply under the now-pre-existing marker, then the stale owner
// resumes — its write refuses stale and its compensating rollback
// must NOT withdraw the marker. The subsequent revocation (retained
// user, keys emptied) must then remove the key file.
func TestStaleOwnerKeyRollbackKeepsNewerMarker16830(t *testing.T) {
	stageLoginTree15539(t)
	keysFile := seedAliceKeys15539(t, "ssh-ed25519 OLDKEY alice@xpf\n")

	origChown := chownSSHDir
	h := newSupersedeHarness15539()
	chownSSHDir = func(string, int, int) error { h.block(); return nil }
	t.Cleanup(func() { chownSSHDir = origChown })

	d := &Daemon{}
	errCh := make(chan error, 1)
	gen := beginHostAuthAuthority14969()
	go func() {
		errCh <- runWithHostAuthGeneration14969(gen, func() error {
			return d.applySystemLogin(aliceCfg15539())
		})
	}()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stale owner never reached the blocked chown seam")
	}
	if !markerExists16830(provisionedKeysDir(), "alice") {
		t.Fatal("premise: stale owner did not claim the key marker before parking")
	}

	// Newer authority: advance the epoch and complete the same apply
	// uncaptured (the normal tail). It sees the marker pre-existing
	// and is never fence-refused.
	beginHostAuthAuthority14969()
	chownSSHDir = func(string, int, int) error { return nil }
	if cerr := d.applySystemLogin(aliceCfg15539()); errors.Is(cerr, errHostAuthStaleOwner14969) {
		t.Fatalf("newer authority apply fence-refused: %v", cerr)
	}
	if !markerExists16830(provisionedKeysDir(), "alice") {
		t.Fatal("premise: marker missing after newer authority completed")
	}

	// Release the stale owner: its fenced write now refuses stale and
	// its rollback fires. Pre-fix the rollback unlinks the marker.
	close(h.release)
	select {
	case err := <-errCh:
		if !errors.Is(err, errHostAuthStaleOwner14969) {
			t.Fatalf("stale owner apply = %v, want errHostAuthStaleOwner14969", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stale owner did not return after supersession")
	}
	if !markerExists16830(provisionedKeysDir(), "alice") {
		t.Fatal("stale owner's rollback withdrew the newer authority's key marker (#16830)")
	}

	// Revocation: retained user with an emptied key list is
	// marker-gated. With the marker intact the key file is removed;
	// pre-fix the marker was gone and it survived a successful commit.
	emptyCfg := &config.Config{}
	emptyCfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{{
		Name:              "alice",
		Class:             "super-user",
		EncryptedPassword: config.NewSecret(testHash15539),
	}}}
	if rerr := d.applySystemLogin(emptyCfg); rerr != nil {
		t.Fatalf("revocation apply: %v", rerr)
	}
	if _, serr := os.Stat(keysFile); !os.IsNotExist(serr) {
		got, _ := os.ReadFile(keysFile)
		t.Fatalf("revoked key file survived (stat err=%v): %q — marker-gated revocation was disarmed by the stale rollback", serr, got)
	}
}

// TestStaleRollbackKeepsNewerMarkerDirect16830 pins the rollback unit
// directly: a claim created while current, followed by supersession,
// must survive the stale owner's rollback. The non-stale control
// still withdraws a claim this pass created.
func TestStaleRollbackKeepsNewerMarkerDirect16830(t *testing.T) {
	stageLoginTree15539(t)
	dir := provisionedKeysDir()

	gen := beginHostAuthAuthority14969()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runWithHostAuthGeneration14969(gen, func() error {
			claim, err := claimOwnershipFenced14969(dir, "alice", 1001)
			if err != nil {
				return err
			}
			if claim.preExisting {
				return errors.New("premise: first claim must not be pre-existing")
			}
			beginHostAuthAuthority14969() // newer authority supersedes
			claim.rollback()              // compensating withdrawal — must abstain
			return nil
		})
	}()
	<-done
	if !markerExists16830(dir, "alice") {
		t.Fatal("stale rollback removed the key marker (#16830)")
	}

	// Control: an uncaptured (current) rollback still withdraws.
	fresh, err := claimOwnership(dir, "carol", 1003)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.preExisting {
		t.Fatal("premise: carol claim must be fresh")
	}
	fresh.rollback()
	if markerExists16830(dir, "carol") {
		t.Fatal("control: current-owner rollback did not withdraw its fresh claim")
	}
}

// TestStaleFaillockRollbackKeepsNewerFaillock16830 is the PAM defect
// cell at the seam level: a stale owner's direct PAM write is refused
// by the fenced writer and its compensating restore abstains, so the
// installed faillock survives. The uncaptured control restore still
// restores the stock stack.
func TestStaleFaillockRollbackKeepsNewerFaillock16830(t *testing.T) {
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())

	gen := beginHostAuthAuthority14969()
	var writeErr, restoreErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runWithHostAuthGeneration14969(gen, func() error {
			installed, prior, err := applySSHPAMFaillockChanged()
			if err != nil {
				return err
			}
			if !installed {
				return errors.New("premise: faillock not installed by owner")
			}
			beginHostAuthAuthority14969() // newer authority supersedes
			writeErr = sshdPAMWriteFile(commonAuth, stockCommonAuth11492(), 0o644)
			restoreErr = restoreSSHPAMFaillockOnRollback(true, prior)
			return nil
		})
	}()
	<-done
	if !errors.Is(writeErr, errHostAuthStaleOwner14969) {
		t.Fatalf("stale PAM write = %v, want errHostAuthStaleOwner14969", writeErr)
	}
	if !errors.Is(restoreErr, errHostAuthStaleOwner14969) {
		t.Fatalf("stale faillock restore = %v, want errHostAuthStaleOwner14969", restoreErr)
	}
	got, err := os.ReadFile(commonAuth)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "pam_faillock.so") {
		t.Fatalf("stale rollback stripped the newer authority's faillock:\n%s", got)
	}

	// Control: uncaptured restore still restores stock.
	if err := restoreSSHPAMFaillockOnRollback(true, stockCommonAuth11492()); err != nil {
		t.Fatalf("control restore: %v", err)
	}
	got, err = os.ReadFile(commonAuth)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "pam_faillock.so") {
		t.Fatalf("control: uncaptured rollback did not restore stock common-auth:\n%s", got)
	}
}

// TestStaleApplySSHConfigKeepsNewerFaillock16830 drives the real
// applySSHConfig deferred rollback: the owner installs faillock,
// parks inside the validate seam, is superseded, then validation
// fails — retErr is set and the deferred restore fires while stale.
// It must keep the faillock. Pre-fix it restored the stock bytes.
func TestStaleApplySSHConfigKeepsNewerFaillock16830(t *testing.T) {
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())
	r := &sshdSeamRecorder{}
	installSSHDSeam(t, r)
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }

	origValidate := sshdValidateCmd
	h := newSupersedeHarness15539()
	sshdValidateCmd = func() ([]byte, error) {
		h.block()
		return []byte("bad configuration"), errors.New("bad sshd config")
	}
	t.Cleanup(func() { sshdValidateCmd = origValidate })

	d := &Daemon{}
	err := h.run(t, func() error {
		return d.applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"}))
	})
	if err == nil {
		t.Fatal("apply with failing validation must return an error")
	}
	got, rerr := os.ReadFile(commonAuth)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(got), "pam_faillock.so") {
		t.Fatalf("stale applySSHConfig rollback stripped the faillock:\n%s", got)
	}
}

// TestCompletedExecSupersededKeepsResult16830 pins the exec-seam arm:
// a child that completes successfully but whose owner is superseded
// while it runs reports the completed-but-superseded marker (with its
// real output), NOT the stale sentinel — so claim rollback does not
// withdraw provenance for a mutation that may have landed. A
// watcher-KILLED child still reports stale (pinned unchanged by
// TestSupersededInFlightExecKilled15539).
func TestCompletedExecSupersededKeepsResult16830(t *testing.T) {
	// The body advances the epoch itself, then returns success. The
	// context is not cancelled at the post-check instant in this
	// deterministic interleaving (the body does not wait on ctx), so
	// the seam classifies it as completed-but-superseded.
	gen := beginHostAuthAuthority14969()
	var out []byte
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runWithHostAuthGeneration14969(gen, func() error {
			out, err = runWithHostAuthExec15539(func(context.Context) ([]byte, error) {
				beginHostAuthAuthority14969()
				return []byte("child-output"), nil
			})
			return nil
		})
	}()
	<-done
	if string(out) != "child-output" {
		t.Fatalf("completed child output discarded: %q", out)
	}
	if !errors.Is(err, errHostAuthExecCompletedSuperseded16830) {
		t.Fatalf("completed-but-superseded exec = %v, want errHostAuthExecCompletedSuperseded16830", err)
	}
	if errors.Is(err, errHostAuthStaleOwner14969) {
		t.Fatalf("completed child must not report the stale sentinel (callers would roll back): %v", err)
	}

	// Control: no supersession → plain success, no marker.
	genNow := hostAuthGeneration14969.Load()
	var cerr error
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		_ = runWithHostAuthGeneration14969(genNow, func() error {
			_, cerr = runWithHostAuthExec15539(func(context.Context) ([]byte, error) {
				return []byte("ok"), nil
			})
			return nil
		})
	}()
	<-done2
	if cerr != nil {
		t.Fatalf("control exec = %v, want nil", cerr)
	}

	// Completed-with-error child: the real error is preserved under
	// the completed marker, still without the stale sentinel.
	gen3 := beginHostAuthAuthority14969()
	childErr := errors.New("child failed")
	var err3 error
	done3 := make(chan struct{})
	go func() {
		defer close(done3)
		_ = runWithHostAuthGeneration14969(gen3, func() error {
			_, err3 = runWithHostAuthExec15539(func(context.Context) ([]byte, error) {
				beginHostAuthAuthority14969()
				return nil, childErr
			})
			return nil
		})
	}()
	<-done3
	if !errors.Is(err3, errHostAuthExecCompletedSuperseded16830) || !errors.Is(err3, childErr) {
		t.Fatalf("completed failed child = %v, want completed marker wrapping the child error", err3)
	}
	if errors.Is(err3, errHostAuthStaleOwner14969) {
		t.Fatalf("completed failed child must not report the stale sentinel: %v", err3)
	}
}
