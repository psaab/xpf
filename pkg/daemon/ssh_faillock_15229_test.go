package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15229 (A45-02): on a non-appliance host whose managed PAM faillock
// block was locally tuned (body no longer byte-equal to any known-good
// variant), applySSHPAMFaillockChanged returned a hard error that was
// NOT wrapped in errSSHPAMFaillockUnsupported. applySSHConfig treated
// only the unsupported sentinel as advisory and returned before
// buildSSHDConfigErr / the drop-in write, so every later SSH policy
// apply — including a PermitRootLogin revocation — was hard-failed by
// an unrelated host-PAM state the operator, not xpf, owns.
//
// Fix direction: every faillock failure is advisory — log it and
// continue to the drop-in. The tuned block itself must stay untouched,
// and the PAM issue must still be reported (log).
//
// RED-on-revert: restoring the hard-return arm in applySSHConfig makes
// both tests fail — applySSHConfig returns the faillock error and the
// recorder sees no drop-in write/removal.

func tunedCommonAuth15229() []byte {
	// Stock stack carrying managed blocks whose body was tuned
	// (deny=99 instead of deny=5): still recognisably xpf-managed,
	// but byte-different from every known-good body.
	return []byte("# Debian pam-auth-update common-auth\n" +
		pamFaillockPreBegin + "\n" +
		"auth requisite pam_faillock.so preauth silent deny=99 fail_interval=600 unlock_time=300 even_deny_root\n" +
		pamFaillockPreEnd + "\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		pamFaillockPostBegin + "\n" +
		"auth [default=die] pam_faillock.so authfail deny=99 fail_interval=600 unlock_time=300 even_deny_root\n" +
		"auth [success=1 default=ignore] pam_faillock.so authsucc deny=99 fail_interval=600 unlock_time=300 even_deny_root\n" +
		pamFaillockPostEnd + "\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
}

// setupTunedFaillockApply15229 installs the sshd seam, then re-points
// the PAM seams at a temp common-auth seeded with the tuned block and
// makes the host non-appliance (installSSHDSeam sets an appliance
// marker, which would exempt the PAM leg entirely).
func setupTunedFaillockApply15229(t *testing.T, r *sshdSeamRecorder) string {
	t.Helper()
	commonAuth := setupFaillockApply14973(t, tunedCommonAuth15229())
	installSSHDSeam(t, r)
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMReadFile = os.ReadFile
	sshdPAMModuleAvailable = func() bool { return true }
	return commonAuth
}

func TestApplySSHConfigTunedFaillockBlockDoesNotBlockRootLoginDeny15229(t *testing.T) {
	r := &sshdSeamRecorder{}
	commonAuth := setupTunedFaillockApply15229(t, r)

	buf, restore := captureSlog(t)
	err := (&Daemon{}).applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"}))
	restore()
	if err != nil {
		t.Fatalf("applySSHConfig with tuned managed faillock block must still apply the sshd drop-in, got: %v", err)
	}
	// The revocation must be in the written drop-in.
	if len(r.writes) == 0 {
		t.Fatal("no sshd drop-in was written — the tuned faillock block blocked the SSH policy apply")
	}
	written := string(r.writes[len(r.writes)-1])
	if !strings.Contains(written, "PermitRootLogin no") {
		t.Fatalf("written drop-in does not carry the root-login revocation:\n%s", written)
	}
	if r.reloads == 0 {
		t.Fatal("sshd was never reloaded — the revocation is not in force")
	}
	// The PAM issue must still be reported, not silently swallowed.
	if !strings.Contains(buf.String(), "faillock") {
		t.Fatalf("tuned faillock block was not reported in the log; logs:\n%s", buf.String())
	}
	// The tuned block is administrator-owned once modified: xpf must
	// neither rewrite nor strip it as a side effect of the drop-in apply.
	got, rerr := os.ReadFile(commonAuth)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != string(tunedCommonAuth15229()) {
		t.Fatalf("tuned common-auth was modified by the drop-in apply:\n got:\n%s\nwant:\n%s", got, tunedCommonAuth15229())
	}
}

func TestApplySSHConfigTunedFaillockBlockDoesNotBlockDropInRemoval15229(t *testing.T) {
	// Clearing the ssh stanza must remove the drop-in even when the
	// managed faillock block is tuned — the hard-fail previously skipped
	// removals as well as writes.
	r := &sshdSeamRecorder{present: []byte("# Managed by xpf\nPermitRootLogin yes\n")}
	_ = setupTunedFaillockApply15229(t, r)

	if err := (&Daemon{}).applySSHConfig(sshConfig(nil)); err != nil {
		t.Fatalf("applySSHConfig clearing ssh with tuned faillock block: %v", err)
	}
	if r.removed == 0 {
		t.Fatal("existing drop-in was not removed — the tuned faillock block blocked the removal")
	}
	if r.reloads == 0 {
		t.Fatal("sshd was never reloaded after drop-in removal")
	}
}
