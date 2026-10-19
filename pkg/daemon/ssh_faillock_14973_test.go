package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// D31-05 (#14973) has three legs:
//  1. The managed faillock lines exempt root (no even_deny_root), so root
//     password guessing is never locked out.
//  2. A comment mentioning pam_faillock.so makes renderSSHPAMFaillock believe
//     an admin faillock already exists and silently skip installing.
//  3. applySSHConfig installs the PAM rules but its rollback (drop-in revert
//     on validate/reload failure, content-build failure, write failure) never
//     strips them, leaving lockout policy behind after a failed apply.

func TestRenderSSHPAMFaillockEnforcesRoot14973(t *testing.T) {
	got, changed, err := renderSSHPAMFaillock(stockCommonAuth11492(), true)
	if err != nil || !changed {
		t.Fatalf("render: changed=%v err=%v", changed, err)
	}
	text := string(got)
	for _, line := range []string{pamFaillockPreauth, pamFaillockAuthfail, pamFaillockAuthsucc} {
		if !strings.Contains(line, "even_deny_root") {
			t.Fatalf("managed faillock line %q lacks even_deny_root — root is exempt from lockout", line)
		}
		if !strings.Contains(text, line) {
			t.Fatalf("rendered stack missing managed line %q:\n%s", line, text)
		}
	}
}

func TestRenderSSHPAMFaillockUpgradesLegacyRules14973(t *testing.T) {
	// A host already carrying the pre-#14973 managed rules (no
	// even_deny_root) must be upgraded in place, not refused as
	// "modified": exact-compare against only the new constants would make
	// every previously-installed host fail its next SSH apply.
	legacy := []byte("# Debian pam-auth-update common-auth\n" +
		pamFaillockPreBegin + "\n" + pamFaillockPreauthLegacy + "\n" + pamFaillockPreEnd + "\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		pamFaillockPostBegin + "\n" + pamFaillockAuthfailLegacy + "\n" + pamFaillockAuthsuccLegacy + "\n" + pamFaillockPostEnd + "\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
	got, changed, err := renderSSHPAMFaillock(legacy, true)
	if err != nil || !changed {
		t.Fatalf("upgrade legacy rules: changed=%v err=%v", changed, err)
	}
	text := string(got)
	for _, legacyLine := range []string{pamFaillockPreauthLegacy, pamFaillockAuthfailLegacy, pamFaillockAuthsuccLegacy} {
		if strings.Contains(text, legacyLine+"\n") {
			t.Fatalf("legacy rule %q not upgraded to even_deny_root:\n%s", legacyLine, text)
		}
	}
	for _, line := range []string{pamFaillockPreauth, pamFaillockAuthfail, pamFaillockAuthsucc} {
		if !strings.Contains(text, line) {
			t.Fatalf("upgraded stack missing %q:\n%s", line, text)
		}
	}
	if strings.Count(text, "pam_faillock.so") != 3 {
		t.Fatalf("upgraded stack has %d faillock calls, want 3:\n%s", strings.Count(text, "pam_faillock.so"), text)
	}
	// The upgrade must reach the same bytes as a fresh install.
	fresh, _, err := renderSSHPAMFaillock(stockCommonAuth11492(), true)
	if err != nil || text != string(fresh) {
		t.Fatalf("upgrade != fresh install:\n got:\n%s\nwant:\n%s", text, fresh)
	}
	// And removal strips the legacy body too (rollback path).
	restored, changed, err := renderSSHPAMFaillock(legacy, false)
	if err != nil || !changed || string(restored) != string(stockCommonAuth11492()) {
		t.Fatalf("strip legacy rules: changed=%v err=%v\n%s", changed, err, restored)
	}
	// A tampered body is still refused, not silently stripped.
	tampered := strings.Replace(string(legacy), "deny=5", "deny=99", 1)
	if _, _, err := renderSSHPAMFaillock([]byte(tampered), true); err == nil {
		t.Fatal("tampered managed block must be refused")
	}
}

func TestRenderSSHPAMFaillockIgnoresCommentMention14973(t *testing.T) {
	commented := []byte("# Debian pam-auth-update common-auth\n" +
		"# pam_faillock.so is mentioned in this comment only\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
	got, changed, err := renderSSHPAMFaillock(commented, true)
	if err != nil {
		t.Fatalf("render with comment mention: %v", err)
	}
	if !changed {
		t.Fatalf("comment mentioning pam_faillock.so suppressed faillock install:\n%s", got)
	}
	text := string(got)
	if !strings.Contains(text, pamFaillockPreauth) || !strings.Contains(text, pamFaillockAuthfail) {
		t.Fatalf("comment-mention stack did not gain managed faillock rules:\n%s", text)
	}
	// The comment itself must survive untouched.
	if !strings.Contains(text, "# pam_faillock.so is mentioned in this comment only") {
		t.Fatalf("comment line was not preserved:\n%s", text)
	}
	// Idempotent: re-rendering the installed stack is a no-op.
	again, changed, err := renderSSHPAMFaillock(got, true)
	if err != nil || changed || string(again) != text {
		t.Fatalf("re-render after comment-mention install: changed=%v err=%v", changed, err)
	}
}

func TestRenderSSHPAMFaillockHonoursRealAdminRule14973(t *testing.T) {
	// Control: a REAL (non-comment) admin faillock rule must still suppress
	// the managed install — we must not double-install over admin policy.
	admin := []byte("# Debian pam-auth-update common-auth\n" +
		"auth requisite pam_faillock.so preauth silent deny=3 even_deny_root\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
	got, changed, err := renderSSHPAMFaillock(admin, true)
	if err != nil {
		t.Fatalf("render with real admin rule: %v", err)
	}
	if changed || string(got) != string(admin) {
		t.Fatalf("real admin faillock stack was modified (changed=%v):\n%s", changed, got)
	}
}

// setupFaillockApply14973 points the PAM seams at a real temp common-auth
// seeded with content and makes the host non-appliance.
func setupFaillockApply14973(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	commonAuth := filepath.Join(dir, "common-auth")
	if err := os.WriteFile(commonAuth, content, 0o644); err != nil {
		t.Fatal(err)
	}
	oldMarker, oldPath, oldRead, oldAvail := applianceMarkerFile, sshdPAMCommonAuthPath, sshdPAMReadFile, sshdPAMModuleAvailable
	applianceMarkerFile = filepath.Join(dir, "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMReadFile = os.ReadFile
	// sshdPAMWriteFile keeps its production value (fsatomic.WriteFileAtomic),
	// as in TestApplySSHConfigInstallsFaillockOnNonAppliance11492.
	sshdPAMModuleAvailable = func() bool { return true }
	t.Cleanup(func() {
		applianceMarkerFile, sshdPAMCommonAuthPath, sshdPAMReadFile, sshdPAMModuleAvailable = oldMarker, oldPath, oldRead, oldAvail
	})
	return commonAuth
}

func TestApplySSHConfigRollbackStripsFaillockOnReloadFailure14973(t *testing.T) {
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())
	r := &sshdSeamRecorder{reloadErr: errors.New("reload failed"), failNthReload: 1}
	installSSHDSeam(t, r)
	// installSSHDSeam sets an appliance marker; undo it so the PAM leg runs,
	// and re-point PAM at our file (TestMain defaults point elsewhere).
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }

	err := (&Daemon{}).applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"}))
	if err == nil {
		t.Fatal("apply with failing reload must return an error")
	}
	got, rerr := os.ReadFile(commonAuth)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if strings.Contains(string(got), "pam_faillock.so") || strings.Contains(string(got), "xpf SSH faillock") {
		t.Fatalf("rollback after reload failure left managed faillock rules in common-auth:\n%s", got)
	}
	if string(got) != string(stockCommonAuth11492()) {
		t.Fatalf("rollback did not restore stock common-auth:\n got:\n%s\nwant:\n%s", got, stockCommonAuth11492())
	}
}

func TestApplySSHConfigRollbackStripsFaillockOnValidateFailure14973(t *testing.T) {
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())
	r := &sshdSeamRecorder{validateErr: errors.New("bad sshd config")}
	installSSHDSeam(t, r)
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }

	err := (&Daemon{}).applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"}))
	if err == nil {
		t.Fatal("apply with failing validation must return an error")
	}
	got, rerr := os.ReadFile(commonAuth)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if strings.Contains(string(got), "pam_faillock.so") {
		t.Fatalf("rollback after validate failure left managed faillock rules:\n%s", got)
	}
}

func TestApplySSHConfigRollbackStripsFaillockOnWriteFailure14973(t *testing.T) {
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())
	r := &sshdSeamRecorder{writeErr: errors.New("disk full")}
	installSSHDSeam(t, r)
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }

	err := (&Daemon{}).applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"}))
	if err == nil {
		t.Fatal("apply with failing drop-in write must return an error")
	}
	got, rerr := os.ReadFile(commonAuth)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if strings.Contains(string(got), "pam_faillock.so") {
		t.Fatalf("rollback after write failure left managed faillock rules:\n%s", got)
	}
}

func TestApplySSHConfigRollbackStripsFaillockOnContentBuildFailure14973(t *testing.T) {
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())
	r := &sshdSeamRecorder{}
	installSSHDSeam(t, r)
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }

	// A key-exchange restriction that filters to nothing makes
	// buildSSHDConfigErr fail (#14111) after faillock was installed.
	err := (&Daemon{}).applySSHConfig(sshConfig(&config.SSHServiceConfig{
		RootLogin: "deny", KeyExchange: []string{"!!!not-an-algorithm!!!"},
	}))
	if err == nil {
		t.Fatal("apply with unbuildable sshd config must return an error")
	}
	got, rerr := os.ReadFile(commonAuth)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if strings.Contains(string(got), "pam_faillock.so") {
		t.Fatalf("rollback after content-build failure left managed faillock rules:\n%s", got)
	}
}

func TestApplySSHConfigSuccessKeepsFaillock14973(t *testing.T) {
	// Control: a successful apply must KEEP the installed faillock rules.
	commonAuth := setupFaillockApply14973(t, stockCommonAuth11492())
	r := &sshdSeamRecorder{}
	installSSHDSeam(t, r)
	applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }

	if err := (&Daemon{}).applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"})); err != nil {
		t.Fatalf("successful apply: %v", err)
	}
	got, err := os.ReadFile(commonAuth)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), pamFaillockPreauth) {
		t.Fatalf("successful apply must keep faillock rules:\n%s", got)
	}
}
