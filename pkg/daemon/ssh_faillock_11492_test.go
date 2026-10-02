package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stockCommonAuth11492() []byte {
	return []byte("# Debian pam-auth-update common-auth\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
}

func TestRenderSSHPAMFaillockAddsAccountLockout11492(t *testing.T) {
	original := stockCommonAuth11492()
	got, changed, err := renderSSHPAMFaillock(original, true)
	if err != nil {
		t.Fatalf("renderSSHPAMFaillock: %v", err)
	}
	if !changed {
		t.Fatal("stock PAM authentication stack did not gain cross-connection lockout rules")
	}
	text := string(got)
	pre := strings.Index(text, pamFaillockPreauth)
	unix := strings.Index(text, "pam_unix.so nullok")
	failed := strings.Index(text, pamFaillockAuthfail)
	success := strings.Index(text, pamFaillockAuthsucc)
	deny := strings.Index(text, "pam_deny.so")
	if pre < 0 || unix <= pre || failed <= unix || success <= failed || deny <= success {
		t.Fatalf("faillock control flow does not check lockout, record failure, clear success, then fall through to pam_deny:\n%s", text)
	}
	for _, required := range []string{"deny=5", "fail_interval=600", "unlock_time=300"} {
		if !strings.Contains(text, required) {
			t.Errorf("faillock policy omitted %q:\n%s", required, text)
		}
	}
	if strings.Count(text, "pam_faillock.so") != 3 {
		t.Fatalf("rendered PAM stack has %d faillock calls, want preauth/authfail/authsucc", strings.Count(text, "pam_faillock.so"))
	}
}

func TestRenderSSHPAMFaillockIsIdempotentAndReversible11492(t *testing.T) {
	original := stockCommonAuth11492()
	installed, changed, err := renderSSHPAMFaillock(original, true)
	if err != nil || !changed {
		t.Fatalf("initial install: changed=%v err=%v", changed, err)
	}
	repeated, changed, err := renderSSHPAMFaillock(installed, true)
	if err != nil || changed || string(repeated) != string(installed) {
		t.Fatalf("repeat install: changed=%v err=%v; stack should be byte-identical", changed, err)
	}
	restored, changed, err := renderSSHPAMFaillock(installed, false)
	if err != nil || !changed || string(restored) != string(original) {
		t.Fatalf("remove managed rules: changed=%v err=%v\nrestored:\n%s\noriginal:\n%s", changed, err, restored, original)
	}
}

func TestRenderSSHPAMFaillockLeavesCustomStackUntouched11492(t *testing.T) {
	custom := []byte("auth sufficient pam_sss.so\nauth requisite pam_deny.so\n")
	got, changed, err := renderSSHPAMFaillock(custom, true)
	if !errors.Is(err, errSSHPAMFaillockUnsupported) || changed || got != nil {
		t.Fatalf("custom PAM stack result = (%q, %v, %v), want unsupported without mutation", got, changed, err)
	}
}

func TestApplySSHConfigInstallsFaillockOnNonAppliance11492(t *testing.T) {
	installSSHDSeam(t, &sshdSeamRecorder{})
	dir := t.TempDir()
	commonAuth := filepath.Join(dir, "common-auth")
	if err := os.WriteFile(commonAuth, stockCommonAuth11492(), 0o644); err != nil {
		t.Fatal(err)
	}
	oldMarker := applianceMarkerFile
	oldPAMPath := sshdPAMCommonAuthPath
	oldPAMRead := sshdPAMReadFile
	oldPAMWrite := sshdPAMWriteFile
	oldPAMAvailable := sshdPAMModuleAvailable
	applianceMarkerFile = filepath.Join(dir, "not-an-appliance")
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMReadFile = os.ReadFile
	sshdPAMModuleAvailable = func() bool { return true }
	t.Cleanup(func() {
		applianceMarkerFile = oldMarker
		sshdPAMCommonAuthPath = oldPAMPath
		sshdPAMReadFile = oldPAMRead
		sshdPAMWriteFile = oldPAMWrite
		sshdPAMModuleAvailable = oldPAMAvailable
	})

	if err := (&Daemon{}).applySSHConfig(sshConfig(nil)); err != nil {
		t.Fatalf("applySSHConfig: %v", err)
	}
	got, err := os.ReadFile(commonAuth)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), pamFaillockAuthfail) || !strings.Contains(string(got), pamFaillockAuthsucc) {
		t.Fatalf("non-appliance SSH apply did not install cross-connection account lockout rules:\n%s", got)
	}
}

func TestApplySSHPAMFaillockSkipsAppliance11492(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "appliance")
	if err := os.WriteFile(marker, []byte("appliance\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commonAuth := filepath.Join(dir, "common-auth")
	if err := os.WriteFile(commonAuth, stockCommonAuth11492(), 0o644); err != nil {
		t.Fatal(err)
	}
	oldMarker := applianceMarkerFile
	oldPAMPath := sshdPAMCommonAuthPath
	oldPAMAvailable := sshdPAMModuleAvailable
	applianceMarkerFile = marker
	sshdPAMCommonAuthPath = commonAuth
	sshdPAMModuleAvailable = func() bool { return true }
	t.Cleanup(func() {
		applianceMarkerFile = oldMarker
		sshdPAMCommonAuthPath = oldPAMPath
		sshdPAMModuleAvailable = oldPAMAvailable
	})

	if err := applySSHPAMFaillock(); err != nil {
		t.Fatalf("appliance should skip host PAM faillock setup: %v", err)
	}
	got, err := os.ReadFile(commonAuth)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(stockCommonAuth11492()) {
		t.Fatalf("appliance PAM stack was modified:\n%s", got)
	}
}
