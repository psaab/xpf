package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// legacyCommonAuth16421 is the pre-#14973 managed stack: the same stock
// Debian sequence carrying the legacy (no even_deny_root) managed blocks.
func legacyCommonAuth16421() []byte {
	return []byte("# Debian pam-auth-update common-auth\n" +
		pamFaillockPreBegin + "\n" + pamFaillockPreauthLegacy + "\n" + pamFaillockPreEnd + "\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		pamFaillockPostBegin + "\n" + pamFaillockAuthfailLegacy + "\n" + pamFaillockAuthsuccLegacy + "\n" + pamFaillockPostEnd + "\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
}

// #16421: a failed first post-upgrade apply must restore the legacy
// faillock rules it upgraded, not strip every managed block and leave
// the host with no SSH password lockout at all. A failed apply that
// freshly installed the rules from stock must still end at stock.
func TestApplySSHConfigRollbackRestoresPriorFaillock16421(t *testing.T) {
	legacy := legacyCommonAuth16421()
	stock := stockCommonAuth11492()
	denySSH := &config.SSHServiceConfig{RootLogin: "deny"}

	tests := []struct {
		name     string
		seed     []byte
		recorder *sshdSeamRecorder
		ssh      *config.SSHServiceConfig
		want     []byte // exact common-auth bytes after the apply; nil = success control
	}{
		{
			name:     "legacy reload failure restores legacy rules",
			seed:     legacy,
			recorder: &sshdSeamRecorder{reloadErr: errors.New("reload failed"), failNthReload: 1},
			ssh:      denySSH,
			want:     legacy,
		},
		{
			name:     "legacy validate failure restores legacy rules",
			seed:     legacy,
			recorder: &sshdSeamRecorder{validateErr: errors.New("bad sshd config")},
			ssh:      denySSH,
			want:     legacy,
		},
		{
			name:     "legacy write failure restores legacy rules",
			seed:     legacy,
			recorder: &sshdSeamRecorder{writeErr: errors.New("disk full")},
			ssh:      denySSH,
			want:     legacy,
		},
		{
			name:     "legacy content-build failure restores legacy rules",
			seed:     legacy,
			recorder: &sshdSeamRecorder{},
			ssh: &config.SSHServiceConfig{
				RootLogin: "deny", KeyExchange: []string{"!!!not-an-algorithm!!!"},
			},
			want: legacy,
		},
		{
			name:     "stock reload failure still ends at stock",
			seed:     stock,
			recorder: &sshdSeamRecorder{reloadErr: errors.New("reload failed"), failNthReload: 1},
			ssh:      denySSH,
			want:     stock,
		},
		{
			name:     "legacy success keeps upgraded rules",
			seed:     legacy,
			recorder: &sshdSeamRecorder{},
			ssh:      denySSH,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			commonAuth := setupFaillockApply14973(t, tc.seed)
			installSSHDSeam(t, tc.recorder)
			// installSSHDSeam sets an appliance marker; undo it so the
			// PAM leg runs, and re-point PAM at our file.
			applianceMarkerFile = filepath.Join(filepath.Dir(commonAuth), "not-an-appliance")
			sshdPAMCommonAuthPath = commonAuth
			sshdPAMModuleAvailable = func() bool { return true }

			err := (&Daemon{}).applySSHConfig(sshConfig(tc.ssh))
			got, rerr := os.ReadFile(commonAuth)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if tc.want == nil {
				// Success control: the legacy rules were upgraded in
				// place and kept.
				if err != nil {
					t.Fatalf("successful apply: %v", err)
				}
				text := string(got)
				if !strings.Contains(text, pamFaillockPreauth) ||
					strings.Contains(text, pamFaillockPreauthLegacy+"\n") {
					t.Fatalf("successful apply must keep upgraded faillock rules:\n%s", text)
				}
				if strings.Count(text, "pam_faillock.so") != 3 {
					t.Fatalf("successful apply has %d faillock calls, want 3:\n%s",
						strings.Count(text, "pam_faillock.so"), text)
				}
				return
			}
			if err == nil {
				t.Fatal("failing apply must return an error")
			}
			if string(got) != string(tc.want) {
				t.Fatalf("rollback did not restore prior common-auth:\n got:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}
