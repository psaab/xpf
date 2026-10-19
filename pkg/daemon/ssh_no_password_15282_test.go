package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15282 (V31-S1, residual of #4305): buildSSHDConfigErr must render the
// Junos password-forbidding leaves into the xpf-managed sshd drop-in.
// Before the fix the knobs had no config field at all, so the drop-in never
// carried PasswordAuthentication and a .deb host fell back to its sshd
// default.
//
// RED on revert: removing the render in buildSSHDConfigErr (or the config
// fields feeding it) drops the lines and every positive cell below fails;
// the absent-leaf controls pin that existing stanzas are unchanged.

func TestBuildSSHDConfigNoPasswordKnobs15282(t *testing.T) {
	count := func(s, sub string) int { return strings.Count(s, sub) }
	for _, tc := range []struct {
		name string
		ssh  *config.SSHServiceConfig
		want []string
		not  []string
	}{
		{
			name: "no-password-authentication forbids password only",
			ssh:  &config.SSHServiceConfig{NoPasswordAuthentication: true},
			want: []string{"PasswordAuthentication no"},
			not:  []string{"KbdInteractiveAuthentication"},
		},
		{
			name: "no-passwords forbids password and keyboard-interactive",
			ssh:  &config.SSHServiceConfig{NoPasswords: true},
			want: []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no"},
		},
		{
			name: "both leaves render each line exactly once",
			ssh:  &config.SSHServiceConfig{NoPasswordAuthentication: true, NoPasswords: true},
			want: []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no"},
		},
		{
			name: "absent leaves keep host posture (control)",
			ssh:  &config.SSHServiceConfig{RootLogin: "deny"},
			want: []string{"PermitRootLogin no"},
			not:  []string{"PasswordAuthentication", "KbdInteractiveAuthentication"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildSSHDConfigErr(tc.ssh)
			if err != nil {
				t.Fatalf("buildSSHDConfigErr: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w+"\n") {
					t.Errorf("drop-in missing %q; got:\n%s", w, got)
				}
				if n := count(got, w); n != 1 {
					t.Errorf("drop-in carries %q %d times, want exactly 1; got:\n%s", w, n, got)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(got, n) {
					t.Errorf("drop-in unexpectedly contains %q; got:\n%s", n, got)
				}
			}
			// The plain renderer used by compare/live-check callers agrees.
			if plain := buildSSHDConfig(tc.ssh); plain != got {
				t.Errorf("buildSSHDConfig disagrees with Err variant:\n%q\nvs\n%q", plain, got)
			}
		})
	}
}
