package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowSystemServicesSSHRootLoginUnsetDefault_16735 is the RED cell
// for #16735 on the remote (common operator) surface: an ssh stanza
// with no root-login leaf leaves the factory `PermitRootLogin
// prohibit-password` posture in force (root key login accepted), so
// rendering "deny" misstated the enforced posture. The row must report
// the effective deny-password default, matching the local CLI.
func TestShowSystemServicesSSHRootLoginUnsetDefault_16735(t *testing.T) {
	s := newActiveConfigServer(t)
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: ""},
	}

	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()
	if !strings.Contains(out, "SSH:            enabled (root-login: deny-password (default))") {
		t.Errorf("unset root-login must render the effective deny-password default (#16735):\n%s", out)
	}
	if strings.Contains(out, "root-login: deny)") {
		t.Errorf("unset root-login still renders the false deny posture (#16735):\n%s", out)
	}
}

// TestShowSystemServicesSSHRootLoginExplicit_16735 is the
// positive/control cell: every explicitly authored leaf renders as
// authored, unchanged by the unset-default fix.
func TestShowSystemServicesSSHRootLoginExplicit_16735(t *testing.T) {
	for _, tc := range []struct {
		rootLogin string
		want      string
	}{
		{"allow", "root-login: allow"},
		{"deny", "root-login: deny"},
		{"deny-password", "root-login: deny-password"},
	} {
		t.Run(tc.rootLogin, func(t *testing.T) {
			s := newActiveConfigServer(t)
			cfg := s.store.ActiveConfig()
			if cfg == nil {
				t.Fatal("no active config")
			}
			cfg.System.Services = &config.SystemServicesConfig{
				SSH: &config.SSHServiceConfig{RootLogin: tc.rootLogin},
			}
			var buf strings.Builder
			s.showSystemServices(&buf)
			out := buf.String()
			if !strings.Contains(out, tc.want) {
				t.Errorf("explicit %q must render as authored:\n%s", tc.rootLogin, out)
			}
			if strings.Contains(out, "(default)") {
				t.Errorf("explicit %q must not be labelled default:\n%s", tc.rootLogin, out)
			}
		})
	}
}
