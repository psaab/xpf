package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/sysservices"
)

// #16737 (R3-A45-03): with no `system services ssh` stanza, the local
// CLI must retain an SSH row with the observed host state. RED pre-fix:
// no SSH row was printed.
func TestShowSystemServicesSSHNotManaged16737(t *testing.T) {
	c := newCLIActiveConfigStore(t)
	c.sshdStateFn = func() sysservices.SSHDState { return sysservices.SSHDRunning }
	cfg := c.store.ActiveConfig()
	cfg.System.Services = &config.SystemServicesConfig{}

	var runErr error
	out := captureStdout(t, func() { runErr = c.showSystemServices() })
	if runErr != nil {
		t.Fatalf("showSystemServices(): %v", runErr)
	}
	if !strings.Contains(out, "SSH:            running (not managed") {
		t.Errorf("local CLI dropped the SSH row with no stanza; want the not-managed row:\n%s", out)
	}
}

// #16737 control: with the stanza present, the managed row is unchanged.
func TestShowSystemServicesSSHManagedControl16737(t *testing.T) {
	c := newCLIActiveConfigStore(t)
	cfg := c.store.ActiveConfig()
	cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}

	var runErr error
	out := captureStdout(t, func() { runErr = c.showSystemServices() })
	if runErr != nil {
		t.Fatalf("showSystemServices(): %v", runErr)
	}
	if !strings.Contains(out, "SSH:            enabled (root-login: deny)") {
		t.Errorf("local CLI managed SSH row changed:\n%s", out)
	}
	if strings.Contains(out, "not managed") {
		t.Errorf("local CLI claimed not-managed with a stanza present:\n%s", out)
	}
}
