package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowSystemAlarmsIncludesFabricAuthUnarmed_13245(t *testing.T) {
	c := newCLIActiveConfigStore(t)
	c.SetFabricAuthUnarmedAlarmFn(func() string {
		return "CRITICAL: fabric authentication remains unarmed; tokenless read-only RPCs are denied"
	})
	var runErr error
	out := captureStdout(t, func() {
		runErr = c.handleShowSystem([]string{"alarms"})
	})
	if runErr != nil {
		t.Fatalf("handleShowSystem(alarms): %v", runErr)
	}
	if !strings.Contains(out, "1 active alarm(s):") ||
		!strings.Contains(out, "fabric authentication remains unarmed") {
		t.Fatalf("local CLI omitted fabric-auth downgrade alarm:\n%s", out)
	}
}

func TestShowSystemServicesIncludesSharedConfigRows_13245(t *testing.T) {
	c := newCLIActiveConfigStore(t)
	cfg := c.store.ActiveConfig()
	cfg.System.Services = &config.SystemServicesConfig{
		SSH:           &config.SSHServiceConfig{RootLogin: "deny"},
		WebManagement: &config.WebManagementConfig{HTTP: true},
		DNSEnabled:    true,
	}
	cfg.Security.Log.Mode = "stream"

	var runErr error
	out := captureStdout(t, func() { runErr = c.showSystemServices() })
	if runErr != nil {
		t.Fatalf("showSystemServices(): %v", runErr)
	}
	for _, want := range []string{
		"SSH:            enabled (root-login: deny)",
		"Web HTTP:       enabled (interface: all)",
		"DNS:            enabled",
		"Security log:   mode stream",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("local CLI system services omitted %q:\n%s", want, out)
		}
	}
}
