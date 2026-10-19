package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15781: `show system services` must not present `system services
// netconf ssh` as a served NETCONF service. With NetconfSSH compiled,
// the row states configured-but-NOT-served; without it, no row appears.
func TestShowSystemServicesNetconfNotServed15781(t *testing.T) {
	c := newCLIActiveConfigStore(t)
	cfg := c.store.ActiveConfig()
	cfg.System.Services = &config.SystemServicesConfig{
		SSH:        &config.SSHServiceConfig{RootLogin: "deny"},
		NetconfSSH: true,
	}
	var runErr error
	out := captureStdout(t, func() { runErr = c.showSystemServices() })
	if runErr != nil {
		t.Fatalf("showSystemServices(): %v", runErr)
	}
	if !strings.Contains(out, "NETCONF SSH:    configured but NOT served") {
		t.Errorf("local CLI omitted NETCONF not-served row:\n%s", out)
	}
	if strings.Contains(out, "NETCONF SSH:    enabled") {
		t.Errorf("local CLI presented NETCONF as enabled/served:\n%s", out)
	}
}

func TestShowSystemServicesNetconfAbsent15781(t *testing.T) {
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
	if strings.Contains(out, "NETCONF") {
		t.Errorf("local CLI showed NETCONF row without netconf ssh:\n%s", out)
	}
}
