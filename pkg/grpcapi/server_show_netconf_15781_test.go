package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15781: the gRPC `show system services` twin must not present
// `system services netconf ssh` as served. With NetconfSSH compiled the
// row states configured-but-NOT-served; without it, no row appears.
func TestShowSystemServicesNetconfNotServed15781(t *testing.T) {
	s := newActiveConfigServer(t)
	cfg := s.store.ActiveConfig()
	cfg.System.Services = &config.SystemServicesConfig{
		SSH:        &config.SSHServiceConfig{RootLogin: "deny"},
		NetconfSSH: true,
	}
	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()
	if !strings.Contains(out, "NETCONF SSH:    configured but NOT served") {
		t.Errorf("gRPC renderer omitted NETCONF not-served row:\n%s", out)
	}
	if strings.Contains(out, "NETCONF SSH:    enabled") {
		t.Errorf("gRPC renderer presented NETCONF as enabled/served:\n%s", out)
	}
}

func TestShowSystemServicesNetconfAbsent15781(t *testing.T) {
	s := newActiveConfigServer(t)
	cfg := s.store.ActiveConfig()
	cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	var buf strings.Builder
	s.showSystemServices(&buf)
	if out := buf.String(); strings.Contains(out, "NETCONF") {
		t.Errorf("gRPC renderer showed NETCONF row without netconf ssh:\n%s", out)
	}
}
