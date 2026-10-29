package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/sysservices"
)

// #16737 (R3-A45-03): the gRPC renderer must retain the SSH row when
// `system services ssh` is absent, with the observed host state.
// RED pre-fix: no SSH row printed.
func TestShowSystemServicesSSHNotManaged16737(t *testing.T) {
	s := newActiveConfigServer(t)
	s.sshdStateFn = func() sysservices.SSHDState { return sysservices.SSHDRunning }
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	cfg.System.Services = &config.SystemServicesConfig{}

	var buf strings.Builder
	s.showSystemServices(context.Background(), &buf)
	out := buf.String()
	if !strings.Contains(out, "SSH:            running (not managed") {
		t.Errorf("gRPC renderer dropped the SSH row with no stanza; want the not-managed row:\n%s", out)
	}
}

// #16737: the row must also appear when System.Services itself is nil.
func TestShowSystemServicesSSHNotManagedNilServices16737(t *testing.T) {
	s := newActiveConfigServer(t)
	s.sshdStateFn = func() sysservices.SSHDState { return sysservices.SSHDRunning }
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	cfg.System.Services = nil

	var buf strings.Builder
	s.showSystemServices(context.Background(), &buf)
	if out := buf.String(); !strings.Contains(out, "SSH:            running (not managed") {
		t.Errorf("gRPC renderer dropped the SSH row with nil services:\n%s", out)
	}
}

// #16737 control: with the stanza present, the managed row is unchanged.
func TestShowSystemServicesSSHManagedControl16737(t *testing.T) {
	s := newActiveConfigServer(t)
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}

	var buf strings.Builder
	s.showSystemServices(context.Background(), &buf)
	out := buf.String()
	if !strings.Contains(out, "SSH:            enabled (root-login: deny)") {
		t.Errorf("gRPC managed SSH row changed:\n%s", out)
	}
	if strings.Contains(out, "not managed") {
		t.Errorf("gRPC renderer claimed not-managed with a stanza present:\n%s", out)
	}
}
