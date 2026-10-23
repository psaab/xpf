package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15944 H21-01 (show arm): the remote `show system backup-router`
// renderer read only the scalar first destination and hardcoded
// `Destination: 0.0.0.0/0 (default)` when absent, so a multi-prefix or
// IPv6 effective set could never be shown remotely. The local CLI
// (#15780) already renders every destination with a family-aware
// default; the gRPC renderer must agree.
//
// FAIL-ON-REVERT: restoring the scalar read drops the second prefix
// and mislabels the IPv6 default below.

func TestShowBackupRouterRendersAllDestinations15944(t *testing.T) {
	s := &Server{}
	cfg := &config.Config{}
	cfg.System.BackupRouter = "192.0.2.1"
	cfg.System.BackupRouterDsts = []string{"10.0.0.0/8", "172.16.0.0/12"}
	cfg.System.BackupRouterDst = "10.0.0.0/8"
	var buf strings.Builder
	s.showBackupRouter(cfg, &buf)
	out := buf.String()
	for _, want := range []string{"Backup router: 192.0.2.1", "  Destination: 10.0.0.0/8", "  Destination: 172.16.0.0/12"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}

	// IPv6 next-hop with no explicit destination: family-aware default.
	cfg6 := &config.Config{}
	cfg6.System.BackupRouter = "2001:db8::1"
	buf.Reset()
	s.showBackupRouter(cfg6, &buf)
	if !strings.Contains(buf.String(), "  Destination: ::/0 (default)") {
		t.Fatalf("IPv6 default output = %q, want ::/0 (default)", buf.String())
	}

	// Hand-built scalar-only config still renders its one prefix.
	cfgS := &config.Config{}
	cfgS.System.BackupRouter = "192.0.2.1"
	cfgS.System.BackupRouterDst = "10.0.0.0/8"
	buf.Reset()
	s.showBackupRouter(cfgS, &buf)
	if !strings.Contains(buf.String(), "  Destination: 10.0.0.0/8") {
		t.Fatalf("scalar output = %q, want the one destination", buf.String())
	}
}
